# cli/pipeline_runner.py
"""
Pipeline orchestration and parallel collection for the threat-intel CLI.

Responsibilities
----------------
  COLLECTOR_REGISTRY  — maps source keys to (label, factory_fn) pairs.
                        Factory functions create fresh instances per thread.
  SOURCE_MENU_ORDER   — ordered list for interactive menu display.
  collect_parallel()  — runs N collectors concurrently via ThreadPoolExecutor.
  run_preprocess()    — thin wrapper around preprocessor.pipeline.
  run_enrich()        — regex IOC extraction + spaCy NER.
  run_report()        — behavior translation → KG query → LLM summarisation.
  reprocess_item()    — reset + re-run enrichment for a single item.
  run_full_pipeline() — chains all stages end-to-end.

Thread-safety note
------------------
Each worker creates its own collector instance AND its own SQLite connection
(sqlite_manager uses a context-manager that opens/closes per call), so
concurrent writes are safe under SQLite's default journal-mode locking.
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from pathlib import Path
from typing import Any, Callable

from cli.formatter import print_header, print_status

logger = logging.getLogger(__name__)


# ── Collector registry ────────────────────────────────────────────────────────

def _factory_nvd() -> Any:
    from collectors.nvd_collector import NVDCollector
    return NVDCollector()

def _factory_otx() -> Any:
    from collectors.otx_collector import OTXCollector
    return OTXCollector()

def _factory_exploitdb() -> Any:
    from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
    return RSSCollector(feed_url=KNOWN_FEEDS["exploitdb"], source_name="exploitdb")

def _factory_bleeping() -> Any:
    from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
    return RSSCollector(feed_url=KNOWN_FEEDS["bleeping_computer"], source_name="bleeping_computer")

def _factory_sans() -> Any:
    from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
    return RSSCollector(feed_url=KNOWN_FEEDS["sans_isc"], source_name="sans_isc")

def _factory_xakep():
    from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
    return RSSCollector(feed_url=KNOWN_FEEDS["xakep"], source_name="xakep")

def _factory_reddit_netsec() -> Any:
    from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
    return RSSCollector(feed_url=KNOWN_FEEDS["reddit_netsec"], source_name="reddit_netsec")

def _factory_reddit_cybersec() -> Any:
    from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
    return RSSCollector(feed_url=KNOWN_FEEDS["reddit_cybersecurity"], source_name="reddit_cybersecurity")


# Registry: source_key -> (display_label, factory_fn)
COLLECTOR_REGISTRY: dict[str, tuple[str, Callable]] = {
    "nvd":                  ("NVD  — CVE Database",           _factory_nvd),
    "otx":                  ("OTX  — AlienVault Pulses",      _factory_otx),
    "exploitdb":            ("RSS  — Exploit-DB",             _factory_exploitdb),
    "bleeping_computer":    ("RSS  — BleepingComputer",       _factory_bleeping),
    "sans_isc":             ("RSS  — SANS ISC",               _factory_sans),
    "xakep":                ("RSS  — Xakep",                  _factory_xakep),
    "reddit_netsec":        ("RSS  — Reddit r/netsec",        _factory_reddit_netsec),
    "reddit_cybersecurity": ("RSS  — Reddit r/cybersecurity", _factory_reddit_cybersec),
}

# Canonical order for menu display and "all" expansion
SOURCE_MENU_ORDER: list[str] = [
    "reddit_netsec",
    "reddit_cybersecurity",
    "exploitdb",
    "bleeping_computer",
    "sans_isc",
    "xakep", 
    "nvd",
    "otx",
]


# ── Parallel collection ───────────────────────────────────────────────────────

def _collection_worker(
    label:    str,
    factory:  Callable,
    db_path:  Path,
    mode:     str,
    kwargs:   dict,
) -> tuple[str, int, int, str | None]:
    """Thread-pool worker — collector instance created inside worker thread."""
    try:
        collector         = factory()
        inserted, skipped = collector.collect_and_store(db_path, mode=mode, **kwargs)
        return (label, inserted, skipped, None)
    except Exception as exc:
        return (label, 0, 0, str(exc))


def collect_parallel(
    source_keys: list[str],
    db_path:     Path,
    mode:        str = "time",
    max_workers: int = 4,
    **fetch_kwargs,
) -> dict[str, tuple[int, int]]:
    """
    Collect from multiple sources concurrently using ThreadPoolExecutor.

    Args:
        source_keys  : list of COLLECTOR_REGISTRY keys, or ["all"].
        db_path      : SQLite database file path.
        mode         : "time" or "keyword".
        max_workers  : concurrent thread cap (default 4).
        **fetch_kwargs : forwarded to each collector's fetch method.

    Returns:
        {source_key: (inserted, skipped)}
    """
    if "all" in source_keys:
        source_keys = SOURCE_MENU_ORDER[:]

    valid_tasks = [
        (key, *COLLECTOR_REGISTRY[key])
        for key in source_keys
        if key in COLLECTOR_REGISTRY
    ]
    for key in source_keys:
        if key not in COLLECTOR_REGISTRY and key != "all":
            print_status(f"Unknown source key '{key}' — skipped.", "warn")

    if not valid_tasks:
        print_status("No valid sources to collect from.", "warn")
        return {}

    print_status(
        f"Launching parallel collection from {len(valid_tasks)} source(s) "
        f"[mode={mode}] ...",
        "info",
    )
    t0 = time.perf_counter()
    results: dict[str, tuple[int, int]] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(valid_tasks), max_workers),
        thread_name_prefix="collector",
    ) as pool:
        future_to_key = {
            pool.submit(
                _collection_worker, label, factory, db_path, mode, fetch_kwargs
            ): key
            for (key, label, factory) in valid_tasks
        }

        for future in concurrent.futures.as_completed(future_to_key):
            key                   = future_to_key[future]
            label, ins, skip, err = future.result()
            if err:
                print_status(f"{label}: FAILED — {err}", "error")
                results[key] = (0, 0)
            else:
                print_status(f"{label}: {ins} inserted, {skip} skipped", "ok")
                results[key] = (ins, skip)

    elapsed    = time.perf_counter() - t0
    total_ins  = sum(v[0] for v in results.values())
    total_skip = sum(v[1] for v in results.values())
    print_status(
        f"Collection complete — {total_ins} new items, "
        f"{total_skip} duplicates skipped  [{elapsed:.1f}s]",
        "ok",
    )
    return results


# ── Stage 2: Preprocess ───────────────────────────────────────────────────────

def run_preprocess(batch_size: int = 10) -> int:
    """
    HTML stripping > language detection > XML encapsulation > mark processed.

    Loops in batches until no unprocessed items remain.
    The original single-call approach left items behind whenever
    more than batch_size records were collected in one run.

    Returns total items preprocessed.
    """
    print_header("PREPROCESS")
    try:
        from preprocessor.pipeline import run_preprocessing_batch
    except ImportError:
        print_status("preprocessor.pipeline not found — skipping.", "warn")
        return 0

    total = 0
    while True:
        try:
            processed = run_preprocessing_batch(batch_size=batch_size)
            count = len(processed)
            total += count
            if count == 0:
                break
            print_status(
                f"Batch complete: {count} items preprocessed ({total} total).", "ok"
            )
        except Exception as exc:
            print_status(f"Preprocessing error: {exc}", "error")
            logger.exception("Preprocessing stage failed")
            break

    print_status(f"Preprocessing complete — {total} items processed this run.", "ok")
    return total



# ── Stage 3: Enrich ──────────────────────────────────────────────────────────

def run_enrich(source_id: int | None = None) -> tuple[int, dict[int, dict]]:
    """
    Regex IOC extraction + spaCy NER + behavior translation + KG query.

    Args:
        source_id : enrich only this item when provided; all processed items otherwise.

    Returns:
        (total_entities, kg_payloads)   where kg_payloads is {source_id: payload_dict}
    """
    print_header("ENRICH")
    from enrichment.entity_extractor import extract_and_store
    from enrichment.ner_spacy import extract_and_store_ner
    from db.sqlite_manager import get_db_connection, get_entities
    from preprocessor.encapsulator import encapsulate_threat_data

    with get_db_connection() as conn:
        if source_id is not None:
            rows = conn.execute(
                "SELECT id, description FROM raw_items WHERE processed = 1 AND id = ?",
                (source_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT ri.id, ri.description
                   FROM raw_items ri
                   WHERE ri.processed = 1
                     AND NOT EXISTS (
                         SELECT 1 FROM entities e WHERE e.source_id = ri.id
                     )"""
            ).fetchall()

    if not rows:
        print_status("No new items to enrich.", "info")
        return 0, {}

    print_status(f"Enriching {len(rows)} new item(s) ...", "info")

    total = 0
    kg_payloads: dict[int, dict] = {}

    for row in rows:
        sid  = row["id"]
        text = row["description"] or ""

        # ── Stage 3a: Regex IOC extraction ───────────────────────────────────
        try:
            extract_and_store(source_id=sid, cleaned_text=text)
        except Exception as exc:
            logger.warning("entity_extractor failed for id=%d: %s", sid, exc)

        # ── Stage 3b: spaCy NER ───────────────────────────────────────────────
        try:
            extract_and_store_ner(source_id=sid, cleaned_text=text)
        except Exception as exc:
            logger.warning("ner_spacy failed for id=%d: %s", sid, exc)

        n      = len(get_entities(sid))
        total += n
        print_status(f"ID {sid}: {n} entities stored", "ok")

        # ── Stage 3c: Behavior translation + KG query ─────────────────────────
        # Encapsulate before passing to _run_kg_stage (same guard as run_report)
        encapsulated = (
            text if text.strip().startswith("<THREAT_DATA>")
            else encapsulate_threat_data(text)
        )
        payload = _run_kg_stage(encapsulated)
        kg_payloads[sid] = payload
        print_status(
            f"ID {sid}: KG — "
            f"{len(payload.get('matched_cves', []))} CVEs, "
            f"{len(payload.get('matched_ttps', []))} TTPs, "
            f"zero-day={payload.get('is_zero_day')}",
            "ok",
        )

    return total, kg_payloads

# ── Stage 4: Report ───────────────────────────────────────────────────────────

def run_report(
    source_id:   int | None        = None,
    kg_payloads: dict[int, dict] | None = None,   # ← new optional parameter
) -> int:
        
    """
    LLM report generation.

    Args:
        source_id   : generate only for this item when provided.
        kg_payloads : pre-computed KG results from run_enrich().
                      Falls back to inline _run_kg_stage() when absent
                      (preserves standalone `python -m cli.main report` behaviour).
    
    Returns:
        Number of reports generated.
    """
    print_header("GENERATE REPORTS")
    from reports.report_generator import generate_analyst_summary
    from db.sqlite_manager import get_db_connection, get_entities
    from preprocessor.encapsulator import encapsulate_threat_data

    with get_db_connection() as conn:
        if source_id is not None:
            rows = conn.execute(
                """SELECT ri.id, ri.description
                   FROM raw_items ri
                   LEFT JOIN reports r ON r.source_id = ri.id
                   WHERE ri.processed = 1 AND r.id IS NULL AND ri.id = ?""",
                (source_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT ri.id, ri.description
                   FROM raw_items ri
                   LEFT JOIN reports r ON r.source_id = ri.id
                   WHERE ri.processed = 1 AND r.id IS NULL"""
            ).fetchall()

    generated = 0
    for row in rows:
        sid  = row["id"]
        text = row["description"] or ""

        if not text.strip().startswith("<THREAT_DATA>"):
            text = encapsulate_threat_data(text)

        entities = get_entities(sid)

        # Use pre-computed payload from enrich stage when available;
        # otherwise compute inline (standalone call or item missed by enrich)
        if kg_payloads is not None and sid in kg_payloads:
            kg_payload = kg_payloads[sid]
            print_status(f"ID {sid}: using pre-computed KG payload", "info")
        else:
            kg_payload = _run_kg_stage(text)

        try:
            generate_analyst_summary(
                source_id=sid,
                cleaned_text=text,
                entities_list=entities,
                kg_payload=kg_payload,
            )
            print_status(f"Report generated for ID {sid}", "ok")
            generated += 1
        except Exception as exc:
            print_status(f"Report failed for ID {sid}: {exc}", "error")
            logger.error("report_generator failed for id=%d: %s", sid, exc)

    return generated



# ── Reprocess single item ─────────────────────────────────────────────────────

def reprocess_item(source_id: int) -> None:
    """
    Reset a single item to unprocessed and re-run the full enrichment chain.
    Use after improving prompts or NER patterns without re-collecting.

    Sequence: remark_processed → preprocess → enrich → report
    """
    from db.sqlite_manager import remark_processed

    print_status(f"Resetting item {source_id} to unprocessed ...", "info")
    remark_processed(source_id)

    run_preprocess()
    _, kg_payloads = run_enrich(source_id=source_id)
    run_report(source_id=source_id, kg_payloads=kg_payloads)

    print_status(f"Reprocessing complete for item {source_id}.", "ok")


# ── Full pipeline ─────────────────────────────────────────────────────────────

def run_full_pipeline(
    source_keys: list[str],
    db_path:     Path,
    mode:        str  = "time",
    run_review:  bool = True,
    **fetch_kwargs,
) -> None:
    """
    Chain all pipeline stages end-to-end.

    Stages: collect_parallel → preprocess → enrich → report → (optional) review_gate
    """
    print_header("FULL PIPELINE")

    collect_parallel(source_keys, db_path, mode=mode, **fetch_kwargs)
    run_preprocess()
    _, kg_payloads = run_enrich()           # unpack: (total_entities, payloads)
    run_report(kg_payloads=kg_payloads)

    if run_review:
        from cli.review_gate import run_review_gate
        run_review_gate()


# ── Internal KG helper ────────────────────────────────────────────────────────

def _run_kg_stage(text: str) -> dict:
    """
    Run HyDE behavior translation and Neo4j vector search.
    Returns a safe empty payload on any failure.
    """
    _empty: dict = {
        "matched_cves": [], "matched_ttps": [], "systems_at_risk": [],
        "unmatched_behaviors": [], "is_zero_day": False,
    }

    try:
        from enrichment.behavior_translator import translate_to_behaviors
        behaviors = translate_to_behaviors(text)
    except Exception as exc:
        logger.warning("behavior_translator unavailable (%s) — skipping KG stage.", exc)
        return _empty

    if not behaviors:
        return _empty

    try:
        from enrichment.kg_engine import KnowledgeEngine
        engine  = KnowledgeEngine()
        payload = engine.evaluate_threat(behaviors)
        engine.close()
        return payload
    except Exception as exc:
        logger.warning("kg_engine unavailable (%s) — returning empty KG payload.", exc)
        return _empty
