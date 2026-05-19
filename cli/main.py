# cli/main.py

import argparse
import sys
from pathlib import Path
from db.db import DB_PATH, init_db
from cli.formatter import print_header, print_status

def cmd_collect(args):
    from collectors.nvd_collector  import NVDCollector
    from collectors.otx_collector  import OTXCollector
    from collectors.rss_collector  import RSSCollector

    collectors = {
        "nvd": NVDCollector(),
        "otx": OTXCollector(),
        "rss": RSSCollector(),
    }
    targets = [args.source] if args.source != "all" else list(collectors.keys())
    db = Path(DB_PATH)

    print_header("COLLECT")
    for name in targets:
        col = collectors[name]
        mode = "keyword" if args.query else "time"
        kwargs = {"query": args.query} if args.query else {"days_back": args.days}
        ins, skip = col.collect_and_store(db, mode=mode, **kwargs)
        print_status(f"{name}: {ins} inserted, {skip} skipped", "ok")

def cmd_preprocess(args):
    print_header("PREPROCESS")
    from preprocessor.pipeline import run_preprocessing_batch
    run_preprocessing_batch()

def cmd_enrich(args):
    print_header("ENRICH")
    from enrichment.entity_extractor import extract_entities
    from enrichment.attack_mapper import map_ttps
    from db.queries                  import insert_entity
    from db.db                       import get_db_connection

    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT id, description FROM raw_items WHERE processed = 1"
        ).fetchall()

    for row in rows:
        source_id = row['id']
        text      = row['description'] or ''
        entities  = extract_entities(text)          # only takes text
        for e in entities:
            insert_entity(source_id, e.entity_type, e.entity_value)
        ttps = map_ttps(source_id, text)
        print_status(f"ID {source_id}: {len(entities)} entities, {len(ttps)} TTPs", "ok")

def cmd_report(args):
    print_header("GENERATE REPORTS")
    from enrichment.report_generator import generate_analyst_summary
    from db.db                       import get_db_connection
    from db.queries                  import insert_report

    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT ri.id, ri.description FROM raw_items ri
               LEFT JOIN reports r ON r.source_id = ri.id
               WHERE ri.processed = 1 AND r.id IS NULL"""
        ).fetchall()
        
        items = []
        for row in rows:
            sid = row['id']
            entities = [dict(e) for e in conn.execute(
                "SELECT entity_type, entity_value FROM entities WHERE source_id = ?", (sid,)
            ).fetchall()]
            ttps = [dict(t) for t in conn.execute(
                "SELECT ttp_id, technique_name FROM ttp_mappings WHERE source_id = ?", (sid,)
            ).fetchall()]
            items.append((sid, row['description'] or '', entities, ttps))

    for source_id, text, entities, ttps in items:
        summary = generate_analyst_summary(source_id, text, entities, ttps)
        insert_report(source_id, summary)
        print_status(f"Report generated for ID {source_id}", "ok")

def cmd_review(args):
    print_header("HUMAN-IN-THE-LOOP REVIEW")
    from cli.review_gate import run_review_gate
    run_review_gate()

def cmd_run_all(args):
    """Chain all stages end-to-end."""
    cmd_collect(args)
    cmd_preprocess(args)
    cmd_enrich(args)
    cmd_report(args)
    cmd_review(args)

def main():
    parser = argparse.ArgumentParser(
        prog="threatcli",
        description="LLM-Based Threat Intelligence Pipeline"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── collect ──────────────────────────────────────────────────
    p_col = sub.add_parser("collect", help="Fetch data from NVD / OTX / RSS")
    p_col.add_argument("--source", default="all",
                       choices=["nvd", "otx", "rss", "all"])
    p_col.add_argument("--days",   type=int, default=7,
                       help="Days back for time-based fetch")
    p_col.add_argument("--query",  type=str, default=None,
                       help="Keyword for keyword-based fetch")
    p_col.set_defaults(func=cmd_collect)

    # ── preprocess ───────────────────────────────────────────────
    p_pre = sub.add_parser("preprocess", help="Strip HTML, deduplicate, encapsulate")
    p_pre.set_defaults(func=cmd_preprocess)

    # ── enrich ───────────────────────────────────────────────────
    p_enr = sub.add_parser("enrich", help="Extract entities and map TTPs")
    p_enr.set_defaults(func=cmd_enrich)

    # ── report ───────────────────────────────────────────────────
    p_rep = sub.add_parser("report", help="Generate LLM analyst reports")
    p_rep.set_defaults(func=cmd_report)

    # ── review ───────────────────────────────────────────────────
    p_rev = sub.add_parser("review", help="Human-in-the-loop review gate")
    p_rev.set_defaults(func=cmd_review)

    # ── run-all ──────────────────────────────────────────────────
    p_all = sub.add_parser("run-all", help="Run full pipeline end-to-end")
    p_all.add_argument("--source", default="all",
                       choices=["nvd", "otx", "rss", "all"])
    p_all.add_argument("--days",   type=int, default=7)
    p_all.add_argument("--query",  type=str, default=None)
    p_all.set_defaults(func=cmd_run_all)

    args = parser.parse_args()

    # Ensure DB exists before any command runs
    init_db()
    args.func(args)

if __name__ == "__main__":
    main()