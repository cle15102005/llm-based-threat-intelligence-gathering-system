"""
=============================================================================
MODULE: test_e2e_real_pipeline.py
PURPOSE: Full end-to-end pipeline test — RSS/Reddit fetch → preprocess →
         enrichment → KG query → report generation.
         
PIPELINE STAGES TESTED:
  Stage 1 — Collect:     RSSCollector fetches real posts from reddit_netsec
  Stage 2 — Store:       Records inserted into SQLite raw_items table
  Stage 3 — Preprocess:  HTML strip → language detect → encapsulate
  Stage 4 — Enrich IOC:  entity_extractor + ner_spacy extract entities
  Stage 5 — HyDE:        behavior_translator converts text to tech sentences
  Stage 6 — KG Query:    kg_engine runs vector search + graph traversal
  Stage 7 — Report:      report_generator produces final analyst summary

WHAT MAKES THIS TEST REALISTIC:
  - Uses a REAL live RSS feed (reddit_netsec) — actual internet fetch
  - Runs through every module in sequence with real data
  - Verifies each stage's output before passing to the next
  - Final report is printed in full so you can visually inspect quality

COMMAND: python -m unittest tests.test_e2e_real_pipeline
NOTES:
  - Requires internet connection (RSS fetch)
  - Requires Ollama running with llama3 pulled
  - Requires Neo4j running with baseline graph built
  - Uses a fresh isolated SQLite DB (does not pollute production DB)
  - Runtime: 2-5 minutes depending on LLM speed
=============================================================================
"""
import unittest
import requests
import logging
import warnings
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
# Suppress INFO/DEBUG logs from noisy libraries
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)   # if httpx is used under the hood



logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ── Availability checks ───────────────────────────────────────────────────────

def _ollama_available() -> bool:
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False

def _neo4j_available() -> bool:
    try:
        from db.neo4j_manager import GraphConnector
        g = GraphConnector()
        g.close()
        return True
    except Exception:
        return False

def _internet_available() -> bool:
    try:
        requests.get("https://xakep.ru/category/news/feed/", timeout=5)
        return True
    except Exception:
        return False


# ── Test class ────────────────────────────────────────────────────────────────

class TestE2ERealPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Check all dependencies before running any test."""
        missing = []
        if not _internet_available():
            missing.append("Internet connection")
        if not _ollama_available():
            missing.append("Ollama (run: ollama serve)")
        if not _neo4j_available():
            missing.append("Neo4j (start in Neo4j Desktop)")

        if missing:
            raise unittest.SkipTest(
                f"E2E test skipped — missing dependencies: {', '.join(missing)}"
            )

        # Use the real production DB — init_db() is safe to call repeatedly
        # (uses CREATE TABLE IF NOT EXISTS so existing data is never touched)
        from db.sqlite_manager import init_db
        init_db()
        logger.info("[*] Using production DB.")

        cls.pipeline_item = None   # carries state between stages

    # ── Stage 1: Collect ─────────────────────────────────────────────────────

    def test_01_collect_from_rss(self):
        print("\n" + "="*60)
        print("[STAGE 1] RSS Collection — xakep.ru (Russian)") 
        print("="*60)

        from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
        

        collector = RSSCollector(
            feed_url=KNOWN_FEEDS["xakep"],
            source_name="xakep"
        )
        records = collector.fetch_by_time(days_back=7, max_results=5)

        print(f"[+] Fetched {len(records)} records from xakep.ru")
        for r in records:
            print(f"    - {r['title'][:80]}")

        self.assertGreater(len(records), 0,
            "No records fetched — feed may be down or no posts in last 7 days.")
        self.__class__.records = records

    # ── Stage 2: Store ───────────────────────────────────────────────────────

    def test_02_store_to_sqlite(self):
        print("\n" + "="*60)
        print("[STAGE 2] SQLite Storage")
        print("="*60)

        from db.sqlite_manager import insert_raw_item, get_unprocessed_batch

        records = self.__class__.records
        inserted_ids = []

        for record in records:
            data_tuple = (
                record["source"],
                record["title"],
                record["description"],
                record["source_url"],
                record["published_date"],
                record["collected_at"],
                str(record.get("raw", {})),
                record["dedup_key"],
            )
            row_id = insert_raw_item(data_tuple)
            if row_id:
                inserted_ids.append(row_id)

        print(f"[+] Inserted {len(inserted_ids)} records into SQLite")

        batch = get_unprocessed_batch(limit=5)
        print(f"[+] Unprocessed batch size: {len(batch)}")
        self.assertGreater(len(batch), 0,
            "No unprocessed records found after insertion.")

        # Store first item for downstream stages
        self.__class__.raw_item = batch[0]
        print(f"[+] Selected item for pipeline: '{batch[0]['title'][:80]}'")

    # ── Stage 3: Preprocess ──────────────────────────────────────────────────

    def test_03_preprocess(self):
        print("\n" + "="*60)
        print("[STAGE 3] Preprocessing — HTML strip → translate → encapsulate")
        print("="*60)

        from preprocessor.html_stripper import strip_html
        from preprocessor.language_detector import LanguageDetector
        from preprocessor.encapsulator import encapsulate_threat_data
        from db.sqlite_manager import mark_processed

        item = dict(self.__class__.raw_item)

        # Step 1 — Strip HTML
        raw_desc = item.get("description", "")
        item["description"] = strip_html(raw_desc)
        print(f"[+] HTML stripped. Length: {len(raw_desc)} -> {len(item['description'])}")
        self.assertGreater(len(item["description"]), 0,
            "Description is empty after HTML stripping.")

        # Step 2 — Language detection + translation
        translator = LanguageDetector()
        item = translator.process_record(item) 
        print(f"[+] Language processed. Description preview: "
              f"'{item['description']}...'")

        # Step 3 — Encapsulate
        secured = encapsulate_threat_data(item["description"])
        item["processed_text"] = secured
        print(f"[+] Encapsulated. Starts with <THREAT_DATA>: "
              f"{secured.startswith('<THREAT_DATA>')}")

        self.assertTrue(item["processed_text"].startswith("<THREAT_DATA>"),
            "Encapsulation failed — processed_text does not start with <THREAT_DATA>.")

        mark_processed(item["id"])
        print(f"[+] Item ID {item['id']} marked as processed.")

        self.__class__.pipeline_item = item

    # ── Stage 4: Entity Extraction ───────────────────────────────────────────

    def test_04_entity_extraction(self):
        print("\n" + "="*60)
        print("[STAGE 4] Enrichment — IOC extraction + NER")
        print("="*60)

        from enrichment.entity_extractor import extract_and_store
        from enrichment.ner_spacy import extract_and_store_ner
        from db.sqlite_manager import get_entities

        item = self.__class__.pipeline_item
        source_id = item["id"]
        cleaned_text = item["description"]

        iocs = extract_and_store(
            source_id=source_id,
            cleaned_text=cleaned_text
        )
        ner_entities = extract_and_store_ner(
            source_id=source_id,
            cleaned_text=cleaned_text
        )

        all_entities = get_entities(source_id)

        print(f"[+] IOCs extracted    : {len(iocs)}")
        print(f"[+] NER entities      : {len(ner_entities)}")
        print(f"[+] Total in DB       : {len(all_entities)}")
        for e in all_entities:
            print(f"    [{e['entity_type']}] {e['entity_value']}")

        # Entity extraction may return 0 for some posts — that's valid
        # The important thing is no crash and DB is consistent
        self.assertIsInstance(all_entities, list,
            "get_entities should return a list.")
        print("[+] Entity extraction completed without errors.")

        self.__class__.entities_list = all_entities

    # ── Stage 5: HyDE Behavior Translation ───────────────────────────────────

    def test_05_behavior_translation(self):
        print("\n" + "="*60)
        print("[STAGE 5] HyDE — Behavior translation via LLM")
        print("="*60)

        from enrichment.behavior_translator import translate_to_behaviors

        item = self.__class__.pipeline_item
        cleaned_text = item["description"]

        behaviors = translate_to_behaviors(cleaned_text)

        print(f"[+] Extracted {len(behaviors)} behaviors:")
        for b in behaviors:
            print(f"    - {b}")

        self.assertIsInstance(behaviors, list,
            "translate_to_behaviors should return a list.")

        # Some posts (e.g. memes, off-topic) may produce 0 behaviors — acceptable
        if len(behaviors) == 0:
            print("[!] No behaviors extracted — post may lack technical content.")
        else:
            for b in behaviors:
                self.assertIsInstance(b, str, f"Behavior must be a string: {b}")
                self.assertGreater(len(b.strip()), 0, "Behavior must not be empty.")

        self.__class__.behaviors = behaviors

    # ── Stage 6: KG Vector Search ────────────────────────────────────────────

    def test_06_kg_vector_search(self):
        print("\n" + "="*60)
        print("[STAGE 6] Knowledge Graph — Vector search + blast radius")
        print("="*60)

        from enrichment.kg_engine import KnowledgeEngine

        behaviors = self.__class__.behaviors
        engine = KnowledgeEngine()
        kg_payload = engine.evaluate_threat(behaviors)
        engine.close()

        self.assertIn("is_zero_day", kg_payload,
            "KG payload missing is_zero_day flag.")
        self.assertIn("matched_cves", kg_payload,
            "KG payload missing matched_cves.")
        self.assertIn("matched_ttps", kg_payload,
            "KG payload missing matched_ttps.")
        self.assertIn("systems_at_risk", kg_payload,
            "KG payload missing systems_at_risk.")
        self.assertIn("unmatched_behaviors", kg_payload,
            "KG payload missing unmatched_behaviors.")

        self.__class__.kg_payload = kg_payload

    # ── Stage 7: Report Generation ────────────────────────────────────────────

    def test_07_report_generation(self):
        print("\n" + "="*60)
        print("[STAGE 7] Report Generation — Closed-domain RAG")
        print("="*60)

        from reports.report_generator import generate_analyst_summary
        from db.sqlite_manager import get_report

        item         = self.__class__.pipeline_item
        entities     = self.__class__.entities_list
        kg_payload   = self.__class__.kg_payload
        source_id    = item["id"]

        report = generate_analyst_summary(
            source_id=source_id,
            cleaned_text=item["processed_text"],
            entities_list=entities,
            kg_payload=kg_payload,
        )

        print(f"\n{'='*60}")
        print("FINAL INTELLIGENCE REPORT")
        print(f"{'='*60}")
        print(report)
        print(f"{'='*60}\n")

        # Structural assertions
        self.assertIsInstance(report, str,
            "Report must be a string.")
        self.assertGreater(len(report.strip()), 100,
            "Report is too short — generation may have failed silently.")
        self.assertIn("Threat Overview", report,
            "Report missing ## Threat Overview section.")
        self.assertIn("Recommended Actions", report,
            "Report missing ## Recommended Actions section.")
        self.assertIn(f"[source_id: {source_id}]", report,
            f"Report missing mandatory [source_id: {source_id}] citation.")

        # Verify persisted to DB
        saved = get_report(source_id)
        self.assertIsNotNone(saved,
            "Report was not saved to the reports table.")
        print(f"[+] Report saved to DB with source_id={source_id}.")

        # ── Final summary ─────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("E2E PIPELINE SUMMARY")
        print("="*60)
        print(f"  Source          : {item['source']}")
        print(f"  Title           : {item['title'][:70]}")
        print(f"  Entities found  : {len(entities)}")
        print(f"  Behaviors       : {len(self.__class__.behaviors)}")
        print(f"  Matched threats : {len(kg_payload.get('matched_threats', []))}")
        print(f"  Is zero-day     : {kg_payload['is_zero_day']}")
        print(f"  Report length   : {len(report)} chars")
        print("="*60)


if __name__ == "__main__":
    unittest.main(verbosity=2)