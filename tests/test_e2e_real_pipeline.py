"""
=============================================================================
MODULE: test_e2e_real_pipeline.py
PURPOSE: Executes a full end-to-end test of the entire pipeline using real data.
HOW IT TESTS:   
1. Collects recent data from RSS, NVD, and OTX sources.
2. Runs the preprocessing pipeline on the collected data.   
3. Extracts entities using both regex and spaCy methods.
4. Maps the cleaned text to MITRE TTPs using a local LLM (Llama 3).
5. Generates and prints the final RAG report.     
COMMAND: python -m unittest tests.test_e2e_real_pipeline
=============================================================================
"""
import unittest
import os
import sqlite3
from dotenv import load_dotenv

# Load API Keys before initializing collectors
load_dotenv() 

from db.db import init_db, DB_PATH
from collectors.rss_collector import RSSCollector
from collectors.nvd_collector import NVDCollector
from collectors.otx_collector import OTXCollector

from preprocessor.pipeline import run_preprocessing_batch
from enrichment.entity_extractor import extract_and_store
from enrichment.ner_spacy import extract_and_store_ner
from enrichment.attack_mapper import map_text_to_mitre
from enrichment.report_generator import generate_analyst_summary

class TestEndToEndRealPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*60)
        print("[*] INITIALIZING FULL END-TO-END PIPELINE TEST (3 SOURCES)")
        print("="*60)
        
        # Reset DB for a clean state
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()

    def test_full_pipeline(self):
        # ---------------------------------------------------------
        # PHASE 1: COLLECT DATA FROM ALL 3 SOURCES
        # ---------------------------------------------------------
        print("\n[PHASE 1] COLLECTING REAL DATA FROM RSS, NVD, OTX...")
        collectors = [
            RSSCollector(),
            NVDCollector(),
            OTXCollector()
        ]
        
        all_raw_items = []
        for col in collectors:
            print(f" -> Fetching from {col.source_name}...")
            # Fetch 1 recent record from each source to test the integration
            items = col.fetch_by_time(days_back=7, max_results=2)
            all_raw_items.extend(items)
            
        self.assertTrue(len(all_raw_items) > 0, "No data found from any source.")
        
        # Insert the fetched data directly into the DB to simulate the collector process
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        for item in all_raw_items:
            try:
                conn.execute(
                    """INSERT INTO raw_items (source, title, description, source_url, published_date, collected_at, processed, raw, dedup_key) 
                       VALUES (:source, :title, :description, :source_url, :published_date, :collected_at, :processed, '{}', :dedup_key)""",
                    item
                )
            except sqlite3.IntegrityError: 
                pass # Ignore duplicates if any
        conn.commit()
        conn.close()
        print(f" -> Inserted {len(all_raw_items)} combined articles into Database.")

        # ---------------------------------------------------------
        # PHASE 2: PREPROCESSING
        # ---------------------------------------------------------
        print("\n[PHASE 2] PREPROCESSING & SANITIZATION...")
        # Process 1 item to verify the pipeline flow
        processed_batch = run_preprocessing_batch(batch_size=6)
        self.assertEqual(len(processed_batch), 6)
        
# ---------------------------------------------------------
# LOOP FOR EACH PROCESSED ITEM TO EXTRACT ENTITIES, MAP TTPs, AND GENERATE FINAL REPORT
# ---------------------------------------------------------
        for target_item in processed_batch:
            source_id = target_item["source_id"]
            cleaned_text = target_item["cleaned_text"]
            secured_text = target_item["secured_text"] 
            
            print("\n" + "="*60)
            print(f"[*] PROCESSING ARTICLE ID {source_id}: {target_item['title']}")
            print("="*60)

            # ---------------------------------------------------------
            # PHASE 3: ENRICHMENT (Regex & spaCy) - EXTRACT ENTITIES
            # ---------------------------------------------------------
            
            print("[PHASE 3] EXTRACTING ENTITIES...")
            hard_iocs = extract_and_store(source_id=source_id, cleaned_text=cleaned_text)
            soft_entities = extract_and_store_ner(source_id=source_id, cleaned_text=cleaned_text)
            
            all_entities = hard_iocs + soft_entities
            
            print(f" -> Found {len(hard_iocs)} Hard IOCs (IP/Hash/CVE)")
            print(f" -> Found {len(soft_entities)} Soft Entities (Actors/Malware)")

            # ----------------------------------------------------------
            # PHASE 4: LLM MAPPING & REPORTING (Llama 3)
            # ----------------------------------------------------------

            print("\n[PHASE 4] FIRING UP LOCAL LLM (LLAMA 3)...")

            # Find valid TTPs and save to DB
            mapped_ttps = map_text_to_mitre(source_id=source_id, cleaned_text=secured_text)
            print(f" -> Identified {len(mapped_ttps)} valid TTPs.")

            # Generate final report based on all extracted info (entities + TTPs), cite source_id for traceability
            final_report = generate_analyst_summary(
                source_id=source_id,
                cleaned_text=cleaned_text,
                entities_list=[{"type": e.entity_type, "value": e.entity_value} for e in all_entities],
                ttp_list=mapped_ttps
            )

            print("\n" + "*"*70)
            print(f"[FINAL CYBER THREAT INTELLIGENCE REPORT - ID {source_id}]")
            print("*"*70)
            print(final_report)
            print("*"*70 + "\n")
            
            # Kiểm tra xem AI có tuân thủ format cho TỪNG báo cáo hay không
            self.assertIn(f"[source_id: {source_id}]", final_report, f"LLM failed to cite the source_id for article {source_id}.")

if __name__ == '__main__':
    unittest.main(verbosity=2)