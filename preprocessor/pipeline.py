"""
FILE: preprocessor/pipeline.py
ROLE: Data Sanitization Orchestrator
PURPOSE: Retrieves raw records from the database, sanitizes HTML, detects/translates 
language, encapsulates the text for prompt injection defense, and marks items as processed. 
NO LLM INFERENCE OCCURS HERE. The sanitized data is passed to the Enrichment layer.
"""
import logging
import sys

# Import the 3 core preprocessing components
from db.sqlite_manager import store_processed_description
from preprocessor.html_stripper import strip_html
from preprocessor.language_detector import LanguageDetector
from preprocessor.encapsulator import encapsulate_threat_data

# Corrected import: DB manager functions live in sqlite_manager.py
try:
    from db.sqlite_manager import get_unprocessed_batch, mark_processed
except ImportError as e:
    print(f"Database import failed: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def run_preprocessing_batch(batch_size: int = 1) -> list:
    """
    Executes the preprocessing pipeline for a specific batch size.
    Returns a list of dictionaries containing the sanitized items.
    """
    logger.info(f"[*] Waking up Preprocessor. Fetching batch of {batch_size}...")
    
    # Initialize the Language Detector (Component 2)
    translator = LanguageDetector()
    
    # Step 1: Pulls a new raw_text batch from the SQLite database
    raw_items = get_unprocessed_batch(limit=batch_size)
    processed_items = []
    
    for item in raw_items:
        # Extract the raw text (fallback to empty string if missing)
        raw_text = item.get('description') or ""
        
        try:
            # Step 2: Clean HTML from the description field
            item['description'] = strip_html(raw_text)
            
            # Step 3: process_record() detects language on item['description']
            # and translates it in-place if non-English
            item = translator.process_record(item)
            
            # Step 4: Encapsulate the now-clean, English description
            secured_string = encapsulate_threat_data(item['description'])
            
            item['processed_text'] = secured_string
            # store_processed_description(item['id'], item['description'])  # Update the DB with the cleaned description
            store_processed_description(item['id'], item['description'])
            
            # Sanity-check: downstream enrichment must use processed_text, not description
            assert item['processed_text'].startswith("<THREAT_DATA>"), (
                f"Encapsulation failed for item ID {item['id']} — "
                "pass item['processed_text'] to the enrichment layer, not item['description']"
            )
            processed_items.append(item)
            
            mark_processed(item['id'])
            logger.info(f"[+] Successfully processed item ID: {item['id']}")
            
        except Exception as e:
            logger.error(f"[-] Failed to process item ID: {item['id']}. Error: {e}")
            continue
            
    return processed_items

