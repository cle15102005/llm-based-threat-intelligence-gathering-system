import yaml
import logging
import argparse
import sys
from preprocessor.html_stripper import strip_html
from preprocessor.deduplicator import Deduplicator
from preprocessor.encapsulator import build_langchain_prompt

try:
    from db.queries import get_unprocessed_batch, mark_processed
except ImportError:
    def get_unprocessed_batch(limit):
        return []
    def mark_processed(item_id):
        pass

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def load_settings(config_path):
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logger.error(f"Config file {config_path} not found.")
        sys.exit(1)

def run_pipeline():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='settings.yaml')
    args = parser.parse_args()

    settings = load_settings(args.config)
    batch_size = settings.get('preprocessing', {}).get('batch_size', 50)
    
    logger.info(f"Starting pipeline with batch size: {batch_size}")

    raw_items = get_unprocessed_batch(limit=batch_size)
    if not raw_items:
        logger.info("No unprocessed items found.")
        return

    dedup = Deduplicator()
    processed_count = 0
    skipped_count = 0

    for item in raw_items:
        item_id = item.get('id')
        content = item.get('description', '')
        cve_id = item.get('cve_id', '')

        clean_text = strip_html(content)

        if dedup.is_duplicate(clean_text, cve_id):
            logger.info(f"Skipping duplicate: ID {item_id}")
            skipped_count += 1
            mark_processed(item_id)
            continue

        messages = build_langchain_prompt(clean_text)
        
        mark_processed(item_id)
        processed_count += 1

    logger.info(f"Completed. Processed: {processed_count}, Skipped: {skipped_count}")

if __name__ == '__main__':
    run_pipeline()