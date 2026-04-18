import json
import datetime
from db.db import get_db_connection

# =====================================================================
# MODULE 1: DATA COLLECTION 
# =====================================================================

def insert_raw_item(data_dict: dict) -> int:
    """
    Inserts a newly scraped threat report into the raw_items table.
    Returns the inserted row ID, or None if it's a duplicate.
    """
    sql = """
        INSERT OR IGNORE INTO raw_items 
        (source, title, description, source_url, published_date, collected_at, processed, raw, dedup_key)
        VALUES (?,?,?,?,?,?,?,?,?)
    """
    # Convert 'raw' dictionary to a JSON string for SQLite storage
    raw_str = json.dumps(data_dict.get('raw', {}))
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, (
            data_dict.get('source'),
            data_dict.get('title'),
            data_dict.get('description'),
            data_dict.get('source_url'),
            data_dict.get('published_date'),
            data_dict.get('collected_at'),
            data_dict.get('processed', 0),
            raw_str,
            data_dict.get('dedup_key')
        ))
        return cursor.lastrowid

# =====================================================================
# MODULE 2: PREPROCESSING 
# =====================================================================

def get_unprocessed_batch(batch_size: int = 10) -> list:
    """
    Fetches a batch of raw_items that haven't been cleaned yet (processed=0).
    Returns a list of dictionaries.
    """
    sql = "SELECT * FROM raw_items WHERE processed = 0 LIMIT?"
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, (batch_size,))
        # Convert sqlite3.Row objects into standard Python dictionaries
        return [dict(row) for row in cursor.fetchall()]

def mark_processed(item_id: int):
    """
    Flags a raw item as processed (=1) so it won't be picked up again.
    """
    sql = "UPDATE raw_items SET processed = 1 WHERE id =?"
    with get_db_connection() as conn:
        conn.execute(sql, (item_id,))

# =====================================================================
# MODULE 3: ENRICHMENT & LLM MAPPING 
# =====================================================================

def insert_entity(source_id: int, entity_type: str, entity_value: str):
    """
    Saves an extracted IOC (IP, Hash, CVE) to the entities table.
    """
    sql = "INSERT INTO entities (source_id, entity_type, entity_value) VALUES (?,?,?)"
    with get_db_connection() as conn:
        conn.execute(sql, (source_id, entity_type, entity_value))

def insert_ttp_mapping(source_id: int, ttp_id: str, technique_name: str):
    """
    Saves a MITRE ATT&CK TTP mapped by the LLM to the ttp_mappings table.
    """
    sql = "INSERT INTO ttp_mappings (source_id, ttp_id, technique_name) VALUES (?,?,?)"
    with get_db_connection() as conn:
        conn.execute(sql, (source_id, ttp_id, technique_name))

def insert_report(source_id: int, summary: str):
    """
    Saves the final LLM-generated analyst summary into the reports table.
    Default status is 'pending' for the Human-In-The-Loop review.
    """
    sql = "INSERT INTO reports (source_id, summary, status, created_at) VALUES (?,?, 'pending',?)"
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    with get_db_connection() as conn:
        conn.execute(sql, (source_id, summary, created_at))

# =====================================================================
# MODULE 4: HUMAN-IN-THE-LOOP CLI 
# =====================================================================

def update_report_status(source_id: int, status: str):
    """
    Updates the report status based on analyst input ('approved', 'rejected').
    """
    sql = "UPDATE reports SET status =? WHERE source_id =?"
    with get_db_connection() as conn:
        conn.execute(sql, (status, source_id))