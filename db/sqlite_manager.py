import sqlite3
import logging
from pathlib import Path
from contextlib import contextmanager
from db.queries import (
    GET_POST_DATE,
    GET_SOURCE_URL,
    INSERT_RAW_ITEM, 
    GET_UNPROCESSED_BATCH, 
    MARK_PROCESSED, 
    REMARK_PROCESSED,
    INSERT_ENTITY, 
    INSERT_REPORT,
    GET_ENTITIES_BY_SOURCE,
    GET_REPORT,
    STORE_PROCESSED_ITEM_DESCRIPTION
)

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "threat_intel.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

@contextmanager
def get_db_connection():
    """Provides a safe connection context for SQLite, yielding dictionary-like rows."""
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()

def init_db():
    """Reads schema.sql and initializes the database tables during system boot."""
    if not SCHEMA_PATH.exists():
        logger.error(f"Schema file not found at {SCHEMA_PATH}")
        return

    with open(SCHEMA_PATH, "r") as f:
        schema_script = f.read()

    with get_db_connection() as conn:
        conn.executescript(schema_script)
    logger.info("SQLite database initialized successfully.")

def insert_raw_item(data: tuple) -> int:
    """Inserts a scraped OSINT post. Returns the primary key ID (existing row if duplicate)."""
    with get_db_connection() as conn:
        cursor = conn.execute(INSERT_RAW_ITEM, data)
        if cursor.lastrowid:
            return cursor.lastrowid
        # INSERT OR IGNORE skipped a duplicate — fetch the existing row's ID - the row that has the same dedup_key
        cursor2 = conn.execute(
            "SELECT id FROM raw_items WHERE dedup_key = ?", (data[-1],)
        )
        row = cursor2.fetchone()
        return row["id"] if row else 0

def store_processed_description(item_id: int, description: str):
    """Updates the description field of a raw item after HTML stripping and translation."""
    with get_db_connection() as conn:
        conn.execute(STORE_PROCESSED_ITEM_DESCRIPTION, (description, item_id))
    
def get_post_date(item_id: int) -> str:
    """Fetches the published date of a raw item by its ID."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_POST_DATE, (item_id,))
        row = cursor.fetchone()
        return row["published_date"] if row else "Unknown"
    
def get_source_url(item_id: int) -> str:
    """Fetches the source URL of a raw item by its ID."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_SOURCE_URL, (item_id,))
        row = cursor.fetchone()
        return row["source_url"] if row else "Unknown"

def get_unprocessed_batch(limit: int = 10) -> list:
    """Fetches raw records for the preprocessing pipeline to sanitize."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_UNPROCESSED_BATCH, (limit,))
        return [dict(row) for row in cursor.fetchall()]

def count_unprocessed_items() -> int:
    """Counts the number of unprocessed items in the database."""
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) as count FROM raw_items WHERE processed = 0")
        row = cursor.fetchone()
        return row["count"] if row else 0
    
def count_preprocessed_unenriched_items() -> int:
    """Counts the number of items that have been preprocessed but not yet enriched/reported."""
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) as count FROM raw_items LEFT JOIN reports ON raw_items.id = reports.source_id WHERE raw_items.processed = 1 AND reports.id IS NULL")
        row = cursor.fetchone()
        return row["count"] if row else 0

def mark_processed(item_id: int):
    """Flags a raw item as securely sanitized and ready for enrichment."""
    with get_db_connection() as conn:
        conn.execute(MARK_PROCESSED, (item_id,))

def remark_processed(item_id: int):
    """Resets the processed status of a raw item."""
    with get_db_connection() as conn:
        conn.execute(REMARK_PROCESSED, (item_id,))

def insert_entity(source_id: int, entity_type: str, entity_value: str):
    """Stores hard IOCs or soft entities extracted via regex/spaCy."""
    with get_db_connection() as conn:
        conn.execute(INSERT_ENTITY, (source_id, entity_type, entity_value))

def get_entities(source_id: int) -> list:
    """Retrieves all entities associated with a specific raw item."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_ENTITIES_BY_SOURCE, (source_id,))
        return [dict(row) for row in cursor.fetchall()]

def insert_report(data: tuple):
    """Saves the final generated LLM intelligence report."""
    with get_db_connection() as conn:
        conn.execute(INSERT_REPORT, data)

def get_report(source_id: int) -> dict:
    """Fetches a saved report by its source ID."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_REPORT, (source_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
def get_pending_reports() -> list:
    """Fetches all reports that are pending human review."""
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM reports WHERE status = 'pending'")
        return [dict(row) for row in cursor.fetchall()]
    
def update_report_status(report_id: int, new_status: str):
    """Updates the status of a specific report."""
    with get_db_connection() as conn:
        conn.execute("UPDATE reports SET status = ? WHERE id = ?", (new_status, report_id))

def delete_report(report_id: int):
    """Deletes a report from the database, used for cleanup after reprocessing."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))

if __name__ == "__main__":
    remark_processed(3)
    delete_report(3)