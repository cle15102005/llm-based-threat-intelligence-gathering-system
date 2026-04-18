import sqlite3
import os
from contextlib import contextmanager

# Define paths for the database and schema files
DB_PATH = os.path.join(os.path.dirname(__file__), 'threat_intel.db')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schema.sql')

@contextmanager
def get_db_connection():
    """
    Context manager to handle SQLite database connections safely.
    It automatically closes the connection and commits transactions.
    It also uses row_factory so query results behave like Python dictionaries.
    """
    conn = None
    try:
        # Establish connection
        conn = sqlite3.connect(DB_PATH)
        
        # Enable dictionary-like access to rows (e.g., row['title'])
        conn.row_factory = sqlite3.Row
        
        # Enforce Foreign Key constraints (SQLite disables them by default)
        conn.execute("PRAGMA foreign_keys = ON;")
        
        # Yield connection to the calling block
        yield conn
        
        # Commit automatically if no exceptions occur
        conn.commit()
        
    except sqlite3.Error as e:
        # Rollback changes if a database error happens
        if conn:
            conn.rollback()
        print(f"[!] Database Connection Error: {e}")
        raise
        
    finally:
        # Always close the connection to prevent file locking
        if conn:
            conn.close()

def init_db():
    """
    Reads schema.sql and initializes the database tables if they do not exist.
    """
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"Schema file missing at: {SCHEMA_PATH}")

    print("[*] Initializing SQLite Database...")
    with get_db_connection() as conn:
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            schema_script = f.read()
            conn.executescript(schema_script)
    print("[+] Database tables are ready.")

# Run this file directly to create the database initially
if __name__ == '__main__':
    init_db()