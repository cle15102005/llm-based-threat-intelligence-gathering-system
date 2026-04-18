-- ==============================================================================
-- Database Schema for LLM-Based Threat Intelligence Gathering System
-- ==============================================================================

-- 1. Table for storing raw scraped data from collectors (NVD, OTX, RSS)
CREATE TABLE IF NOT EXISTS raw_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,               -- Source name (e.g., 'NVD', 'AlienVault')
    title TEXT,                         -- Title of the article/threat
    description TEXT,                   -- Main content or summary
    source_url TEXT,                    -- Original URL
    published_date TEXT,                -- Publication date
    collected_at TEXT NOT NULL,         -- UTC timestamp of collection
    processed INTEGER DEFAULT 0,        -- 0 = Unprocessed, 1 = Cleaned & Encapsulated
    raw TEXT,                           -- Full raw JSON or HTML (stored as string)
    dedup_key TEXT UNIQUE               -- Unique hash to prevent duplicate entries
);

-- 2. Table for storing hard technical indicators (Extracted by Regex & spaCy)
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,         -- Links to raw_items.id
    entity_type TEXT NOT NULL,          -- 'CVE', 'IPv4', 'Domain', 'Threat_Actor', etc.
    entity_value TEXT NOT NULL,         -- The actual extracted value
    FOREIGN KEY (source_id) REFERENCES raw_items(id) ON DELETE CASCADE
);

-- 3. Table for storing MITRE ATT&CK mappings (Extracted by LLM)
CREATE TABLE IF NOT EXISTS ttp_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,         -- Links to raw_items.id
    ttp_id TEXT NOT NULL,               -- MITRE Technique ID (e.g., 'T1190')
    technique_name TEXT NOT NULL,       -- MITRE Technique Name
    FOREIGN KEY (source_id) REFERENCES raw_items(id) ON DELETE CASCADE
);

-- 4. Table for storing final AI reports and Human-in-the-Loop statuses
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,         -- Links to raw_items.id
    summary TEXT,                       -- LLM generated executive summary
    status TEXT DEFAULT 'pending',      -- HITL status: 'pending', 'approved', 'rejected'
    created_at TEXT NOT NULL,           -- UTC timestamp of report generation
    FOREIGN KEY (source_id) REFERENCES raw_items(id) ON DELETE CASCADE
);