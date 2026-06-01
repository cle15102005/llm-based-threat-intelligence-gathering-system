"""
Centralized dictionary for all database queries.
Contains both SQLite statements for OSINT tracking and Neo4j Cypher queries for the Knowledge Graph.
"""

# ---------------------------------------------------------
# SQLite Queries (Relational Data)
# ---------------------------------------------------------

INSERT_RAW_ITEM = """
    INSERT OR IGNORE INTO raw_items 
    (source, title, description, source_url, published_date, collected_at, raw, dedup_key) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
"""
STORE_PROCESSED_ITEM_DESCRIPTION = """
    UPDATE raw_items
    SET description = ?
    WHERE id = ?;
"""

GET_POST_DATE = """
    SELECT published_date FROM raw_items
    WHERE id = ?;"""

GET_SOURCE_URL = """
    SELECT source_url FROM raw_items    
    WHERE id = ?;"""

# Used by pipeline.py to fetch uncleaned records
GET_UNPROCESSED_BATCH = """
    SELECT * FROM raw_items 
    WHERE processed = 0 
    LIMIT ?;
"""

# Updates the status of an item once HTML stripping and encapsulation are complete
MARK_PROCESSED = """
    UPDATE raw_items 
    SET processed = 1 
    WHERE id = ?;
"""
# Resets processed status to 0 for a given item ID — used when re-running the pipeline on a specific record after making improvements to the enrichment logic.
REMARK_PROCESSED = """
    UPDATE raw_items 
    SET processed = 0
    WHERE id = ?;
"""

INSERT_ENTITY = """
    INSERT OR IGNORE INTO entities 
    (source_id, entity_type, entity_value) 
    VALUES (?, ?, ?);
"""

# Retrieves extracted actors and malware to feed into the final report generation
GET_ENTITIES_BY_SOURCE = """
    SELECT * FROM entities 
    WHERE source_id = ?;
"""

INSERT_REPORT = """
    INSERT OR IGNORE INTO reports 
    (source_id, summary, created_at) 
    VALUES (?, ?, ?);
"""

GET_REPORT = """
    SELECT * FROM reports 
    WHERE source_id = ?;
"""

# ---------------------------------------------------------
# Neo4j Cypher Queries (Semantic Graph)
# ---------------------------------------------------------

# Inserts official MITRE tactics/techniques along with their 384-dimensional vector embedding
MERGE_MITRE_TTP = """
    MERGE (t:MITRE_TTP {ttp_id: $ttp_id})
    SET t.name = $name, 
        t.description = $description, 
        t.embedding = $embedding
"""

# Inserts official vulnerabilities along with their vector embedding
MERGE_CVE = """
    MERGE (c:CVE {cve_id: $cve_id})
    SET c.description = $description, 
        c.cvss_score = $cvss_score, 
        c.embedding = $embedding
"""

# Connects vulnerabilities to the systems they put at risk
LINK_CVE_SOFTWARE = """
    MATCH (c:CVE {cve_id: $cve_id})
    MERGE (s:Software {name: $software_name})
    MERGE (c)-[:AFFECTS]->(s)
"""

# Connects CVEs to MITRE techniques based on LLM-inferred relationships (e.g., "CVE-2021-12345 exploits T1548")
LINK_CVE_MITRE = """
    MATCH (c:CVE {cve_id: $cve_id})
    MATCH (t:MITRE_TTP {ttp_id: $ttp_id})
    MERGE (c)-[:EXPLOITS_TECHNIQUE]->(t)
"""

# Link MITRE technique explicitly to targeted Software/Platforms
LINK_MITRE_SOFTWARE = """
    MATCH (t:MITRE_TTP {ttp_id: $ttp_id})
    MERGE (s:Software {name: $software_name})
    MERGE (t)-[:TARGETS]->(s)
"""

# Complex Traversal finding direct affects, and multi-hop technique targets
VECTOR_SEARCH_CVE = """
    CALL db.index.vector.queryNodes('threat_embeddings_index', $top_k, $post_vector)
    YIELD node AS matched_threat, score
    WHERE score >= $threshold AND matched_threat:CVE

    OPTIONAL MATCH (matched_threat)-[:AFFECTS]->(s1:Software)
    OPTIONAL MATCH (matched_threat)-[:EXPLOITS_TECHNIQUE]->(t1:MITRE_TTP)-[:TARGETS]->(s2:Software)

    RETURN
        matched_threat.cve_id AS threat_id,
        'CVE' AS threat_type,
        score AS similarity_score,
        collect(DISTINCT s1.name) + collect(DISTINCT s2.name) AS systems_at_risk,
        collect(DISTINCT t1.ttp_id) AS explicit_ttps
    ORDER BY score DESC
"""

VECTOR_SEARCH_TTP = """
    CALL db.index.vector.queryNodes('threat_embeddings_index', $top_k, $post_vector)
    YIELD node AS matched_threat, score
    WHERE score >= $threshold AND matched_threat:MITRE_TTP

    OPTIONAL MATCH (matched_threat)-[:TARGETS]->(s3:Software)

    RETURN
        matched_threat.ttp_id AS threat_id,
        'MITRE_TTP' AS threat_type,
        score AS similarity_score,
        collect(DISTINCT s3.name) AS systems_at_risk,
        [] AS explicit_ttps
    ORDER BY score DESC
"""

# find TTP IDs to check against hallucinated TTPs from attack mapper
GET_TTP_IDS = """
    MATCH (t:MITRE_TTP {ttp_id: $ttp_id})
    RETURN t.name, t.ttp_id
"""

# find CVE descriptions to check against hallucinated CVEs from attack mapper
GET_CVE_IDS = """
    MATCH (c:CVE {cve_id: $cve_id})
    RETURN c.description, c.cve_id
"""