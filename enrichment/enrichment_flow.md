# LLM-Based Threat Intelligence Gathering System: Enrichment Architecture (Hybrid Graph-Vector Update)

The Enrichment layer is designed as a multi-stage pipeline that transitions from deterministic data extraction to semantic vector search and complex graph reasoning. This layer ensures that raw threat data is enriched with technical context, mapped to official frameworks, and evaluated for impact before reaching the final analyst.

---

## Stage 1: Deterministic Indicator Extraction

- **Primary File:** `entity_extractor.py`
- **Mechanism:** Pre-compiled Regular Expressions (Regex) + compiled software pattern list (`_SYSTEM_PATTERNS`)
- **Purpose:** Identifies two categories of entities from cleaned threat text:
  - **Hard IOCs** — CVE IDs, TTP IDs, IPv4/IPv6 addresses, Domains, MD5/SHA1/SHA256 hashes
  - **SYSTEM/SOFTWARE** — known software, OS, frameworks, protocols, cloud platforms, network devices matched against `_SYSTEM_PATTERNS`
- **Strategy:** Regex handles fixed-format data with 100% precision and zero latency. Hash extraction uses span-overlap tracking — SHA256 (64 chars) is captured first, preventing SHA1 (40 chars) and MD5 (32 chars) from re-matching inside already-captured hex strings. `extract_entities()` handles hard IOCs, `extract_systems()` handles software pattern matching. Both are called inside `extract_and_store()` which merges results and persists everything to the SQLite `entities` table via `db/sqlite_manager.insert_entity()`. Deduplication is enforced at the `(type, value)` level.

---

## Stage 2: Semantic Entity Recognition (NER)

- **Primary File:** `ner_spacy.py`
- **Mechanism:** spaCy NLP Pipeline (`en_core_web_sm`) boosted with a custom `EntityRuler` containing static pattern lists
- **Purpose:** Extracts "Soft Entities" — Threat Actor groups and Malware families — that do not follow fixed regex patterns.
- **Strategy:** A custom `EntityRuler` is injected *before* spaCy's built-in NER component so domain-specific patterns take precedence over spaCy's generic model. The ruler is loaded with two static catalogues: `MALWARE_PATTERNS` (ransomware, banking trojans, RATs, spyware) and `APT_PATTERNS` (known APT group aliases). spaCy's `PERSON` label is also mapped to `THREAT_ACTOR` with false positive suppression — the 3 preceding tokens are checked for safe titles (`researcher`, `analyst`, `dr`, etc.) to avoid tagging security researchers as threat actors. `GPE`, `ORG`, `DATE` and other labels are intentionally excluded. Results are stored in SQLite via `db/sqlite_manager.insert_entity()`.

---

## Stage 3: Behavioral Translation (HyDE Pattern)

- **Primary File:** `behavior_translator.py`
- **Mechanism:** Local LLM (Llama 3) via structured JSON prompting using LangChain
- **Purpose:** Eliminates the **"Vocabulary Mismatch"** problem between informal OSINT slang and formal MITRE ATT&CK terminology.
- **Strategy:** The LLM receives the sanitized OSINT text and converts each core adversarial behavior into a single formal technical sentence that mirrors MITRE ATT&CK description language. The output is a strict JSON array:
  ```json
  {"behaviors": ["Adversary used valid accounts with stolen credentials...", "..."]}
  ```
  Key constraints enforced in the prompt: sentences must use formal MITRE ATT&CK phrasing, incident-specific details (organization names, countries, dates) are stripped to focus on the technique, TTP ID prefixes must not be prepended. Post-processing strips any TTP ID prefixes the LLM prepends anyway (e.g. `"T1059: Adversary..."`) via regex and repairs missing commas between JSON array elements — a common LLaMA 3 formatting failure — before parsing.

---

## Stage 4: Attack Mapping + Semantic Vector Search & Graph Traversal

- **Primary Files:** `kg_engine.py`, `attack_mapper.py`
- **Mechanism:** LLM-based TTP/CVE extraction + Local Embedding Model (`all-MiniLM-L6-v2`) + Neo4j Vector Index & Cypher Graph Traversal
- **Purpose:** Maps technical behaviors to official MITRE TTPs/CVEs, calculates the potential blast radius across affected software, and catches threats that vector search misses due to vocabulary mismatch.
- **Strategy:**

  All behaviors start in `unmatched_behaviors`. Both the attack mapper and vector search remove behaviors from this list as they find matches. Only behaviors that neither pass can find anything for remain in the final `unmatched_behaviors`.

  **Step 1 — Attack Mapper (runs first, per behavior):**
  For each behavior sentence individually, `attack_mapper.py` uses the LLM to directly identify MITRE ATT&CK technique IDs via `extract_ttps_from_behavior()`. This runs first because TTPs are high-level abstractions whose descriptions rarely match specific incident reports via cosine similarity alone. If TTPs are found for a behavior, that behavior is immediately removed from `unmatched_behaviors`. The attack mapper also extracts the single most relevant CVE ID across all behaviors via `extract_cve_from_behaviors()`. Both functions use two-step verification:
  1. **Format check** — regex `^T\d{4}(\.\d{3})?$` for TTPs, `^CVE-\d{4}-\d{4,}$` for CVEs
  2. **Graph check** — verifies each ID exists in Neo4j via `GraphConnector().get_ttp_by_id()` and `GraphConnector().get_cve_by_id()` — eliminates hallucinations using the live graph as ground truth

  For each verified TTP, a graph query fetches `MITRE_TTP -[:TARGETS]-> Software` to build the initial blast radius. For each verified CVE, a graph query fetches `CVE -[:EXPLOITS]-> Software`.

  **Step 2 — Combined Context Search (noise filter):**
  All behavior sentences are joined into one paragraph and embedded together using `all-MiniLM-L6-v2`. This holistic vector is searched against the graph at threshold 0.75, producing a set of `context_relevant_ids`. Only threats matching the FULL attack context pass through — individual sentences matching unrelated CVEs due to shared generic vocabulary are filtered out.

  **Step 3 — Per-Behavior Vector Search:**
  Each behavior sentence is embedded individually and searched against the graph at threshold 0.80. Results are filtered against `context_relevant_ids` from Step 2. If results exist for a behavior, that behavior is removed from `unmatched_behaviors` and `zero_day_flag` is set to `False`. Two separate Cypher queries run for each search — one targeting CVE nodes, one targeting MITRE_TTP nodes — so TTPs are never crowded out by the much larger CVE node pool. `matched_ttps` starts with attack mapper results and vector search matches are appended. Blast radius systems from all hops are aggregated into `systems_at_risk`.

  **Zero-Day flag logic:**
  `is_zero_day` starts as `True`. It is set to `False` only if vector search finds a match (`zero_day_flag = False` inside the per-behavior loop) OR if `matched_cves` or `matched_ttps` is non-empty after both passes. Attack mapper finding a TTP or CVE does NOT directly clear `zero_day_flag` — only vector search does. This means attack mapper results represent broad category matches while a cleared zero-day flag means a specific semantic match was found.

  **Blast Radius Traversal:**
  For every matched node across both passes, Cypher queries traverse three hop paths:
  - **Hop 1:** `CVE -[:AFFECTS]-> Software` (direct CPE-based software links)
  - **Hop 2:** `CVE -[:EXPLOITS_TECHNIQUE]-> MITRE_TTP -[:TARGETS]-> Software` (CTID-mapped technique targets)
  - **Hop 3:** `MITRE_TTP -[:TARGETS]-> Software` (when the matched node is a TTP directly)

  All affected software names from all hops are aggregated into a single `systems_at_risk` set.

---

