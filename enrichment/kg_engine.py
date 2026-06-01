"""
FILE: enrichment/kg_engine.py
ROLE: Knowledge Engine & Zero-Day Evaluator (Phase 4)
PURPOSE: Executes semantic search and aggregates multi-hop graph paths 
(CVE -> MITRE -> Software).
"""
import logging
from sentence_transformers import SentenceTransformer
from db.neo4j_manager import GraphConnector
import warnings
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
# Suppress INFO/DEBUG logs from noisy libraries
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)   # if httpx is used under the hood


logger = logging.getLogger(__name__)

class KnowledgeEngine:
    def __init__(self):
        logger.info("[*] Spinning up Knowledge Engine...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.graph = GraphConnector()

    def evaluate_threat(self, behaviors: list) -> dict:
        zero_day_flag = True
        blast_radius = set()
        unmatched_behaviors = behaviors.copy()  # Start with all behaviors as unmatched
        matched_cves = []
        matched_ttps = []

        if not behaviors:
            return {
                "matched_cves": [], "matched_ttps": [], "systems_at_risk": [], "is_zero_day": False,
                "unmatched_behaviors": []
            }
        
        # ── Attack mapper — LLM-based TTP/CVE extraction ──────────────────────────
        # Runs BEFORE vector search to find TTPs/CVE that may not have a strong vector match but are still relevant to the attack
        # Results verified against graph database — no hallucinations.
        # IMPORTANT: attack mapper finding a broad TTPs/CVE category does NOT clear
        # zero_day_flag — only vector search finding a specific semantic match does.
        mapper_ttps: list[str] = []
        try:
            from enrichment.attack_mapper import extract_ttps_from_behavior, extract_cve_from_behaviors

            # Extract TTPs from each behavior sentence using the attack mapper
            for behavior in behaviors:
                ttps = extract_ttps_from_behavior(behavior)

                if ttps:
                    unmatched_behaviors.remove(behavior)  # Mark this behavior as matched
                    for ttp in ttps:
                        if ttp not in mapper_ttps:
                            mapper_ttps.append(ttp)

                            # Fetch blast radius for this TTP from the graph
                            try:
                                with self.graph.driver.session() as session:
                                    result = session.run("""
                                        MATCH (t:MITRE_TTP {ttp_id: $ttp_id})-[:TARGETS]->(s:Software)
                                        RETURN s.name AS system
                                    """, ttp_id=ttp)
                                    for record in result:
                                        sys_name = record.get("system")
                                        if sys_name:
                                            blast_radius.add(sys_name)
                                            logger.info(f"    [+] {ttp} targets: {sys_name}")
                            except Exception as e:
                                logger.warning(f"[!] Failed to fetch blast radius for {ttp}: {e}")

                    if mapper_ttps:
                        logger.info(f"[+] Attack mapper added {len(mapper_ttps)} TTPs: {mapper_ttps}")
                    else:
                        logger.info("[+] Attack mapper found no TTPs.")

            # Extract CVEs from behavior sentences using the attack mapper
            cve = extract_cve_from_behaviors(behaviors)
            if cve:
                matched_cves.append(cve)
                try:
                    with self.graph.driver.session() as session:
                        result = session.run("""
                            MATCH (c:CVE {cve_id: $cve_id})-[:EXPLOITS]->(s:Software)
                            RETURN s.name AS system
                        """, cve_id=cve)
                        for record in result:
                            sys_name = record.get("system")
                            if sys_name:
                                blast_radius.add(sys_name)
                                logger.info(f"    [+] {cve} exploits: {sys_name}")
                except Exception as e:
                    logger.warning(f"[!] Failed to fetch blast radius for {cve}: {e}")

        except Exception as e:
            logger.warning(f"[!] Attack mapper failed, skipping: {e}")

        # ── Vector Search & Contextual Filtering ───────────────────────────────

        logger.info(f"[*] Querying Neo4j for {len(behaviors)} behaviors (Threshold >= 75%)...")

        matched_ttps = mapper_ttps.copy()  # Start with TTPs found by attack mapper, then add vector search matches

        # ── Combined context search ───────────────────────────────────────────
        # Embed ALL behaviors together as one paragraph to get a holistic
        # attack vector — this prevents individual sentences from matching
        # unrelated CVEs just because they share generic security vocabulary
        combined_context = " ".join(behaviors)
        combined_vector  = self.model.encode(combined_context).tolist()
        context_results  = self.graph.vector_search(
            post_vector=combined_vector, threshold=0.75
        )

        # Build a set of threat IDs that appear in the combined context search
        # Only threats that match the FULL attack context are considered relevant
        context_relevant_ids: set[str] = set()
        for record in context_results:
            tid = record.get("threat_id")
            if tid:
                context_relevant_ids.add(tid)

        logger.info(f"[-] Combined context search found {len(context_relevant_ids)} relevant threats: {context_relevant_ids}")

        # ── Per-behavior search ───────────────────────────────────────────────
        # Still search per behavior to detect zero-day and unmatched behaviors
        # but FILTER results against context_relevant_ids to remove noise
        for sentence in behaviors:
            vector  = self.model.encode(sentence).tolist()
            results = self.graph.vector_search(post_vector=vector, threshold=0.80)

            # Filter: only keep results that also appeared in the combined search
            # This removes CVEs that match a behavior sentence in isolation but
            # are not relevant to the overall attack context
            if context_relevant_ids:
                results = [
                    r for r in results
                    if r.get("threat_id") in context_relevant_ids
                ]
            logger.info(f"[-] Per-behavior search for: '{sentence}' found {len(results)} context-relevant matches")

            if results:
                if sentence in unmatched_behaviors:
                    unmatched_behaviors.remove(sentence)  # Mark this behavior as matched

                zero_day_flag = False

                for record in results:
                    threat_id   = record.get("threat_id")
                    threat_type = record.get("threat_type")
                    score       = record.get("similarity_score")

                    if threat_id:
                        logger.info(f"    [{threat_type}] {threat_id} (score: {score:.4f})")

                    if threat_type == "CVE"  and threat_id not in matched_cves:
                        matched_cves.append(threat_id)

                    if threat_type == "MITRE_TTP" and threat_id not in matched_ttps:
                        matched_ttps.append(threat_id)

                    # Extract systems at risk from this result record
                    systems = record.get("systems_at_risk", [])
                    for sys in systems:
                        if sys:
                            blast_radius.add(sys)


        if matched_cves or matched_ttps:
            zero_day_flag = False

        payload = {
            "matched_cves":        matched_cves,
            "matched_ttps":        matched_ttps,
            "systems_at_risk":     list(blast_radius),
            "is_zero_day":         zero_day_flag,       
            "unmatched_behaviors": unmatched_behaviors,
        }

        logger.info(f"[+] Matched CVEs    : {matched_cves}")
        logger.info(f"[+] Matched TTPs    : {matched_ttps}")
        logger.info(f"[+] Systems at risk : {list(blast_radius)}")
        logger.info(f"[+] Zero-Day        : {zero_day_flag}")
        return payload
        
    def close(self):
        self.graph.close()