"""
PURPOSE:
Maps cleaned threat text to MITRE ATT&CK TTPs using a local LLM and Few-Shot prompting.
Includes an anti-hallucination filter to validate generated TTP IDs against the official MITRE dataset.
"""
import json
import os
import sqlite3

from mitreattack.stix20 import MitreAttackData

# Using the specialized factory for few-shot pipelines
from llm.chain_builder import build_few_shot_chain
from enrichment.few_shot_examples import FEW_SHOT_EXAMPLES, EXAMPLE_PROMPT, SYSTEM_PREFIX, SUFFIX_TEMPLATE
from db.db import DB_PATH

MITRE_FILE = "enterprise-attack.json"
mitre_data = None

# Initialize MITRE reference data for validation
if os.path.exists(MITRE_FILE):
    try:
        mitre_data = MitreAttackData(MITRE_FILE)
    except Exception as e:
        print(f"[!] Error loading '{MITRE_FILE}': {e}")
else:
    print(f"[!] Warning: '{MITRE_FILE}' not found. Validation disabled.")

def validate_ttp_id(ttp_id: str) -> bool:
    """
    Checks if a generated TTP ID exists in the official MITRE ATT&CK dataset.
    This prevents the LLM from inventing fake IDs (Hallucination).
    """
    if not mitre_data:
        return False
    try:
        obj = mitre_data.get_object_by_attack_id(ttp_id, 'attack-pattern')
        return True if obj else False
    except Exception:
        return False

def map_ttps(source_id: int, cleaned_text: str) -> list:
    """
    Orchestrates the mapping process by invoking the Few-Shot chain,
    filtering the output, and storing valid TTPs in the database.
    """
    chain = build_few_shot_chain(
        examples=FEW_SHOT_EXAMPLES,
        example_prompt_str=EXAMPLE_PROMPT,
        system_prefix=SYSTEM_PREFIX,
        suffix_str=SUFFIX_TEMPLATE,
        input_vars=["threat_text"]
    )
    
    print("[*] Requesting LLM to analyze MITRE ATT&CK mapping...")
    response = chain.invoke({"threat_text": cleaned_text})
    
    valid_ttps = []
    try:
        start_idx = response.find('[')
        end_idx = response.rfind(']') + 1
        
        if start_idx != -1 and end_idx != -1:
            json_str = response[start_idx:end_idx]
            extracted_ttps = json.loads(json_str)
            
            for ttp in extracted_ttps:
                ttp_id = ttp.get("id", "").strip()
                
                # --- JUST CHECK ID AND FETCH NAME FROM OFFICIAL MITRE DATABASE ---
                if validate_ttp_id(ttp_id):
                    official_name = "Unknown Technique"
                    if mitre_data:
                        obj = mitre_data.get_object_by_attack_id(ttp_id, 'attack-pattern')
                        if obj:
                            # Flexibly handle both list and single object returns
                            stix_obj = obj[0] if isinstance(obj, list) and len(obj) > 0 else obj
                            
                            # Safely get the technique name, accounting for both dict and object structures
                            official_name = getattr(stix_obj, 'name', stix_obj.get('name', 'Unknown Technique'))
                    
                    valid_ttps.append({
                        "ttp_id": ttp_id,
                        "technique_name": official_name
                    })
                else:
                    print(f"[!] HALLUCINATION BLOCKED: Fabricated ID {ttp_id}")
                    
            # --- SAVE TO DATABASE ---
            if valid_ttps:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    for ttp in valid_ttps:
                        # Dùng INSERT OR IGNORE để tránh crash do UNIQUE constraint
                        cursor.execute(
                            """INSERT OR IGNORE INTO ttp_mappings (source_id, ttp_id, technique_name) 
                               VALUES (?, ?, ?)""",
                            (source_id, ttp["ttp_id"], ttp["technique_name"])
                        )
                    conn.commit()
                    conn.close()
                    print(f"[*] Successfully saved verified TTPs to the database.")
                except Exception as db_err:
                    print(f"[!] Database Error while saving TTPs: {db_err}")
                    
        else:
            print("[!] Error: LLM response did not contain a valid JSON array.")
            
    except json.JSONDecodeError as e:
        print(f"[!] JSON Parsing Error: {e}")
        
    return valid_ttps