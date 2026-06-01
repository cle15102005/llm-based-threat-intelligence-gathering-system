"""
FILE: enrichment/behavior_translator.py
ROLE: Semantic Translation (Phase 3)
PURPOSE: Implements the HyDE pattern. Instructs the LLM to read informal 
OSINT text and output a strict JSON array of single-sentence technical behaviors.
"""
import json
import logging
import re
from llm.ollama_client import get_llm
from langchain_core.prompts import PromptTemplate

logger = logging.getLogger(__name__)

# Strict prompt template requiring a specific JSON schema
HYDE_PROMPT = """You are an expert Cyber Threat Intelligence Analyst with deep knowledge of MITRE ATT&CK and CVE databases.
Read the following OSINT text. Extract ONLY the core adversarial behaviors and technical attack actions.
Convert each distinct action into a single formal technical sentence.

CRITICAL RULES:
1. Use formal MITRE ATT&CK terminology. Match the exact phrasing style of ATT&CK technique descriptions:
   - "Adversary used valid accounts with stolen credentials to maintain persistent access"
   - "Attacker executed remote code on target system by exploiting a buffer overflow vulnerability"
   - "Adversary performed data exfiltration over C2 channel using encrypted DNS tunneling"
   - "Attacker moved laterally using Pass-the-Hash with compromised NTLM credentials"
   - "Adversary established persistence by installing a malicious scheduled task"
   - "Attacker disabled security tools by modifying registry keys to evade detection"
2. Extract AS MANY distinct adversarial behaviors as possible. Each sentence describes ONE specific adversarial action — do not combine multiple techniques.
3. Strip all incident-specific details (company names, country names, dates, victim names).
   Focus on WHAT was done, not WHERE or WHEN.
4. Only include sentences that describe an adversary's action, not news narrative or context.
5. If the text has no adversarial behaviors (e.g., it's a patch announcement with no attack description),
   return an empty list: {{"behaviors": []}}
6. Output ONLY a valid JSON object. No preamble, no explanation, no markdown fences.
7. Do NOT prepend TTP IDs (e.g. "T1059:") to behavior sentences. Write only the
   plain technical sentence without any TTP ID prefix.

JSON format:
{{"behaviors": ["sentence 1", "sentence 2"]}}

Input Text:
{osint_text}
"""

def translate_to_behaviors(osint_text: str) -> list:
    """Passes text to Llama 3 and returns a list of technical behavior strings."""

    # Early return for empty/whitespace input — no point calling the LLM
    if not osint_text or not osint_text.strip():
        logger.info("[*] Empty input — skipping LLM call.")
        return []

    # Chunking: if text is too long (> 4000 characters), process it in chunks to avoid context limits
    # and improve the quality of behavior extraction from long Reddit posts/articles.
    
    MAX_CHUNK_SIZE = 4000
    if len(osint_text) > MAX_CHUNK_SIZE:
        logger.info(f"[*] Input text too large ({len(osint_text)} chars) — splitting into chunks.")
        chunks = [osint_text[i:i + MAX_CHUNK_SIZE] for i in range(0, len(osint_text), MAX_CHUNK_SIZE)]
        all_behaviors = []
        for i, chunk in enumerate(chunks):
            logger.info(f"[*] Processing chunk {i+1}/{len(chunks)}...")
            all_behaviors.extend(translate_to_behaviors(chunk))
        return list(set(all_behaviors)) # deduplicate across chunks

    logger.info("[*] Translating OSINT text to technical behaviors via LLM (HyDE)...")

    # Prefer translation-optimized models if available
    llm = get_llm(model="behavior_extraction", num_ctx=8192, num_predict=2048)
    prompt = PromptTemplate(input_variables=["osint_text"], template=HYDE_PROMPT)
    chain = prompt | llm
    
    try:
        # Generate LLM response
        response = chain.invoke({"osint_text": osint_text})
        
        # Strip markdown fences first
        clean_json_str = response.strip().strip("```json").strip("```").strip()
        
        # Strip any natural language preamble before the JSON object
        # LLMs often add "Here is the output:" before the actual JSON
        brace_idx = clean_json_str.find("{")
        if brace_idx > 0:
            clean_json_str = clean_json_str[brace_idx:]
        
        # Also strip any trailing note after the closing brace
        last_brace_idx = clean_json_str.rfind("}")
        if last_brace_idx != -1:
            clean_json_str = clean_json_str[:last_brace_idx + 1]
        
        # Repair common LLM JSON formatting error: missing commas between array items
        # e.g. ["item1"\n"item2"] -> ["item1",\n"item2"]
        import re as _re
        clean_json_str = _re.sub(
            r'"\s*\n\s*"',
            '",\n"',
            clean_json_str
        )

        data = json.loads(clean_json_str)
        
        # Handle both {"behaviors": [...]} and bare [...] responses
        if isinstance(data, list):
            behaviors = data
        else:
            behaviors = data.get("behaviors", [])

        # Strip TTP ID prefixes the LLM sometimes prepends (e.g. "T1059: Adversary...")
        import re as _re
        _TTP_PREFIX = _re.compile(r'^T\d{4}(?:\.\d{3})?:\s*', re.IGNORECASE)
        behaviors = [
            _TTP_PREFIX.sub("", b).strip()
            for b in behaviors
            if isinstance(b, str) and b.strip()
        ]

        logger.info(f"[+] Extracted {len(behaviors)} distinct behaviors.")
        return behaviors
        
    except json.JSONDecodeError as e:
        logger.error(f"[-] LLM failed to return valid JSON. Error: {e}\nRaw LLM Output: {response}")
        return []
    except Exception as e:
        logger.error(f"[-] Behavior translation failed: {e}")
        return []