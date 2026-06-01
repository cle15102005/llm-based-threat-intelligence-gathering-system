from __future__ import annotations

from typing import Any
from langdetect import detect, DetectorFactory

# Import centralized LLM client from the shared module to ensure consistent configuration and error handling across all components. 
from llm.ollama_client import get_llm

# Enforce consistent language detection results across runs
DetectorFactory.seed = 0

class LanguageDetector:
    """
    Preprocessing module for the Threat Intelligence Pipeline.
    Detects input language and translates non-English text to English using 
    the centralized LangChain Ollama client, preserving technical entities.
    """

    def __init__(self) -> None:
        # Initialize the LLM once using the centralized client
        self.llm = get_llm(model="translation")
        
        # System prompt explicitly designed for Cyber Threat Intelligence.
        self.system_prompt = (
            "You are a professional Cyber Threat Intelligence translator.\n"
            "Translate the following technical text into fluent English.\n"
            "CRITICAL RULES: (DO NOT ECHO THESE RULES INTO THE OUTPUT)\n"
            "1. Preserve all CVE IDs (e.g., CVE-2024-1234), IP addresses, URLs, domains, and MD5/SHA hashes EXACTLY as they are.\n"
            "2. DO NOT INVENT OR ALTER ANY TECHNICAL ENTITIES. DO NOT SUMMARY the DESCRIPTION of a TTP/CVE into TTP/CVE IDs\n"
            "3. Keep specific malware families or threat actor names verbatim (e.g., 'Cobalt Strike', 'APT28', 'Nitrogen').\n"
            "4. Do not add any conversational filler, meta-commentary, or introductory remarks. Output ONLY the raw translated text."
        )

    def process_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """
        Processes a single record from a Collector.
        Translates the 'description' field to English if necessary.
        """
        # Ensure record is a mutable dict — sqlite3.Row objects are not assignable
        if not isinstance(record, dict):
            record = dict(record)
            print(record)  # Debug: Show the record being processed

        text_to_check = record.get("description", "")
        print(f"text_to_check: {text_to_check[:60]}...")  # Debug: Show a snippet of the text being processed
        if not text_to_check.strip():
            return record

        try:
            # 1. Fast, offline language detection
            detected_lang = detect(text_to_check)
            
            if detected_lang == "en":
                return record

            print(f"[*] Detected non-English text ({detected_lang}) for: '{record.get('title')}' -> Triggering Translation...")
            
            # 2. Trigger translation via the centralized LangChain LLM
            translated_text = self._translate_via_llama(text_to_check)
            
            if translated_text:
                record["description"] = translated_text
                # raw field is stored as string in SQLite — parse it safely
                # before adding original_language key
                raw = record.get("raw", {})
                if isinstance(raw, str):
                    try:
                        import ast
                        raw = ast.literal_eval(raw)
                    except Exception:
                        raw = {}
                raw["original_language"] = detected_lang
                record["raw"] = raw

        except Exception as e:
            print(f"[!] LanguageDetector error on item '{record.get('title')}': {e}")
        
        return record

    def _translate_via_llama(self, text: str) -> str:
        prompt = (
            f"{self.system_prompt}\n\n"
            f"Text to translate:\n{text}\n\n"
            f"English translation:"
        )

        try:
            response = self.llm.invoke(prompt)
            result = response.strip()

            if result.lower().startswith("english translation:"):
                result = result[20:].strip()

            print(f"    [*] Translation result: {result}")  # Print full translation result for debugging
            return result

        except Exception as e:
            print(f"    [!] Translation request failed: {e}")
            return ""