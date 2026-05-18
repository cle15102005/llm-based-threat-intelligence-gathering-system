from __future__ import annotations

from typing import Any
from langdetect import detect, DetectorFactory

# Import centralized LLM client from the shared module to ensure consistent configuration and error handling across all components. 
from ollama_client import get_llm 

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
        self.llm = get_llm()
        
        # System prompt explicitly designed for Cyber Threat Intelligence.
        self.system_prompt = (
            "You are a professional Cyber Threat Intelligence translator.\n"
            "Translate the following technical text into fluent English.\n"
            "CRITICAL RULES:\n"
            "1. Preserve all CVE IDs (e.g., CVE-2024-1234), IP addresses, URLs, domains, and MD5/SHA hashes EXACTLY as they are.\n"
            "2. Keep specific malware families or threat actor names verbatim (e.g., 'Cobalt Strike', 'APT28', 'Nitrogen').\n"
            "3. Do not add any conversational filler, meta-commentary, or introductory remarks. Output ONLY the raw translated text."
        )

    def process_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """
        Processes a single record from a Collector.
        Translates the 'description' field to English if necessary.
        """
        text_to_check = record.get("description", "")
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
                record.setdefault("raw", {})["original_language"] = detected_lang

        except Exception as e:
            print(f"[!] LanguageDetector error on item '{record.get('title')}': {e}")
        
        return record

    def _translate_via_llama(self, text: str) -> str:
        """Hits the centralized LLM client to perform the translation."""
        # LangChain automatically handles formatting this string into the correct prompt structure
        prompt = f"{self.system_prompt}\n\nText to translate:\n{text}"
        
        try:
            # Use LangChain's invoke method instead of raw requests.post
            response = self.llm.invoke(prompt)
            return response.strip()
        except Exception as e:
            print(f"    [!] LangChain translation request failed: {e}")
            return ""

# ---- Quick Test Block ----
if __name__ == "__main__":
    detector = LanguageDetector()
    
    mock_russian_record = {
        "title": "Foxconn пострадала от Nitrogen",
        "description": "Тайваньский гигант Foxconn подвергся кибератаке. Злоумышленники использовали вредоносное ПО Nitrogen для получения доступа. CVE-2024-21111 не подтвержден.",
        "url": "https://xakep.ru/mock-test",
        "raw": {}
    }
    
    processed = detector.process_record(mock_russian_record)
    print("\n[+] OUTPUT PIPELINE RESULT:")
    print(f"Title: {processed['title']}")
    print(f"Translated Description:\n{processed['description']}")