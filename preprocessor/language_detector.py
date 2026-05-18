from __future__ import annotations

import requests
from typing import Any
from langdetect import detect, DetectorFactory

# Enforce consistent language detection results across runs
DetectorFactory.seed = 0

class LanguageDetector:
    """
    Preprocessing module for the Threat Intelligence Pipeline.
    Detects input language and translates non-English text to English using 
    a local Llama 3 instance, preserving technical entities for vectorization.
    """

    def __init__(self, ollama_url: str = "http://localhost:11434") -> None:
        self.ollama_endpoint = f"{ollama_url}/api/generate"
        
        # System prompt explicitly designed for Cyber Threat Intelligence.
        # It forces Llama 3 to act purely as a translator and prevents hallucination.
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
            
            # If it is already English, bypass the LLM to save compute time
            if detected_lang == "en":
                return record

            print(f"[*] Detected non-English text ({detected_lang}) for: '{record.get('title')}' -> Triggering Llama 3 Translation...")
            
            # 2. Trigger local Llama 3 translation via Ollama API
            translated_text = self._translate_via_llama(text_to_check)
            
            if translated_text:
                # Overwrite the description with the English translation
                record["description"] = translated_text
                # Store the original language in metadata for auditing
                record.setdefault("raw", {})["original_language"] = detected_lang

        except Exception as e:
            print(f"[!] LanguageDetector error on item '{record.get('title')}': {e}")
            # Fallback: keep original text so the pipeline does not crash
        
        return record

    def _translate_via_llama(self, text: str) -> str:
        """Hits the local Ollama API to perform the translation."""
        payload = {
            "model": "llama3",
            "prompt": f"{self.system_prompt}\n\nText to translate:\n{text}",
            "stream": False,  
            "options": {
                # Temperature 0.0 stops the LLM from being "creative" 
                # and forces a deterministic, strict translation.
                "temperature": 0.0  
            }
        }
        
        try:
            response = requests.post(self.ollama_endpoint, json=payload, timeout=60)
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except Exception as e:
            print(f"    [!] Ollama translation request failed: {e}")
            return ""