"""
=============================================================================
MODULE: 02_test_language_detector.py
PURPOSE: Executes performance and accuracy telemetry on the Language Detector.
METRICS: Execution time, Translation Accuracy (Entity Preservation).
COMMAND: python -m tests.02_test_language_detector
=============================================================================
"""
import time
import json
from preprocessor.language_detector import LanguageDetector

def run_test():
    print("="*60)
    print("[*] Initializing Language Detector (Connecting to Local Ollama)...")
    detector = LanguageDetector()
    print("[+] Detector Ready.\n")

    # Define test cases covering different edge cases
    test_cases = [
        {
            "test_name": "1. Standard English (Should Bypass LLM)",
            "record": {
                "title": "New Ransomware Variant",
                "description": "A new ransomware variant similar to LockBit has been observed targeting Linux servers.",
                "url": "https://reddit.com/r/netsec/..."
            }
        },
        {
            "test_name": "2. Russian Threat Intel (Should Translate & Keep Entities)",
            "record": {
                "title": "Уязвимость в Apache",
                "description": "Хакерская группа APT28 использует новую уязвимость CVE-2024-12345 для атаки на серверы. Вредоносное ПО Cobalt Strike связывается с IP 192.168.100.50. Хэш файла: 5d41402abc4b2a76b9719d911017c592.",
                "url": "https://xakep.ru/..."
            }
        },
        {
            "test_name": "3. Chinese Threat Intel (Should Translate & Keep Entities)",
            "record": {
                "title": "针对关键基础设施的网络攻击",
                "description": "研究人员发现了一个新的后门。攻击者利用了 Log4Shell (CVE-2021-44228) 漏洞。木马名称为 Nitrogen。",
                "url": "https://freebuf.com/..."
            }
        },
        {
            "test_name": "4. Empty/Invalid Description (Should handle gracefully)",
            "record": {
                "title": "Image post only",
                "description": "   ",
                "url": "https://reddit.com/..."
            }
        }
    ]

    print("="*60)
    print("STARTING TRANSLATION TESTS")
    print("="*60)

    for idx, case in enumerate(test_cases):
        print(f"\n[Test {idx+1}] {case['test_name']}")
        print(f"[-] Original Text: {case['record']['description']}")
        
        start_time = time.perf_counter()
        
        # Run the processor
        processed_record = detector.process_record(case['record'])
        
        end_time = time.perf_counter()
        execution_time = end_time - start_time

        detected_lang = processed_record.get("raw", {}).get("original_language", "en")
        
        print(f"[+] Detected Language: {detected_lang}")
        print(f"[+] Processed Text : {processed_record['description']}")
        print(f"[!] Time Taken     : {execution_time:.4f} seconds")
        print("-" * 60)

if __name__ == "__main__":
    run_test()