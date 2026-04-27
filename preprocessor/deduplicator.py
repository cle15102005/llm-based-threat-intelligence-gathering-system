import hashlib
import unittest

def generate_hash(content: str) -> str:
    if not content or not isinstance(content, str):
        return ""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def generate_dedup_key(content: str, cve_id: str = "") -> str:
    content_hash = generate_hash(content)
    cve_id_clean = cve_id.strip().upper() if cve_id else "NO_CVE"
    return f"{cve_id_clean}_{content_hash}"

class Deduplicator:
    def __init__(self, existing_keys=None):
        self.seen_keys = set(existing_keys) if existing_keys else set()

    def is_duplicate(self, content: str, cve_id: str = "") -> bool:
        key = generate_dedup_key(content, cve_id)
        if key in self.seen_keys:
            return True
        
        self.seen_keys.add(key)
        return False

class TestDeduplicator(unittest.TestCase):
    def setUp(self):
        self.dedup = Deduplicator()
        self.sample_text = "Critical RCE in web server."

    def test_hash_generation(self):
        h1 = generate_hash(self.sample_text)
        h2 = generate_hash(self.sample_text)
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, generate_hash("Different text"))

    def test_dedup_key_format(self):
        key = generate_dedup_key(self.sample_text, "CVE-2024-1234")
        self.assertTrue(key.startswith("CVE-2024-1234_"))
        
        key_no_cve = generate_dedup_key(self.sample_text)
        self.assertTrue(key_no_cve.startswith("NO_CVE_"))

    def test_duplicate_detection(self):
        self.assertFalse(self.dedup.is_duplicate(self.sample_text, "CVE-2024-1234"))
        self.assertTrue(self.dedup.is_duplicate(self.sample_text, "CVE-2024-1234"))

    def test_same_cve_different_content_is_not_duplicate(self):
        self.dedup.is_duplicate("Initial report", "CVE-2024-1111")
        self.assertFalse(self.dedup.is_duplicate("Updated report with PoC", "CVE-2024-1111"))

    def test_same_content_different_cve_is_not_duplicate(self):
        self.dedup.is_duplicate(self.sample_text, "CVE-2024-2222")
        self.assertFalse(self.dedup.is_duplicate(self.sample_text, "CVE-2024-3333"))

if __name__ == "__main__":
    unittest.main(verbosity=2)