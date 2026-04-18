from __future__ import annotations

import os
import re
import requests
from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base_collector import BaseCollector
from db.queries import insert_raw_item, get_unprocessed_batch

# Regular expression to identify CVE IDs (e.g., CVE-2021-44228)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Valid severity labels accepted by NVD cvssV3Severity parameter
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class NVDCollector(BaseCollector):
    """
    Fetches CVE data from the NVD REST API v2.
    https://nvd.nist.gov/developers/vulnerabilities

    Rate limits:
        No API key : 5 requests / 30 s  → DEFAULT_DELAY = 6.0 s
        With API key: 50 requests / 30 s → DEFAULT_DELAY = 0.6 s
    """

    DEFAULT_DELAY = 6.0

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(source_name="nvd")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.getenv("OTX_API_KEY")
        self.headers = {
            "User-Agent": "llm-threat-intel-collector/1.0",
            "Accept":     "application/json",
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key
            self.DEFAULT_DELAY = 0.6
            print("[*] NVD API key detected. Using faster request rate.")
        else:
            print("[!] Warning: No NVD API key found. Requests will be slower and may fail under heavy load.")

    # ── Task 1: fetch by time window ──────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
        cvss_severity: str | None = None, 
    ) -> list[dict[str, Any]]:
        
        # Enforce valid server-side values upfront
        if cvss_severity is not None:
            cvss_severity = cvss_severity.upper()
            if cvss_severity not in VALID_SEVERITIES:
                raise ValueError(
                    f"Invalid cvss_severity '{cvss_severity}'. "
                    f"Must be one of: {sorted(VALID_SEVERITIES)}"
                )

        if year is not None:
            # Chunk the year into 4 quarters to safely bypass the NIST 120-day limit
            chunks = [
                (datetime(year, 1, 1, tzinfo=timezone.utc),  datetime(year, 3, 31, 23, 59, 59, tzinfo=timezone.utc)),
                (datetime(year, 4, 1, tzinfo=timezone.utc),  datetime(year, 6, 30, 23, 59, 59, tzinfo=timezone.utc)),
                (datetime(year, 7, 1, tzinfo=timezone.utc),  datetime(year, 9, 30, 23, 59, 59, tzinfo=timezone.utc)),
                (datetime(year, 10, 1, tzinfo=timezone.utc), datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
            ]
            
            all_results = []
            for start, end in chunks:
                remaining = max_results - len(all_results)
                if remaining <= 0:
                    break

                params: dict[str, Any] = {
                    # Added 'Z' to strictly follow NVD API ISO-8601 requirements
                    "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "resultsPerPage": min(remaining, 2000), 
                    "startIndex":     0,
                }
                if cvss_severity:
                    params = cvss_severity

                all_results.extend(self._paginate(params, remaining))
                
            return all_results[:max_results]

        else:
            # Rolling window from now
            end   = datetime.now(timezone.utc)
            start = end - timedelta(days=days_back or 7)

            params: dict[str, Any] = {
                # Added 'Z' to strictly follow NVD API ISO-8601 requirements
                "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "resultsPerPage": min(max_results, 2000),
                "startIndex":     0,
            }
            if cvss_severity:
                params = cvss_severity

            return self._paginate(params, max_results)

    # ── Task 2: fetch by keyword or CVE ID ────────────────────────────────────

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Search CVEs by keyword, phrase, or exact CVE ID.

        Matching behavior:
            - Plain word  'wannacry'       → fuzzy, NVD searches full description
            - Phrase      'apache log4j'   → both words must appear
            - Partial     'wanna'          → still matches WannaCry entries
            - CVE ID      'CVE-2021-44228' → routed to exact-ID endpoint
            - Multi-word  'log4shell rce'  → treated as phrase search by NVD

        No exact match required — NVD keywordSearch is full-text across
        CVE ID, description, and reference URLs.
        """
        query = query.strip()

        if CVE_ID_PATTERN.match(query):
            return self._fetch_by_cve_id(query)

        params: dict[str, Any] = {
            "keywordSearch":  query,
            "resultsPerPage": min(max_results, 2000),
            "startIndex":     0,
        }
        return self._paginate(params, max_results)

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        records = []
        for container in raw_data:
            cve    = container.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            description              = self._extract_english_description(
                                           cve.get("descriptions", []))
            published                = cve.get("published", "")
            url                      = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            cvss_score, cvss_sev, cvss_vec = self._extract_cvss(cve.get("metrics", {}))
            cwes                     = self._extract_cwes(cve.get("weaknesses", []))

            records.append(self.format_record(
                title          = cve_id,
                description    = description,
                url            = url,
                published_date = published,
                raw            = {
                    "cvss_score":    cvss_score,
                    "cvss_severity": cvss_sev,
                    "cvss_vector":   cvss_vec,
                    "cwes":          cwes,
                },
            ))
        return records

    # ── Private helpers ───────────────────────────────────────────────────────

    def _paginate(self, params: dict, max_results: int) -> list[dict[str, Any]]:
        """Run paginated NVD requests until max_results reached or exhausted."""
        all_vulns: list[dict] = []

        while True:
            self._throttle()
            try:
                resp = requests.get(
                    self.base_url, headers=self.headers,
                    params=params, timeout=30,
                )
                resp.raise_for_status()
                data  = resp.json()
                total = data.get("totalResults", 0)
                batch = data.get("vulnerabilities", [])
                all_vulns.extend(batch)

                fetched = params["startIndex"] + len(batch)
                if fetched >= min(total, max_results) or not batch:
                    break
                params["startIndex"] = fetched

            except requests.exceptions.RequestException as e:
                print(f"[!] NVD request error: {e}")
                break

        return self.normalize(all_vulns)

    def _fetch_by_cve_id(self, cve_id: str) -> list[dict[str, Any]]:
        """Exact CVE-ID lookup via dedicated NVD parameter."""
        self._throttle()
        try:
            resp = requests.get(
                self.base_url, headers=self.headers,
                params={"cveId": cve_id.upper()}, timeout=30,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                print(f"[!] CVE not found: {cve_id}")
                return []
            return self.normalize(vulns)
        except requests.exceptions.RequestException as e:
            print(f"[!] NVD CVE-ID lookup error: {e}")
            return []

    @staticmethod
    def _extract_english_description(descriptions: list[dict]) -> str:
        for d in descriptions:
            if d.get("lang") == "en" and d.get("value"):
                return d["value"]
        if descriptions and descriptions[0].get("value"):
            return descriptions[0]["value"]
        return "No description available."

    @staticmethod
    def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                return (
                    data.get("baseScore"),
                    data.get("baseSeverity"),
                    data.get("vectorString"),
                )
        return None, None, None

    @staticmethod
    def _extract_cwes(weaknesses: list[dict]) -> list[str]:
        return [
            d["value"]
            for w in weaknesses
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        ]
    
#--------------test--------------------------------------
if __name__ == "__main__":
    print("[*] Starting test run for NVDCollector...")
    # Init the collector
    collector = NVDCollector()

    print("[*] Fetching recent threat reports from the year 2024...")
    # Call the function to fetch data (year 2024)
    recent_threats = collector.fetch_by_time(max_results=50, year=2024)

    print(f"[*] Found {len(recent_threats)} reports. Starting to save to Database...")

    success_count = 0
    duplicate_count = 0

    # Scan through the fetched reports and save them to the database
    for threat_data in recent_threats:
        try:
            # Call the insert function from db/queries.py to save the data
            inserted_id = insert_raw_item(threat_data)
            
            if inserted_id:
                print(f"[+] Saved: {threat_data['title']} (ID: {inserted_id})")
                success_count += 1
            else:
                print(f"[-] Ignored duplicate: {threat_data['title']}")
                duplicate_count += 1
                
        except Exception as e:
            print(f"[!] Error saving article '{threat_data['title']}': {e}")

    print("-" * 60)
    print(f"[*] Success! Saved new: {success_count} | Duplicates: {duplicate_count}")
    # print(get_unprocessed_batch(10))
