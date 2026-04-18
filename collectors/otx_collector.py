from __future__ import annotations

import os
import requests
from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base_collector import BaseCollector
from db.queries import insert_raw_item


class OTXCollector(BaseCollector):
    """
    Fetches threat pulse data from AlienVault OTX.
    https://otx.alienvault.com/api

    Free API key required: https://otx.alienvault.com
    """

    DEFAULT_DELAY = 1.0

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(source_name="alienvault")
        self.api_key = api_key or os.getenv("OTX_API_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "User-Agent": "llm-threat-intel-collector/1.0",
            "Accept":     "application/json",
        }
        if self.api_key:
            self.headers["X-OTX-API-KEY"] = self.api_key
            print("[*] OTX API key detected. Requests will be successful.")
        else:
            print("[!] Warning: No OTX API key found. Requests will likely fail.")

    # ── Task 1: fetch by time window ──────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Fetch OTX pulses within a time window.

        Examples:
            col.fetch_by_time()               # last 7 days
            col.fetch_by_time(days_back=30)   # last 30 days
            col.fetch_by_time(year=2021)      # pulses created in 2021

        Note: OTX activity endpoint filters by modified_since.
        Year mode uses Jan 1 of that year as the cutoff.
        """
        if year is not None:
            since = datetime(year, 1, 1, tzinfo=timezone.utc)
        else:
            since = datetime.now(timezone.utc) - timedelta(days=days_back or 7)

        params = {
            "limit":          min(max_results, 50),  # OTX max per page is 50
            "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        return self._paginate_activity(params, max_results)

    # ── Task 2: fetch by keyword ──────────────────────────────────────────────

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Search OTX pulses by keyword, threat name, or malware family.

        Matching behavior:
            - 'WannaCry'       → matches pulses about the WannaCry campaign
            - 'wanna'          → partial match, still finds WannaCry pulses
            - 'ransomware'     → matches any pulse tagged/described as ransomware
            - 'CVE-2021-44228' → matches pulses referencing Log4Shell by text

        OTX search is full-text across pulse title, description, and tags.
        Partial and case-insensitive matching supported server-side.

        Note: for CVE-ID specific pulse lookup (more precise than keyword),
        use fetch_by_cve_id() instead.
        """
        self._throttle()
        try:
            resp = requests.get(
                f"{self.base_url}/search/pulses",
                headers=self.headers,
                params={"q": query.strip(), "limit": max_results},
                timeout=30,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            return self.normalize(results)
        except requests.exceptions.RequestException as e:
            print(f"[!] OTX keyword search error: {e}")
            return []

    def fetch_by_cve_id(self, cve_id: str) -> list[dict[str, Any]]:
        """
        Retrieve OTX pulses directly linked to a specific CVE ID.

        Uses OTX's dedicated indicator endpoint:
            GET /api/v1/indicator/CVE/<cve_id>/general

        This is more precise than fetch_by_keyword("CVE-2017-0144") because:
          - It only returns pulses that explicitly tagged this CVE as an IOC,
            not pulses that merely mention the ID in free text.
          - It also returns associated threat actors and malware families
            that OTX has structurally linked to this CVE.

        Typical usage in the enrichment pipeline:
            # NVD returns CVE-2017-0144 (EternalBlue)
            pulses = otx.fetch_by_cve_id("CVE-2017-0144")
            # → returns WannaCry, NotPetya, and other campaigns exploiting it

        Args:
            cve_id : CVE identifier string, e.g. 'CVE-2017-0144'.
                     Normalized to uppercase internally.

        Returns:
            List of normalized record dicts, same schema as all other methods.
            Empty list if CVE not found in OTX or on error.
        """
        cve_id = cve_id.upper().strip()
        self._throttle()
        try:
            resp = requests.get(
                f"{self.base_url}/indicator/CVE/{cve_id}/general",
                headers=self.headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            # OTX indicator/CVE endpoint returns pulse_info.pulses list
            pulses = data.get("pulse_info", {}).get("pulses", [])
            if not pulses:
                print(f"[!] No OTX pulses found for {cve_id}")
                return []

            records = self.normalize(pulses)

            # Tag every record with the queried CVE ID so downstream
            # enrichment knows which CVE triggered this collection
            for r in records:
                r["raw"].setdefault("linked_cve", cve_id)

            return records

        except requests.exceptions.RequestException as e:
            print(f"[!] OTX CVE lookup error for {cve_id}: {e}")
            return []

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        records = []
        for pulse in raw_data:
            pulse_id = pulse.get("id")
            if not pulse_id:
                continue

            indicators = pulse.get("indicators", [])
            ioc_counts: dict[str, int] = {}
            for ind in indicators:
                t = ind.get("type", "unknown")
                ioc_counts[t] = ioc_counts.get(t, 0) + 1

            records.append(self.format_record(
                title          = pulse.get("name"),
                description    = pulse.get("description"),
                url            = f"https://otx.alienvault.com/pulse/{pulse_id}",
                published_date = pulse.get("created"),
                raw            = {
                    "adversary":        pulse.get("adversary", ""),
                    "malware_families": [
                        m.get("display_name", "")
                        for m in pulse.get("malware_families", [])
                    ],
                    "attack_ids": [
                        a.get("id", "") for a in pulse.get("attack_ids", [])
                    ],
                    "ioc_counts": ioc_counts,
                    "tags":       pulse.get("tags", []),
                },
            ))
        return records

    # ── Private helpers ───────────────────────────────────────────────────────

    def _paginate_activity(
        self,
        params: dict,
        max_results: int,
    ) -> list[dict[str, Any]]:
        """Paginate OTX activity feed via the `next` URL OTX returns."""
        all_records: list[dict] = []
        url = f"{self.base_url}/pulses/activity"

        while url and len(all_records) < max_results:
            self._throttle()
            try:
                resp = requests.get(url, headers=self.headers,
                                    params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                all_records.extend(self.normalize(data.get("results", [])))
                url    = data.get("next")  # OTX returns full next-page URL
                params = {}                # params already encoded in next URL
            except requests.exceptions.RequestException as e:
                print(f"[!] OTX activity fetch error: {e}")
                break

        return all_records[:max_results]
    
#--------------test--------------------------------------
if __name__ == "__main__":
    print("[*] Starting test run for OTXCollector...")
    # Init the collector
    collector = OTXCollector()

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