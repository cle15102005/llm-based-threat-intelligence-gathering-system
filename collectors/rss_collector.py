from __future__ import annotations

import feedparser
from datetime import datetime, timezone
from typing import Any

from collectors.base_collector import BaseCollector

from db.queries import insert_raw_item

# Well-known security RSS feeds — extend as needed
KNOWN_FEEDS: dict[str, str] = {
    "exploitdb":         "https://www.exploit-db.com/rss.xml",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/",
    "sans_isc":          "https://isc.sans.edu/rssfeed_full.xml",
    "packet_storm":      "https://rss.packetstormsecurity.com/files/",
}


class RSSCollector(BaseCollector):
    """
    Fetches threat intelligence from public RSS feeds.
    Defaults to Exploit-DB. No API key required.

    Fixes applied:
        FIX 1 — dedup_key is now present in every record automatically
                 because format_record() in BaseCollector generates it.
                 No code changes needed in this file.

    Note: RSS feeds have no server-side filtering API.
    Both fetch_by_time() and fetch_by_keyword() pull the full feed
    and filter client-side. Acceptable given typical feed sizes (50–200).
    """

    DEFAULT_DELAY = 2.0

    def __init__(self, feed_url: str = KNOWN_FEEDS["exploitdb"]) -> None:
        super().__init__(source_name="exploit-db")
        self.feed_url = feed_url

    # ── Task 1: fetch by time window ──────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Fetch RSS entries within a time window.

        Examples:
            col.fetch_by_time()           # entries from last 7 days
            col.fetch_by_time(year=2023)  # entries published in 2023

        Filtering is client-side — the full feed is pulled then filtered
        by the parsed published date of each entry.
        """
        all_records = self.normalize(self._fetch_raw())

        if year is not None:
            filtered = [
                r for r in all_records
                if self._entry_year(r["published_date"]) == year
            ]
        else:
            cutoff = datetime.now(timezone.utc).timestamp() - (days_back or 7) * 86400
            filtered = [
                r for r in all_records
                if self._entry_timestamp(r["published_date"]) >= cutoff
            ]

        return filtered[:max_results]

    # ── Task 2: fetch by keyword ──────────────────────────────────────────────

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Search RSS entries by keyword in title or description.

        Matching behavior:
            - 'WannaCry'   → matches any entry mentioning WannaCry
            - 'wanna'      → partial match, case-insensitive
            - 'apache rce' → ALL words must appear (AND logic)

        Filtering is client-side — full feed is pulled then filtered.
        """
        all_records = self.normalize(self._fetch_raw())
        terms = query.strip().lower().split()

        matched = [
            r for r in all_records
            if all(
                term in r["title"].lower() or term in r["description"].lower()
                for term in terms
            )
        ]
        return matched[:max_results]

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        records = []
        for entry in raw_data:
            records.append(self.format_record(
                title          = entry.get("title"),
                description    = entry.get("summary") or entry.get("description"),
                url            = entry.get("link"),
                published_date = entry.get("published"),
                # dedup_key generated automatically by format_record()
            ))
        return records

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch_raw(self) -> list[Any]:
        """Pull and parse the RSS feed. Returns feedparser entry objects."""
        feed = feedparser.parse(self.feed_url)
        if feed.bozo:
            print(f"[!] RSS parse warning: {feed.bozo_exception}")
        return feed.entries

    @staticmethod
    def _entry_timestamp(date_str: str) -> float:
        """Parse an RSS date string to a UTC Unix timestamp. Returns 0 on failure."""
        if not date_str:
            return 0.0
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str).timestamp()
        except Exception:
            return 0.0

    @staticmethod
    def _entry_year(date_str: str) -> int | None:
        """Extract the year from an RSS date string. Returns None on failure."""
        if not date_str:
            return None
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str).year
        except Exception:
            return None
        

#--------------test--------------------------------------
if __name__ == "__main__":
    print("[*] Starting test run for RSSCollector...")
    # Init the collector
    collector = RSSCollector()

    print("[*] Fetching recent threat reports from the last 30 days...")
    # Call the function to fetch data (get the most recent 30 days for speed)
    recent_threats = collector.fetch_by_time(days_back=30)

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