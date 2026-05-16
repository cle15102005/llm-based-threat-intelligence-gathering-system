from __future__ import annotations

import feedparser
import hashlib
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from typing import Any

from collectors.base_collector import BaseCollector

# Well-known security RSS feeds - extend as needed
KNOWN_FEEDS: dict[str, str] = {
    "exploitdb":         "https://www.exploit-db.com/rss.xml",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/",
    "sans_isc":          "https://isc.sans.edu/rssfeed_full.xml",
    "packet_storm":      "https://rss.packetstormsecurity.com/files/",
    # EXTENSION POINT: Add more feeds here as needed
    "xakep":             "https://xakep.ru/category/news/feed/",  # Russian - passes through language_detector.py
}

# ---------------------------------------------------------------------------
# Per-domain scraping config
#
# "selectors"    : CSS selectors tried IN ORDER. First match with meaningful
#                  content wins.  Generic fallback ("p") is appended automatically
#                  and only used if all named selectors fail.
# "paywall_skip" : If True, skip scraping entirely and use the RSS summary.
#                  Use for hard paywalls where scraping always returns noise.
# "paywall_markers": Strings whose presence in scraped text signals a paywall
#                  page was returned instead of article content.  When any
#                  marker is found the scraper falls back to the RSS summary.
# ---------------------------------------------------------------------------
DOMAIN_CONFIG: dict[str, dict] = {
    "xakep.ru": {
        # Xakep is a subscription magazine. Free visitors see only a short
        # teaser inside .post-box or .entry-content; everything below the
        # fold is a subscription upsell block.  The generic <p> approach
        # grabs the sidebar promo text ("Годовая подписка на Хакер …")
        # instead of the teaser, so we use a specific selector chain.
        "selectors": [
            ".post-box",          # teaser block visible to free readers
            ".entry-content",     # standard WordPress body
            "article .content",
        ],
        "paywall_markers": [
            "годовая подписка",   # "Annual subscription" promo header
            "подписка на хакер",  # "Subscribe to Hacker"
            "оформить подписку",  # "Subscribe now"
        ],
    },
    "default": {
        "selectors": [
            "article",
            "[itemprop='articleBody']",
            ".article-body",
            ".post-content",
            ".entry-content",
            ".article__body",
            ".tm-article-body",   # Habr / Tproger
            "main .content",
        ],
        "paywall_markers": [
            "subscribe to read",
            "create a free account",
            "sign in to continue",
            "this content is for subscribers",
        ],
    },
}


def _domain_cfg(url: str) -> dict:
    """Return the DOMAIN_CONFIG entry that matches *url*, or 'default'."""
    for domain, cfg in DOMAIN_CONFIG.items():
        if domain != "default" and domain in (url or ""):
            return cfg
    return DOMAIN_CONFIG["default"]


class RSSCollector(BaseCollector):
    """
    Fetches threat intelligence from public RSS feeds.
    Defaults to Exploit-DB. No API key required.

    Scraping strategy (per request, applied in normalize()):
      1. Try domain-specific CSS selectors from DOMAIN_CONFIG.
      2. Validate scraped text:
           a. Must be longer than the RSS summary (otherwise scraping added nothing).
           b. Must NOT contain paywall marker strings.
      3. If validation fails → fall back to the original RSS summary.
      4. Generic <p> soup is the last resort only for domains with no config.

    """

    DEFAULT_DELAY = 2.0

    def __init__(self, feed_url: str = KNOWN_FEEDS["exploitdb"]) -> None:
        super().__init__(source_name="exploit-db")
        self.feed_url = feed_url

    # ── Public API ────────────────────────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Fetch RSS entries within a time window.

        Examples:
            col.fetch_by_time()            # entries from last 7 days
            col.fetch_by_time(year=2023)   # entries published in 2023

        Filtering is client-side - the full feed is pulled then filtered by
        the parsed published date of each entry.
        """
        raw_entries = self._fetch_raw()

        if year is not None:
            filtered = [
                e for e in raw_entries
                if self._entry_year(e.get("published")) == year
            ]
        else:
            cutoff = (
                datetime.now(timezone.utc).timestamp() - (days_back or 7) * 86400
            )
            filtered = [
                e for e in raw_entries
                if self._entry_timestamp(e.get("published")) >= cutoff
            ]

        return self.normalize(filtered[:max_results])

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Search RSS entries by keyword in title or description.

        Matching behaviour:
            'WannaCry'   → any entry mentioning WannaCry (case-insensitive)
            'wanna'      → partial match
            'apache rce' → ALL words must appear (AND logic)

        Filtering is client-side.
        """
        raw_entries = self._fetch_raw()
        terms = query.strip().lower().split()

        filtered = [
            e for e in raw_entries
            if all(
                term in str(e.get("title", "")).lower()
                or term in str(e.get("summary", "")).lower()
                for term in terms
            )
        ]

        return self.normalize(filtered[:max_results])

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        records = []
        for entry in raw_data:
            link     = entry.get("link")
            entry_id = entry.get("id") or link
            rss_summary = entry.get("summary") or entry.get("description") or ""

            description = self._scrape_full_text(link, rss_summary)

            records.append(self.format_record(
                title          = entry.get("title"),
                description    = description,
                url            = link,
                published_date = entry.get("published"),
                raw            = {"entry_id": entry_id},
            ))
        return records

    # ── Dedup key ─────────────────────────────────────────────────────────────

    def _make_dedup_key(self, title: str, description: str, raw: dict) -> str:
        """
        Hash the immutable RSS entry ID / URL so that dynamic page changes
        (navbar updates, sidebar content rotations) never create false duplicates.
        """
        entry_id = raw.get("entry_id")
        content  = (
            f"{self.source_name}:id:{entry_id}"
            if entry_id
            else f"{self.source_name}:{title}"   # malformed feed fallback
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ── Scraping helpers ──────────────────────────────────────────────────────

    def _scrape_full_text(self, url: str | None, rss_summary: str) -> str:
        """
        Attempt to scrape the full article text from *url*.

        Strategy
        --------
        1. Fetch the page with a browser-like User-Agent.
        2. Try domain-specific CSS selectors (DOMAIN_CONFIG) in order.
        3. Validate the result:
             • Must be longer than the RSS summary (scraping must add value).
             • Must not contain paywall marker strings (would be noise).
        4. Fall back to the RSS summary on any failure or failed validation.

        Returns the best available text, never an empty string (unless the
        feed entry itself had no summary).
        """
        if not url:
            return rss_summary

        cfg = _domain_cfg(url)

        try:
            print(f"    [Scraping] {url}")
            resp = requests.get(
                url,
                timeout=10,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
                },
            )

            if resp.status_code != 200:
                print(f"    [!] HTTP {resp.status_code} - using RSS summary")
                return rss_summary

            soup = BeautifulSoup(resp.text, "html.parser")
            scraped = self._extract_text(soup, cfg)

            # ── Validation gate ───────────────────────────────────────────────
            if not scraped:
                print("    [!] No text extracted - using RSS summary")
                return rss_summary

            if self._is_paywall_content(scraped, cfg):
                print("    [!] Paywall detected - using RSS summary")
                return rss_summary

            if len(scraped) <= len(rss_summary):
                print("    [!] Scraped text not longer than summary - using RSS summary")
                return rss_summary

            return scraped

        except Exception as exc:
            print(f"    [!] Scraping failed: {exc} - using RSS summary")
            return rss_summary

    def _extract_text(self, soup: BeautifulSoup, cfg: dict) -> str:
        """
        Try each CSS selector in *cfg['selectors']* in order.
        Returns the text of the first element that yields > 100 characters,
        or an empty string if none matched.

        The generic <p>-tag sweep is the absolute last resort and only
        runs when all named selectors fail.
        """
        for selector in cfg.get("selectors", []):
            el = soup.select_one(selector)
            if el:
                text = el.get_text(separator=" ", strip=True)
                if len(text) > 100:
                    return text

        # Last resort: all paragraph tags (original behaviour, now gated)
        paragraphs = soup.find_all("p")
        fallback = "\n".join(
            p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)
        )
        return fallback if len(fallback) > 100 else ""

    @staticmethod
    def _is_paywall_content(text: str, cfg: dict) -> bool:
        """
        Return True if *text* contains any paywall marker from *cfg*.
        Comparison is case-insensitive.
        """
        lowered = text.lower()
        return any(
            marker.lower() in lowered
            for marker in cfg.get("paywall_markers", [])
        )

    # ── RSS fetch ─────────────────────────────────────────────────────────────

    def _fetch_raw(self) -> list[Any]:
        """Pull and parse the RSS feed. Returns feedparser entry objects."""
        import requests, ssl
        try:
            # Bypass SSL verification for Windows environments with missing certs
            resp = requests.get(self.feed_url, timeout=15, verify=False)
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)
        except Exception as e:
            print(f"[!] RSS fetch error: {e}")
            return []
        if feed.bozo and not feed.entries:
            print(f"[!] RSS parse warning: {feed.bozo_exception}")
        return feed.entries
        
        # feed = feedparser.parse(self.feed_url)
        # if feed.bozo:
        #     print(f"[!] RSS parse warning: {feed.bozo_exception}")
        # return feed.entries

    # ── Date helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _entry_timestamp(date_str: str) -> float:
        """Parse an RSS date string to a UTC Unix timestamp. Returns 0.0 on failure."""
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