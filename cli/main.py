# cli/main.py
"""
LLM-Based Threat Intelligence Pipeline — Main CLI Entry Point.

Two execution modes:
  Interactive  (no args)  : python -m cli.main
                            Guided session: source select → operation → review gate
  Non-interactive (args)  : python -m cli.main collect --source all --days 7
                            Backward-compatible argparse path for scripts / CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from db.sqlite_manager import DB_PATH, init_db
from cli.formatter import (
    print_header, print_status,
    BOLD, RESET, CYAN, GREEN, YELLOW, RED, GRAY,
)
from cli.pipeline_runner import (
    COLLECTOR_REGISTRY,
    SOURCE_MENU_ORDER,
    collect_parallel,
    run_preprocess,
    run_report,
    reprocess_item,
    run_full_pipeline,
)

# ── Interactive helpers ───────────────────────────────────────────────────────

def _banner() -> None:
    width = 60
    print(f"\n{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  LLM-BASED THREAT INTELLIGENCE PIPELINE{RESET}")
    print(f"{BOLD}{CYAN}  IT4413E — Penetration Testing | HUST SOICT{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}\n")


def _prompt(text: str, default: str = "") -> str:
    """Simple input wrapper that shows a default value."""
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"  {BOLD}{text}{hint}: {RESET}").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _select_sources() -> list[str]:
    """
    Numbered multi-select for data sources.
    Returns a list of source keys from COLLECTOR_REGISTRY.
    """
    print(f"\n{BOLD}{CYAN}  ── Select Data Source(s) ──────────────────────{RESET}")
    entries = [(i + 1, key, COLLECTOR_REGISTRY[key][0])
               for i, key in enumerate(SOURCE_MENU_ORDER)]

    for num, _key, label in entries:
        print(f"  {CYAN}[{num}]{RESET} {label}")
    print(f"  {CYAN}[A]{RESET} All Sources")
    print()

    raw = _prompt("Enter number(s) separated by commas, or A for all", "A")

    if raw.upper() == "A" or raw == "":
        return ["all"]

    selected: list[str] = []
    for token in raw.split(","):
        token = token.strip()
        try:
            idx = int(token) - 1
            if 0 <= idx < len(entries):
                selected.append(entries[idx][1])
            else:
                print_status(f"'{token}' out of range — skipped.", "warn")
        except ValueError:
            print_status(f"'{token}' is not a valid number — skipped.", "warn")

    if not selected:
        print_status("No valid sources selected, defaulting to All.", "warn")
        return ["all"]
    return selected


def _select_operation() -> str:
    """
    Shows the main operation menu.
    Returns a string operation key.
    """
    ops = [
        ("full_date",    "Full Pipeline — Fetch by Date"),
        ("full_keyword", "Full Pipeline — Fetch by Keyword"),
        ("collect",      "Collect Only"),
        ("preprocess",   "Preprocess Only"),
        ("enrichment_report",       "Enrich and Generate Reports"),
        ("review",       "Review Pending Reports"),
        ("reprocess",    "Reprocess Item by ID"),
        ("exit",         "Exit"),
    ]

    print(f"\n{BOLD}{CYAN}  ── Select Operation ────────────────────────────{RESET}")
    for i, (_key, label) in enumerate(ops, 1):
        color = RED if _key == "exit" else CYAN
        print(f"  {color}[{i}]{RESET} {label}")
    print()

    while True:
        raw = _prompt("Choice", "1")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(ops):
                return ops[idx][0]
        except ValueError:
            pass
        print_status("Invalid choice, try again.", "warn")


def _get_days() -> int:
    raw = _prompt("Days back to collect", "7")
    try:
        return int(raw)
    except ValueError:
        print_status("Invalid number, using 7.", "warn")
        return 7


def _get_keyword() -> str:
    kw = _prompt("Search keyword (e.g. 'ransomware', 'CVE-2024-1234')")
    if not kw:
        print_status("Empty keyword, using 'ransomware'.", "warn")
        return "ransomware"
    return kw


def _get_source_id() -> int | None:
    raw = _prompt("Item ID to reprocess")
    try:
        return int(raw)
    except ValueError:
        print_status("Invalid ID.", "error")
        return None


# ── Post-processing analyst gate ──────────────────────────────────────────────

def _post_processing_gate() -> str:
    """
    Shown after a pipeline run completes.
    Returns: 'review' | 'continue' | 'exit'
    """
    print(f"\n{BOLD}{GREEN}  ── Processing Complete ─────────────────────────{RESET}")
    options = [
        ("review",   "Review & approve / reject pending reports"),
        ("continue", "Continue — start a new collection session"),
        ("exit",     "Exit"),
    ]
    for i, (_key, label) in enumerate(options, 1):
        color = RED if _key == "exit" else GREEN
        print(f"  {color}[{i}]{RESET} {label}")
    print()

    while True:
        raw = _prompt("Action", "1")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            pass
        print_status("Invalid choice, try again.", "warn")


# ── Interactive session ───────────────────────────────────────────────────────

def run_interactive_session() -> None:
    """
    Guided analyst session.

    Loop:
      1. Source selection
      2. Operation selection
      3. Execute operation
      4. Post-processing gate (for full-pipeline operations)
    """
    _banner()
    db = Path(DB_PATH)

    while True:
        try:
            # ── Source selection (only needed for collection operations) ──────
            source_keys = _select_sources()

            # ── Operation selection ───────────────────────────────────────────
            operation = _select_operation()

            if operation == "exit":
                print_status("Goodbye.", "info")
                break

            # ── Execute ───────────────────────────────────────────────────────

            if operation == "full_date":
                days = _get_days()
                print_header("FULL PIPELINE — FETCH BY DATE")
                run_full_pipeline(
                    source_keys, db,
                    mode="time",
                    run_review=False,   # handled by post-processing gate below
                    days_back=days,
                )
                action = _post_processing_gate()
                if action == "review":
                    _run_review()
                elif action == "exit":
                    break
                # "continue" falls through to next loop iteration

            elif operation == "full_keyword":
                kw = _get_keyword()
                print_header("FULL PIPELINE — FETCH BY KEYWORD")
                run_full_pipeline(
                    source_keys, db,
                    mode="keyword",
                    run_review=False,
                    query=kw,
                )
                action = _post_processing_gate()
                if action == "review":
                    _run_review()
                elif action == "exit":
                    break

            elif operation == "collect":
                mode = "time"
                kwargs: dict = {}
                sub = _prompt("Mode — (D)ate or (K)eyword", "D").upper()
                if sub == "K":
                    mode = "keyword"
                    kwargs["query"] = _get_keyword()
                else:
                    kwargs["days_back"] = _get_days()
                print_header("COLLECT")
                collect_parallel(source_keys, db, mode=mode, **kwargs)

            elif operation == "preprocess":
                # check if database exists:
                if not db.exists():
                    print_status("Database not found. Please run a collection operation first.", "warn")
                    continue
                # check database for unprocessed items, if none found, prompt to run collection first
                from db.sqlite_manager import count_unprocessed_items
                unprocessed_count = count_unprocessed_items()
                if unprocessed_count == 0:
                    print_status("No unprocessed items found. Please run a collection operation first.", "warn")
                else:
                    print_status(f"Found {unprocessed_count} unprocessed item(s). Starting preprocessing...", "info")
                    run_preprocess()

            elif operation == "enrichment_report":
                # check if database exists:
                if not db.exists():
                    print_status("Database not found. Please run a collection operation first.", "warn")
                    continue
                # check database for preprocessed but not enriched items, if none found, prompt to run preprocess first
                from db.sqlite_manager import count_preprocessed_unenriched_items   
                pending_count = count_preprocessed_unenriched_items()
                if pending_count == 0:
                    print_status("No preprocessed but unenriched items found. Please run preprocessing first.", "warn") 
                else:
                    print_status(f"Found {pending_count} preprocessed but unenriched item(s). Starting enrichment and report generation...", "info")
                    run_report()

            elif operation == "review":
                _run_review()

            elif operation == "reprocess":
                sid = _get_source_id()
                if sid is not None:
                    reprocess_item(sid)

        except KeyboardInterrupt:
            print(f"\n{YELLOW}  [!] Interrupted. Press Ctrl+C again to exit or Enter to continue.{RESET}")
            try:
                input()
                continue
            except (KeyboardInterrupt, EOFError):
                print_status("Goodbye.", "info")
                break


def _run_review() -> None:
    """Thin wrapper so review_gate import errors don't crash the session."""
    try:
        from cli.review_gate import run_review_gate
        run_review_gate()
    except ImportError as exc:
        print_status(f"review_gate unavailable: {exc}", "error")


# ── Argparse (non-interactive / scripting path) ───────────────────────────────
# Kept for backward compatibility with SAMPLE_CLI_USAGE.md

def _argparse_main() -> None:
    parser = argparse.ArgumentParser(
        prog="threatcli",
        description="LLM-Based Threat Intelligence Pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # collect
    p_col = sub.add_parser("collect", help="Fetch data from NVD / OTX / RSS")
    p_col.add_argument("--source", default="all",
                       choices=list(COLLECTOR_REGISTRY.keys()) + ["all"])
    p_col.add_argument("--days",  type=int, default=7)
    p_col.add_argument("--query", type=str, default=None)

    # preprocess
    sub.add_parser("preprocess", help="Strip HTML, deduplicate, encapsulate")

    # enrich and report
    sub.add_parser("report", help="Enrich and generate LLM analyst reports")

    # review
    sub.add_parser("review", help="Human-in-the-loop review gate")

    # run-all-date  (new spec name)
    p_date = sub.add_parser("run-all-date", help="Full pipeline — fetch by date")
    p_date.add_argument("--source", default="all",
                        choices=list(COLLECTOR_REGISTRY.keys()) + ["all"])
    p_date.add_argument("--days", type=int, default=7)

    # run-all-keyword  (new spec name)
    p_kw = sub.add_parser("run-all-keyword", help="Full pipeline — fetch by keyword")
    p_kw.add_argument("--source", default="all",
                      choices=list(COLLECTOR_REGISTRY.keys()) + ["all"])
    p_kw.add_argument("--keyword", type=str, required=True)

    # run-all  (legacy alias)
    p_all = sub.add_parser("run-all", help="Full pipeline end-to-end (legacy)")
    p_all.add_argument("--source", default="all",
                       choices=list(COLLECTOR_REGISTRY.keys()) + ["all"])
    p_all.add_argument("--days",  type=int, default=7)
    p_all.add_argument("--query", type=str, default=None)

    # reprocess
    p_re = sub.add_parser("reprocess", help="Reset and re-enrich a single item")
    p_re.add_argument("--id", type=int, required=True, dest="item_id")

    args = parser.parse_args()
    db   = Path(DB_PATH)

    if args.command == "collect":
        sources = [args.source] if args.source != "all" else ["all"]
        mode    = "keyword" if args.query else "time"
        kwargs  = {"query": args.query} if args.query else {"days_back": args.days}
        collect_parallel(sources, db, mode=mode, **kwargs)

    elif args.command == "preprocess":
        run_preprocess()


    elif args.command == "report":
        run_report()

    elif args.command == "enrichment_report":
        _run_review()

    elif args.command == "run-all-date":
        sources = [args.source] if args.source != "all" else ["all"]
        run_full_pipeline(sources, db, mode="time", run_review=True,
                          days_back=args.days)

    elif args.command == "run-all-keyword":
        sources = [args.source] if args.source != "all" else ["all"]
        run_full_pipeline(sources, db, mode="keyword", run_review=True,
                          query=args.keyword)

    elif args.command == "run-all":
        sources = [args.source] if args.source != "all" else ["all"]
        mode    = "keyword" if args.query else "time"
        kwargs  = {"query": args.query} if args.query else {"days_back": args.days}
        run_full_pipeline(sources, db, mode=mode, run_review=True, **kwargs)

    elif args.command == "reprocess":
        reprocess_item(args.item_id)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    # Ensure DB is initialized before any operations (interactive or argparse)
    init_db()
    print_status(f"Database initialized at {DB_PATH}", "info")
    # No CLI args → interactive session.  Any arg → argparse path.
    if len(sys.argv) == 1:
        run_interactive_session()
    else:
        _argparse_main()


if __name__ == "__main__":
    main()
