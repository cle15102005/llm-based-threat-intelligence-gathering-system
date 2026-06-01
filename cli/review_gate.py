# cli/review_gate.py
"""
Human-in-the-loop review gate.

Analyst decisions per pending report:
  approve  (a) — write .txt to reports/, mark DB status 'approved'
  reject   (r) — mark DB status 'rejected'
  reprocess(p) — reset item to unprocessed and re-run full enrichment chain
  skip     (s) — leave as 'pending', continue loop
"""

import datetime
import os
from pathlib import Path

from cli.formatter import (print_header, print_report, print_status,
                            GREEN, RED, YELLOW, CYAN, BOLD, RESET)

REPORTS_DIR = Path("reports")


def _save_report_txt(report: dict) -> Path:
    """Write the approved report to a timestamped .txt file."""
    REPORTS_DIR.mkdir(exist_ok=True)
    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = REPORTS_DIR / f"report_{report['source_id']}_{ts}.txt"

    with open(fname, "w", encoding="utf-8") as f:
        f.write("THREAT INTELLIGENCE REPORT\n")
        f.write(f"Generated : {report['created_at']}\n")
        f.write(f"Approved  : {datetime.datetime.now().isoformat()}\n")
        f.write(f"Source ID : {report['source_id']}\n")

        f.write("── REPORT DETAILS ─────────────────────────────\n")
        f.write(report['summary'])

    return fname


def run_review_gate() -> None:
    from db.sqlite_manager import (get_pending_reports, update_report_status, delete_report)
    pending = get_pending_reports()

    if not pending:
        print_status("No pending reports to review.", "info")
        return

    print_header(f"HUMAN-IN-THE-LOOP REVIEW  ({len(pending)} pending)")

    approved = rejected = skipped = reprocessed = 0

    for report in pending:
        source_id = report['source_id']

        print_report(report['summary'])

        while True:
            choice = input(
                f"{BOLD}Decision [{GREEN}approve{RESET}{BOLD}/"
                f"{RED}reject{RESET}{BOLD}/"
                f"{CYAN}reprocess{RESET}{BOLD}/"
                f"{YELLOW}skip{RESET}{BOLD}]: {RESET}"
            ).strip().lower()

            if choice in ("approve", "a"):
                path = _save_report_txt(report)
                update_report_status(report['id'], "approved")
                print_status(f"Approved. Saved → {path}", "ok")
                approved += 1
                break

            elif choice in ("reject", "r"):
                update_report_status(report['id'], "rejected")
                print_status("Marked as rejected in DB.", "warn")
                rejected += 1
                break

            elif choice in ("reprocess", "p"):
                # Import here to avoid circular dependency at module load time
                try:
                    from cli.pipeline_runner import reprocess_item
                    print_status(
                        f"Re-running enrichment for source_id={source_id} …",
                        "info",
                    )
                    delete_report(report['id'])  # delete old report
                    reprocess_item(source_id)
                    print_status(
                        "Reprocessing complete. "
                        "The updated report will appear in the next review session.",
                        "ok",
                    )
                except Exception as exc:
                    print_status(f"Reprocess failed: {exc}", "error")
                reprocessed += 1
                break

            elif choice in ("skip", "s", ""):
                print_status("Skipped (remains pending).", "info")
                skipped += 1
                break

            else:
                print_status(
                    "Please type: approve / reject / reprocess / skip", "warn"
                )

        print()  # blank line between items

    print_header(
        f"Review complete — "
        f"{GREEN}{approved} approved{RESET}  "
        f"{RED}{rejected} rejected{RESET}  "
        f"{CYAN}{reprocessed} reprocessed{RESET}  "
        f"{YELLOW}{skipped} skipped{RESET}"
    )
