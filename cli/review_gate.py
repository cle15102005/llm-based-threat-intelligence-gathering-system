# 1. Fetch all reports with status='pending' from DB
# 2. For each one:
#    a. Load the raw_item (title, source)
#    b. Load entities linked to source_id
#    c. Load ttps linked to source_id
#    d. Use formatter to display everything
#    e. input() → approve / reject / skip
#    f. On approve → write .txt to reports/ folder, update DB status
#    g. On reject  → update DB status to 'rejected'
#    h. On skip    → leave as 'pending', continue loop

# cli/review_gate.py

import datetime
import os
from pathlib import Path

from cli.formatter import (print_header, print_item_summary, print_entities,
                            print_ttps, print_report, print_status,
                            GREEN, RED, YELLOW, BOLD, RESET)
from db.queries import (get_pending_reports, get_entities_for_source,
                        get_ttps_for_source, update_report_status)

REPORTS_DIR = Path("reports")

def _save_report_txt(report: dict, entities: list, ttps: list) -> Path:
    """Write the approved report to a timestamped .txt file."""
    REPORTS_DIR.mkdir(exist_ok=True)
    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = REPORTS_DIR / f"report_{report['source_id']}_{ts}.txt"

    with open(fname, "w", encoding="utf-8") as f:
        f.write(f"THREAT INTELLIGENCE REPORT\n")
        f.write(f"Generated : {report['created_at']}\n")
        f.write(f"Approved  : {datetime.datetime.now().isoformat()}\n")
        f.write(f"Source ID : {report['source_id']}\n")
        f.write(f"Title     : {report['title']}\n")
        f.write(f"Source    : {report['source']}\n\n")

        f.write("── ENTITIES ──────────────────────────────────\n")
        for e in entities:
            f.write(f"  {e['entity_type']:<16} {e['entity_value']}\n")

        f.write("\n── MITRE ATT&CK TTPs ─────────────────────────\n")
        for t in ttps:
            f.write(f"  {t['ttp_id']:<12} {t['technique_name']}\n")

        f.write("\n── ANALYST SUMMARY ───────────────────────────\n")
        f.write(report['summary'] + "\n")

    return fname

def run_review_gate():
    pending = get_pending_reports()

    if not pending:
        print_status("No pending reports to review.", "info")
        return

    print_header(f"HUMAN-IN-THE-LOOP REVIEW  ({len(pending)} pending)")

    approved = rejected = skipped = 0

    for report in pending:
        source_id = report['source_id']
        entities  = get_entities_for_source(source_id)
        ttps      = get_ttps_for_source(source_id)

        print_item_summary(report)
        print_entities(entities)
        print_ttps(ttps)
        print_report(report['summary'])

        # Analyst prompt
        while True:
            choice = input(
                f"  {BOLD}Decision [{GREEN}approve{RESET}{BOLD}/"
                f"{RED}reject{RESET}{BOLD}/{YELLOW}skip{RESET}{BOLD}]: {RESET}"
            ).strip().lower()

            if choice in ("approve", "a"):
                path = _save_report_txt(report, entities, ttps)
                update_report_status(source_id, "approved")
                print_status(f"Approved. Saved → {path}", "ok")
                approved += 1
                break

            elif choice in ("reject", "r"):
                update_report_status(source_id, "rejected")
                print_status("Marked as rejected in DB.", "warn")
                rejected += 1
                break

            elif choice in ("skip", "s", ""):
                print_status("Skipped (remains pending).", "info")
                skipped += 1
                break
            else:
                print_status("Please type: approve / reject / skip", "warn")

        print()  # blank line between items

    print_header(
        f"Review complete — "
        f"{GREEN}{approved} approved{RESET}  "
        f"{RED}{rejected} rejected{RESET}  "
        f"{YELLOW}{skipped} skipped{RESET}"
    )