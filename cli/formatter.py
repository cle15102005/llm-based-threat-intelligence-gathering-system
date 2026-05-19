# cli/formatter.py

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RED    = "\033[91m"
GRAY   = "\033[90m"

def print_header(title: str):
    width = 60
    print(f"\n{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}\n")

def print_item_summary(item: dict):
    print(f"{BOLD}  Source ID : {RESET}{item.get('id')}")
    print(f"{BOLD}  Source    : {RESET}{item.get('source', '—')}")
    print(f"{BOLD}  Title     : {RESET}{item.get('title', '—')}")
    print(f"{BOLD}  Published : {RESET}{item.get('published_date', '—')}\n")

def print_entities(entities: list[dict]):
    if not entities:
        print(f"  {GRAY}No entities extracted.{RESET}\n")
        return
    print(f"{BOLD}{YELLOW}  ── Extracted Entities ──────────────────────{RESET}")
    # Group by type for cleaner display
    from collections import defaultdict
    grouped = defaultdict(list)
    for e in entities:
        grouped[e['entity_type']].append(e['entity_value'])
    for etype, values in grouped.items():
        print(f"  {YELLOW}{etype:<16}{RESET} {', '.join(values)}")
    print()

def print_ttps(ttps: list[dict]):
    if not ttps:
        print(f"  {GRAY}No TTPs mapped.{RESET}\n")
        return
    print(f"{BOLD}{CYAN}  ── MITRE ATT&CK TTPs ───────────────────────{RESET}")
    for t in ttps:
        print(f"  {CYAN}{t['ttp_id']:<12}{RESET} {t['technique_name']}")
    print()

def print_report(summary: str):
    print(f"{BOLD}{GREEN}  ── Generated Report ────────────────────────{RESET}")
    # Word-wrap at 70 chars
    import textwrap
    for line in textwrap.wrap(summary, width=70):
        print(f"  {line}")
    print()

def print_status(message: str, level: str = "info"):
    icons = {"info": f"{CYAN}[*]{RESET}", "ok": f"{GREEN}[+]{RESET}",
             "warn": f"{YELLOW}[!]{RESET}", "error": f"{RED}[-]{RESET}"}
    print(f"  {icons.get(level, '[?]')} {message}")