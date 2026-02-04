#!/usr/bin/env python3

import argparse
import json
import sys
import re
from tabulate import tabulate

# --- ANSI Color Codes ---
if sys.stdout.isatty():
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, \
    COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE, COLOR_BOLD, COLOR_DIM = \
    ("\033[0m", "\033[91m", "\033[92m", "\033[93m", "\033[94m",
     "\033[95m", "\033[96m", "\033[97m", "\033[1m", "\033[2m")
else:
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, \
    COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE, COLOR_BOLD, COLOR_DIM = \
    ("", "", "", "", "", "", "", "", "", "")

# --- Constants ---
DESC_MAX_LEN = 60
TEST_FILE_REGEX = r'([\/\-_\s]+test[\/\-_\s]*)'

# --- Core logic functions ---

def resolve_severity(semgrep_severity):
    """Maps Semgrep severity strings to standardized labels and ANSI colors."""
    s = str(semgrep_severity).upper()
    if s == "ERROR":
        return "HIGH", COLOR_RED
    if s == "WARNING":
        return "MEDIUM", COLOR_YELLOW
    if s == "INFO":
        return "LOW", COLOR_CYAN
    return s, COLOR_WHITE

def is_test_file(filepath):
    """Returns True if the file path indicates a test file."""
    clean_path = str(filepath).replace("\\", "/")
    return bool(re.search(TEST_FILE_REGEX, clean_path, re.IGNORECASE))

def truncate_desc(msg):
    msg = str(msg or "")
    if len(msg) > DESC_MAX_LEN:
        return msg[:DESC_MAX_LEN-3] + "..."
    return msg

def process_findings(data, include_description=True):
    """Filters and formats findings from the raw JSON."""
    processed_rows = []
    severity_counts = {}

    raw_results = data.get("results", [])

    for finding in raw_results:
        path = finding.get("path", "")

        # 1. Filter excluded files
        if is_test_file(path):
            continue

        # 2. Extract line and col
        start = finding.get("start", {})
        line_info = f"Col:{start.get('col', '?')}/Line:{start.get('line', '?')}"

        # 3. Extract rule id
        rule_name = finding.get("check_id", "UNKNOWN_RULE")

        # 4. Extract description (optional)
        msg = finding.get("extra", {}).get("message", "")
        msg = truncate_desc(msg) if include_description else ""

        # 5. Map Severity
        raw_sev = finding.get("extra", {}).get("severity", "UNKNOWN")
        sev_label, sev_color = resolve_severity(raw_sev)

        # 6. Aggregate Stats
        colored_key = f"{sev_color}{COLOR_BOLD}{sev_label}{COLOR_RESET}"
        severity_counts[colored_key] = severity_counts.get(colored_key, 0) + 1

        row = {
            "path": path,
            "line": line_info,
            "sev_label": sev_label,
            "sev_color": sev_color,
            "rule": rule_name
        }

        if include_description:
            row["desc"] = msg

        processed_rows.append(row)

    # Sort alphabetically by path (matches original behavior)
    processed_rows.sort(key=lambda x: x["path"])

    return processed_rows, severity_counts

# --- Main function ---
def main():
    parser = argparse.ArgumentParser(
        description=f"{COLOR_BOLD}Format Semgrep JSON report.{COLOR_RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{COLOR_BOLD}Example:{COLOR_RESET}
  semgrep scan --json-output=findings.json
  python generate-report-semgrep.py findings.json
  python generate-report-semgrep.py findings.json --no-desc
        """
    )
    parser.add_argument("input_file", help="Path to the Semgrep JSON findings")
    parser.add_argument(
        "--no-desc",
        action="store_true",
        help="Hide the description column for a cleaner display",
    )
    args = parser.parse_args()

    include_description = not args.no_desc

    # 1. Load Data
    try:
        with open(args.input_file, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        sys.exit(f"{COLOR_RED}[!] Error reading file: {e}{COLOR_RESET}")

    # 2. Process Findings
    rows, stats = process_findings(data, include_description=include_description)

    # 3. Print Main Table
    print(f"{COLOR_YELLOW}[+] Vulnerabilities ({len(rows)}):{COLOR_RESET}")

    table_data = []
    if include_description:
        headers = ["File", "Line", "Severity", "Rule", "Description"]
        for r in rows:
            colored_sev = f"{r['sev_color']}{COLOR_BOLD}{r['sev_label']}{COLOR_RESET}"
            table_data.append([r["path"], r["line"], colored_sev, r["rule"], r["desc"]])
    else:
        headers = ["File", "Line", "Severity", "Rule"]
        for r in rows:
            colored_sev = f"{r['sev_color']}{COLOR_BOLD}{r['sev_label']}{COLOR_RESET}"
            table_data.append([r["path"], r["line"], colored_sev, r["rule"]])

    print(tabulate(table_data, headers=headers))
    print("")

    # 4. Print Distribution
    print(f"{COLOR_YELLOW}[+] Vulnerabilities severity distribution:{COLOR_RESET}")

    dist_data = []
    for sev_colored, count in stats.items():
        dist_data.append([sev_colored, count])

    dist_data.sort()
    print(tabulate(dist_data, headers=["Severity", "Vulnerability count"]))
    print("")

if __name__ == "__main__":
    main()
