#!/usr/bin/env python

import argparse
import json
import sys
import re
import shutil
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


def truncate_text(text, max_len):
    text = str(text or "")
    if max_len <= 0:
        return ""
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def normalize_path(p):
    return str(p or "").replace("\\", "/")


def get_terminal_width():
    try:
        return shutil.get_terminal_size(fallback=(120, 30)).columns
    except Exception:
        return 120


def shorten_left(text, max_len):
    """
    Keep the end of long paths (usually more useful), trim from the left.
    Example: ".../deep/path/file.js"
    """
    t = str(text or "")
    if max_len <= 0:
        return ""
    if len(t) <= max_len:
        return t
    if max_len <= 3:
        return t[:max_len]
    return "..." + t[-(max_len - 3):]


def process_findings(
    data,
    include_description=True,
    only_file=None,
    only_rule=None,
    only_multi_file=False,
    only_multi_rule=False,
):
    """Filters and formats findings from the raw JSON."""
    processed_rows = []
    severity_counts = {}

    raw_results = data.get("results", [])

    # First pass: collect rows (unformatted), then optionally filter "multi" modes
    rows_raw = []

    for finding in raw_results:
        path = finding.get("path", "")
        path_norm = normalize_path(path)

        # 1. Filter excluded files
        if is_test_file(path_norm):
            continue

        rule_name = finding.get("check_id", "UNKNOWN_RULE")

        # Filter by specific file (substring match) if requested
        if only_file:
            if normalize_path(only_file) not in path_norm:
                continue

        # Filter by specific rule (substring match) if requested
        if only_rule:
            if str(only_rule) not in str(rule_name):
                continue

        start = finding.get("start", {})
        line_info = f"Col:{start.get('col', '?')}/Line:{start.get('line', '?')}"

        raw_sev = finding.get("extra", {}).get("severity", "UNKNOWN")
        sev_label, sev_color = resolve_severity(raw_sev)

        msg = finding.get("extra", {}).get("message", "")
        msg = truncate_text(msg, DESC_MAX_LEN) if include_description else ""

        rows_raw.append({
            "path": path_norm,
            "line": line_info,
            "sev_label": sev_label,
            "sev_color": sev_color,
            "rule": rule_name,
            "desc": msg,
        })

    # Optional: keep only files that have multiple findings
    if only_multi_file:
        file_counts = {}
        for r in rows_raw:
            file_counts[r["path"]] = file_counts.get(r["path"], 0) + 1
        rows_raw = [r for r in rows_raw if file_counts.get(r["path"], 0) > 1]

    # Optional: keep only rules that appear multiple times
    if only_multi_rule:
        rule_counts = {}
        for r in rows_raw:
            rule_counts[r["rule"]] = rule_counts.get(r["rule"], 0) + 1
        rows_raw = [r for r in rows_raw if rule_counts.get(r["rule"], 0) > 1]

    # Stats and final rows
    for r in rows_raw:
        colored_key = f"{r['sev_color']}{COLOR_BOLD}{r['sev_label']}{COLOR_RESET}"
        severity_counts[colored_key] = severity_counts.get(colored_key, 0) + 1
        processed_rows.append(r)

    # Sort alphabetically by path
    processed_rows.sort(key=lambda x: x["path"])
    return processed_rows, severity_counts


def print_section_header(title):
    print(f"{COLOR_YELLOW}[+] {title}{COLOR_RESET}")


def build_table(rows, include_description=True):
    """
    Make the first column (File) fit nicely into terminal width.
    We do manual truncation so the table never exceeds terminal width too much.
    """
    term_w = get_terminal_width()

    # Fixed-ish columns
    sev_max = 8   # "CRITICAL" or our "MEDIUM" etc
    line_max = 18 # "Col:999/Line:99999"
    rule_max = 58 # tweakable

    # Basic separators and padding estimate
    # tabulate adds spacing; we keep conservative margins
    sep_overhead = 3 * 4 + 8

    if include_description:
        desc_max = min(DESC_MAX_LEN, 70)
        fixed = line_max + sev_max + rule_max + desc_max + sep_overhead
        file_max = max(20, term_w - fixed)
    else:
        fixed = line_max + sev_max + rule_max + sep_overhead
        file_max = max(20, term_w - fixed)

    table_data = []
    for r in rows:
        colored_sev = f"{r['sev_color']}{COLOR_BOLD}{r['sev_label']}{COLOR_RESET}"
        file_cell = shorten_left(r["path"], file_max)
        rule_cell = truncate_text(r["rule"], rule_max)

        if include_description:
            desc_cell = truncate_text(r["desc"], min(DESC_MAX_LEN, 70))
            table_data.append([file_cell, r["line"], colored_sev, rule_cell, desc_cell])
        else:
            table_data.append([file_cell, r["line"], colored_sev, rule_cell])

    if include_description:
        headers = ["File", "Line", "Severity", "Rule", "Description"]
    else:
        headers = ["File", "Line", "Severity", "Rule"]

    return headers, table_data


# --- Main function ---
def main():
    parser = argparse.ArgumentParser(
        description=f"{COLOR_BOLD}Format Semgrep JSON report.{COLOR_RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{COLOR_BOLD}Example:{COLOR_RESET}
  semgrep scan --json-output=findings.json
  python format-semgrep-json.py findings.json
  python format-semgrep-json.py findings.json --no-desc
  python format-semgrep-json.py findings.json --file odc-staging/js-libs/comment-popup.js
  python format-semgrep-json.py findings.json --rule insecure-document-method
  python format-semgrep-json.py findings.json --only-multi-file
  python format-semgrep-json.py findings.json --only-multi-rule
        """
    )
    parser.add_argument("input_file", help="Path to the Semgrep JSON findings")
    parser.add_argument("--no-desc", action="store_true", help="Hide the description column for a cleaner display")
    parser.add_argument("--file", dest="only_file", default=None, help="Only show findings for paths containing this value")
    parser.add_argument("--rule", dest="only_rule", default=None, help="Only show findings for rules containing this value")
    parser.add_argument(
        "--only-multi-file",
        action="store_true",
        help="Only show findings for files that contain more than 1 finding",
    )
    parser.add_argument(
        "--only-multi-rule",
        action="store_true",
        help="Only show findings for rules that appear more than 1 time",
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
    rows, stats = process_findings(
        data,
        include_description=include_description,
        only_file=args.only_file,
        only_rule=args.only_rule,
        only_multi_file=args.only_multi_file,
        only_multi_rule=args.only_multi_rule,
    )

    # 3. Print Main Table
    print_section_header(f"Vulnerabilities ({len(rows)}):")

    headers, table_data = build_table(rows, include_description=include_description)
    print(tabulate(table_data, headers=headers))
    print("")

    # 4. Print Distribution
    print_section_header("Vulnerabilities severity distribution:")

    dist_data = []
    for sev_colored, count in stats.items():
        dist_data.append([sev_colored, count])

    dist_data.sort()
    print(tabulate(dist_data, headers=["Severity", "Vulnerability count"]))
    print("")


if __name__ == "__main__":
    main()
