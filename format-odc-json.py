#!/usr/bin/env python3

import argparse
import json
import sys
import csv
from tabulate import tabulate

# --- ANSI Color Codes ---
if sys.stdout.isatty():
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, \
    COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE, COLOR_BOLD, COLOR_DIM = \
    ("\033[0m", "\033[91m", "\033[92m", "\033[93m", "\033[94m",
     "\033[95m", "\033[96m", "\033[97m", "\033[1m", "\033[2m")
else:
    # Assign empty strings if not a TTY
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, \
    COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE, COLOR_BOLD, COLOR_DIM = \
    ("", "", "", "", "", "", "", "", "", "")

# --- Core logic functions ---

def get_severity_color(severity):
    """Map severity strings to ANSI color codes."""
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"): return COLOR_RED
    if sev in ("MEDIUM", "MODERATE"): return COLOR_YELLOW
    if sev == "LOW": return COLOR_CYAN
    return COLOR_WHITE

def extract_vulnerabilities(data):
    """Parses JSON data and returns processed stats and vulnerability lists."""
    vulnerabilities = []
    seen_ids = set()
    cve_list = set()
    stats = {"clean_deps": 0, "vuln_deps": 0, "severities": {}}

    for dep in data.get("dependencies", []):
        vuln_data = dep.get("vulnerabilities", [])
        
        if not vuln_data:
            stats["clean_deps"] += 1
            continue
            
        stats["vuln_deps"] += 1
        name = dep.get("fileName", "unknown")

        for v in vuln_data:
            cve = v.get("name", "UNKNOWN")
            severity = v.get("severity", "UNKNOWN").upper()
            
            # Score logic: v3 -> v2 -> 0
            score = 0.0
            if "cvssv3" in v:
                score = float(v["cvssv3"]["baseScore"])
            elif "cvssv2" in v:
                score = float(v["cvssv2"]["score"])

            # Deduplication ID
            unique_id = (name, cve, severity, score)
            
            if unique_id not in seen_ids:
                seen_ids.add(unique_id)
                cve_list.add(cve)
                
                # Update severity stats
                stats["severities"][severity] = stats["severities"].get(severity, 0) + 1
                
                # Add to list
                vulnerabilities.append({
                    "cvss": score,
                    "severity": severity,
                    "file": name,
                    "cve": cve
                })

    # Sort by score descending
    vulnerabilities.sort(key=lambda x: x["cvss"], reverse=True)
    return vulnerabilities, cve_list, stats

def print_section_header(title):
    print(f"{COLOR_YELLOW}[+] {title}{COLOR_RESET}")

def main():
    parser = argparse.ArgumentParser(
        description=f"{COLOR_BOLD}Format OWASP Dependency Check JSON report.{COLOR_RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{COLOR_BOLD}Example:{COLOR_RESET}
  python generate-report.py odc.json
  python generate-report.py odc.json --csv
        """
    )
    parser.add_argument("input_file", help="Path to the ODC JSON report")
    parser.add_argument("--csv", action="store_true", help="Generate 'vulns.csv' file")
    
    args = parser.parse_args()

    # 1. Load Data
    try:
        with open(args.input_file, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        sys.exit(f"{COLOR_RED}[!] Error reading file: {e}{COLOR_RESET}")

    # 2. Process Data
    vulns, cves, stats = extract_vulnerabilities(data)

    # 3. Print Main Table
    print_section_header("Vulnerabilities:")
    table_rows = []
    for v in vulns:
        # Colorize severity for display only
        color = get_severity_color(v["severity"])
        sev_colored = f"{color}{COLOR_BOLD}{v['severity']}{COLOR_RESET}"
        table_rows.append([v["cvss"], sev_colored, v["file"], v["cve"]])
    
    print(tabulate(table_rows, headers=["CVSS v3", "Severity", "File", "CVE/CWE/GHSA"], numalign="right", stralign="left"))
    print(" ")

    # 4. Severity Distribution
    print_section_header("Vulnerabilities severity distribution:")
    dist_rows = []
    total_vulns = len(vulns)
    
    if total_vulns > 0:
        for sev, count in stats["severities"].items():
            pct = round((count * 100) / total_vulns)
            dist_rows.append([sev, count, pct])
            
    print(tabulate(dist_rows, headers=["Severity", "Vulnerability count", "% distribution of severity"], numalign="right", stralign="left"))
    print(" ")

    # 5. CSV Generation
    if args.csv:
        print(f"{COLOR_YELLOW}[+] Generate CSV file 'vulns.csv'...{COLOR_RESET}", end="", flush=True)
        try:
            with open("vulns.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["CVSS v3", "Severity", "File", "CVE/CWE"])
                for v in vulns:
                    writer.writerow([v["cvss"], v["severity"], v["file"], v["cve"]])
            print("OK")
        except Exception as e:
            print(f"{COLOR_RED}Error: {e}{COLOR_RESET}")

    # 6. General Stats
    print_section_header("Vulnerabilities distribution:")
    total_deps = stats["clean_deps"] + stats["vuln_deps"]
    vuln_pct = round((stats["vuln_deps"] * 100) / total_deps) if total_deps else 0
    
    stats_row = [[
        stats["clean_deps"],
        stats["vuln_deps"],
        total_deps,
        vuln_pct,
        total_vulns
    ]]
    headers = ["Clean Dependencies", "Vulnerable Dependencies", 
               "Total Dependencies", "% of Vulnerable Dependencies", 
               "Total Vulnerabilities"]
    print(tabulate(stats_row, headers=headers, numalign="right", stralign="left"))
    print(" ")

    # 7. CVE List
    print(f"{COLOR_YELLOW}[+] List of CVE ({len(cves)}):{COLOR_RESET}")
    print("\n".join(sorted(cves, reverse=True)))
    print(" ")

if __name__ == "__main__":
    main()