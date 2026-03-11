#!/usr/bin/env python3
"""
main.py
=======
LogSentinel — Log Analysis and Incident Report Automation Tool
CLI entry point and main menu.

Usage:
    python main.py

The menu offers five operations:
  1. Parse & Analyse  — parse all sample log files and detect threats
  2. Generate Report  — pull findings from DB and render the HTML report
  3. View Summary     — print a colour-coded threat summary to the terminal
  4. Full Pipeline    — run all of the above in one shot
  5. Clear Database   — wipe all stored data for a fresh run
  6. Exit
"""

import os
import sys

# Ensure UTF-8 output on Windows (needed for box-drawing characters in banner)
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Load .env before importing any module that calls os.getenv()
from dotenv import load_dotenv
load_dotenv()

from parser.ssh_parser     import parse_ssh_log
from parser.apache_parser  import parse_apache_log
from parser.windows_parser import parse_windows_log

from detector.threat_detector import detect_threats

from database.db_handler import (
    init_database,
    insert_log_entry,
    insert_threat_event,
    get_all_threats,
    get_all_log_entries,
    get_summary_stats,
    clear_database,
)

from reporter.report_generator import generate_report


# ---------------------------------------------------------------------------
# Sample log file paths (relative to this script)
# ---------------------------------------------------------------------------

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SAMPLE_LOGS = {
    "ssh":     os.path.join(_BASE_DIR, "sample_logs", "auth.log"),
    "apache":  os.path.join(_BASE_DIR, "sample_logs", "access.log"),
    "windows": os.path.join(_BASE_DIR, "sample_logs", "windows_events.csv"),
}

# ANSI colour codes for terminal output
_R  = "\033[91m"   # red
_Y  = "\033[93m"   # yellow
_G  = "\033[92m"   # green
_B  = "\033[94m"   # blue
_DIM= "\033[2m"    # dim
_W  = "\033[0m"    # reset


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def _print_banner():
    """Print the LogSentinel ASCII art banner."""
    print(f"""
{_B}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗    ║
║    ██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║    ║
║    ██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║    ║
║    ██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║    ║
║    ███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║    ║
║    ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝    ║
║                                                              ║
║         Security Incident Report Automation Tool             ║
╚══════════════════════════════════════════════════════════════╝{_W}
""")


def _print_menu():
    """Print the main menu."""
    print(f"""  {_DIM}┌─────────────────────────────────────────────────┐{_W}
  {_DIM}│{_W}              {_B}MAIN MENU{_W}                          {_DIM}│{_W}
  {_DIM}├─────────────────────────────────────────────────┤{_W}
  {_DIM}│{_W}  {_G}[1]{_W}  Parse & Analyse Logs                  {_DIM}│{_W}
  {_DIM}│{_W}  {_G}[2]{_W}  Generate HTML Incident Report         {_DIM}│{_W}
  {_DIM}│{_W}  {_G}[3]{_W}  View Threat Summary (terminal)        {_DIM}│{_W}
  {_DIM}│{_W}  {_G}[4]{_W}  Run Full Pipeline                     {_DIM}│{_W}
  {_DIM}│{_W}  {_Y}[5]{_W}  Clear Database                        {_DIM}│{_W}
  {_DIM}│{_W}  {_R}[6]{_W}  Exit                                  {_DIM}│{_W}
  {_DIM}└─────────────────────────────────────────────────┘{_W}""")


def _info(msg: str):
    """Print a status message."""
    print(f"  {_B}[*]{_W} {msg}")


def _ok(msg: str):
    """Print a success message."""
    print(f"  {_G}[✓]{_W} {msg}")


def _warn(msg: str):
    """Print a warning / error message."""
    print(f"  {_R}[!]{_W} {msg}")


# ---------------------------------------------------------------------------
# Core pipeline steps
# ---------------------------------------------------------------------------

def run_parsers() -> list:
    """
    Parse all three sample log files, store each entry in the database,
    and return the combined list of entry dicts (with 'db_id' set).
    """
    _info("Initialising database schema ...")
    init_database()
    _ok("Database ready")

    all_entries = []

    # --- SSH auth.log ---
    if os.path.exists(SAMPLE_LOGS["ssh"]):
        _info(f"Parsing SSH log:     {SAMPLE_LOGS['ssh']}")
        entries = parse_ssh_log(SAMPLE_LOGS["ssh"])
        _ok(f"{len(entries)} SSH entries parsed")
        all_entries.extend(entries)
    else:
        _warn(f"SSH log not found: {SAMPLE_LOGS['ssh']}")

    # --- Apache access.log ---
    if os.path.exists(SAMPLE_LOGS["apache"]):
        _info(f"Parsing Apache log:  {SAMPLE_LOGS['apache']}")
        entries = parse_apache_log(SAMPLE_LOGS["apache"])
        _ok(f"{len(entries)} Apache entries parsed")
        all_entries.extend(entries)
    else:
        _warn(f"Apache log not found: {SAMPLE_LOGS['apache']}")

    # --- Windows Event Log CSV ---
    if os.path.exists(SAMPLE_LOGS["windows"]):
        _info(f"Parsing Windows log: {SAMPLE_LOGS['windows']}")
        entries = parse_windows_log(SAMPLE_LOGS["windows"])
        _ok(f"{len(entries)} Windows event entries parsed")
        all_entries.extend(entries)
    else:
        _warn(f"Windows log not found: {SAMPLE_LOGS['windows']}")

    # Store every entry and capture the auto-generated DB id
    _info(f"Storing {len(all_entries)} entries to database ...")
    for entry in all_entries:
        db_id = insert_log_entry(entry)
        # Attach the DB id so threat_detector can link threats to their origin
        entry["db_id"] = db_id

    _ok("All log entries stored")
    return all_entries


def run_detection(entries: list) -> list:
    """
    Run the threat detection engine on the parsed entries, store results,
    and return the list of threat dicts.
    """
    _info("Running threat detection engine ...")
    threats = detect_threats(entries)

    # Severity breakdown for the console summary
    high   = sum(1 for t in threats if t["severity"] == "HIGH")
    medium = sum(1 for t in threats if t["severity"] == "MEDIUM")
    low    = sum(1 for t in threats if t["severity"] == "LOW")

    _ok(
        f"{len(threats)} threat(s) detected — "
        f"{_R}HIGH:{high}{_W}  {_Y}MEDIUM:{medium}{_W}  {_G}LOW:{low}{_W}"
    )

    _info("Storing threat events to database ...")
    for threat in threats:
        insert_threat_event(threat)
    _ok("Threats stored")

    return threats


def run_report() -> str:
    """Fetch data from the database and render the HTML report."""
    _info("Fetching data from database ...")
    log_entries = get_all_log_entries()
    threats     = get_all_threats()
    stats       = get_summary_stats()
    _ok(f"{len(log_entries)} log entries | {len(threats)} threats retrieved")

    _info("Rendering HTML report ...")
    report_path = generate_report(log_entries, threats, stats)
    _ok(f"Report saved: {report_path}")
    print(f"\n      Open in browser: {_B}file://{report_path}{_W}\n")
    return report_path


def view_summary():
    """Print a colour-coded threat summary to the terminal."""
    threats = get_all_threats()
    stats   = get_summary_stats()

    sev_colour = {"HIGH": _R, "MEDIUM": _Y, "LOW": _G}

    print(f"\n  {'═'*68}")
    print(f"  {'THREAT SUMMARY':^68}")
    print(f"  {'═'*68}")
    print(f"  {'Total log entries:':<28} {stats['total_logs']}")
    print(f"  {'Total threats detected:':<28} {stats['total_threats']}")
    print(f"  {_R}{'  HIGH severity:':<28}{_W} {stats['by_severity'].get('HIGH',   0)}")
    print(f"  {_Y}{'  MEDIUM severity:':<28}{_W} {stats['by_severity'].get('MEDIUM', 0)}")
    print(f"  {_G}{'  LOW severity:':<28}{_W} {stats['by_severity'].get('LOW',    0)}")

    if stats.get("by_type"):
        print(f"\n  Threat type breakdown:")
        for row in stats["by_type"]:
            print(f"    {row['threat_type']:<30} {row['count']} event(s)")

    print(f"  {'═'*68}\n")

    if not threats:
        _ok("No threats found in the database.")
        return

    # Column headers
    hdr = f"  {'#':<4} {'SEVERITY':<10} {'TYPE':<22} {'IP / USER':<20} DESCRIPTION"
    print(hdr)
    print(f"  {'-'*110}")

    for i, t in enumerate(threats, 1):
        sev   = t["severity"]
        col   = sev_colour.get(sev, _W)
        desc  = t["description"]
        if len(desc) > 55:
            desc = desc[:52] + "..."
        src = t.get("ip_address") or t.get("user") or "—"
        print(f"  {i:<4} {col}{sev:<10}{_W} {t['threat_type']:<22} {src:<20} {desc}")

    print()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    _print_banner()

    while True:
        _print_menu()

        try:
            choice = input("  Enter choice [1-6]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Goodbye!\n")
            sys.exit(0)

        print()

        try:
            if choice == "1":
                # ---------- Parse & Analyse ----------
                entries = run_parsers()
                run_detection(entries)
                print(f"\n  {_G}Done!{_W} Use option [2] to generate the HTML report.\n")

            elif choice == "2":
                # ---------- Generate Report ----------
                run_report()

            elif choice == "3":
                # ---------- View Summary ----------
                view_summary()

            elif choice == "4":
                # ---------- Full Pipeline ----------
                _info("Starting full analysis pipeline ...\n")
                entries = run_parsers()
                run_detection(entries)
                run_report()
                view_summary()
                _ok("Full pipeline complete!")

            elif choice == "5":
                # ---------- Clear Database ----------
                confirm = input(
                    f"  {_Y}WARNING:{_W} This will delete ALL data. "
                    "Type 'yes' to confirm: "
                ).strip()
                if confirm.lower() == "yes":
                    clear_database()
                    _ok("Database cleared.\n")
                else:
                    _info("Cancelled — no data was deleted.\n")

            elif choice == "6":
                print("  Goodbye!\n")
                sys.exit(0)

            else:
                _warn("Invalid choice. Please enter a number from 1 to 6.\n")

        except Exception as exc:  # noqa: BLE001
            _warn(f"An error occurred: {exc}")
            print(
                f"\n  {_DIM}Tip: Make sure your .env credentials are correct "
                f"and MySQL is running.{_W}\n"
            )

        input(f"  {_DIM}Press Enter to return to the menu ...{_W}")
        print()


if __name__ == "__main__":
    main()
