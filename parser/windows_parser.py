"""
parser/windows_parser.py
========================
Parses Windows Event Log exports in CSV format.

Expected CSV columns:
    EventID, TimeGenerated, SourceName, ComputerName, UserName, Message

Key Event IDs handled:
    4624 — Successful logon
    4625 — Failed logon
    4648 — Logon with explicit credentials
    4634 — Account logoff
    4672 — Special privileges assigned
    4720 — User account created
    4726 — User account deleted
    4740 — Account locked out

CSV exports can be produced via:
    Get-WinEvent ... | Export-Csv  (PowerShell)
    wevtutil qe Security /f:csv    (Windows CLI)
"""

import csv
from datetime import datetime


# ---------------------------------------------------------------------------
# EventID -> human-readable action mapping
# ---------------------------------------------------------------------------

_EVENT_ACTIONS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4648": "Logon with Explicit Credentials",
    "4634": "Account Logoff",
    "4672": "Special Privileges Assigned",
    "4720": "User Account Created",
    "4726": "User Account Deleted",
    "4740": "Account Locked Out",
}

# EventIDs that represent failed / denied activity
_FAILED_EVENT_IDS = {"4625", "4740"}

# EventIDs that represent successful activity
_SUCCESS_EVENT_IDS = {"4624", "4634", "4648", "4672"}


def _parse_timestamp(raw: str) -> datetime | None:
    """
    Attempt to parse a timestamp string in common Windows event log formats.
    Returns a naive datetime or None if parsing fails.
    """
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def parse_windows_log(filepath: str) -> list:
    """
    Parse a Windows Event Log CSV export and return a list of log entry dicts.

    Parameters
    ----------
    filepath : str
        Path to the CSV file.

    Returns
    -------
    list of dict
    """
    entries = []

    with open(filepath, "r", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)

        for row in reader:
            event_id  = row.get("EventID", "").strip()
            time_raw  = row.get("TimeGenerated", "").strip()
            username  = row.get("UserName", "").strip() or None
            computer  = row.get("ComputerName", "").strip()
            message   = row.get("Message", "").strip()

            timestamp = _parse_timestamp(time_raw)

            # Map EventID to a friendly action label
            action = _EVENT_ACTIONS.get(event_id, f"Event {event_id}")

            # Classify the event status
            if event_id in _FAILED_EVENT_IDS:
                status = "FAILED"
            elif event_id in _SUCCESS_EVENT_IDS:
                status = "SUCCESS"
            else:
                status = "INFO"

            # Build a concise raw_line since the original CSV row isn't a log line
            raw_line = (
                f"EventID={event_id} | Computer={computer} | "
                f"User={username} | {message[:100]}"
            )

            entry = {
                "source_file": filepath,
                "log_type": "WINDOWS",
                "timestamp": timestamp,
                "ip_address": None,   # Windows event logs don't always include IP
                "user": username,
                "action": action,
                "status": status,
                "raw_line": raw_line,
            }

            entries.append(entry)

    return entries
