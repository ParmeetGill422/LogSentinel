"""
parser/windows_parser.py
========================
Parses Windows Event Log exports in CSV format.

Supports two export formats:

Format A (legacy/wevtutil):
    EventID, TimeGenerated, SourceName, ComputerName, UserName, Message

Format B (Get-WinEvent | Select TimeCreated, Id, LevelDisplayName, Message):
    TimeCreated, Id, LevelDisplayName, Message
    Username and IP are extracted from the Message text via regex.

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
import re
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
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",   # e.g. 3/11/2026 11:01:33 AM
    ):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def _extract_field(message: str, label: str) -> str | None:
    """Extract a labelled field value from a Windows event message block."""
    match = re.search(rf"{re.escape(label)}\s+([^\n\r]+)", message)
    if match:
        value = match.group(1).strip()
        return value if value not in ("-", "") else None
    return None


def _extract_new_logon_user(message: str) -> str | None:
    """
    Extract 'Account Name' from the 'New Logon' section of a 4624/4648 message.
    Falls back to the first Account Name found.
    """
    new_logon_match = re.search(
        r"New Logon:.*?Account Name:\s+([^\n\r]+)", message, re.DOTALL
    )
    if new_logon_match:
        value = new_logon_match.group(1).strip()
        return value if value not in ("-", "") else None
    return _extract_field(message, "Account Name:")


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
        fieldnames = reader.fieldnames or []

        # Detect format: Format B uses 'Id' and 'TimeCreated' (Get-WinEvent export)
        format_b = "Id" in fieldnames and "TimeCreated" in fieldnames

        for row in reader:
            if format_b:
                event_id = row.get("Id", "").strip()
                time_raw = row.get("TimeCreated", "").strip()
                message  = row.get("Message", "").strip()

                # Extract username and IP from message text
                if event_id in ("4624", "4648"):
                    username = _extract_new_logon_user(message)
                else:
                    username = _extract_field(message, "Account Name:")

                ip_address = _extract_field(message, "Source Network Address:")
                computer   = _extract_field(message, "Workstation Name:") or ""
            else:
                event_id  = row.get("EventID", "").strip()
                time_raw  = row.get("TimeGenerated", "").strip()
                username  = row.get("UserName", "").strip() or None
                computer  = row.get("ComputerName", "").strip()
                message   = row.get("Message", "").strip()
                ip_address = None

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

            # Build a concise raw_line
            raw_line = (
                f"EventID={event_id} | Computer={computer} | "
                f"User={username} | {message[:100]}"
            )

            entry = {
                "source_file": filepath,
                "log_type": "WINDOWS",
                "timestamp": timestamp,
                "ip_address": ip_address,
                "user": username,
                "action": action,
                "status": status,
                "raw_line": raw_line,
            }

            entries.append(entry)

    return entries
