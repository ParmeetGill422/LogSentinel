"""
parser/ssh_parser.py
====================
Parses Linux SSH authentication logs (typically /var/log/auth.log).

Log format:
    Mon DD HH:MM:SS hostname sshd[PID]: <message>

Detects and extracts the following event types:
  - Failed password (for valid and invalid users)
  - Accepted password / publickey
  - Invalid user attempts
  - Other sshd messages (stored as INFO)
"""

import re
from datetime import datetime


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Matches the standard syslog prefix produced by sshd
_LINE_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(.*)"
)

# "Failed password for invalid user USERNAME from IP port PORT ssh2"
_FAIL_INVALID = re.compile(
    r"Failed password for invalid user (\S+) from (\S+) port \d+"
)

# "Failed password for USERNAME from IP port PORT ssh2"
_FAIL_VALID = re.compile(
    r"Failed password for (\S+) from (\S+) port \d+"
)

# "Accepted password|publickey for USERNAME from IP port PORT"
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\S+) port \d+"
)

# "Invalid user USERNAME from IP"  (appears before password attempt)
_INVALID_USER = re.compile(
    r"Invalid user (\S+) from (\S+)"
)


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def parse_ssh_log(filepath: str) -> list:
    """
    Parse an SSH auth.log file and return a list of log entry dicts.

    Each dict contains the keys expected by db_handler.insert_log_entry:
        source_file, log_type, timestamp, ip_address,
        user, action, status, raw_line

    Parameters
    ----------
    filepath : str
        Path to the auth.log file on disk.

    Returns
    -------
    list of dict
    """
    entries = []

    # auth.log does not include the year, so we inject the current year
    current_year = datetime.now().year

    with open(filepath, "r", errors="replace") as fh:
        for raw_line in fh:
            raw_line = raw_line.rstrip("\n")
            if not raw_line.strip():
                continue

            # Only process lines that match the sshd syslog format
            line_match = _LINE_RE.match(raw_line)
            if not line_match:
                continue

            time_str, message = line_match.groups()

            # Build a naive datetime from the syslog timestamp + injected year
            # e.g. "Mar 10 01:23:41" -> datetime(2026, 3, 10, 1, 23, 41)
            try:
                timestamp = datetime.strptime(
                    f"{current_year} {time_str.strip()}", "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                timestamp = None

            # Initialise the entry with defaults; action-specific matches
            # below will overwrite ip_address, user, action, and status.
            entry = {
                "source_file": filepath,
                "log_type": "SSH",
                "timestamp": timestamp,
                "ip_address": None,
                "user": None,
                "action": None,
                "status": "INFO",
                "raw_line": raw_line,
            }

            # ---- Pattern matching (order matters — most specific first) ----

            if m := _FAIL_INVALID.search(message):
                # Failed attempt for a username that does not exist on the system
                entry["user"] = m.group(1)
                entry["ip_address"] = m.group(2)
                entry["action"] = "Failed password"
                entry["status"] = "FAILED_INVALID_USER"

            elif m := _FAIL_VALID.search(message):
                # Failed attempt for a real system user (wrong password)
                entry["user"] = m.group(1)
                entry["ip_address"] = m.group(2)
                entry["action"] = "Failed password"
                entry["status"] = "FAILED"

            elif m := _ACCEPTED.search(message):
                # Successful authentication
                entry["user"] = m.group(1)
                entry["ip_address"] = m.group(2)
                entry["action"] = "Accepted authentication"
                entry["status"] = "SUCCESS"

            elif m := _INVALID_USER.search(message):
                # sshd logs this before the password attempt for unknown users
                entry["user"] = m.group(1)
                entry["ip_address"] = m.group(2)
                entry["action"] = "Invalid user"
                entry["status"] = "FAILED_INVALID_USER"

            else:
                # Catch-all: store the raw message snippet as the action
                entry["action"] = message[:120]
                entry["status"] = "INFO"

            entries.append(entry)

    return entries
