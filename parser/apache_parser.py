"""
parser/apache_parser.py
=======================
Parses Apache HTTP Server access logs in the Combined Log Format.

Combined Log Format:
    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

Example line:
    192.168.1.1 - frank [10/Mar/2026:13:55:36 +0000] "GET /page HTTP/1.1" 200 2326 "-" "Mozilla/5.0"

Extracted fields:
  - ip_address   : client IP (%h)
  - user         : authenticated user (%u), or None if '-'
  - timestamp    : request time (%t)
  - action       : "METHOD /path"
  - status       : HTTP status code as string (e.g. "200", "404")
"""

import re
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Compiled regex for the Apache Combined Log Format
# ---------------------------------------------------------------------------

_LOG_RE = re.compile(
    r'(\S+)'              # %h  — client IP address
    r'\s+\S+'             # %l  — ident (almost always '-')
    r'\s+(\S+)'           # %u  — authenticated user or '-'
    r'\s+\[([^\]]+)\]'   # %t  — timestamp inside brackets
    r'\s+"(\S+)\s+(\S+)\s+\S+"'  # %r  — "METHOD path HTTP/ver"
    r'\s+(\d{3})'         # %>s — HTTP status code (exactly 3 digits)
    r'\s+(\S+)'           # %b  — response size in bytes or '-'
)


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def parse_apache_log(filepath: str) -> list:
    """
    Parse an Apache Combined Log Format file and return a list of
    log entry dicts compatible with db_handler.insert_log_entry.

    Parameters
    ----------
    filepath : str
        Path to the Apache access.log file.

    Returns
    -------
    list of dict
    """
    entries = []

    with open(filepath, "r", errors="replace") as fh:
        for raw_line in fh:
            raw_line = raw_line.rstrip("\n")
            if not raw_line.strip():
                continue

            m = _LOG_RE.match(raw_line)
            if not m:
                # Skip lines that don't match (e.g. comment lines, errors)
                continue

            ip, user, time_str, method, path, status_code, _ = m.groups()

            # Parse Apache timestamp: "10/Mar/2026:13:55:36 +0000"
            # Strip timezone info so we store a naive datetime in MySQL
            try:
                dt_aware = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
                timestamp = dt_aware.replace(tzinfo=None)
            except ValueError:
                timestamp = None

            # Treat '-' as an anonymous / unauthenticated request
            user = None if user == "-" else user

            entry = {
                "source_file": filepath,
                "log_type": "APACHE",
                "timestamp": timestamp,
                "ip_address": ip,
                "user": user,
                "action": f"{method} {path}",   # e.g. "GET /admin.php"
                "status": status_code,           # e.g. "404"
                "raw_line": raw_line,
            }

            entries.append(entry)

    return entries
