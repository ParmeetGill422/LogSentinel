"""
detector/threat_detector.py
===========================
Threat detection engine for LogSentinel.

Analyses a list of parsed log entry dicts and returns detected threat events.

Detection rules
---------------
1. BRUTE_FORCE (HIGH)
   - SSH: 5 or more failed login attempts (FAILED or FAILED_INVALID_USER)
     from the same IP address.
   - Windows: 5 or more failed logon events (EventID 4625) for the same
     username on the same host.

2. SUSPICIOUS_HOURS (MEDIUM)
   - Any failed, forbidden, or error-status activity occurring between
     00:00 (midnight) and 05:00 AM inclusive.

3. REPEATED_404 (MEDIUM)
   - 5 or more HTTP 404 responses originating from the same IP address,
     indicating directory/path enumeration or scanning activity.

4. UNKNOWN_USER_LOGIN (MEDIUM)
   - SSH login attempts targeting usernames that do not exist on the system
     (status == FAILED_INVALID_USER), flagged individually.

Severity guide
--------------
  HIGH   — Active attack; immediate investigation required.
  MEDIUM — Suspicious pattern; warrants review.
  LOW    — Informational anomaly; low immediate risk.
"""

from collections import defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------

BRUTE_FORCE_THRESHOLD = 5    # Number of failures that triggers a HIGH alert
REPEATED_404_THRESHOLD = 5   # Number of 404s that triggers a MEDIUM alert

# Hours (24-hour clock) considered abnormal — midnight to just before 5 AM
SUSPICIOUS_HOUR_START = 0    # inclusive
SUSPICIOUS_HOUR_END   = 5    # exclusive  (hour < 5 is flagged)

# Status values that represent failures / errors across all log types
_FAILED_STATUSES = {"FAILED", "FAILED_INVALID_USER", "404", "403", "400", "500", "503"}


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def detect_threats(log_entries: list) -> list:
    """
    Scan all parsed log entries and return a list of detected threat dicts.

    Each threat dict contains:
        log_entry_id : int | None  — DB id of the triggering log entry
        threat_type  : str         — one of the rule names above
        severity     : str         — 'HIGH', 'MEDIUM', or 'LOW'
        description  : str         — human-readable explanation
        detected_at  : datetime    — when the detection was run

    Parameters
    ----------
    log_entries : list of dict
        Each dict must have a 'db_id' key (set after inserting into DB),
        plus all parsed fields: log_type, status, ip_address, user,
        timestamp, action.

    Returns
    -------
    list of dict
    """
    threats = []
    now = datetime.now()

    # -----------------------------------------------------------------------
    # Rule 1a — SSH Brute Force
    # Group failed SSH logins by source IP; alert if count >= threshold.
    # -----------------------------------------------------------------------
    ssh_failures_by_ip: dict[str, list] = defaultdict(list)

    for entry in log_entries:
        if (
            entry.get("log_type") == "SSH"
            and entry.get("status") in ("FAILED", "FAILED_INVALID_USER")
            and entry.get("ip_address")
        ):
            ssh_failures_by_ip[entry["ip_address"]].append(entry)

    for ip, failed_entries in ssh_failures_by_ip.items():
        if len(failed_entries) >= BRUTE_FORCE_THRESHOLD:
            # Reference the earliest failure entry in the DB
            ref = failed_entries[0]
            threats.append({
                "log_entry_id": ref.get("db_id"),
                "threat_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "description": (
                    f"SSH brute force attack detected: {len(failed_entries)} failed "
                    f"login attempts from IP {ip}. "
                    f"Targets include user(s): "
                    f"{', '.join(sorted({e.get('user', '?') for e in failed_entries if e.get('user')}))}"
                ),
                "detected_at": now,
            })

    # -----------------------------------------------------------------------
    # Rule 1b — Windows Logon Brute Force
    # Group Windows FAILED logons by username; alert if count >= threshold.
    # -----------------------------------------------------------------------
    win_failures_by_user: dict[str, list] = defaultdict(list)

    for entry in log_entries:
        if (
            entry.get("log_type") == "WINDOWS"
            and entry.get("status") == "FAILED"
            and entry.get("user")
        ):
            win_failures_by_user[entry["user"]].append(entry)

    for user, failed_entries in win_failures_by_user.items():
        if len(failed_entries) >= BRUTE_FORCE_THRESHOLD:
            ref = failed_entries[0]
            threats.append({
                "log_entry_id": ref.get("db_id"),
                "threat_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "description": (
                    f"Windows logon brute force detected: {len(failed_entries)} failed "
                    f"logon attempts for account '{user}'. "
                    f"Account may be locked or under dictionary attack."
                ),
                "detected_at": now,
            })

    # -----------------------------------------------------------------------
    # Rule 2 — Suspicious Hours Activity
    # Any failed/error activity between SUSPICIOUS_HOUR_START and _END.
    # -----------------------------------------------------------------------
    for entry in log_entries:
        ts = entry.get("timestamp")
        if not ts:
            continue

        hour = ts.hour
        if not (SUSPICIOUS_HOUR_START <= hour < SUSPICIOUS_HOUR_END):
            continue

        status = entry.get("status", "")
        if status not in _FAILED_STATUSES:
            continue

        ip_or_host = entry.get("ip_address") or entry.get("user") or "unknown"
        threats.append({
            "log_entry_id": entry.get("db_id"),
            "threat_type": "SUSPICIOUS_HOURS",
            "severity": "MEDIUM",
            "description": (
                f"Suspicious activity detected at {ts.strftime('%H:%M')} "
                f"(between midnight and 05:00 AM). "
                f"Source: {ip_or_host} | Log type: {entry.get('log_type')} | "
                f"Action: {entry.get('action', 'N/A')} | Status: {status}"
            ),
            "detected_at": now,
        })

    # -----------------------------------------------------------------------
    # Rule 3 — Repeated 404 Errors (Apache path scanning)
    # -----------------------------------------------------------------------
    apache_404s_by_ip: dict[str, list] = defaultdict(list)

    for entry in log_entries:
        if (
            entry.get("log_type") == "APACHE"
            and entry.get("status") == "404"
            and entry.get("ip_address")
        ):
            apache_404s_by_ip[entry["ip_address"]].append(entry)

    for ip, err_entries in apache_404s_by_ip.items():
        if len(err_entries) >= REPEATED_404_THRESHOLD:
            ref = err_entries[0]
            # Collect the paths requested to give context
            paths = [e.get("action", "") for e in err_entries[:5]]
            threats.append({
                "log_entry_id": ref.get("db_id"),
                "threat_type": "REPEATED_404",
                "severity": "MEDIUM",
                "description": (
                    f"Path enumeration / scanning detected: {len(err_entries)} HTTP 404 "
                    f"responses from IP {ip}. "
                    f"Sample paths probed: {', '.join(paths)}"
                ),
                "detected_at": now,
            })

    # -----------------------------------------------------------------------
    # Rule 4 — Unknown User Login Attempts (SSH)
    # Flag every attempt targeting a non-existent system account.
    # -----------------------------------------------------------------------
    for entry in log_entries:
        if (
            entry.get("log_type") == "SSH"
            and entry.get("status") == "FAILED_INVALID_USER"
        ):
            username = entry.get("user", "unknown")
            src_ip   = entry.get("ip_address", "unknown")
            threats.append({
                "log_entry_id": entry.get("db_id"),
                "threat_type": "UNKNOWN_USER_LOGIN",
                "severity": "MEDIUM",
                "description": (
                    f"SSH login attempt for non-existent user '{username}' "
                    f"from IP {src_ip}. "
                    f"This may indicate credential stuffing or user enumeration."
                ),
                "detected_at": now,
            })

    return threats
