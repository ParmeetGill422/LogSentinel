# LogSentinel 🛡️

**A Log Analysis and Incident Report Automation Tool for Cybersecurity**

LogSentinel parses raw log files from multiple sources, detects common attack patterns, stores every finding in a MySQL database, and generates a clean, dark-themed HTML security incident report — all from a simple CLI menu.

---

## Features

| Feature | Details |
|---|---|
| **Multi-source parsing** | SSH `auth.log`, Apache Combined Log Format, Windows Event Log CSV |
| **Threat detection** | Brute force, suspicious-hours activity, path scanning (404s), unknown user attempts |
| **Severity classification** | `HIGH` / `MEDIUM` / `LOW` with clear rules |
| **MySQL persistence** | Two-table schema; log entries linked to threat events |
| **HTML incident report** | Dark security-themed design rendered with Jinja2 |
| **CLI menu** | Simple numbered menu — no flags to remember |
| **Sample data included** | Realistic fake log files produce output immediately |

---

## Project Structure

```
LogSentinel/
├── main.py                     # CLI entry point & menu
│
├── parser/
│   ├── __init__.py
│   ├── ssh_parser.py           # Parses /var/log/auth.log (SSH)
│   ├── apache_parser.py        # Parses Apache Combined Log Format
│   └── windows_parser.py       # Parses Windows Event Log CSV exports
│
├── detector/
│   ├── __init__.py
│   └── threat_detector.py      # Threat detection & severity classification
│
├── database/
│   ├── __init__.py
│   └── db_handler.py           # All MySQL operations
│
├── reporter/
│   ├── __init__.py
│   └── report_generator.py     # Renders the HTML report via Jinja2
│
├── templates/
│   └── report.html             # Jinja2 HTML report template (dark theme)
│
├── sample_logs/
│   ├── auth.log                # Realistic fake SSH auth log
│   ├── access.log              # Realistic fake Apache access log
│   └── windows_events.csv      # Realistic fake Windows Event Log CSV
│
├── schema.sql                  # MySQL CREATE TABLE statements
├── requirements.txt
├── .env.example                # Credential template (copy to .env)
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.10 or later
- MySQL 8.0+ or MariaDB 10.5+

### 1 — Clone and install dependencies

```bash
git clone https://github.com/yourusername/LogSentinel.git
cd LogSentinel
pip install -r requirements.txt
```

### 2 — Configure your database credentials

```bash
cp .env.example .env
# Open .env and fill in your MySQL host, user, password, and database name
```

Your `.env` file should look like:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=logsentinel
```

### 3 — Create the database and tables

```bash
# Create the database (one-time)
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS logsentinel;"

# Apply the schema
mysql -u root -p logsentinel < schema.sql
```

### 4 — Run LogSentinel

```bash
python main.py
```

Choose **`[4] Run Full Pipeline`** to parse all sample logs, detect threats, generate the HTML report, and print a terminal summary — all in one step.

The generated report is saved as **`incident_report.html`** in the project root. Open it in any browser.

---

## GitHub Codespaces Setup

MySQL is not running by default in Codespaces. Use the following commands to get started:

```bash
# Start the MySQL service
sudo service mysql start

# Set a root password (optional in Codespaces)
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';"

# Create the database and apply the schema
sudo mysql -e "CREATE DATABASE IF NOT EXISTS logsentinel;"
sudo mysql logsentinel < schema.sql
```

Update your `.env` to match:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=logsentinel
```

Then install dependencies and run:

```bash
pip install -r requirements.txt
python main.py
```

---

## Threat Detection Rules

| Threat Type | Trigger Condition | Severity |
|---|---|---|
| `BRUTE_FORCE` | 5 or more failed SSH logins from the same IP address | **HIGH** |
| `BRUTE_FORCE` | 5 or more failed Windows logons for the same username | **HIGH** |
| `SUSPICIOUS_HOURS` | Failed or error-status activity between 00:00 and 05:00 AM | **MEDIUM** |
| `REPEATED_404` | 5 or more HTTP 404 responses from the same IP (path scanning) | **MEDIUM** |
| `UNKNOWN_USER_LOGIN` | SSH login attempt for a non-existent system user | **MEDIUM** |

---

## Database Schema

### `log_entries`

| Column | Type | Description |
|---|---|---|
| `id` | INT PK | Auto-generated primary key |
| `source_file` | VARCHAR(255) | Path to the parsed log file |
| `log_type` | VARCHAR(50) | `SSH`, `APACHE`, or `WINDOWS` |
| `timestamp` | DATETIME | Parsed event timestamp |
| `ip_address` | VARCHAR(45) | Source IP (IPv4 or IPv6) |
| `user` | VARCHAR(100) | Username involved |
| `action` | VARCHAR(255) | Short description of the action |
| `status` | VARCHAR(50) | `SUCCESS`, `FAILED`, HTTP code, etc. |
| `raw_line` | TEXT | Original unmodified log line |
| `created_at` | TIMESTAMP | Row insertion time |

### `threat_events`

| Column | Type | Description |
|---|---|---|
| `id` | INT PK | Auto-generated primary key |
| `log_entry_id` | INT FK | References `log_entries.id` |
| `threat_type` | VARCHAR(100) | E.g. `BRUTE_FORCE`, `REPEATED_404` |
| `severity` | ENUM | `LOW`, `MEDIUM`, or `HIGH` |
| `description` | TEXT | Human-readable explanation |
| `detected_at` | TIMESTAMP | When the threat was flagged |

---

## Sample Output

Running the full pipeline on the included sample logs produces:

- **~110+ log entries** across SSH, Apache, and Windows sources
- **Detected threats** including brute force attempts (multiple IPs), late-night attack activity, HTTP path-scanning, and unknown user login attempts
- **`incident_report.html`** — a professional dark-themed security report ready to share

---

## AI-Assisted Development

> This project was built using an **AI-assisted development workflow with Claude** (Anthropic). Claude was used to design the overall architecture, generate all source code and templates, and produce documentation — demonstrating how AI tools can accelerate the development of practical cybersecurity software while maintaining code quality, clear comments, and security best practices.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
