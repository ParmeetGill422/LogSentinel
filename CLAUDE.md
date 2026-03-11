# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the tool

```bash
python main.py          # launch the interactive CLI menu
```

The menu options run these internal steps in order:
1. `run_parsers()` — parse all three sample logs, store to DB, attach `db_id` to each entry dict
2. `run_detection(entries)` — pass the enriched entry list to the detector, store threats to DB
3. `run_report()` — query DB, render `incident_report.html` via Jinja2
4. `view_summary()` — print colour-coded threat table to terminal

**Option 4 (Full Pipeline)** runs all four steps in sequence.

## Database setup

```bash
# Apply schema (drops and recreates both tables)
mysql -u root -p logsentinel < schema.sql

# Wipe data without dropping tables (also available via menu option 5)
# Uses TRUNCATE inside db_handler.clear_database()
```

Credentials are read from `.env` at startup via `python-dotenv`. The `.env` file is gitignored; `.env.example` is the template. Required variables: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.

## Architecture

### Data flow

```
sample_logs/  →  parser/*_parser.py  →  list of entry dicts
                                               ↓
                                     db_handler.insert_log_entry()
                                     (sets entry["db_id"])
                                               ↓
                                     detector/threat_detector.py
                                     (reads db_id to link threats)
                                               ↓
                                     db_handler.insert_threat_event()
                                               ↓
                                     reporter/report_generator.py
                                     + templates/report.html  →  incident_report.html
```

### The entry dict contract

Every parser returns a list of dicts with these exact keys — `db_handler` and `threat_detector` both depend on this shape:

```python
{
    "source_file": str,
    "log_type":    "SSH" | "APACHE" | "WINDOWS",
    "timestamp":   datetime | None,
    "ip_address":  str | None,
    "user":        str | None,
    "action":      str | None,
    "status":      str | None,   # see status values below
    "raw_line":    str,
    # added by main.py after DB insert:
    "db_id":       int,
}
```

**Status values by log type:**
- SSH: `SUCCESS`, `FAILED`, `FAILED_INVALID_USER`, `INFO`
- Apache: HTTP status code string (`"200"`, `"404"`, etc.)
- Windows: `SUCCESS`, `FAILED`, `INFO`

### Threat detection

`detect_threats(log_entries)` in `detector/threat_detector.py` operates entirely in-memory on the entry list. It must be called **after** `db_id` is set on each entry (i.e. after DB insert) so it can link `threat_event.log_entry_id` back to the correct row.

Thresholds are module-level constants at the top of `threat_detector.py`:
- `BRUTE_FORCE_THRESHOLD = 5`
- `REPEATED_404_THRESHOLD = 5`
- `SUSPICIOUS_HOUR_START = 0`, `SUSPICIOUS_HOUR_END = 5`

### Database

`db_handler.get_connection()` opens a new connection per call (no connection pool). Every function opens, uses, and closes its own connection. `init_database()` reads and executes `schema.sql` from the project root — it **drops and recreates** both tables, so it is destructive on re-run.

### HTML report

The Jinja2 template at `templates/report.html` receives three variables:
- `log_entries` — list of dicts from `get_all_log_entries()` (MySQL `dictionary=True` cursor rows)
- `threats` — list of dicts from `get_all_threats()` (JOIN of `threat_events` + `log_entries`)
- `stats` — dict with keys `total_logs`, `total_threats`, `by_severity` (dict), `by_type` (list), `by_log_type` (list)

`detected_at` and `timestamp` in the template are Python `datetime` objects — use `.strftime()` directly in Jinja2.

## Adding a new log parser

1. Create `parser/your_parser.py` with a `parse_your_log(filepath) -> list` function that returns entry dicts matching the contract above.
2. Export it from `parser/__init__.py`.
3. Add the file path to `SAMPLE_LOGS` in `main.py` and call `parse_your_log()` inside `run_parsers()`.

## Adding a new threat rule

All detection logic lives in `detector/threat_detector.py` inside the single `detect_threats()` function. Add a new block following the existing pattern — group entries, apply a threshold, append a dict with `log_entry_id`, `threat_type`, `severity`, `description`, and `detected_at` to the `threats` list. The severity `ENUM` in MySQL only accepts `'LOW'`, `'MEDIUM'`, `'HIGH'`.
