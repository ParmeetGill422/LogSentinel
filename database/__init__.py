# database/__init__.py
# Makes 'database' a Python package.

from .db_handler import (
    init_database,
    insert_log_entry,
    insert_threat_event,
    get_all_threats,
    get_all_log_entries,
    get_summary_stats,
    clear_database,
)
