"""
reporter/report_generator.py
============================
Generates the HTML incident report from data retrieved from the database.

Uses Jinja2 to render the report template (templates/report.html) with:
  - All log entries (up to 500, capped in db_handler)
  - All detected threat events
  - Summary statistics (totals, severity breakdown, type breakdown)

The output is a self-contained HTML file with all CSS inline in the <head>,
so it can be opened directly in any browser without additional dependencies.
"""

import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def generate_report(
    log_entries: list,
    threats: list,
    stats: dict,
    output_path: str = "incident_report.html",
) -> str:
    """
    Render the Jinja2 HTML template with the provided data and write it
    to *output_path*.

    Parameters
    ----------
    log_entries : list of dict
        Rows from the log_entries table (from db_handler.get_all_log_entries).
    threats : list of dict
        Rows from the threat_events JOIN log_entries query
        (from db_handler.get_all_threats).
    stats : dict
        Aggregate statistics (from db_handler.get_summary_stats).
    output_path : str
        File path for the generated HTML report.

    Returns
    -------
    str
        The absolute path of the written report file.
    """
    # Locate the templates directory relative to this file's location
    # reporter/ -> project root -> templates/
    project_root  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(project_root, "templates")

    # Initialise Jinja2 with autoescaping enabled for HTML output
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html")

    # Pass all data to the template context
    html_output = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        log_entries=log_entries,
        threats=threats,
        stats=stats,
    )

    # Write the rendered HTML to disk
    abs_output = os.path.abspath(output_path)
    with open(abs_output, "w", encoding="utf-8") as fh:
        fh.write(html_output)

    return abs_output
