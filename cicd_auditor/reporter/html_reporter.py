"""
reporter/html_reporter.py
--------------------------
Renders an AuditReport into a polished HTML file using Jinja2.

WHY JINJA2?
    Jinja2 is the de-facto Python templating engine (used by Flask, Ansible,
    dbt, and many others).  It lets us keep all the HTML/CSS in a separate
    .j2 file, making it easy for clients to brand or customise the report
    without touching any Python.

TEMPLATE LOCATION
    The template lives next to this file in templates/report.html.j2.
    We load it relative to this file's location so the package works
    correctly whether installed via pip or run from source.

CUSTOM FILTERS
    We register two extra Jinja2 filters:
        basename  → os.path.basename, for showing just the repo folder name
        strftime  → already on datetime objects, exposed via the template
"""

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import AuditReport

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _basename(path: str) -> str:
    return os.path.basename(path.rstrip("/\\"))


def render_html(report: AuditReport, output_path: str) -> str:
    """
    Render the report to an HTML file.

    Parameters
    ----------
    report      : The completed AuditReport
    output_path : Where to write the HTML file

    Returns
    -------
    The absolute path to the written file.
    """
    env = Environment(
        loader       = FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape   = select_autoescape(["html"]),
        trim_blocks  = True,
        lstrip_blocks= True,
    )
    env.filters["basename"] = _basename

    template = env.get_template("report.html.j2")
    html     = template.render(report=report)

    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path
