"""Report rendering (spec sections 25-27): JSON, CSV, HTML, PDF.

Pure, DB-free renderers over the report dict built by
:func:`app.services.report_service.build_report_data`. All evidence persisted by
the scanner is already redacted, so reports are safe to share. PDF rendering
uses WeasyPrint, whose native libraries are installed in the Docker image; if
they are unavailable the API returns a clear 501 rather than crashing.
"""
from __future__ import annotations

import csv
import io
import json


class ReportFormatUnavailable(RuntimeError):
    """Raised when a requested format cannot be produced in this environment."""


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> object:
    """Neutralise spreadsheet formulas: target-controlled text (URLs, header
    values in evidence) starting with = + - @ would run when the CSV is opened
    in Excel/Sheets. Numbers are left alone."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def render_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "rule_id", "title", "category", "severity", "cvss_base_score",
        "context_class", "context_multiplier", "response_bonus",
        "cawasma_final_score", "endpoint_url", "limitation",
    ])
    for f in data["findings"]:
        writer.writerow([csv_safe(v) for v in (
            f["rule_id"], f["title"], f["category"], f["severity"],
            f["cvss_base_score"], f["context_class"],
            f["cawasma_context_multiplier"], f["response_bonus"],
            f["cawasma_final_score"], f["endpoint_url"] or "",
            (f["limitation"] or "").replace("\n", " "),
        )])
    return buf.getvalue()


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>CAWASMA Report — {{ scan.target_url }}</title>
<style>
 body{font-family:Arial,Helvetica,sans-serif;margin:2rem;color:#1a1a1a}
 h1{font-size:1.5rem} h2{margin-top:1.6rem;border-bottom:2px solid #eee;padding-bottom:.3rem}
 table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.85rem}
 th,td{border:1px solid #ddd;padding:.4rem .5rem;text-align:left;vertical-align:top}
 th{background:#f4f4f4}
 .CRITICAL{color:#fff;background:#9b1c1c;padding:1px 6px;border-radius:3px}
 .HIGH{color:#fff;background:#b45309;padding:1px 6px;border-radius:3px}
 .MEDIUM{color:#1a1a1a;background:#fde68a;padding:1px 6px;border-radius:3px}
 .LOW{color:#1a1a1a;background:#d1fae5;padding:1px 6px;border-radius:3px}
 .INFO{color:#1a1a1a;background:#e5e7eb;padding:1px 6px;border-radius:3px}
 .muted{color:#666;font-size:.8rem} .limit{color:#92400e;font-style:italic}
 pre{white-space:pre-wrap;background:#fafafa;padding:.6rem;border:1px solid #eee}
</style></head><body>
<h1>CAWASMA Security Report</h1>
<p class="muted">Target: <strong>{{ scan.target_url }}</strong> &middot;
 Status: {{ scan.status }} &middot; Completed: {{ scan.completed_at or "—" }}</p>

<h2>Executive summary</h2>
<pre>{{ insight or "No summary available." }}</pre>
<p>
{% for s,n in summary.by_severity.items() %}<span class="{{ s }}">{{ s }}: {{ n }}</span>&nbsp;{% endfor %}
</p>
<p class="muted">{{ summary.total_findings }} findings &middot;
 {{ summary.total_endpoints }} endpoints &middot;
 {{ summary.total_chains }} attack chains &middot; highest score {{ summary.max_score }}</p>

{% if chains %}
<h2>Attack chains (context-aware correlation)</h2>
<table><tr><th>Code</th><th>Chain</th><th>Composite</th><th>Severity</th><th>Members</th></tr>
{% for c in chains %}<tr><td>{{ c.code }}</td><td>{{ c.name }}<br><span class="muted">{{ c.description }}</span></td>
<td>{{ c.composite_score }}</td><td><span class="{{ c.severity }}">{{ c.severity }}</span></td>
<td>{{ c.member_findings|join(", ") }}</td></tr>{% endfor %}
</table>
{% endif %}

<h2>Findings (ranked by context-aware score)</h2>
<table><tr><th>Severity</th><th>Score</th><th>Rule</th><th>Endpoint</th>
<th>CVSS base</th><th>Context</th></tr>
{% for f in findings %}<tr>
<td><span class="{{ f.severity }}">{{ f.severity }}</span></td>
<td><strong>{{ f.cawasma_final_score }}</strong></td>
<td>{{ f.rule_id }} — {{ f.title }}
 {% if f.limitation %}<br><span class="limit">Limitation: {{ f.limitation }}</span>{% endif %}</td>
<td class="muted">{{ f.endpoint_url or "—" }}</td>
<td>{{ f.cvss_base_score }}</td>
<td>{{ f.context_class or "—" }} ×{{ f.cawasma_context_multiplier }}
 {% if f.response_bonus %}+{{ f.response_bonus }}{% endif %}</td>
</tr>{% endfor %}
</table>

<h2>Endpoints</h2>
<table><tr><th>Path</th><th>Status</th><th>Context</th><th>Confidence</th><th>Discovered</th></tr>
{% for e in endpoints %}<tr><td>{{ e.path }}</td><td>{{ e.status_code or "—" }}</td>
<td>{{ e.context_class or "—" }}</td><td>{{ "%.2f"|format(e.context_confidence or 0) }}</td>
<td>{{ e.discovered_by }}</td></tr>{% endfor %}
</table>

{% if tls %}
<h2>TLS</h2>
<table><tr><th>Host</th><th>Protocol</th><th>Cipher</th><th>Issuer</th><th>Expires</th><th>Self-signed</th></tr>
{% for t in tls %}<tr><td>{{ t.host }}</td><td>{{ t.negotiated_protocol }}</td>
<td>{{ t.negotiated_cipher }}</td><td>{{ t.cert_issuer }}</td>
<td>{{ t.cert_not_after }}</td><td>{{ t.is_self_signed }}</td></tr>{% endfor %}
</table>
{% endif %}

<hr><p class="muted">CAWASMA — Context-Aware Web &amp; API Security Misconfiguration
Analyzer. The context-aware final score is a custom prioritization metric and is
not an official CVSS value. Findings marked with a limitation require manual
verification.</p>
</body></html>"""


def render_html(data: dict) -> str:
    # Autoescape: titles, URLs and evidence come from the scanned target, so an
    # unescaped Server header or path would be live HTML/JS in the report.
    from jinja2 import Environment

    return Environment(autoescape=True).from_string(_HTML_TEMPLATE).render(**data)


def render_pdf(data: dict) -> bytes:
    html = render_html(data)
    try:
        from weasyprint import HTML
    except Exception as exc:  # noqa: BLE001 - native libs may be absent
        raise ReportFormatUnavailable(
            "PDF rendering requires WeasyPrint native libraries (available in the "
            "Docker image)."
        ) from exc
    return HTML(string=html).write_pdf()
