"""Report rendering (spec sections 25-27): JSON, CSV, HTML, PDF.

Pure, DB-free renderers over the report dict built by
:func:`app.services.contract_service.report_data` (contract export). The HTML
comes from the Jinja2 template ``app/templates/report.html.j2``; the PDF is that
same HTML through WeasyPrint. Evidence is redacted when stored and again here. PDF rendering
uses WeasyPrint, whose native libraries are installed in the Docker image; if
they are unavailable the API returns a clear 501 rather than crashing.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from app.utils.redaction import redact_text


class ReportFormatUnavailable(RuntimeError):
    """Raised when a requested format cannot be produced in this environment."""


_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> object:
    """Neutralise spreadsheet formulas: target-controlled text (URLs, header
    values in evidence) starting with = + - @ would run when the CSV is opened
    in Excel/Sheets. Numbers are left alone."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
TEMPLATE = "report.html.j2"
_TEMPLATES = Path(__file__).resolve().parents[1] / "templates"

_METRIC_NAMES = {
    "CR": "Confidentiality requirement",
    "IR": "Integrity requirement",
    "AR": "Availability requirement",
}
_LEVELS = {"H": "High", "M": "Medium", "L": "Low", "X": "Not defined"}


def _reason_source(source: str) -> str:
    kind, _, value = source.partition(":")
    if kind == "sensitivity":
        return f"endpoint sensitivity is {value}"
    if kind == "signal":
        return f"the response contains {value}"
    return source


def score_story(f: dict[str, Any]) -> list[str]:
    """Plain-language reasons the final score differs from (or equals) the base.

    Spec-registry findings carry ``score_reasons`` from the CVSS environmental
    scoring (core/cvss.py), e.g. ``CR:H<-sensitivity:CRITICAL+signal:PII``.
    Legacy findings were scored by the interim formula (docs/06), so their
    multiplier and response bonus explain the difference.
    """
    base, final = f.get("cvss_base_score"), f.get("cawasma_final_score")
    reasons = list(f.get("score_reasons") or [])
    lines: list[str] = []
    if f.get("final_vector") or reasons:
        lines.append(
            "Scored with CVSS v3.1 environmental metrics: the base vector plus the "
            "security requirements this endpoint's context sets."
        )
        for r in reasons:
            if "<-" in r:
                metric, sources = r.split("<-", 1)
                name, _, level = metric.partition(":")
                why = ", ".join(_reason_source(x) for x in sources.split("+"))
                lines.append(
                    f"{_METRIC_NAMES.get(name, name)} {_LEVELS.get(level, level)}"
                    f" because {why}."
                )
            elif r == "no-context-change":
                lines.append(
                    "Nothing in the context raises a requirement, so the final "
                    "score equals the base score."
                )
            elif r.startswith(("base:", "environmental:", "sensitivity:", "signal:")):
                continue  # shown elsewhere (scores, context line)
            else:
                lines.append(r)
    else:
        mult, bonus = f.get("cawasma_context_multiplier"), f.get("response_bonus")
        ctx = f.get("context_class")
        parts = [
            "Scored with the interim formula: min(10, base × context multiplier "
            "+ response bonus)."
        ]
        if mult not in (None, ""):
            parts.append(
                f"Context multiplier ×{mult}" + (f" for a {ctx} endpoint." if ctx else ".")
            )
        elif ctx:
            parts.append(f"Endpoint sensitivity is {ctx}.")
        signals = ", ".join(f.get("body_signals") or [])
        if bonus:
            parts.append(
                f"Response bonus +{bonus} for sensitive data in the response"
                + (f" ({signals})." if signals else ".")
            )
        elif signals:
            parts.append(f"The response contains {signals}, which adds a response bonus.")
        lines.extend(parts)
    if isinstance(base, int | float) and isinstance(final, int | float):
        delta = round(final - base, 1)
        change = "unchanged" if delta == 0 else f"{delta:+.1f}"
        lines.append(f"Base {base} → final {final} ({change}).")
    return lines


def redact_evidence(value: Any) -> Any:
    """Defence in depth: evidence is redacted when stored; redact again on the way
    out so no report format can carry a secret even from an older row."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_evidence(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_evidence(v) for v in value]
    return value


def _view(data: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for f in data.get("findings", []):
        f = dict(f)
        f["evidence"] = redact_evidence(f.get("evidence"))
        f["score_story"] = score_story(f)
        findings.append(f)
    return {**data, "findings": findings, "severities": SEVERITIES}


@lru_cache(maxsize=1)
def _environment() -> Any:
    # Autoescape: titles, URLs and evidence come from the scanned target, so an
    # unescaped Server header or path would be live HTML/JS in the report.
    from jinja2 import Environment, FileSystemLoader

    return Environment(
        loader=FileSystemLoader(_TEMPLATES), autoescape=True, trim_blocks=True, lstrip_blocks=True
    )


def render_html(data: dict[str, Any]) -> str:
    return str(_environment().get_template(TEMPLATE).render(**_view(data)))


def render_pdf(data: dict) -> bytes:
    html = render_html(data)
    try:
        from weasyprint import HTML
    except Exception as exc:
        raise ReportFormatUnavailable(
            "PDF rendering requires WeasyPrint native libraries (available in the " "Docker image)."
        ) from exc
    return HTML(string=html).write_pdf()
