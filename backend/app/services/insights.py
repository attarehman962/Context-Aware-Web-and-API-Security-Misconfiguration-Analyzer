"""Executive insight generation.

A deterministic, template-based summary generated from the scan's own data --
NOT an external LLM call. This keeps the tool self-contained, reproducible and
honest: the ``provider`` is recorded as ``builtin``. (A pluggable LLM provider
could be added later; the data contract is already in place via AiInsight.)
"""

from __future__ import annotations

from app.core.pipeline import ScanResult

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def generate_insight(result: ScanResult) -> str:
    """Write a short executive summary of the scan."""
    by_sev = result.stats["by_severity"]
    crit, high = by_sev.get("CRITICAL", 0), by_sev.get("HIGH", 0)
    n_find, n_ep, n_chain = (
        result.stats["findings"],
        result.stats["endpoints"],
        result.stats["chains"],
    )

    if crit:
        posture = "high risk"
    elif high:
        posture = "elevated risk"
    elif n_find:
        posture = "moderate risk"
    else:
        posture = "low risk"

    lines = [
        f"Overall posture: {posture.upper()}. "
        f"Scanned {n_ep} endpoint(s); {n_find} finding(s) across "
        + ", ".join(f"{by_sev[s]} {s.lower()}" for s in _SEV_ORDER if by_sev.get(s))
        + "."
    ]

    # Top findings by context-aware score.
    top = sorted(result.findings, key=lambda f: f.cawasma_final_score, reverse=True)[:3]
    if top:
        lines.append("Highest-priority issues (context-aware score):")
        for f in top:
            lines.append(
                f"  - [{f.severity.value}] {f.raw.rule_id} {f.raw.title} "
                f"(score {f.cawasma_final_score}; CVSS base {f.cvss_base_score})"
            )

    if result.chains:
        lines.append(
            f"{n_chain} attack chain(s) detected, indicating findings that "
            "combine into higher-impact paths:"
        )
        for c in result.chains:
            lines.append(f"  - {c.code} {c.name} (composite {c.composite_score})")

    if crit:
        lines.append(
            "Recommendation: remediate CRITICAL items first, "
            "prioritizing sensitive (CRITICAL/HIGH) endpoints."
        )
    return "\n".join(lines)
