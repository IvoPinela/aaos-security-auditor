"""Self-contained HTML report: one file, no JavaScript, no external resources.

Meant for people who will not run a terminal (managers, auditors, customers). Every value is escaped, and a
Content-Security-Policy forbids scripts and network loads, so opening a report from an untrusted scan is safe.
"""

from __future__ import annotations

from html import escape
from typing import Any

from aaos_auditor.masvs import MASVS_CONTROLS
from aaos_auditor.threat_model import with_threat_model

SEVERITIES = ("critical", "high", "medium", "low", "info")
RISK_LABELS = {"elevated": "Elevated risk", "review": "Needs review", "informational": "No high or medium findings"}

STYLE = """
:root{--bg:#f6f8fb;--panel:#fff;--text:#142033;--muted:#5b6b82;--line:#d9e1ec;--accent:#0f766e;
--critical:#b42318;--high:#d92d20;--medium:#b54708;--low:#175cd3;--info:#475467}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--panel:#111b2d;--text:#e8eef9;--muted:#98a8bf;--line:#25344b;--accent:#5eead4;
--critical:#ff8a80;--high:#ff8181;--medium:#ffc96b;--low:#8ab5ff;--info:#a7b4c7}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1020px;margin:0 auto;padding:28px 20px 60px}h1{margin:.1em 0;font-size:1.7rem}h2{margin:2em 0 .6em;font-size:1.15rem;
border-bottom:1px solid var(--line);padding-bottom:.3em}h3{margin:1.2em 0 .3em;font-size:1rem}.muted{color:var(--muted)}small{color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.stat{text-align:center;padding:12px 6px}.stat b{display:block;font-size:1.6rem}
table{width:100%;border-collapse:collapse;font-size:.9rem;margin:8px 0}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}code{font:.85em ui-monospace,Consolas,monospace;word-break:break-word}
.sev{display:inline-block;padding:1px 8px;border-radius:99px;font-size:.75rem;font-weight:700;color:#fff;text-transform:uppercase}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.finding{border-left:4px solid var(--line)}.finding.critical{border-color:var(--critical)}.finding.high{border-color:var(--high)}
.finding.medium{border-color:var(--medium)}.finding.low{border-color:var(--low)}.finding.info{border-color:var(--info)}
.notice{border-left:4px solid var(--medium);background:var(--panel);padding:10px 14px;border-radius:6px}
ul.check{list-style:none;padding-left:0}ul.check li::before{content:"\\2610  ";color:var(--accent)}
@media print{body{background:#fff;color:#000}.card{break-inside:avoid}main{padding:0}}
@media (max-width:640px){.grid{grid-template-columns:repeat(2,1fr)}}
"""


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _badge(severity: Any) -> str:
    level = str(severity) if str(severity) in SEVERITIES else "info"
    return f'<span class="sev {level}">{_e(level)}</span>'


def _list(items: list[Any]) -> str:
    return "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in items) + "</ul>" if items else ""


def to_html(report: dict[str, Any], generated_by: str = "AAOS Security Auditor") -> str:
    """Render a complete HTML document for a report produced by this tool."""
    report = with_threat_model(report)
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)]
    counts = report.get("severity_counts") or {level: sum(i.get("severity") == level for i in findings) for level in SEVERITIES}
    is_source = report.get("report_type") == "source_directory"
    package = str(report.get("package_name") or "")
    title = report.get("project_name") if is_source else package
    if is_source and package and package not in {"Unknown", "Android project", "Multiple modules"} and title in {None, "", "app", "src"}:
        title = package
    sha = report.get("source_sha256") or report.get("apk_sha256") or ""
    policy = report.get("policy") or {}
    model = report.get("threat_model") or {}
    suppressed = report.get("suppressed_findings") or []
    dependencies = report.get("dependencies") or []

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        # No scripts, no network: only inline styles are allowed.
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        f"<title>Security report: {_e(title or 'analysis')}</title>",
        f"<style>{STYLE}</style></head><body><main>",
        f'<p class="muted">{_e(generated_by)} · static analysis report</p>',
        f"<h1>{_e(title or 'Analysis')}</h1>",
        f'<p class="muted">Package <code>{_e(report.get("package_name", "unknown"))}</code> · '
        f'{_e(report.get("profile_label") or report.get("analysis_profile") or "APK")} · '
        f'target SDK {_e(report.get("target_sdk", "?"))} · analyzed {_e(report.get("analyzed_at", "?"))}'
        + (f" · SHA-256 <code>{_e(str(sha)[:16])}…</code>" if sha else "") + "</p>",
        f'<div class="card"><b>{_e(RISK_LABELS.get(report.get("risk_level"), report.get("risk_level", "")))}</b> '
        f"<small>heuristic level, not a certification</small></div>",
        '<div class="grid">' + "".join(
            f'<div class="card stat">{_badge(level)}<b>{_e(counts.get(level, 0))}</b></div>' for level in SEVERITIES
        ) + "</div>",
    ]

    if policy.get("suppressed"):
        parts.append(f'<p class="muted">{_e(policy["suppressed"])} finding(s) suppressed by project policy with a recorded reason (listed below).</p>')

    parts.append("<h2>Findings</h2>")
    if not findings:
        parts.append('<div class="card">No findings from the rules that ran. This does not prove the application is secure.</div>')
    for item in findings:
        tags = ", ".join([*(item.get("masvs") or []), *(item.get("maswe") or [])]) + (" · " + ", ".join(item.get("cwe") or []) if item.get("cwe") else "")
        parts.append(
            f'<div class="card finding {_e(item.get("severity", "info"))}">'
            f'{_badge(item.get("severity"))} <b>{_e(item.get("title", ""))}</b>'
            f'<p>{_e(item.get("summary", ""))}</p>'
            f'<p><b>Recommendation:</b> {_e(item.get("recommendation", ""))}</p>'
            f'<small><code>{_e(item.get("rule_id", ""))}</code> · {_e(item.get("evidence", ""))}'
            + (f" · {_e(tags)}" if tags.strip(" ·") else "") + "</small></div>"
        )

    masvs = report.get("masvs_summary") or {}
    if masvs:
        parts.append("<h2>OWASP MASVS coverage (guidance only)</h2><table><tr><th>Control</th><th>Findings</th><th>Description</th></tr>")
        parts += [f"<tr><td><code>{_e(control)}</code></td><td>{_e(count)}</td><td>{_e(MASVS_CONTROLS.get(control, ''))}</td></tr>" for control, count in masvs.items()]
        parts.append("</table>")

    if suppressed or policy.get("expired") or policy.get("warnings"):
        parts.append("<h2>Policy decisions</h2>")
        if suppressed:
            parts.append("<table><tr><th>Rule</th><th>Where</th><th>Kind</th><th>Reason</th><th>Expires</th></tr>")
            for item in suppressed:
                decision = item.get("suppression") or {}
                parts.append(
                    f"<tr><td><code>{_e(item.get('rule_id'))}</code></td><td>{_e(item.get('evidence'))}</td><td>{_e(decision.get('kind'))}</td>"
                    f"<td>{_e(decision.get('reason'))}</td><td>{_e(decision.get('expires') or '-')}</td></tr>"
                )
            parts.append("</table>")
        for item in policy.get("expired", []):
            parts.append(f'<div class="notice">Expired: {_e(item.get("suppression"))} on {_e(item.get("expired_on"))}; the finding is active again.</div>')
        for item in policy.get("unused", []):
            parts.append(f'<div class="notice">Stale: {_e(item)} matches nothing.</div>')
        for warning in policy.get("warnings", []):
            parts.append(f'<div class="notice">Warning: {_e(warning)}</div>')

    if model.get("threats"):
        parts.append("<h2>Applicable threats (derived, not proven)</h2><table><tr><th>ID</th><th>STRIDE</th><th>Threat</th><th>Rules</th></tr>")
        for threat in model["threats"]:
            parts.append(
                f"<tr><td><code>{_e(threat.get('id'))}</code></td><td>{_e(threat.get('stride'))}</td><td>{_e(threat.get('title'))}"
                + (f"<br><small>{_e(threat.get('chain'))}</small>" if threat.get("chain") else "")
                + f"</td><td><small>{_e(', '.join(threat.get('matched_rules', [])[:4]))}</small></td></tr>"
            )
        parts.append("</table>")
    if model.get("validation_phases"):
        parts.append("<h2>Phased validation plan</h2><p class=\"muted\">Manual and authorized. Use an isolated AAOS emulator or bench, never a road vehicle.</p>")
        for phase in model["validation_phases"]:
            parts.append(f"<h3>{_e(phase.get('name'))}</h3><small>{_e(phase.get('goal'))}</small><ul class=\"check\">")
            parts += [f"<li><code>{_e(check.get('id'))}</code> {_e(check.get('title'))}</li>" for check in phase.get("checks", [])]
            parts.append("</ul>")
    if model.get("not_assessed"):
        parts.append("<h2>Not covered by this analysis</h2>" + _list(model["not_assessed"]))

    if dependencies:
        summary = report.get("dependency_summary") or {}
        parts.append(
            f"<h2>Declared dependencies</h2><p>{_e(summary.get('total', len(dependencies)))} declared "
            f"({_e(summary.get('pinned', 0))} pinned, {_e(summary.get('dynamic', 0))} dynamic, {_e(summary.get('unresolved', 0))} unresolved). "
            "Transitive dependencies and BOM-managed versions are not resolved.</p>"
        )

    parts.append(
        f'<h2>Scope</h2><p class="muted">{_e(report.get("analysis_scope", ""))} Heuristic classification, not a certification; validate manually.</p>'
        "</main></body></html>"
    )
    return "\n".join(parts)
