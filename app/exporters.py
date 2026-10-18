"""Convert auditor reports to SARIF 2.1.0 and Markdown, and compare reports against a baseline."""

from __future__ import annotations

from typing import Any

from app.masvs import MASVS_CONTROLS
from app.rules_catalog import rule_catalog

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub code scanning reads security-severity (0-10) to bucket alerts.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
TOOL_NAME = "AAOS Security Auditor"


def finding_key(finding: dict[str, Any], use_fingerprint: bool = True) -> tuple[str, str]:
    """Identity used for deduplication and baseline comparison.

    The fingerprint survives line shifts; the evidence string is the fallback for reports
    produced before fingerprints existed.
    """
    if use_fingerprint and finding.get("fingerprint"):
        return str(finding.get("rule_id", "")), str(finding["fingerprint"])
    return str(finding.get("rule_id", "")), str(finding.get("evidence", ""))


def severity_at_least(severity: str, threshold: str) -> bool:
    if threshold not in SEVERITY_ORDER:
        return False
    rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return rank <= SEVERITY_ORDER.index(threshold)


def filter_by_severity(findings: list[dict[str, Any]], minimum: str) -> list[dict[str, Any]]:
    return [finding for finding in findings if severity_at_least(str(finding.get("severity", "info")), minimum)]


def compare_with_baseline(report: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Split findings into new / unchanged / resolved relative to an earlier report."""
    baseline_findings = [finding for finding in baseline.get("findings", []) if isinstance(finding, dict)]
    current_findings = report.get("findings", [])
    # Mixed reports (one side without fingerprints) must fall back to evidence on both sides.
    use_fingerprint = all(finding.get("fingerprint") for finding in baseline_findings + current_findings)
    current = {finding_key(finding, use_fingerprint): finding for finding in current_findings}
    previous = {finding_key(finding, use_fingerprint): finding for finding in baseline_findings}
    new = [finding for key, finding in current.items() if key not in previous]
    resolved = [finding for key, finding in previous.items() if key not in current]
    return {
        "baseline_sha256": baseline.get("source_sha256") or baseline.get("apk_sha256") or "",
        "new_count": len(new),
        "resolved_count": len(resolved),
        "unchanged_count": len(current) - len(new),
        "new": new,
        "resolved": [
            {key: finding.get(key, "") for key in ("rule_id", "severity", "title", "evidence")}
            for finding in resolved
        ],
    }


def to_sarif(report: dict[str, Any], tool_version: str = "0.2.0") -> dict[str, Any]:
    """Emit SARIF 2.1.0 without source snippets; locations are path/line only."""
    catalog = {entry["id"]: entry for entry in rule_catalog()}
    suppressed = report.get("suppressed_findings", []) or []
    findings = list(report.get("findings", [])) + list(suppressed)
    rule_ids = sorted({str(finding.get("rule_id", "")) for finding in findings})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    rules: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        entry = catalog.get(rule_id, {})
        sample = next(finding for finding in findings if finding.get("rule_id") == rule_id)
        severity = str(entry.get("severity") or sample.get("severity", "info"))
        masvs = entry.get("masvs") or sample.get("masvs") or []
        cwe = entry.get("cwe") or sample.get("cwe") or []
        cwe_tags = [f"external/cwe/cwe-{str(item).split('-')[-1]}" for item in cwe if str(item).upper().startswith("CWE-")]
        rules.append({
            "id": rule_id,
            "name": rule_id.title().replace("-", ""),
            "shortDescription": {"text": str(entry.get("title") or sample.get("title", rule_id))},
            "fullDescription": {"text": str(entry.get("summary") or sample.get("summary", ""))},
            "help": {"text": str(entry.get("recommendation") or sample.get("recommendation", ""))},
            "defaultConfiguration": {"level": SARIF_LEVEL.get(severity, "note")},
            "properties": {
                "tags": ["security", *masvs, *cwe_tags],
                "security-severity": SECURITY_SEVERITY.get(severity, "1.0"),
                "profile": str(entry.get("profile") or sample.get("profile", "")),
            },
        })

    results: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        result: dict[str, Any] = {
            "ruleId": finding.get("rule_id", ""),
            "ruleIndex": rule_index[str(finding.get("rule_id", ""))],
            "level": SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f"{finding.get('title', '')}: {finding.get('summary', '')}".strip(": ")},
            "properties": {"severity": severity, "masvs": finding.get("masvs", []), "cwe": finding.get("cwe", [])},
        }
        decision = finding.get("suppression")
        if isinstance(decision, dict):
            # Recorded team decision: code scanning closes the alert and keeps the justification.
            result["suppressions"] = [{
                "kind": "inSource" if decision.get("kind") == "inline" else "external",
                "status": "accepted",
                "justification": str(decision.get("reason", ""))[:500],
            }]
        if finding.get("fingerprint"):
            # Stable across line shifts, so code scanning keeps alerts open instead of recreating them.
            result["partialFingerprints"] = {"aaosFinding/v1": finding["fingerprint"]}
        path = str(finding.get("source_path", ""))
        if path:
            location: dict[str, Any] = {"artifactLocation": {"uri": path}}
            line = str(finding.get("line", ""))
            if line.isdigit() and int(line) > 0:
                location["region"] = {"startLine": int(line)}
            result["locations"] = [{"physicalLocation": location}]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": tool_version,
                "informationUri": "https://mas.owasp.org/MASVS/",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "analysisScope": report.get("analysis_scope", ""),
                "analysisProfile": report.get("analysis_profile", "apk"),
            },
        }],
    }


def _md(value: Any) -> str:
    """Escape table-breaking characters in Markdown cells."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict[str, Any]) -> str:
    """Render a reviewer-friendly Markdown report (no source code or secret values)."""
    findings = report.get("findings", [])
    counts = report.get("severity_counts", {})
    is_source = report.get("report_type") == "source_directory"
    title = report.get("project_name") if is_source else report.get("package_name")
    lines = [
        f"# AAOS Security Auditor Report — {_md(title or 'Analysis')}",
        "",
        f"- **Package:** {_md(report.get('package_name', '—'))}",
        f"- **Profile:** {_md(report.get('profile_label') or report.get('analysis_profile') or 'APK')}",
        f"- **Target SDK:** {_md(report.get('target_sdk', '—'))}",
        f"- **Analyzed at:** {_md(report.get('analyzed_at', '—'))}",
        f"- **SHA-256:** `{report.get('source_sha256') or report.get('apk_sha256') or '—'}`",
        f"- **Heuristic level:** {_md(report.get('risk_level', '—'))}",
        "- **Severities:** " + ", ".join(f"{severity} {counts.get(severity, 0)}" for severity in SEVERITY_ORDER),
    ]
    policy = report.get("policy") or {}
    if policy.get("suppressed"):
        lines.append(f"- **Suppressed by policy:** {policy['suppressed']} (see below)")
    lines.append("")
    comparison = report.get("baseline_comparison")
    if comparison:
        lines += [
            "## Baseline comparison",
            "",
            f"New: **{comparison['new_count']}** · Resolved: **{comparison['resolved_count']}** · Unchanged: {comparison['unchanged_count']}",
            "",
        ]
    lines += ["## Findings", ""]
    if findings:
        lines += ["| Severity | Rule | Title | Evidence | MASVS | CWE |", "|---|---|---|---|---|---|"]
        for finding in findings:
            lines.append(
                f"| {_md(finding.get('severity', ''))} | `{_md(finding.get('rule_id', ''))}` | {_md(finding.get('title', ''))} "
                f"| {_md(finding.get('evidence', ''))} | {_md(', '.join(finding.get('masvs', [])))} | {_md(', '.join(finding.get('cwe', [])))} |"
            )
        lines += ["", "### Recommendations", ""]
        seen: set[str] = set()
        for finding in findings:
            rule_id = str(finding.get("rule_id", ""))
            if rule_id in seen:
                continue
            seen.add(rule_id)
            lines.append(f"- **{_md(rule_id)}** — {_md(finding.get('recommendation', ''))}")
    else:
        lines.append("No findings from the rules that ran. This does not prove the application is secure.")

    masvs = report.get("masvs_summary") or {}
    if masvs:
        lines += ["", "## OWASP MASVS coverage (guidance only)", "", "| Control | Findings | Description |", "|---|---|---|"]
        for control, count in masvs.items():
            lines.append(f"| {control} | {count} | {_md(MASVS_CONTROLS.get(control, ''))} |")

    suppressed = report.get("suppressed_findings") or []
    if suppressed or policy.get("expired") or policy.get("warnings"):
        lines += ["", "## Policy decisions", ""]
        if suppressed:
            lines += ["| Rule | Where | Kind | Reason | Expires |", "|---|---|---|---|---|"]
            for item in suppressed:
                decision = item.get("suppression") or {}
                lines.append(
                    f"| `{_md(item.get('rule_id', ''))}` | {_md(item.get('evidence', ''))} | {_md(decision.get('kind', ''))} "
                    f"| {_md(decision.get('reason', ''))} | {_md(decision.get('expires', '') or '—')} |"
                )
        for item in policy.get("expired", []):
            lines.append(f"- **Expired:** {_md(item.get('suppression', ''))} on {_md(item.get('expired_on', ''))}; the finding is active again.")
        for item in policy.get("unused", []):
            lines.append(f"- **Stale:** {_md(item)} matches nothing.")
        for warning in policy.get("warnings", []):
            lines.append(f"- **Warning:** {_md(warning)}")

    model = report.get("threat_model") or {}
    if model.get("threats"):
        lines += ["", "## Applicable threats (derived, not proven)", "", "| ID | STRIDE | Threat | Rules |", "|---|---|---|---|"]
        for threat in model["threats"]:
            lines.append(
                f"| {_md(threat['id'])} | {_md(threat['stride'])} | {_md(threat['title'])} | {_md(', '.join(threat['matched_rules'][:4]))} |"
            )
    if model.get("validation_phases"):
        lines += ["", "## Phased validation plan (manual, authorized)", ""]
        for phase in model["validation_phases"]:
            lines.append(f"**{_md(phase['name'])}**: {_md(phase['goal'])}")
            lines += [f"- [ ] {_md(check['id'])}: {_md(check['title'])}" for check in phase["checks"]]
            lines.append("")
    if model.get("not_assessed"):
        lines += ["## Not covered by this analysis", ""] + [f"- {_md(item)}" for item in model["not_assessed"]]

    lines += [
        "",
        "---",
        "",
        f"_Scope: {_md(report.get('analysis_scope', ''))} Heuristic classification, not a certification; validate manually._",
        "",
    ]
    return "\n".join(lines)
