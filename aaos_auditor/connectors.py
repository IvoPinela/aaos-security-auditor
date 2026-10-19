"""Normalize community static-analysis output into the auditor finding schema.

Supported inputs are detected from the document itself: Semgrep JSON, SARIF 2.1.x (Semgrep, CodeQL,
and others), Gitleaks JSON, OSV-Scanner JSON, Trivy JSON, Android Lint XML and MobSF JSON.

Imported findings keep only: tool rule ID, severity, CWE, confidence, and a path/line (or package
name and version for dependency findings). Messages, code excerpts, matched text and secret values are
deliberately discarded, because they can contain source code or credentials and may later reach an AI.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any
from xml.etree import ElementTree

MAX_CONNECTOR_FINDINGS = 2_000
MAX_LINES_PER_FILE = 10
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
CWE_PATTERN = re.compile(r"cwe[-_ /]?0*(\d{1,5})", re.IGNORECASE)
SAFE_ID = re.compile(r"[^A-Za-z0-9._:@/+-]")
# Directory names that mark the start of project-relative paths inside an absolute path.
PROJECT_MARKERS = ("src", "app", "res", "build.gradle", "build.gradle.kts", "AndroidManifest.xml")

SUPPORTED_FORMATS: tuple[dict[str, Any], ...] = (
    {"id": "semgrep", "label": "Semgrep JSON", "extensions": [".json"], "produces": "SAST",
     "how_to": "semgrep scan --config auto --json --output semgrep.json <directory>"},
    {"id": "sarif", "label": "SARIF 2.1.x", "extensions": [".sarif", ".json"], "produces": "SAST (Semgrep, CodeQL, others)",
     "how_to": "semgrep scan --config auto --sarif --output findings.sarif <directory>"},
    {"id": "gitleaks", "label": "Gitleaks JSON", "extensions": [".json"], "produces": "Secrets",
     "how_to": "gitleaks detect --source <directory> --report-format json --report-path gitleaks.json --redact"},
    {"id": "osv", "label": "OSV-Scanner JSON", "extensions": [".json"], "produces": "Vulnerable dependencies",
     "how_to": "osv-scanner scan --format json --output osv.json <directory>"},
    {"id": "trivy", "label": "Trivy JSON", "extensions": [".json"], "produces": "Dependencies, misconfiguration, secrets",
     "how_to": "trivy fs --format json --output trivy.json <directory>"},
    {"id": "lint", "label": "Android Lint XML", "extensions": [".xml"], "produces": "Lint (Security category only)",
     "how_to": "./gradlew lintRelease  (use app/build/reports/lint-results-release.xml)"},
    {"id": "mobsf", "label": "MobSF JSON", "extensions": [".json"], "produces": "MobSF static report",
     "how_to": "Export the MobSF JSON report after a static analysis in your lab"},
)


def _clean_text(value: Any, limit: int = 120) -> str:
    return CONTROL_CHARACTERS.sub("", str(value or ""))[:limit]


def _safe_id(value: Any, limit: int = 120) -> str:
    """Rule/package identifiers go into IDs and prompts, so keep only a conservative character set."""
    return SAFE_ID.sub("", CONTROL_CHARACTERS.sub("", str(value or "")))[:limit]


def _relativize(path: str) -> str | None:
    """Drop the machine-specific prefix of an absolute path, keeping the project-relative tail."""
    parts = [part for part in PurePosixPath(re.sub(r"^[A-Za-z]:", "", path)).parts if part not in {"/", ""}]
    for index, part in enumerate(parts):
        if part in PROJECT_MARKERS and index > 0:
            # Keep the module directory in front of src/ when present (app/src/main/...).
            start = index - 1 if part == "src" else index
            return "/".join(parts[start:])
        if part in PROJECT_MARKERS:
            return "/".join(parts[index:])
    return None


def _clean_path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = CONTROL_CHARACTERS.sub("", value.replace("\\", "/"))[:300]
    if normalized.startswith("file://"):
        normalized = normalized[7:]
    path = PurePosixPath(normalized)
    if ".." in path.parts:
        return "[external path omitted]"
    if path.is_absolute() or re.match(r"^[A-Za-z]:", normalized) or ":" in normalized:
        return _relativize(normalized) or "[external path omitted]"
    return normalized.removeprefix("./")


def _severity(value: Any) -> str:
    normalized = str(value or "info").upper()
    if normalized == "CRITICAL":
        return "critical"
    if normalized in {"ERROR", "HIGH", "FATAL"}:
        return "high"
    if normalized in {"WARNING", "WARN", "MEDIUM", "MODERATE"}:
        return "medium"
    if normalized == "LOW":
        return "low"
    return "info"


def _severity_from_score(value: Any) -> str | None:
    """Map a 0-10 score (GitHub security-severity / CVSS base score) to our severity scale."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _cwes(*values: Any) -> list[str]:
    found: list[str] = []
    stack: list[Any] = list(values)
    while stack and len(found) < 5:
        value = stack.pop(0)
        if isinstance(value, (list, tuple)):
            stack = list(value) + stack
        elif isinstance(value, int) and not isinstance(value, bool):
            candidate = f"CWE-{value}"
            if candidate not in found:
                found.append(candidate)
        elif isinstance(value, str):
            for number in CWE_PATTERN.findall(value[:400]):
                candidate = f"CWE-{int(number)}"
                if candidate not in found:
                    found.append(candidate)
    return found


def _line(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int) and value > 0:
        return str(value)[:12]
    if isinstance(value, str) and value.isdigit():
        return value[:12]
    return ""


def _confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    mapping = {"very-high": "high", "high": "high", "medium": "medium", "low": "low", "very-low": "low"}
    return mapping.get(normalized, "")


def _external_finding(
    rule_id: Any,
    level: Any,
    path: Any,
    line: Any,
    connector: str,
    *,
    severity: str | None = None,
    cwe: list[str] | None = None,
    confidence: str = "",
    evidence: str = "",
    title: str = "",
    summary: str = "",
    recommendation: str = "",
) -> dict[str, Any]:
    safe_rule = _safe_id(rule_id or "external-rule")
    safe_path = _clean_path(path)
    safe_line = _line(line)
    location = f"{safe_path}:{safe_line}" if safe_path and safe_line else safe_path
    return {
        "rule_id": f"{_safe_id(connector, 40).upper()}-{safe_rule}",
        "title": title or f"External finding: {safe_rule}",
        "severity": severity or _severity(level),
        "summary": summary or f"The {connector} connector reported this rule. See the original report for details; the message and source code were not imported.",
        "recommendation": recommendation or "Manually validate the match, context and false-positive status before prioritizing or fixing.",
        "evidence": evidence or location or "External report",
        "source_path": safe_path,
        "line": safe_line,
        "profile": f"External: {connector}",
        "cwe": cwe or [],
        "confidence": confidence,
        "source_tool": _safe_id(connector, 40),
    }


def _expect_dict(value: Any, message: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


# --- SARIF -------------------------------------------------------------------

def _parse_sarif(document: dict[str, Any], stats: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    if not str(document.get("version", "")).startswith("2.1"):
        raise ValueError("The connector supports SARIF 2.1.x.")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError("The SARIF report does not contain valid runs.")

    findings: list[dict[str, Any]] = []
    tools: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        connector = _clean_text(tool.get("name", "SARIF"), 40) if isinstance(tool, dict) else "SARIF"
        if connector and connector not in tools:
            tools.append(connector)
        raw_rules = tool.get("rules", []) if isinstance(tool, dict) else []
        rules = [rule for rule in raw_rules if isinstance(rule, dict)] if isinstance(raw_rules, list) else []
        rules_by_id = {str(rule.get("id")): rule for rule in rules if rule.get("id")}

        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("A SARIF block contains results in an invalid format.")
        for result in results:
            if len(findings) >= MAX_CONNECTOR_FINDINGS:
                stats["truncated"] = True
                break
            if not isinstance(result, dict):
                continue
            suppressions = result.get("suppressions")
            if isinstance(suppressions, list) and suppressions:
                stats["skipped_suppressed"] += 1
                continue

            locations = result.get("locations", [])
            if locations is not None and not isinstance(locations, list):
                raise ValueError("A SARIF result contains locations in an invalid format.")
            first_location = locations[0] if locations else {}
            if not isinstance(first_location, dict):
                raise ValueError("A SARIF result contains an invalid location.")
            location = first_location.get("physicalLocation", {})
            if location is None:
                location = {}
            if not isinstance(location, dict):
                raise ValueError("A SARIF result contains an invalid physicalLocation.")
            artifact = location.get("artifactLocation", {})
            region = location.get("region", {})
            if artifact is not None and not isinstance(artifact, dict):
                raise ValueError("A SARIF result contains an invalid artifactLocation.")
            if region is not None and not isinstance(region, dict):
                raise ValueError("A SARIF result contains an invalid region.")

            rule_index = result.get("ruleIndex")
            indexed_rule = rules[rule_index] if isinstance(rule_index, int) and 0 <= rule_index < len(rules) else {}
            rule_id = result.get("ruleId") or indexed_rule.get("id") or (str(rule_index) if rule_index is not None else "external-rule")
            rule = rules_by_id.get(str(rule_id)) or indexed_rule
            rule_props = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}
            result_props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
            default_level = (rule.get("defaultConfiguration") or {}).get("level") if isinstance(rule.get("defaultConfiguration"), dict) else None

            score = result_props.get("security-severity") or rule_props.get("security-severity")
            severity = _severity_from_score(score) or _severity(result.get("level") or default_level or "warning")
            tags = rule_props.get("tags") if isinstance(rule_props.get("tags"), list) else []
            findings.append(_external_finding(
                rule_id, None,
                (artifact or {}).get("uri", ""), (region or {}).get("startLine", ""),
                connector or "SARIF",
                severity=severity,
                cwe=_cwes(tags, rule_props.get("cwe"), result_props.get("cwe")),
                confidence=_confidence(rule_props.get("precision") or result_props.get("confidence")),
            ))
    return findings, tools


# --- Semgrep -----------------------------------------------------------------

def _parse_semgrep(document: dict[str, Any], stats: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in document["results"]:
        if len(findings) >= MAX_CONNECTOR_FINDINGS:
            stats["truncated"] = True
            break
        if not isinstance(result, dict):
            continue
        extra = result.get("extra", {}) if isinstance(result.get("extra"), dict) else {}
        if extra.get("is_ignored"):
            stats["skipped_suppressed"] += 1
            continue
        start = result.get("start", {}) if isinstance(result.get("start"), dict) else {}
        metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
        findings.append(_external_finding(
            result.get("check_id"), extra.get("severity", "warning"),
            result.get("path", ""), start.get("line", ""), "Semgrep",
            cwe=_cwes(metadata.get("cwe")),
            confidence=_confidence(metadata.get("confidence")),
        ))
    return findings


# --- Gitleaks ----------------------------------------------------------------

def _parse_gitleaks(document: list[Any], stats: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for entry in document:
        if len(findings) >= MAX_CONNECTOR_FINDINGS:
            stats["truncated"] = True
            break
        if not isinstance(entry, dict):
            continue
        rule = _safe_id(entry.get("RuleID") or entry.get("ruleID") or "secret")
        findings.append(_external_finding(
            rule, None, entry.get("File") or entry.get("file", ""), entry.get("StartLine") or entry.get("startLine", ""), "Gitleaks",
            severity="high", cwe=["CWE-798"], confidence="medium",
            title=f"Secret detected by Gitleaks ({rule})",
            summary="Gitleaks flagged a possible secret at this location. The value and excerpt were not imported.",
            recommendation="Confirm without copying the value; if real, revoke/rotate the credential and remove it from Git history.",
        ))
    return findings


# --- OSV-Scanner / Trivy (dependencies) ---------------------------------------

def _dependency_finding(
    connector: str, advisory_id: Any, package: Any, version: Any, path: Any, severity: str,
    *, aliases: list[str], fixed: str = "", cwe: list[str] | None = None,
) -> dict[str, Any]:
    name = _safe_id(package, 120) or "pacote"
    ver = _safe_id(version, 40)
    alias_text = f" Related identifiers: {', '.join(aliases[:5])}." if aliases else ""
    fix_text = f" Fixed version indicated: {fixed}." if fixed else ""
    return _external_finding(
        advisory_id, None, path, "", connector,
        severity=severity, cwe=cwe, confidence="high",
        evidence=f"{name}@{ver}" if ver else name,
        title=f"Vulnerable dependency: {name}{'@' + ver if ver else ''}",
        summary=f"{connector} associates this version with a security advisory.{alias_text}{fix_text} The library's presence does not prove the vulnerable code is reachable.",
        recommendation="Update to a fixed version and confirm in the code whether the vulnerable functionality is used; record a documented exception if it is not.",
    )


def _parse_osv(document: dict[str, Any], stats: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in document["results"]:
        if not isinstance(result, dict):
            continue
        source = result.get("source", {}) if isinstance(result.get("source"), dict) else {}
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            continue
        for entry in packages:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package", {}) if isinstance(entry.get("package"), dict) else {}
            vulnerabilities = entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if len(findings) >= MAX_CONNECTOR_FINDINGS:
                    stats["truncated"] = True
                    return findings
                if not isinstance(vulnerability, dict):
                    continue
                database = vulnerability.get("database_specific", {}) if isinstance(vulnerability.get("database_specific"), dict) else {}
                raw_severity = database.get("severity")
                ecosystem = vulnerability.get("ecosystem_specific")
                if not raw_severity and isinstance(ecosystem, dict):
                    raw_severity = ecosystem.get("severity")
                # Advisories without a severity string stay "medium" rather than guessing from a CVSS vector.
                severity = _severity(raw_severity) if raw_severity else "medium"
                aliases = [_safe_id(alias, 40) for alias in vulnerability.get("aliases", []) if isinstance(alias, str)][:5]
                findings.append(_dependency_finding(
                    "OSV-Scanner", vulnerability.get("id"), package.get("name"), package.get("version"), source.get("path", ""),
                    severity, aliases=aliases, cwe=_cwes(database.get("cwe_ids")) or ["CWE-1104"],
                ))
    return findings


def _parse_trivy(document: dict[str, Any], stats: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in document.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "")
        for vulnerability in result.get("Vulnerabilities") or []:
            if len(findings) >= MAX_CONNECTOR_FINDINGS:
                stats["truncated"] = True
                return findings
            if not isinstance(vulnerability, dict):
                continue
            findings.append(_dependency_finding(
                "Trivy", vulnerability.get("VulnerabilityID"), vulnerability.get("PkgName"),
                vulnerability.get("InstalledVersion"), target, _severity(vulnerability.get("Severity")),
                aliases=[], fixed=_safe_id(vulnerability.get("FixedVersion"), 60),
                cwe=_cwes(vulnerability.get("CweIDs")) or ["CWE-1104"],
            ))
        for misconfiguration in result.get("Misconfigurations") or []:
            if len(findings) >= MAX_CONNECTOR_FINDINGS:
                stats["truncated"] = True
                return findings
            if not isinstance(misconfiguration, dict):
                continue
            cause = misconfiguration.get("CauseMetadata") if isinstance(misconfiguration.get("CauseMetadata"), dict) else {}
            findings.append(_external_finding(
                misconfiguration.get("ID") or misconfiguration.get("AVDID"), misconfiguration.get("Severity"),
                target, cause.get("StartLine", ""), "Trivy",
            ))
        for secret in result.get("Secrets") or []:
            if len(findings) >= MAX_CONNECTOR_FINDINGS:
                stats["truncated"] = True
                return findings
            if not isinstance(secret, dict):
                continue
            findings.append(_external_finding(
                secret.get("RuleID"), None, target, secret.get("StartLine", ""), "Trivy",
                severity=_severity(secret.get("Severity")) if secret.get("Severity") else "high", cwe=["CWE-798"],
                title="Secret detected by Trivy",
                summary="Trivy flagged a possible secret. The value and excerpt were not imported.",
                recommendation="Confirm without copying the value; if real, revoke/rotate the credential and remove it from Git history.",
            ))
    return findings


# --- Android Lint ------------------------------------------------------------

def _parse_lint(data: bytes, stats: dict[str, Any]) -> list[dict[str, Any]]:
    head = data[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data[:65536].upper():
        raise ValueError("The Lint XML contains DOCTYPE/ENTITY and was refused for security reasons.")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise ValueError("The Android Lint report is not valid XML.") from exc
    if root.tag != "issues":
        raise ValueError("Unsupported XML format. Use the Android Lint XML report.")

    issues = list(root.iter("issue"))
    has_categories = any(issue.get("category") for issue in issues)
    findings: list[dict[str, Any]] = []
    for issue in issues:
        if has_categories and "security" not in (issue.get("category") or "").lower():
            stats["skipped_noise"] += 1
            continue
        issue_id = issue.get("id") or "lint-issue"
        severity = _severity(issue.get("severity"))
        for location in issue.iter("location"):
            if len(findings) >= MAX_CONNECTOR_FINDINGS:
                stats["truncated"] = True
                return findings
            findings.append(_external_finding(
                issue_id, None, location.get("file", ""), location.get("line", ""), "Lint", severity=severity,
            ))
            break  # first location is the primary one; secondary locations are related context
    return findings


# --- MobSF -------------------------------------------------------------------

def _mobsf_code_findings(section: Any, stats: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    if isinstance(section, dict) and isinstance(section.get("findings"), dict):
        section = section["findings"]
    if not isinstance(section, dict):
        return
    for rule_key, entry in section.items():
        if not isinstance(entry, dict):
            continue
        metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
        raw_severity = str(metadata.get("severity", "warning")).lower()
        if raw_severity in {"good", "secure"}:
            stats["skipped_noise"] += 1
            continue
        severity = _severity(raw_severity)
        cwe = _cwes(metadata.get("cwe"))
        files = entry.get("files")
        if not isinstance(files, dict) or not files:
            files = {"": ""}
        for path, lines in files.items():
            line_values = [part.strip() for part in str(lines).split(",") if part.strip().isdigit()][:MAX_LINES_PER_FILE] or [""]
            for line in line_values:
                if len(findings) >= MAX_CONNECTOR_FINDINGS:
                    stats["truncated"] = True
                    return
                findings.append(_external_finding(rule_key, None, path, line, "MobSF", severity=severity, cwe=cwe))


def _parse_mobsf(document: dict[str, Any], stats: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for section_name in ("code_analysis", "android_api"):
        _mobsf_code_findings(document.get(section_name), stats, findings)

    manifest = document.get("manifest_analysis")
    manifest_findings: Any = manifest.get("manifest_findings") if isinstance(manifest, dict) else manifest
    if isinstance(manifest_findings, list):
        for entry in manifest_findings:
            if len(findings) >= MAX_CONNECTOR_FINDINGS:
                stats["truncated"] = True
                break
            if not isinstance(entry, dict):
                continue
            raw_severity = str(entry.get("severity", "warning")).lower()
            if raw_severity in {"good", "secure"}:
                stats["skipped_noise"] += 1
                continue
            findings.append(_external_finding(
                entry.get("rule") or entry.get("title"), None, "AndroidManifest.xml", "", "MobSF",
                severity=_severity(raw_severity), evidence=f"AndroidManifest.xml: {_safe_id(entry.get('name'), 80)}".rstrip(": "),
            ))
    return findings


# --- Entry point -------------------------------------------------------------

def detect_format(document: Any, filename: str) -> str:
    """Identify the report format from its structure, not just its extension."""
    if isinstance(document, list):
        if document and all(isinstance(item, dict) for item in document[:5]) and any("RuleID" in item or "ruleID" in item for item in document[:5]):
            return "gitleaks"
        raise ValueError("Unsupported format. Unknown JSON list.")
    if not isinstance(document, dict):
        raise ValueError("The external report has an unknown format.")
    if "runs" in document and "version" in document or filename.lower().endswith(".sarif"):
        return "sarif"
    if "Results" in document and ("ArtifactName" in document or "SchemaVersion" in document):
        return "trivy"
    if "code_analysis" in document or "manifest_analysis" in document or ("package_name" in document and "app_name" in document):
        return "mobsf"
    results = document.get("results")
    if isinstance(results, list):
        sample = next((item for item in results if isinstance(item, dict)), None)
        if sample is not None and "packages" in sample:
            return "osv"
        return "semgrep"
    raise ValueError("Unsupported format. See the accepted formats at /api/connectors.")


def import_static_report(data: bytes, filename: str) -> dict[str, Any]:
    """Import an external scanner report without importing messages, snippets or secret values."""
    stats: dict[str, Any] = {"skipped_suppressed": 0, "skipped_noise": 0, "truncated": False}
    if data.lstrip()[:1] == b"<":
        findings = _parse_lint(data, stats)
        return _result("Android Lint", "lint", ["Android Lint"], findings, stats)

    try:
        document: Any = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("The external report is not valid JSON/SARIF/XML.") from exc

    detected = detect_format(document, filename)
    tools: list[str] = []
    if detected == "sarif":
        findings, tools = _parse_sarif(document, stats)
        return _result("SARIF", detected, tools, findings, stats)
    if detected == "semgrep":
        return _result("Semgrep", detected, ["Semgrep"], _parse_semgrep(document, stats), stats)
    if detected == "gitleaks":
        return _result("Gitleaks", detected, ["Gitleaks"], _parse_gitleaks(document, stats), stats)
    if detected == "osv":
        return _result("OSV-Scanner", detected, ["OSV-Scanner"], _parse_osv(document, stats), stats)
    if detected == "trivy":
        return _result("Trivy", detected, ["Trivy"], _parse_trivy(document, stats), stats)
    return _result("MobSF", detected, ["MobSF"], _parse_mobsf(document, stats), stats)


def _result(connector: str, format_id: str, tools: list[str], findings: list[dict[str, Any]], stats: dict[str, Any]) -> dict[str, Any]:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for finding in findings:
        unique[(finding["rule_id"], finding["source_path"], finding["line"], finding["evidence"])] = finding
    kept = list(unique.values())[:MAX_CONNECTOR_FINDINGS]
    return {
        "connector": connector,
        "format": format_id,
        "tools": tools,
        "findings": kept,
        "stats": {
            "parsed": len(findings),
            "imported": len(kept),
            "duplicates_removed": len(findings) - len(kept),
            "skipped_suppressed": stats["skipped_suppressed"],
            "skipped_noise": stats["skipped_noise"],
            "truncated": bool(stats["truncated"]),
        },
    }


# --- Merge into a report ------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def merge_imported_findings(report: dict[str, Any], imported: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge external findings into a report and recompute counts, risk level and MASVS summary."""
    from aaos_auditor.masvs import enrich_findings, masvs_summary

    existing = {(item.get("rule_id"), item.get("evidence")): item for item in report.get("findings", [])}
    for finding in enrich_findings(imported):
        existing[(finding.get("rule_id"), finding.get("evidence"))] = finding
    findings = sorted(
        existing.values(),
        key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity")), 9), str(item.get("rule_id")), str(item.get("source_path", "")), str(item.get("line", ""))),
    )
    counts = {severity: sum(item.get("severity") == severity for item in findings) for severity in SEVERITY_ORDER}
    report["findings"] = findings
    report["severity_counts"] = counts
    report["risk_level"] = "elevated" if counts["critical"] or counts["high"] else "review" if counts["medium"] else "informational"
    report["masvs_summary"] = masvs_summary(findings)
    return report
