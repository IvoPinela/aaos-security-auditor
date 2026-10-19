"""Derive an attack-surface summary, STRIDE-style threats and phased validation from a report.

Everything here is computed from static findings and inventories. It organizes what a reviewer should
look at next; it does not execute tests, probe devices, or prove that a threat is exploitable.

The AAOS chain modelled below (app -> CarService -> Vehicle HAL -> vehicle network) follows Google's
vehicle system isolation design, where non-system apps reach the Vehicle HAL only through CarService
permissions and sensitive control is reserved for system apps.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

# Each threat lists rule-ID patterns that, when present, make it "applicable" to this report.
THREATS: tuple[dict[str, Any], ...] = (
    {
        "id": "T-IPC", "stride": "Spoofing / Elevation of privilege", "title": "Unauthorized caller uses an exposed component",
        "asset": "Functionality and data behind activities, services, receivers, providers and deep links",
        "rules": ("ANDROID-EXPORTED-*", "ANDROID-PROVIDER-GRANT-URI", "ANDROID-PENDINGINTENT-MUTABLE", "ANDROID-DYNAMIC-RECEIVER", "ANDROID-SHARED-USER-ID"),
        "validation": "Isolated emulator: enumerate exposed components and confirm the intended callers, permissions and input validation using benign data.",
    },
    {
        "id": "T-NET", "stride": "Information disclosure / Tampering", "title": "Traffic intercepted or tampered with",
        "asset": "Credentials, telemetry and backend responses",
        "rules": ("ANDROID-CLEARTEXT", "AAOS-CLEARTEXT", "ANDROID-NSC-*", "ANDROID-TRUST-ALL-CERTS", "ANDROID-WEBVIEW-SSL-PROCEED", "ANDROID-HTTP-URL"),
        "validation": "Against your own test server with an invalid certificate, confirm that the app refuses the connection in all builds.",
    },
    {
        "id": "T-DATA", "stride": "Information disclosure", "title": "Local data readable by another app, a backup or a user",
        "asset": "Tokens, profiles, navigation history and personal data",
        "rules": ("ANDROID-BACKUP-ENABLED", "ANDROID-WORLD-READABLE", "ANDROID-EXTERNAL-STORAGE", "ANDROID-LOG-SENSITIVE", "ANDROID-PREFS-SENSITIVE", "ANDROID-FILEPROVIDER-ROOT"),
        "validation": "Emulator with synthetic accounts: inspect storage, logs and backup content for credentials.",
    },
    {
        "id": "T-SECRETS", "stride": "Information disclosure", "title": "Embedded credentials recoverable from the package",
        "asset": "API keys, tokens and private keys",
        "rules": ("ANDROID-SECRET-LITERAL", "ANDROID-KNOWN-SECRET-FORMAT", "GITLEAKS-*", "TRIVY-*SECRET*"),
        "validation": "With the system owner, confirm whether the credential is real without copying it, and rotate it if so.",
    },
    {
        "id": "T-WEBVIEW", "stride": "Tampering / Elevation of privilege", "title": "Untrusted web content controls the app",
        "asset": "Native bridges, local files and the user session",
        "rules": ("ANDROID-WEBVIEW-*",),
        "validation": "In a test build, open deep links with benign URIs from unexpected hosts and confirm the allow-list of origins.",
    },
    {
        "id": "T-CRYPTO", "stride": "Information disclosure / Tampering", "title": "Weak or predictable cryptographic protection",
        "asset": "Encrypted data, tokens and signatures",
        "rules": ("ANDROID-WEAK-*", "ANDROID-STATIC-IV", "ANDROID-INSECURE-RANDOM"),
        "validation": "Identify what is protected and where the keys are; plan a migration to AES-GCM with the Android Keystore.",
    },
    {
        "id": "T-CODE", "stride": "Elevation of privilege", "title": "External input reaches SQL, commands or dynamic code",
        "asset": "Local database, app process and code integrity",
        "rules": ("ANDROID-SQL-CONCAT", "ANDROID-RUNTIME-EXEC", "ANDROID-DYNAMIC-CODE-LOADING"),
        "validation": "Follow the data flow to its source; confirm with benign malformed inputs in a test build.",
    },
    {
        "id": "T-VEHICLE", "stride": "Tampering / Safety", "title": "Abuse of vehicle APIs from a compromised app",
        "asset": "Vehicle properties (climate, windows, energy) and detailed telemetry",
        "chain": "HMI -> app -> CarService (permissions) -> Vehicle HAL -> vehicle network",
        "rules": ("AAOS-PRIVILEGED-CAR-PERMISSION", "AAOS-VEHICLE-API-REVIEW"),
        "validation": "AAOS emulator or isolated bench: confirm granted permissions and protection level. Never on a road vehicle, CAN or ECU.",
    },
    {
        "id": "T-PRIVACY", "stride": "Information disclosure (privacy)", "title": "Location and vehicle data allow inferring routes",
        "asset": "Position, speed, energy and vehicle identification",
        "rules": ("AAOS-DATA-EGRESS-REVIEW",),
        "validation": "Map which data leaves the vehicle, where it goes and at what granularity; confirm consent and retention.",
    },
    {
        "id": "T-RELEASE", "stride": "Tampering / Repudiation", "title": "Development or badly signed build reaches distribution",
        "asset": "App integrity and updates",
        "rules": ("ANDROID-DEBUGGABLE", "ANDROID-TEST-ONLY", "ANDROID-DEBUG-SIGNING", "ANDROID-RELEASE-NOT-MINIFIED"),
        "validation": "Confirm on the final release artifact (APK/AAB) and the signing chain.",
    },
    {
        "id": "T-SUPPLY", "stride": "Tampering / Elevation of privilege", "title": "Dependency with a known vulnerability",
        "asset": "Third-party code inside the app process",
        "rules": ("OSV-SCANNER-*", "TRIVY-CVE-*", "TRIVY-GHSA-*", "TRIVY-GO-*", "ANDROID-GRADLE-INSECURE-REPO", "ANDROID-DEPENDENCY-DYNAMIC-VERSION"),
        "validation": "Confirm whether the vulnerable functionality is reachable and update; record documented exceptions.",
    },
)

PHASES: tuple[tuple[str, str, str], ...] = (
    ("1-scope", "Scope and authorization", "Owner, version, test environment and prohibited systems documented."),
    ("2-static", "Static confirmation", "Each finding verified in the code and in the release variant."),
    ("3-ipc", "IPC surface and inputs", "Exposed components, deep links, providers and input validation reviewed."),
    ("4-network", "Network and TLS", "Effective network policy and certificate validation confirmed in the lab."),
    ("5-data", "Data, secrets and cryptography", "Storage, backups, secrets and cryptography use reviewed."),
    ("6-aaos", "AAOS vehicle and privacy", "android.car permissions and vehicle data flows justified."),
    ("7-supply", "Supply chain", "Dependencies and SDKs compared against security advisories."),
)
CHECK_PHASE = {
    "PT-SCOPE": "1-scope",
    "PT-DEBUG": "2-static", "PT-PLATFORM": "2-static",
    "PT-INPUTS": "3-ipc", "PT-EXPORTED": "3-ipc", "PT-EXPORTED-DEFAULT": "3-ipc", "PT-DEEPLINKS": "3-ipc",
    "PT-PROVIDER": "3-ipc", "PT-WEBVIEW-URL": "3-ipc", "PT-DYNAMIC-CODE": "3-ipc", "PT-SQL": "3-ipc",
    "PT-NETWORK": "4-network", "PT-NSC-TRUST": "4-network", "PT-TLS": "4-network", "PT-TLS-WEBVIEW": "4-network",
    "PT-DATA": "5-data", "PT-BACKUP": "5-data", "PT-FILEPROVIDER": "5-data", "PT-CRYPTO": "5-data", "PT-SECRETS": "5-data",
    "PT-AAOS-API": "6-aaos", "PT-AAOS-PERMS": "6-aaos", "PT-PRIVACY-EGRESS": "6-aaos",
    "PT-DEPENDENCIES": "7-supply",
}

NOT_ASSESSED = (
    "Final (merged) manifest per variant and flavor",
    "Backend logic and authorization",
    "Permission protection levels on the OEM's AAOS build",
    "Runtime behavior (reachability, initialization order, granted permissions)",
    "Native libraries and obfuscated code",
)


def _matches(rule_id: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(rule_id, pattern) for pattern in patterns)


def _exported_count(components: list[dict[str, Any]]) -> int:
    return sum(component.get("exported") in {"true", "inferred_true"} for component in components)


def build_threat_model(report: dict[str, Any]) -> dict[str, Any]:
    """Return surfaces, applicable threats, phased validation and what the scan did not cover."""
    findings = [finding for finding in report.get("findings", []) if isinstance(finding, dict)]
    components = [component for component in report.get("components", []) if isinstance(component, dict)]
    permissions = {str(permission) for permission in report.get("permissions", [])}
    rule_ids = {str(finding.get("rule_id", "")) for finding in findings}

    car_permissions = sorted(permission for permission in permissions if permission.startswith("android.car.permission."))
    surfaces = [
        {"id": "ipc", "name": "IPC and deep links", "present": bool(components or report.get("deep_links")),
         "detail": f"{_exported_count(components)} exported component(s) of {len(components)}; {len(report.get('deep_links', []))} browsable deep link(s)"},
        {"id": "network", "name": "Network", "present": "android.permission.INTERNET" in permissions or any(_matches(rule, ("*CLEARTEXT*", "ANDROID-NSC-*", "ANDROID-HTTP-URL")) for rule in rule_ids),
         "detail": "INTERNET permission or a network policy with findings"},
        {"id": "webview", "name": "WebView", "present": any(_matches(rule, ("ANDROID-WEBVIEW-*",)) for rule in rule_ids),
         "detail": "WebView use with settings to review"},
        {"id": "storage", "name": "Local storage", "present": any(_matches(rule, ("ANDROID-BACKUP-*", "ANDROID-*STORAGE*", "ANDROID-WORLD-*", "ANDROID-PREFS-*", "ANDROID-FILEPROVIDER-*")) for rule in rule_ids),
         "detail": "Backups, external storage or preferences holding sensitive data"},
        {"id": "vehicle", "name": "Vehicle APIs (AAOS)", "present": bool(car_permissions or report.get("aaos_api_references") or report.get("car_app_library_references")),
         "detail": f"{len(car_permissions)} android.car permission(s); {len(report.get('aaos_api_references', []))} vehicle API reference(s)"},
        {"id": "sensors", "name": "Location and sensors", "present": bool(permissions & {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.RECORD_AUDIO", "android.permission.CAMERA"}),
         "detail": "Location, microphone or camera requested in the manifest"},
        {"id": "supply", "name": "Dependencies", "present": bool(report.get("dependencies")) or any(_matches(rule, ("OSV-SCANNER-*", "TRIVY-*", "ANDROID-GRADLE-*", "ANDROID-DEPENDENCY-*")) for rule in rule_ids),
         "detail": f"{len(report.get('dependencies', []))} declared dependencies; advisories only when OSV-Scanner or Trivy results are imported"},
    ]

    threats: list[dict[str, Any]] = []
    for threat in THREATS:
        matched = sorted(rule for rule in rule_ids if _matches(rule, threat["rules"]))
        if not matched:
            continue
        entry = {key: threat[key] for key in ("id", "stride", "title", "asset", "validation") if key in threat}
        if "chain" in threat:
            entry["chain"] = threat["chain"]
        entry["matched_rules"] = matched
        entry["finding_count"] = sum(1 for finding in findings if str(finding.get("rule_id", "")) in matched)
        threats.append(entry)

    plan_checks = [check for check in (report.get("pentest_plan") or {}).get("checks", []) if isinstance(check, dict)]
    phases: list[dict[str, Any]] = []
    for phase_id, name, goal in PHASES:
        checks = [
            {"id": check["id"], "title": check.get("title", ""), "status": "not_started"}
            for check in plan_checks if CHECK_PHASE.get(str(check.get("id")), "2-static") == phase_id
        ]
        if checks:
            phases.append({"id": phase_id, "name": name, "goal": goal, "checks": checks})

    not_assessed = list(NOT_ASSESSED)
    if not any(surface["id"] == "supply" and surface["present"] for surface in surfaces):
        not_assessed.insert(0, "Dependencies and CVEs (import OSV-Scanner or Trivy to cover)")
    return {
        "mode": "static_derivation",
        "notice": "Derived from static findings; it organizes the review and does not prove that any threat is exploitable.",
        "surfaces": surfaces,
        "threats": threats,
        "validation_phases": phases,
        "not_assessed": not_assessed,
    }


def with_threat_model(report: dict[str, Any]) -> dict[str, Any]:
    """Return the report with `pentest_plan` and `threat_model` present, computing them when missing.

    Exporters call this so a raw analysis result renders the same as one produced by the API or CLI.
    """
    if report.get("threat_model"):
        return report
    from app.pentest_plan import build_pentest_plan

    enriched = {**report}
    findings = [finding for finding in enriched.get("findings", []) if isinstance(finding, dict)]
    enriched.setdefault("pentest_plan", build_pentest_plan(findings, enriched.get("deep_links", [])))
    enriched["threat_model"] = build_threat_model(enriched)
    return enriched
