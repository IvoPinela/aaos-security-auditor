"""Map auditor rule IDs to OWASP MASVS v2 controls for triage and reporting.

The mapping is guidance for reviewers; it is not a claim of MASVS compliance or a formal assessment.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

from app.fingerprints import assign_fingerprints

MASVS_VERSION = "2.1"

MASVS_CONTROLS: dict[str, str] = {
    "MASVS-STORAGE-1": "The app securely stores sensitive data.",
    "MASVS-STORAGE-2": "The app prevents leakage of sensitive data.",
    "MASVS-CRYPTO-1": "The app employs current strong cryptography and uses it according to industry best practices.",
    "MASVS-CRYPTO-2": "The app performs key management according to industry best practices.",
    "MASVS-AUTH-1": "The app uses secure authentication and authorization protocols.",
    "MASVS-NETWORK-1": "The app secures all network traffic according to the current best practices.",
    "MASVS-NETWORK-2": "The app performs identity pinning for all remote endpoints under the developer's control.",
    "MASVS-PLATFORM-1": "The app uses IPC mechanisms securely.",
    "MASVS-PLATFORM-2": "The app uses WebViews securely.",
    "MASVS-PLATFORM-3": "The app uses the user interface securely.",
    "MASVS-CODE-1": "The app requires an up-to-date platform version.",
    "MASVS-CODE-3": "The app only uses software components without known vulnerabilities.",
    "MASVS-CODE-4": "The app validates and sanitizes all untrusted inputs.",
    "MASVS-RESILIENCE-2": "The app implements anti-tampering mechanisms.",
    "MASVS-RESILIENCE-3": "The app implements anti-static analysis mechanisms.",
    "MASVS-RESILIENCE-4": "The app implements anti-dynamic analysis techniques.",
    "MASVS-PRIVACY-1": "The app minimizes access to sensitive data and resources.",
}

# Exact IDs first; glob patterns (fnmatch) cover rule families such as permission checks.
RULE_MASVS: dict[str, tuple[str, ...]] = {
    "ANDROID-DEBUGGABLE": ("MASVS-RESILIENCE-4", "MASVS-CODE-4"),
    "ANDROID-TEST-ONLY": ("MASVS-RESILIENCE-4",),
    "ANDROID-SHARED-USER-ID": ("MASVS-PLATFORM-1", "MASVS-STORAGE-1"),
    "ANDROID-CLEARTEXT": ("MASVS-NETWORK-1",),
    "AAOS-CLEARTEXT": ("MASVS-NETWORK-1",),
    "ANDROID-NSC-CLEARTEXT": ("MASVS-NETWORK-1",),
    "ANDROID-NSC-USER-CERTS": ("MASVS-NETWORK-1", "MASVS-NETWORK-2"),
    "ANDROID-TRUST-ALL-CERTS": ("MASVS-NETWORK-1",),
    "ANDROID-WEBVIEW-SSL-PROCEED": ("MASVS-NETWORK-1", "MASVS-PLATFORM-2"),
    "ANDROID-HTTP-URL": ("MASVS-NETWORK-1",),
    "ANDROID-BACKUP-ENABLED": ("MASVS-STORAGE-2",),
    "ANDROID-WORLD-READABLE": ("MASVS-STORAGE-1", "MASVS-STORAGE-2"),
    "ANDROID-EXTERNAL-STORAGE": ("MASVS-STORAGE-1", "MASVS-STORAGE-2"),
    "ANDROID-FILEPROVIDER-ROOT": ("MASVS-STORAGE-2", "MASVS-PLATFORM-1"),
    "ANDROID-SECRET-LITERAL": ("MASVS-STORAGE-1", "MASVS-CRYPTO-2"),
    "ANDROID-KNOWN-SECRET-FORMAT": ("MASVS-STORAGE-1", "MASVS-CRYPTO-2"),
    "ANDROID-LOG-SENSITIVE": ("MASVS-STORAGE-2",),
    "ANDROID-WEAK-CIPHER": ("MASVS-CRYPTO-1",),
    "ANDROID-WEAK-HASH": ("MASVS-CRYPTO-1",),
    "ANDROID-STATIC-IV": ("MASVS-CRYPTO-1", "MASVS-CRYPTO-2"),
    "ANDROID-SQL-CONCAT": ("MASVS-CODE-4",),
    "ANDROID-RUNTIME-EXEC": ("MASVS-CODE-4",),
    "ANDROID-DYNAMIC-CODE-LOADING": ("MASVS-CODE-4", "MASVS-RESILIENCE-2"),
    "ANDROID-WEBVIEW-*": ("MASVS-PLATFORM-2",),
    "ANDROID-EXPORTED-*": ("MASVS-PLATFORM-1",),
    "ANDROID-PENDINGINTENT-MUTABLE": ("MASVS-PLATFORM-1",),
    "ANDROID-DYNAMIC-RECEIVER": ("MASVS-PLATFORM-1",),
    "ANDROID-PERM-*": ("MASVS-PRIVACY-1",),
    "AAOS-PRIVILEGED-CAR-PERMISSION": ("MASVS-PRIVACY-1", "MASVS-PLATFORM-1"),
    "AAOS-VEHICLE-API-REVIEW": ("MASVS-PLATFORM-1", "MASVS-PRIVACY-1"),
    "ANDROID-OLD-TARGET-SDK": ("MASVS-CODE-1",),
    "ANDROID-COMPILE-SDK-BELOW-TARGET": ("MASVS-CODE-1",),
    "ANDROID-RELEASE-NOT-MINIFIED": ("MASVS-RESILIENCE-3",),
    "ANDROID-DEBUG-SIGNING": ("MASVS-RESILIENCE-2",),
    "ANDROID-WEBVIEW-LOADURL-UNTRUSTED": ("MASVS-PLATFORM-2", "MASVS-CODE-4"),
    "ANDROID-PREFS-SENSITIVE": ("MASVS-STORAGE-1",),
    "ANDROID-INSECURE-RANDOM": ("MASVS-CRYPTO-1",),
    "ANDROID-PROVIDER-GRANT-URI": ("MASVS-PLATFORM-1", "MASVS-STORAGE-2"),
    "AAOS-DATA-EGRESS-REVIEW": ("MASVS-PRIVACY-1", "MASVS-NETWORK-1"),
}

# CWE ids are attached only where the mapping is unambiguous; unknown rules map to no CWE.
RULE_CWE: dict[str, tuple[str, ...]] = {
    "ANDROID-DEBUGGABLE": ("CWE-489",),
    "ANDROID-TEST-ONLY": ("CWE-489",),
    "ANDROID-WEBVIEW-DEBUG": ("CWE-489",),
    "ANDROID-CLEARTEXT": ("CWE-319",),
    "AAOS-CLEARTEXT": ("CWE-319",),
    "ANDROID-NSC-CLEARTEXT": ("CWE-319",),
    "ANDROID-HTTP-URL": ("CWE-319",),
    "ANDROID-NSC-USER-CERTS": ("CWE-295",),
    "ANDROID-TRUST-ALL-CERTS": ("CWE-295",),
    "ANDROID-WEBVIEW-SSL-PROCEED": ("CWE-295",),
    "ANDROID-BACKUP-ENABLED": ("CWE-530",),
    "ANDROID-WORLD-READABLE": ("CWE-732",),
    "ANDROID-EXTERNAL-STORAGE": ("CWE-922",),
    "ANDROID-FILEPROVIDER-ROOT": ("CWE-200",),
    "ANDROID-WEBVIEW-FILE-ACCESS": ("CWE-200",),
    "ANDROID-WEBVIEW-UNIVERSAL-FILE": ("CWE-200",),
    "ANDROID-SECRET-LITERAL": ("CWE-798",),
    "ANDROID-KNOWN-SECRET-FORMAT": ("CWE-798",),
    "ANDROID-LOG-SENSITIVE": ("CWE-532",),
    "ANDROID-PREFS-SENSITIVE": ("CWE-312",),
    "ANDROID-WEAK-CIPHER": ("CWE-327",),
    "ANDROID-WEAK-HASH": ("CWE-328",),
    "ANDROID-STATIC-IV": ("CWE-329",),
    "ANDROID-INSECURE-RANDOM": ("CWE-330",),
    "ANDROID-SQL-CONCAT": ("CWE-89",),
    "ANDROID-RUNTIME-EXEC": ("CWE-78",),
    "ANDROID-DYNAMIC-CODE-LOADING": ("CWE-94",),
    "ANDROID-WEBVIEW-JS-BRIDGE": ("CWE-749",),
    "ANDROID-WEBVIEW-LOADURL-UNTRUSTED": ("CWE-939",),
    "ANDROID-EXPORTED-*": ("CWE-926",),
    "ANDROID-PROVIDER-GRANT-URI": ("CWE-926",),
    "ANDROID-PENDINGINTENT-MUTABLE": ("CWE-927",),
    "ANDROID-DYNAMIC-RECEIVER": ("CWE-927",),
}

# Used for findings imported from external scanners, which report CWE but not our rule IDs.
CWE_MASVS: dict[str, tuple[str, ...]] = {
    "CWE-319": ("MASVS-NETWORK-1",), "CWE-295": ("MASVS-NETWORK-1",), "CWE-297": ("MASVS-NETWORK-1",),
    "CWE-312": ("MASVS-STORAGE-1",), "CWE-313": ("MASVS-STORAGE-1",), "CWE-922": ("MASVS-STORAGE-1",),
    "CWE-532": ("MASVS-STORAGE-2",), "CWE-530": ("MASVS-STORAGE-2",), "CWE-732": ("MASVS-STORAGE-2",),
    "CWE-200": ("MASVS-STORAGE-2",), "CWE-798": ("MASVS-STORAGE-1", "MASVS-CRYPTO-2"),
    "CWE-321": ("MASVS-CRYPTO-2",), "CWE-326": ("MASVS-CRYPTO-1",), "CWE-327": ("MASVS-CRYPTO-1",),
    "CWE-328": ("MASVS-CRYPTO-1",), "CWE-329": ("MASVS-CRYPTO-1",), "CWE-330": ("MASVS-CRYPTO-1",),
    "CWE-89": ("MASVS-CODE-4",), "CWE-78": ("MASVS-CODE-4",), "CWE-94": ("MASVS-CODE-4",),
    "CWE-20": ("MASVS-CODE-4",), "CWE-22": ("MASVS-CODE-4",), "CWE-502": ("MASVS-CODE-4",),
    "CWE-926": ("MASVS-PLATFORM-1",), "CWE-927": ("MASVS-PLATFORM-1",), "CWE-925": ("MASVS-PLATFORM-1",),
    "CWE-939": ("MASVS-PLATFORM-2",), "CWE-749": ("MASVS-PLATFORM-2",), "CWE-79": ("MASVS-PLATFORM-2",),
    "CWE-489": ("MASVS-RESILIENCE-4",), "CWE-1104": ("MASVS-CODE-3",), "CWE-937": ("MASVS-CODE-3",),
    "CWE-1035": ("MASVS-CODE-3",),
}


def masvs_for_rule(rule_id: str) -> list[str]:
    """Return MASVS control IDs for a rule; unknown and external rules map to an empty list."""
    exact = RULE_MASVS.get(rule_id)
    if exact is not None:
        return list(exact)
    for pattern, controls in RULE_MASVS.items():
        if "*" in pattern and fnmatchcase(rule_id, pattern):
            return list(controls)
    return []


def cwe_for_rule(rule_id: str) -> list[str]:
    """Return CWE ids for a rule (exact match first, then glob families)."""
    exact = RULE_CWE.get(rule_id)
    if exact is not None:
        return list(exact)
    for pattern, cwes in RULE_CWE.items():
        if "*" in pattern and fnmatchcase(rule_id, pattern):
            return list(cwes)
    return []


def masvs_for_cwe(cwes: list[str]) -> list[str]:
    """Map CWE ids (from external scanners) to MASVS controls, preserving order without duplicates."""
    controls: list[str] = []
    for cwe in cwes:
        for control in CWE_MASVS.get(cwe.upper(), ()):
            if control not in controls:
                controls.append(control)
    return controls


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add `masvs` and `cwe` lists to each finding in place and return the same list.

    Our own rules use the rule tables; imported findings carry CWE from the source tool, so MASVS
    is derived from that when the rule ID is not one of ours.
    """
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        finding.setdefault("cwe", cwe_for_rule(rule_id))
        finding.setdefault("masvs", masvs_for_rule(rule_id) or masvs_for_cwe(list(finding.get("cwe") or [])))
    assign_fingerprints(findings)
    return findings


def masvs_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per MASVS control, sorted by control ID."""
    counts: dict[str, int] = {}
    for finding in findings:
        for control in finding.get("masvs") or masvs_for_rule(str(finding.get("rule_id", ""))):
            counts[control] = counts.get(control, 0) + 1
    return dict(sorted(counts.items()))
