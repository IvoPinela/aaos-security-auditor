"""Single listing of every deterministic rule the auditor can emit, for docs, SARIF and the UI."""

from __future__ import annotations

from typing import Any

from aaos_auditor.directory_scanner import RULES
from aaos_auditor.platform_scanner import PLATFORM_RULES
from aaos_auditor.masvs import cwe_for_rule, masvs_for_rule

# Rules emitted by manifest/APK/Gradle logic rather than the regex table in directory_scanner.RULES.
STRUCTURAL_RULES: tuple[dict[str, str], ...] = (
    {"id": "ANDROID-DEBUGGABLE", "severity": "high", "title": "Application/manifest allows debugging", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "ANDROID-TEST-ONLY", "severity": "medium", "title": "Manifest marked as testOnly", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "ANDROID-SHARED-USER-ID", "severity": "medium", "title": "android:sharedUserId declared", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "ANDROID-CLEARTEXT", "severity": "high", "title": "Manifest permits cleartext traffic", "profile": "Network security", "scope": "apk,source"},
    {"id": "ANDROID-BACKUP-ENABLED", "severity": "medium", "title": "Application backups permitted", "profile": "Data storage", "scope": "apk,source"},
    {"id": "ANDROID-EXPORTED-IMPLICIT", "severity": "medium", "title": "Component with intent-filter and no explicit exported", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "ANDROID-EXPORTED-BUILD-ERROR", "severity": "high", "title": "Possible build error: exported required", "profile": "Build and dependencies", "scope": "apk,source"},
    {"id": "ANDROID-EXPORTED-UNGUARDED", "severity": "medium", "title": "Component exported without permission", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "ANDROID-OLD-TARGET-SDK", "severity": "medium", "title": "Target SDK below API 31", "profile": "Build and dependencies", "scope": "apk,source"},
    {"id": "ANDROID-COMPILE-SDK-BELOW-TARGET", "severity": "high", "title": "compileSdk lower than targetSdk", "profile": "Build and dependencies", "scope": "source"},
    {"id": "ANDROID-MANIFEST-XML", "severity": "high", "title": "Manifest XML could not be parsed", "profile": "Manifest and AAOS", "scope": "source"},
    {"id": "ANDROID-BUILD-CONFIG-MISSING", "severity": "info", "title": "Gradle configuration not found", "profile": "Build and dependencies", "scope": "source"},
    {"id": "ANDROID-PERM-REQUEST_INSTALL_PACKAGES", "severity": "high", "title": "Package installation requested", "profile": "Permissions", "scope": "apk"},
    {"id": "ANDROID-PERM-MANAGE_EXTERNAL_STORAGE", "severity": "high", "title": "Broad storage access requested", "profile": "Permissions", "scope": "apk"},
    {"id": "ANDROID-PERM-SYSTEM_ALERT_WINDOW", "severity": "medium", "title": "Screen overlay requested", "profile": "Permissions", "scope": "apk"},
    {"id": "ANDROID-PERM-READ_SMS", "severity": "medium", "title": "SMS reading requested", "profile": "Permissions", "scope": "apk"},
    {"id": "ANDROID-PERM-RECORD_AUDIO", "severity": "info", "title": "Microphone access requested", "profile": "Permissions", "scope": "apk"},
    {"id": "ANDROID-PROVIDER-GRANT-URI", "severity": "medium", "title": "Provider exported with grantUriPermissions", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "AAOS-DATA-EGRESS-REVIEW", "severity": "low", "title": "Vehicle/location data with network access", "profile": "AAOS vehicle APIs", "scope": "apk,source:aaos"},
    {"id": "ANDROID-DEPENDENCY-DYNAMIC-VERSION", "severity": "low", "title": "Dependency with a dynamic version", "profile": "Build and dependencies", "scope": "source"},
    {"id": "AAOS-CAR-APP-HOST-VALIDATION", "severity": "info", "title": "Car App service exported: validate the host", "profile": "Manifest and AAOS", "scope": "apk,source:aaos"},
    {"id": "AAOS-MEDIA-BROWSER-CALLER-VALIDATION", "severity": "info", "title": "Media browser service exported: validate the caller", "profile": "Manifest and AAOS", "scope": "apk,source:aaos"},
    {"id": "ANDROID-DEEPLINK-UNVERIFIED", "severity": "low", "title": "Web deep link without App Links verification", "profile": "Manifest and AAOS", "scope": "apk,source"},
    {"id": "AAOS-FEATURE-UNCONFIRMED", "severity": "info", "title": "AAOS compatibility not confirmed", "profile": "Manifest and AAOS", "scope": "apk,source:aaos"},
    {"id": "AAOS-PRIVILEGED-CAR-PERMISSION", "severity": "medium", "title": "Sensitive vehicle permissions requested", "profile": "AAOS vehicle APIs", "scope": "apk,source:aaos"},
    {"id": "AAOS-VEHICLE-API-REVIEW", "severity": "info", "title": "Android Automotive APIs found", "profile": "AAOS vehicle APIs", "scope": "source:aaos"},
    {"id": "AAOS-CAR-APP-LIBRARY", "severity": "info", "title": "AndroidX Car App Library found", "profile": "AAOS and car app compatibility", "scope": "source"},
    {"id": "AAOS-MANIFEST-MISSING", "severity": "medium", "title": "AndroidManifest.xml not found", "profile": "Manifest and AAOS", "scope": "source"},
)


STRUCTURAL_RULES = STRUCTURAL_RULES + PLATFORM_RULES


def rule_catalog() -> list[dict[str, Any]]:
    """Return every rule once, sorted by ID, with severity, profile, scope and MASVS controls."""
    catalog: dict[str, dict[str, Any]] = {}
    for rule in RULES:
        catalog[rule["id"]] = {
            "id": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "summary": rule["summary"],
            "recommendation": rule["recommendation"],
            "profile": rule["profile"],
            "scope": "source",
        }
    for rule in STRUCTURAL_RULES:
        catalog.setdefault(rule["id"], {**rule, "summary": "", "recommendation": ""})
    for entry in catalog.values():
        entry["masvs"] = masvs_for_rule(entry["id"])
        entry["cwe"] = cwe_for_rule(entry["id"])
    return [catalog[rule_id] for rule_id in sorted(catalog)]


def known_rule_ids() -> set[str]:
    return {entry["id"] for entry in rule_catalog()}
