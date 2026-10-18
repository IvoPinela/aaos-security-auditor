"""Conservative, offline-first static checks for Android APK manifests."""

from __future__ import annotations

import os
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from typing import Any

from androguard.core.apk import APK

from app.directory_scanner import (
    data_egress_finding,
    data_egress_signals,
    privileged_car_permission_finding,
    privileged_car_permissions,
)
from app.masvs import enrich_findings, masvs_summary

ANDROID_NS = "http://schemas.android.com/apk/res/android"
AUTOMOTIVE_FEATURE = "android.hardware.type.automotive"
MAX_APK_ENTRIES = 20_000
MAX_APK_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ENTRY_COMPRESSION_RATIO = 1_000


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    summary: str
    recommendation: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _android_attr(element: Any, name: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{name}")


def _tag_name(element: Any) -> str:
    return str(element.tag).rsplit("}", 1)[-1]


def analyze_apk(data: bytes) -> dict[str, Any]:
    """Inspect an APK locally; the uploaded bytes are never persisted by this module."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            archive_names = [entry.filename for entry in entries]
            if len(archive_names) != len(set(archive_names)):
                raise ValueError("The APK contains duplicate, ambiguous ZIP entries.")
            if "AndroidManifest.xml" not in archive_names:
                raise ValueError("The file does not contain AndroidManifest.xml.")
            if len(entries) > MAX_APK_ENTRIES:
                raise ValueError("The APK contains too many files for safe analysis.")
            if sum(item.file_size for item in entries) > MAX_APK_UNCOMPRESSED_BYTES:
                raise ValueError("The uncompressed content exceeds the analysis limit.")
            for entry in entries:
                if entry.filename == "AndroidManifest.xml":
                    if entry.flag_bits & 0x1:
                        raise ValueError("AndroidManifest.xml cannot be encrypted inside the APK.")
                    if entry.file_size > MAX_MANIFEST_BYTES:
                        raise ValueError("AndroidManifest.xml exceeds the 8 MB limit.")
                if entry.file_size > 1_000_000 and entry.compress_size == 0:
                    raise ValueError("The APK contains an invalid compressed file.")
                if entry.file_size > 1_000_000 and entry.compress_size > 0 and entry.file_size / entry.compress_size > MAX_ENTRY_COMPRESSION_RATIO:
                    raise ValueError("The APK contains an abnormally high compression ratio.")
            native_libraries = sorted(
                name for name in archive_names
                if name.startswith("lib/") and name.endswith(".so") and len(name.split("/")) == 3
            )
    except zipfile.BadZipFile as exc:
        raise ValueError("The file is not a valid APK/ZIP.") from exc

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="aaos-audit-", suffix=".apk", delete=False) as temp:
            temp.write(data)
            temp_path = temp.name

        apk = APK(temp_path)
        manifest = apk.get_android_manifest_xml()
        if manifest is None:
            raise ValueError("Could not parse the Android manifest.")

        permissions = sorted(set(apk.get_permissions() or []))
        package_name = apk.get_package() or "Unknown"
        target_sdk = apk.get_target_sdk_version()
        min_sdk = apk.get_min_sdk_version()
        findings: list[Finding] = []
        component_inventory: list[dict[str, str]] = []
        deep_links: list[dict[str, str]] = []

        application = next((node for node in manifest.iter() if _tag_name(node) == "application"), None)
        app_permission = _android_attr(application, "permission") if application is not None else None
        if application is not None:
            if (_android_attr(application, "debuggable") or "false").lower() == "true":
                findings.append(Finding(
                    "ANDROID-DEBUGGABLE", "Application built in debug mode", "high",
                    "The manifest allows debugging of the installed application.",
                    "Disable android:debuggable in distribution builds.",
                    'application android:debuggable="true"',
                ))
            if (_android_attr(application, "testOnly") or "false").lower() == "true":
                findings.append(Finding(
                    "ANDROID-TEST-ONLY", "APK marked as testOnly", "medium",
                    "android:testOnly=true indicates a test build that must not be distributed.",
                    "Confirm the analyzed artifact is not the distribution one, and produce the release without testOnly.",
                    'application android:testOnly="true"',
                ))
            if (_android_attr(application, "usesCleartextTraffic") or "false").lower() == "true":
                findings.append(Finding(
                    "ANDROID-CLEARTEXT", "Plain-text HTTP traffic permitted", "high",
                    "The application declares it may use network traffic without TLS.",
                    "Disable cleartext traffic and use a restrictive Network Security Configuration.",
                    'application android:usesCleartextTraffic="true"',
                ))
            if (_android_attr(application, "allowBackup") or "true").lower() == "true":
                backup_controls = [
                    name for name in ("fullBackupContent", "dataExtractionRules")
                    if _android_attr(application, name)
                ]
                control_note = (
                    f" Additional configuration was declared: {', '.join(backup_controls)}; validate the rules."
                    if backup_controls else " No data exclusion configuration was declared."
                )
                findings.append(Finding(
                    "ANDROID-BACKUP-ENABLED", "Application backups permitted", "medium",
                    "The manifest allows backups; this does not prove data exposure, but sensitive data may be included." + control_note,
                    "Review the backup content and exclude credentials, tokens and sensitive data; also confirm the behavior on the target devices.",
                    f"application android:allowBackup=\"{_android_attr(application, 'allowBackup') or 'true (valor predefinido)'}\"",
                ))

        for node in manifest.iter():
            component_type = _tag_name(node)
            if component_type not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                continue
            component_name = _android_attr(node, "name") or "(unnamed)"
            exported_value = _android_attr(node, "exported")
            component_permission = _android_attr(node, "permission") or app_permission
            intent_filters = [child for child in node if _tag_name(child) == "intent-filter"]
            has_intent_filter = bool(intent_filters)
            requires_explicit_export = component_type in {"activity", "activity-alias", "service", "receiver"}
            provider_default_exported = (
                component_type == "provider"
                and target_sdk is not None
                and target_sdk.isdigit()
                and int(target_sdk) < 17
            )
            implicit_exported = (has_intent_filter and requires_explicit_export) or provider_default_exported
            inferred_exported = exported_value.lower() == "true" if exported_value else implicit_exported
            component_inventory.append({
                "name": component_name,
                "type": component_type,
                "exported": exported_value if exported_value is not None else ("inferred_true" if inferred_exported else "unspecified"),
                "permission": component_permission or "",
            })
            if exported_value is None and has_intent_filter and requires_explicit_export:
                target_requires_explicit_export = bool(target_sdk and target_sdk.isdigit() and int(target_sdk) >= 31)
                findings.append(Finding(
                    "ANDROID-EXPORTED-BUILD-ERROR" if target_requires_explicit_export else "ANDROID-EXPORTED-IMPLICIT",
                    "Component without explicit exported: possible build error" if target_requires_explicit_export else "Component with intent-filter and no explicit exported",
                    "high" if target_requires_explicit_export else "medium",
                    f"Component {component_name} has an intent-filter and does not declare android:exported." + (
                        f" Target SDK {target_sdk} requires the explicit declaration to compile." if target_requires_explicit_export
                        else " Confirm the effective behavior for the target SDK and system concerned."
                    ),
                    "Declare android:exported explicitly, confirm the intended callers, and protect sensitive operations.",
                    f"{component_type} {component_name}: intent-filter presente; android:exported ausente",
                ))
            if (
                component_type == "provider"
                and (_android_attr(node, "grantUriPermissions") or "false").lower() == "true"
                and (exported_value or "").lower() == "true"
            ):
                findings.append(Finding(
                    "ANDROID-PROVIDER-GRANT-URI", "Provider exported with grantUriPermissions", "medium",
                    f"The provider {component_name} is exported and allows granting temporary access to URIs.",
                    "Make the provider non-exported, restrict it with <grant-uri-permission> to specific paths, and validate the URIs received.",
                    f"provider {component_name}: exported=true, grantUriPermissions=true",
                ))
            if inferred_exported and not component_permission:
                if exported_value is None:
                    implicit_reason = (
                        "has an intent-filter and may be implicitly exported"
                        if has_intent_filter
                        else "may be exported by the default value of this Android version"
                    )
                    findings.append(Finding(
                        "ANDROID-EXPORTED-UNGUARDED", "Component probably reachable without permission", "medium",
                        f"Component {component_name} {implicit_reason} and does not declare a permission; confirm the effective value on the target system.",
                        "Confirm the exposure on the target device; restrict the component or require an appropriate permission if the exposure is not intentional.",
                        f"{component_type} {component_name}: android:exported ausente e android:permission ausente",
                    ))
                else:
                    findings.append(Finding(
                        "ANDROID-EXPORTED-UNGUARDED", "Component exported without permission", "medium",
                        f"Component {component_name} is marked as exported without its own permission.",
                        "Confirm the exposure is intentional; restrict the component or require an appropriate permission.",
                        f"{component_type} {component_name}: android:exported=\"true\"",
                    ))

            for intent_filter in intent_filters:
                action_names = {
                    _android_attr(child, "name")
                    for child in intent_filter if _tag_name(child) == "action"
                }
                category_names = {
                    _android_attr(child, "name")
                    for child in intent_filter if _tag_name(child) == "category"
                }
                if "android.intent.action.VIEW" not in action_names or "android.intent.category.BROWSABLE" not in category_names:
                    continue
                for data_node in intent_filter:
                    if _tag_name(data_node) != "data":
                        continue
                    deep_links.append({
                        "component": component_name,
                        "scheme": _android_attr(data_node, "scheme") or "",
                        "host": _android_attr(data_node, "host") or "",
                        "path": _android_attr(data_node, "path") or _android_attr(data_node, "pathPrefix") or _android_attr(data_node, "pathPattern") or "",
                    })

        sensitive_permissions = {
            "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Package installation requested"),
            "android.permission.MANAGE_EXTERNAL_STORAGE": ("high", "Broad storage access requested"),
            "android.permission.SYSTEM_ALERT_WINDOW": ("medium", "Screen overlay requested"),
            "android.permission.READ_SMS": ("medium", "SMS reading requested"),
            "android.permission.RECORD_AUDIO": ("info", "Microphone access requested"),
        }
        for permission, (severity, title) in sensitive_permissions.items():
            if permission in permissions:
                findings.append(Finding(
                    f"ANDROID-PERM-{permission.rsplit('.', 1)[-1]}", title, severity,
                    f"The manifest requests {permission}; its presence does not prove the permission is misused.",
                    "Validate the functional need, request the permission only when needed, and explain it to the user.",
                    permission,
                ))

        car_permissions = privileged_car_permissions(permissions)
        if car_permissions:
            car_finding = privileged_car_permission_finding(car_permissions)
            findings.append(Finding(
                car_finding["rule_id"], car_finding["title"], car_finding["severity"],
                car_finding["summary"], car_finding["recommendation"], ", ".join(car_permissions[:8]),
            ))

        egress_signals = data_egress_signals(permissions)
        if egress_signals:
            egress = data_egress_finding(egress_signals)
            findings.append(Finding(
                egress["rule_id"], egress["title"], egress["severity"],
                egress["summary"], egress["recommendation"], ", ".join(egress_signals[:8]),
            ))

        if manifest is not None and _android_attr(manifest, "sharedUserId"):
            findings.append(Finding(
                "ANDROID-SHARED-USER-ID", "android:sharedUserId declared", "medium",
                "The app shares a UID with other apps signed with the same key; data and permissions become shared.",
                "Remove sharedUserId in new apps and use explicit IPC with permissions.",
                f'manifest android:sharedUserId="{_android_attr(manifest, "sharedUserId")}"',
            ))

        automotive_declared = any(
            _tag_name(node) == "uses-feature" and _android_attr(node, "name") == AUTOMOTIVE_FEATURE
            for node in manifest.iter()
        )
        if not automotive_declared:
            findings.append(Finding(
                "AAOS-FEATURE-UNCONFIRMED", "AAOS compatibility not confirmed", "info",
                "The automotive feature declaration was not found in the manifest; this does not prove incompatibility.",
                "Confirm the compatibility matrix and the Android Automotive OS-specific dependencies.",
                "uses-feature android.hardware.type.automotive not found",
            ))

        if target_sdk and target_sdk.isdigit() and int(target_sdk) < 31:
            findings.append(Finding(
                "ANDROID-OLD-TARGET-SDK", "Outdated target SDK", "medium",
                f"The application declares targetSdkVersion {target_sdk}; modern security behaviors may not be applied.",
                "Update the target SDK after validating compatibility and running regression tests.",
                f"targetSdkVersion={target_sdk}",
            ))

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda item: (order.get(item.severity, 9), item.rule_id))
        severity_counts = {severity: sum(item.severity == severity for item in findings) for severity in order}
        if severity_counts["critical"] or severity_counts["high"]:
            risk_level = "elevated"
        elif severity_counts["medium"]:
            risk_level = "review"
        else:
            risk_level = "informational"
        finding_dicts = enrich_findings([finding.as_dict() for finding in findings])
        return {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "apk_size_bytes": len(data),
            "apk_sha256": sha256(data).hexdigest(),
            "package_name": package_name,
            "version_name": apk.get_androidversion_name() or "Unknown",
            "version_code": apk.get_androidversion_code() or "Unknown",
            "min_sdk": min_sdk or "Unknown",
            "target_sdk": target_sdk or "Unknown",
            "automotive_feature_declared": automotive_declared,
            "permission_count": len(permissions),
            "components": component_inventory,
            "component_count": len(component_inventory),
            "exported_component_count": sum(component["exported"] in {"true", "inferred_true"} for component in component_inventory),
            "deep_links": deep_links,
            "native_libraries": native_libraries,
            "severity_counts": severity_counts,
            "risk_level": risk_level,
            "permissions": permissions,
            "masvs_summary": masvs_summary(finding_dicts),
            "findings": finding_dicts,
            "analysis_scope": "Static analysis of the APK/manifest. It does not run the application or test the vehicle.",
        }
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Failed to analyze the APK. Confirm the file is intact and try again.") from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
