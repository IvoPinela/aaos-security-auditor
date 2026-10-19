"""Offline static inspection for authorized Android/AAOS source directories."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any
from xml.etree import ElementTree

from app.car_permissions import (
    PREFIX as CAR_PERMISSION_PREFIX,
    SOURCE_NOTE as CAR_PERMISSION_SOURCE_NOTE,
    classify_car_permissions,
    is_system_only,
    is_third_party_grantable,
    protection_level,
)
from app.entry_points import FilterInfo, component_role, role_finding, unverified_link_finding, unverified_web_link_hosts
from app.masvs import enrich_findings, masvs_summary
from app.sbom import dependency_summary, parse_gradle_dependencies
from app.source_mask import BlockIndex, mask_comments

ANDROID_NS = "http://schemas.android.com/apk/res/android"
MAX_SOURCE_FILE_BYTES = 1_000_000
MAX_MATCHES_EXAMINED = 200
ALLOWED_SUFFIXES = {".xml", ".kt", ".java", ".gradle", ".kts", ".properties", ".pro", ".toml"}
IGNORED_PARTS = {".git", ".gradle", ".idea", ".venv", "venv", "build", "out", "target", "node_modules", "vendor", "generated"}

# These profiles are deterministic source checks, not proof that a project is secure or compatible.
RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "AAOS-CLEARTEXT",
        "pattern": re.compile(r"usesCleartextTraffic\s*=\s*[\"']true[\"']", re.IGNORECASE),
        "severity": "high",
        "title": "Cleartext traffic permitted",
        "summary": "The configuration allows traffic without TLS; this does not prove the app actually uses HTTP.",
        "recommendation": "Review the Network Security Configuration and restrict cleartext for release builds.",
        "profile": "Network security",
    },
    {
        "id": "ANDROID-WEBVIEW-JS",
        # Java setter and Kotlin property syntax (settings.javaScriptEnabled = true).
        "pattern": re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)|\.javaScriptEnabled\s*=\s*true\b"),
        "severity": "medium",
        "title": "JavaScript enabled in WebView",
        "summary": "JavaScript is enabled in a WebView; the risk depends on the origins and content loaded.",
        "recommendation": "Limit content to trusted origins, validate URLs, and avoid JavaScript bridges exposed to untrusted content.",
        "profile": "WebView",
    },
    {
        "id": "ANDROID-WEBVIEW-JS-BRIDGE",
        "pattern": re.compile(r"addJavascriptInterface\s*\("),
        "severity": "medium",
        "title": "Native JavaScript bridge found",
        "summary": "addJavascriptInterface exposes native methods to page JavaScript; the impact depends on the content loaded and the Android API level.",
        "recommendation": "Avoid the bridge for untrusted content, reduce exposed methods, and confirm origin authentication/validation.",
        "profile": "WebView",
    },
    {
        "id": "ANDROID-WEBVIEW-FILE-ACCESS",
        "pattern": re.compile(r"setAllowFileAccess(?:FromFileURLs)?\s*\(\s*true\s*\)|\.allowFileAccess(?:FromFileURLs)?\s*=\s*true\b"),
        "severity": "medium",
        "title": "File access enabled in WebView",
        "summary": "File access is enabled in a WebView; review local content and the origins loaded.",
        "recommendation": "Disable file access when not needed and do not combine local content with untrusted origins.",
        "profile": "WebView",
    },
    {
        "id": "ANDROID-WEBVIEW-DEBUG",
        "pattern": re.compile(r"WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)"),
        "skip_in_blocks": re.compile(r"(?i)\bBuildConfig\.DEBUG\b|\bisDebug(?:gable)?\b"),
        "severity": "medium",
        "title": "WebView debugging enabled",
        "summary": "WebView content debugging is explicitly enabled.",
        "recommendation": "Enable this option only in development builds and confirm it is disabled in release.",
        "profile": "WebView",
    },
    {
        "id": "ANDROID-TRUST-ALL-CERTS",
        "pattern": re.compile(
            r"checkServerTrusted\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{\s*\}"
            r"|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\s*\([^)]*ALLOW_ALL"
            r"|hostnameVerifier\s*\{[^}]{0,40}->\s*true\s*\}"
            r"|\bboolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}",
            re.IGNORECASE,
        ),
        "severity": "high",
        "title": "Possible TLS validation disabled",
        "summary": "A permissive trust manager / hostname verifier pattern was found and needs review.",
        "recommendation": "Remove permissive trust managers/verifiers and use standard TLS validation with hostname verification.",
        "profile": "Network security",
    },
    {
        "id": "ANDROID-PENDINGINTENT-MUTABLE",
        "pattern": re.compile(r"PendingIntent\.(?:getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\([^;\n]*\bFLAG_MUTABLE\b", re.DOTALL),
        "severity": "medium",
        "title": "Mutable PendingIntent found",
        "summary": "A PendingIntent uses FLAG_MUTABLE; mutability may be necessary, but it makes it more important to validate who can fill it in.",
        "recommendation": "Prefer FLAG_IMMUTABLE when functionally possible and restrict recipients/data when mutable is required.",
        "profile": "IPC and intents",
    },
    {
        "id": "ANDROID-DYNAMIC-RECEIVER",
        "pattern": re.compile(r"\bregisterReceiver\s*\((?![^;\n]*RECEIVER_NOT_EXPORTED)"),
        "severity": "info",
        "title": "Dynamic receiver registration to review",
        "summary": "registerReceiver was found; review whether the receiver is exported and which flag is used on the supported Android versions.",
        "recommendation": "Use RECEIVER_NOT_EXPORTED where appropriate, or document and protect the intentional exposure.",
        "profile": "IPC and intents",
    },
    {
        "id": "ANDROID-WORLD-READABLE",
        "pattern": re.compile(r"MODE_WORLD_(?:READABLE|WRITEABLE)|Context\.MODE_WORLD_(?:READABLE|WRITEABLE)"),
        "severity": "high",
        "title": "Legacy shared file mode found",
        "summary": "A legacy world-readable/world-writable mode was found in code or configuration.",
        "recommendation": "Remove global sharing modes and use private storage or sharing APIs with temporary permissions.",
        "profile": "Data storage",
    },
    {
        "id": "ANDROID-EXTERNAL-STORAGE",
        "pattern": re.compile(r"Environment\.getExternalStorage(?:Directory|PublicDirectory)\s*\("),
        "severity": "medium",
        "title": "Legacy external storage access found",
        "summary": "Legacy external storage APIs were found; confirm the data involved and scoped-storage requirements.",
        "recommendation": "Prefer scoped/private storage and avoid writing sensitive data to shared storage.",
        "profile": "Data storage",
    },
    {
        "id": "ANDROID-SECRET-LITERAL",
        "pattern": re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token)\b\s*(?::\s*[\w.?<>]+\s*)?[:=]\s*"
            r"[\"'](?!\$\{|\$[A-Za-z_]|@string/|\{\{)[^\"'\s]{12,}[\"']"
        ),
        "scan_comments": True,  # a commented-out credential is still in the repository
        "severity": "high",
        "title": "Possible hardcoded secret in code/configuration",
        "summary": "An assignment with a credential-like name and a long literal value was found; it may also be a placeholder or test data.",
        "recommendation": "Confirm the value without copying it into external reports; remove secrets from code and rotate exposed credentials.",
        "profile": "Secrets hygiene",
    },
    {
        "id": "ANDROID-LOG-SENSITIVE",
        # Bounded span: an unbounded [^\n]* is quadratic on long minified lines.
        "pattern": re.compile(
            r"\b(?:Log\.(?:v|d|i|w|e)|System\.out\.print(?:ln)?)\s*\([^\n]{0,300}?(?:password|token|secret|authorization|credential)s?(?![a-z])",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "title": "Possible sensitive data in logs",
        "summary": "A logging call contains an identifier associated with credentials or sensitive data.",
        "recommendation": "Review the value actually written, remove sensitive data from production logs, and protect diagnostics.",
        "profile": "Secrets hygiene",
    },
    {
        "id": "ANDROID-KNOWN-SECRET-FORMAT",
        # Private key headers and AWS access key IDs have distinctive formats with few false positives.
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b"),
        "scan_comments": True,
        "severity": "high",
        "title": "Known credential format found",
        "summary": "A private key header or an AWS-style key identifier was found; it may be test material, but it needs verification.",
        "recommendation": "Confirm without copying the value; remove the credential from the repository and Git history, and rotate it if real.",
        "profile": "Secrets hygiene",
    },
    {
        "id": "ANDROID-WEBVIEW-UNIVERSAL-FILE",
        "pattern": re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|\.allowUniversalAccessFromFileURLs\s*=\s*true\b"),
        "severity": "high",
        "title": "WebView allows universal access from file://",
        "summary": "file:// pages can read content from any origin; combined with untrusted content, this can expose local files.",
        "recommendation": "Disable this option; serve local content with WebViewAssetLoader and controlled https origins.",
        "profile": "WebView",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-WEBVIEW-SSL-PROCEED",
        "pattern": re.compile(r"onReceivedSslError\b[^}]{0,400}?\.proceed\s*\(\s*\)", re.DOTALL),
        "severity": "high",
        "title": "TLS error ignored in WebView",
        "summary": "An onReceivedSslError calls handler.proceed(); certificate errors may be silently accepted.",
        "recommendation": "Call handler.cancel() by default and fix the server certificate configuration instead of ignoring the error.",
        "profile": "Network security",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-NSC-CLEARTEXT",
        "pattern": re.compile(r"cleartextTrafficPermitted\s*=\s*[\"']true[\"']", re.IGNORECASE),
        "severity": "high",
        "title": "Network Security Config permits cleartext",
        "summary": "The Network Security Configuration permits traffic without TLS for a domain or globally; confirm the scope of the block.",
        "recommendation": "Restrict cleartext to development domains in a debug-only file and use HTTPS in release.",
        "profile": "Network security",
        "suffixes": {".xml"},
    },
    {
        "id": "ANDROID-NSC-USER-CERTS",
        "pattern": re.compile(r"<certificates\s+[^>]*src\s*=\s*[\"']user[\"']", re.IGNORECASE),
        "mask_blocks": re.compile(r"<debug-overrides\b.*?</debug-overrides>", re.DOTALL | re.IGNORECASE),
        "severity": "medium",
        "title": "Network Security Config trusts user CAs",
        "summary": "The configuration accepts user-installed certificates; this may be intentional in debug-overrides, but it widens trust in release.",
        "recommendation": "Keep user CAs only in <debug-overrides> and confirm the file used in the release build.",
        "profile": "Network security",
        "suffixes": {".xml"},
    },
    {
        "id": "ANDROID-FILEPROVIDER-ROOT",
        "pattern": re.compile(r"<root-path\b", re.IGNORECASE),
        "severity": "high",
        "title": "FileProvider exposes root-path",
        "summary": "A FileProvider declares root-path, which may allow sharing URIs for any file readable by the app.",
        "recommendation": "Replace with files-path/cache-path using specific subdirectories and share only concrete URIs with temporary permissions.",
        "profile": "Data storage",
        "suffixes": {".xml"},
    },
    {
        "id": "ANDROID-WEAK-CIPHER",
        "pattern": re.compile(r"Cipher\.getInstance\s*\(\s*\"(?!RSA/)(?:AES|DES|DESede|RC4|ARCFOUR|Blowfish|[^\"]*/ECB/[^\"]*|DES/[^\"]*|DESede/[^\"]*|RC4/[^\"]*)\""),
        "severity": "medium",
        "title": "Weak cipher algorithm or mode",
        "summary": "DES/3DES/RC4/Blowfish, ECB mode, or \"AES\" without a mode was found (which on many providers defaults to ECB).",
        "recommendation": "Use AES/GCM/NoPadding with a random IV per message and keys managed by the Android Keystore.",
        "profile": "Cryptography",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-WEAK-HASH",
        "pattern": re.compile(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|MD4|MD2|SHA-?1)\"", re.IGNORECASE),
        "severity": "low",
        "title": "Weak hash function",
        "summary": "MD5/SHA-1 are unsuitable for signatures, passwords or integrity against adversaries; they may be acceptable for non-cryptographic checksums.",
        "recommendation": "Use SHA-256+ for integrity and a KDF (PBKDF2/Argon2/scrypt) for passwords; document non-cryptographic uses.",
        "profile": "Cryptography",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-STATIC-IV",
        "pattern": re.compile(r"IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\s*\d*\s*\]|byteArrayOf\s*\(|ByteArray\s*\(\s*\d+\s*\)|\"[^\"]*\"\s*\.\s*(?:toByteArray|getBytes)\b)"),
        "severity": "medium",
        "title": "Fixed or literal IV in cipher",
        "summary": "An IvParameterSpec is built from a literal or zeroed value; reusing IVs compromises confidentiality in CBC/GCM.",
        "recommendation": "Generate a random IV with SecureRandom per operation (or let the Cipher generate it) and store it alongside the ciphertext.",
        "profile": "Cryptography",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-SQL-CONCAT",
        "pattern": re.compile(r"\.(?:rawQuery|execSQL)\s*\(\s*(?:\"[^\"\n]*\"\s*\+|\"[^\"\n]*\$\{?[A-Za-z_])"),
        "severity": "medium",
        "title": "SQL built by concatenation",
        "summary": "rawQuery/execSQL receives a concatenated or interpolated string; if the value comes from external input, SQL injection may be possible.",
        "recommendation": "Use bound arguments (selectionArgs / bindArgs) or Room with parameters, never input concatenation.",
        "profile": "Code quality and input",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-RUNTIME-EXEC",
        "pattern": re.compile(r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\("),
        "severity": "medium",
        "title": "System command execution",
        "summary": "The app runs native processes; the risk depends on whether the command or arguments can be influenced by external input.",
        "recommendation": "Avoid the shell; use equivalent Android APIs, fixed arguments and strict validation when execution is unavoidable.",
        "profile": "Code quality and input",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-DYNAMIC-CODE-LOADING",
        "pattern": re.compile(r"\b(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader)\s*\("),
        "severity": "medium",
        "title": "Dynamic code loading",
        "summary": "The app loads DEX code at runtime; if the code's origin is not verified, it can be replaced.",
        "recommendation": "Load only signed code from read-only private storage, or prefer Play Feature Delivery.",
        "profile": "Code quality and input",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-HTTP-URL",
        # Ignore XML namespaces, license headers, and emulator/loopback hosts that are expected in dev code.
        "pattern": re.compile(r"\"http://(?!(?:localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.android\.com|www\.w3\.org|www\.apache\.org|ns\.adobe\.com)\b)[A-Za-z0-9][^\"\s]{0,300}\""),
        "severity": "low",
        "title": "HTTP URL without TLS in code",
        "summary": "A literal http:// URL was found; it may be documentation, but if used at runtime the traffic is not encrypted.",
        "recommendation": "Use https:// and confirm the Network Security Configuration blocks cleartext in release.",
        "profile": "Network security",
        "suffixes": {".kt", ".java", ".properties"},
    },
    {
        "id": "ANDROID-WEBVIEW-LOADURL-UNTRUSTED",
        "pattern": re.compile(r"\bloadUrl\s*\([^)\n]{0,200}(?:getStringExtra|getQueryParameter|getDataString|intent\??\.data(?:String)?\b)"),
        "severity": "medium",
        "title": "WebView loads URL from intent or deep link",
        "summary": "loadUrl receives a value that appears to come from an intent/deep link; without scheme and host validation, another app can choose the loaded content.",
        "recommendation": "Validate the https scheme and an allow-list of hosts before loading; avoid combining this with JavaScript or native bridges.",
        "profile": "WebView",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-PREFS-SENSITIVE",
        "pattern": re.compile(r"\.putString\s*\(\s*\"[^\"\n]{0,60}(?:password|passwd|token|secret|pin_?code|credential)[^\"\n]{0,60}\"", re.IGNORECASE),
        "severity": "medium",
        "title": "Credential written to SharedPreferences",
        "summary": "A key named like a credential is written with putString; SharedPreferences is not encrypted by default and is included in backups and root access.",
        "recommendation": "Store tokens with EncryptedSharedPreferences/encrypted DataStore and keys in the Android Keystore; avoid storing passwords.",
        "profile": "Data storage",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "ANDROID-INSECURE-RANDOM",
        "pattern": re.compile(r"(?i)\b(?:token|nonce|salt|otp|session\w*|secret|key)\w*\s*=\s*[^;\n]{0,80}(?:\bRandom\s*\(|Math\.random\s*\()"),
        "severity": "low",
        "title": "Non-cryptographic random generator for sensitive value",
        "summary": "A value named like a token/nonce/salt/key is generated with Random or Math.random, which are predictable.",
        "recommendation": "Use java.security.SecureRandom for tokens, nonces, salts and keys.",
        "profile": "Cryptography",
        "suffixes": {".kt", ".java"},
    },
    {
        "id": "AAOS-CAR-APP-ALLOW-ALL-HOSTS",
        "pattern": re.compile(r"\bALLOW_ALL_HOSTS_VALIDATOR\b"),
        "skip_in_blocks": re.compile(r"(?i)\bBuildConfig\.DEBUG\b|\bisDebug(?:gable)?\b"),
        "severity": "high",
        "title": "Car App host validation disabled",
        "summary": "ALLOW_ALL_HOSTS_VALIDATOR accepts any app as the Car App host. The service is exported so the host can bind, so this removes the only access control and lets another app drive the car app session.",
        "recommendation": "Use HostValidator.Builder with an allow-list of trusted host package names and signatures; keep the allow-all validator for debug builds only.",
        "profile": "AAOS vehicle APIs",
        "suffixes": {".java", ".kt"},
    },
    {
        "id": "ANDROID-GRADLE-INSECURE-REPO",
        "pattern": re.compile(
            r"(?:\burl\s*(?:=\s*)?(?:uri\s*\(\s*)?|\bmaven\s*\(\s*)[\"']http://(?!(?:localhost|127\.0\.0\.1|10\.0\.2\.2)\b)"
            r"|[Aa]llowInsecureProtocol\s*=\s*true\b"
        ),
        "severity": "high",
        "title": "Dependency repository over plain HTTP",
        "summary": "A Gradle repository is declared with http:// or allows an insecure protocol; artifacts can be tampered with in transit, which puts attacker-controlled code into the build.",
        "recommendation": "Use https:// repositories, remove allowInsecureProtocol, and verify artifacts with Gradle dependency verification (checksums or signatures).",
        "profile": "Build and dependencies",
        "suffixes": {".gradle", ".kts"},
    },
    {
        "id": "ANDROID-RELEASE-NOT-MINIFIED",
        "pattern": re.compile(r"\b(?:isMinifyEnabled\s*=\s*false|minifyEnabled\s*(?:=\s*)?false)\b"),
        "skip_in_blocks": re.compile(r"(?i)\bdebug\b"),
        "severity": "low",
        "title": "Minification/obfuscation disabled",
        "summary": "A build type disables R8/ProGuard; in release this makes reverse engineering easier (confirm the block is release).",
        "recommendation": "Enable minification and resource shrinking in the release build type, with reviewed keep rules.",
        "profile": "Build and dependencies",
        "suffixes": {".gradle", ".kts"},
    },
    {
        "id": "ANDROID-DEBUG-SIGNING",
        "pattern": re.compile(r"signingConfig\s*(?:=\s*)?signingConfigs\s*\.\s*(?:getByName\s*\(\s*\"debug\"\s*\)|debug\b)"),
        "skip_in_blocks": re.compile(r"(?i)\bdebug\b"),
        "severity": "medium",
        "title": "Build signed with the debug key",
        "summary": "A build type explicitly uses the debug signingConfig; if it is the release one, the artifact is signed with a well-known public key.",
        "recommendation": "Use a release signingConfig with a protected key (kept outside the repository) and Play App Signing where applicable.",
        "profile": "Build and dependencies",
        "suffixes": {".gradle", ".kts"},
    },
)

# Manifest permissions that grant control or detailed telemetry of vehicle systems.
PRIVILEGED_CAR_PERMISSION = re.compile(
    r"^android\.car\.permission\.(?:CONTROL_[A-Z_]+|CAR_VENDOR_EXTENSION|CAR_ENGINE_DETAILED|CAR_DYNAMICS_STATE|"
    r"CAR_DIAGNOSTICS|CLEAR_CAR_DIAGNOSTICS|CAR_POWERTRAIN|ADJUST_RANGE_REMAINING|CAR_TIRES|CAR_MILEAGE|CAR_IDENTIFICATION|"
    r"VMS_PUBLISHER|VMS_SUBSCRIBER|CAR_POWER|CAR_EXTERIOR_ENVIRONMENT)$"
)


EGRESS_VEHICLE_DATA = re.compile(
    # Personal-data signals only. CAR_INFO, CAR_ENERGY_PORTS and CAR_EXTERIOR_ENVIRONMENT are normal-level
    # (vehicle model, charge port, outside conditions) and would only add noise.
    r"^android\.car\.permission\.(?:CAR_SPEED|CAR_ENERGY|CAR_MILEAGE|CAR_IDENTIFICATION|CAR_ENGINE_DETAILED|CAR_DYNAMICS_STATE)$"
)
LOCATION_PERMISSIONS = {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}


def data_egress_signals(permissions: list[str] | set[str]) -> list[str]:
    """Return vehicle/location data permissions that coexist with INTERNET (a privacy review signal).

    Research on in-vehicle apps shows that location plus speed or energy data sent over the network
    can reveal driving paths; the combination is worth a review, not proof of exfiltration.
    """
    granted = set(permissions)
    if "android.permission.INTERNET" not in granted:
        return []
    return sorted(
        permission for permission in granted
        if permission in LOCATION_PERMISSIONS
        or EGRESS_VEHICLE_DATA.match(permission)
        or PRIVILEGED_CAR_PERMISSION.match(permission)
        # Dangerous android.car permissions can be granted to third-party apps, so they are real data access.
        or (permission.startswith(CAR_PERMISSION_PREFIX) and protection_level(permission) == "dangerous")
    )


def data_egress_finding(signals: list[str], evidence_path: str = "") -> dict[str, str]:
    listed = ", ".join(signal.rsplit(".", 1)[-1] for signal in signals[:6])
    if len(signals) > 6:
        listed += f" (+{len(signals) - 6})"
    return {
        "rule_id": "AAOS-DATA-EGRESS-REVIEW",
        "title": "Vehicle/location data with network access",
        "severity": "low",
        "summary": f"The app requests INTERNET and also {listed}. This combination may allow inferring routes or driving habits if the data leaves the vehicle; the manifest does not prove that this happens.",
        "recommendation": "Document which data leaves the vehicle, for what purpose, legal basis and retention; minimize granularity and confirm user consent.",
        "evidence": evidence_path or "uses-permission INTERNET + vehicle/location data",
        "source_path": evidence_path,
        "line": "1" if evidence_path else "",
        "profile": "AAOS vehicle APIs",
    }


def privileged_car_permissions(permissions: list[str] | set[str]) -> list[str]:
    """Return requested android.car permissions that only platform-signed or privileged apps are granted.

    The AOSP protection-level table decides; permissions the table does not know (older releases,
    OEM additions) fall back to the conservative name list.
    """
    selected = []
    for permission in permissions:
        level = protection_level(permission) if permission.startswith(CAR_PERMISSION_PREFIX) else None
        if level is not None:
            if is_system_only(level):
                selected.append(permission)
        elif PRIVILEGED_CAR_PERMISSION.match(permission):
            selected.append(permission)
    return sorted(selected)


def privileged_car_permission_finding(permissions: list[str], evidence_path: str = "") -> dict[str, str]:
    """Build one finding summarizing privileged vehicle permissions for both APK and source scans."""
    def label(permission: str) -> str:
        return f"{permission.rsplit('.', 1)[-1]} [{protection_level(permission) or 'unverified'}]"

    listed = ", ".join(label(permission) for permission in permissions[:8])
    if len(permissions) > 8:
        listed += f" (+{len(permissions) - 8})"
    return {
        "rule_id": "AAOS-PRIVILEGED-CAR-PERMISSION",
        "title": "Sensitive vehicle permissions requested",
        "severity": "medium",
        "summary": (
            f"The manifest requests {len(permissions)} android.car permission(s) that only platform-signed or privileged apps are granted: {listed}. "
            "A normal third-party app is not granted them, so this matters when the app is, or will ship as, a system/OEM app. "
            f"Levels come from {CAR_PERMISSION_SOURCE_NOTE}."
        ),
        "recommendation": "Confirm whether the app ships as a privileged system app, the protection level on your target AAOS build, the OEM privapp-permissions allow-list, and that control operations validate the vehicle state.",
        "evidence": evidence_path or "uses-permission android.car.permission.*",
        "source_path": evidence_path,
        "line": "1" if evidence_path else "",
        "profile": "AAOS vehicle APIs",
    }

AAOS_API_PATTERN = re.compile(r"\b(?:android\.car(?:\.[A-Za-z_$][\w$]*)*|CarPropertyManager|Car\.createCar)\b")
CAR_APP_PATTERN = re.compile(r"\bandroidx\.car\.app(?:\.[A-Za-z_$][\w$]*)*")


def _finding(rule: dict[str, Any], path: str, line_number: int, line: str) -> dict[str, str]:
    # Evidence is intentionally limited to a path and line number to avoid exporting source secrets.
    return {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "summary": rule["summary"],
        "recommendation": rule["recommendation"],
        "evidence": f"{path}:{line_number}",
        "source_path": path,
        "line": str(line_number),
        "profile": rule["profile"],
        "_anchor": line,  # hashed into the fingerprint, then removed; never reported
    }


def _module_key(path: str) -> str:
    """Infer a Gradle module root from a source-manifest or build-file path."""
    parsed = PurePosixPath(path)
    if parsed.name == "AndroidManifest.xml" and "src" in parsed.parts:
        index = parsed.parts.index("src")
        return "/".join(parsed.parts[:index]) or "."
    return parsed.parent.as_posix() or "."


def _filter_infos(filters: list[Any]) -> list[FilterInfo]:
    """Describe <intent-filter> elements for the entry point checks."""
    infos = []
    for intent_filter in filters:
        data = intent_filter.findall("data")
        infos.append(FilterInfo(
            actions={element.get(f"{{{ANDROID_NS}}}name") or "" for element in intent_filter.findall("action")},
            categories={element.get(f"{{{ANDROID_NS}}}name") or "" for element in intent_filter.findall("category")},
            schemes={element.get(f"{{{ANDROID_NS}}}scheme") or "" for element in data},
            hosts={element.get(f"{{{ANDROID_NS}}}host") or "" for element in data} - {""},
            auto_verify=(intent_filter.get(f"{{{ANDROID_NS}}}autoVerify") or "").lower() == "true",
        ))
    return infos


def _inspect_manifest(path: str, source: str, *, include_aaos: bool) -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    metadata: dict[str, Any] = {
        "package_name": "Unknown",
        "target_sdk": "Unknown",
        "permissions": [],
        "allow_backup": None,
        "components": [],
        "deep_links": [],
    }
    try:
        root = ElementTree.fromstring(source)
    except ElementTree.ParseError:
        findings.append({
            "rule_id": "ANDROID-MANIFEST-XML",
            "title": "Manifest XML could not be parsed",
            "severity": "high",
            "summary": "The AndroidManifest.xml versioned in the project is not well-formed XML.",
            "recommendation": "Fix the XML and confirm the final merge of the variant manifests.",
            "evidence": path,
            "source_path": path,
            "line": "1",
            "profile": "Manifest and AAOS",
        })
        return findings, metadata

    metadata["package_name"] = root.get("package", "Unknown")
    if root.get(f"{{{ANDROID_NS}}}sharedUserId"):
        findings.append({
            "rule_id": "ANDROID-SHARED-USER-ID",
            "title": "android:sharedUserId declared",
            "severity": "medium",
            "summary": "The app shares a UID with other apps signed with the same key; data and permissions become shared. The attribute has been deprecated since API 29.",
            "recommendation": "Remove sharedUserId in new apps and use explicit IPC with permissions; plan the migration with sharedUserMaxSdkVersion if already published.",
            "evidence": f"{path}: manifest android:sharedUserId",
            "source_path": path,
            "line": "1",
            "profile": "Manifest and AAOS",
        })
    sdk = root.find("uses-sdk")
    if sdk is not None:
        metadata["target_sdk"] = sdk.get(f"{{{ANDROID_NS}}}targetSdkVersion", "Unknown")
    metadata["permissions"] = sorted({
        element.get(f"{{{ANDROID_NS}}}name", "")
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] in {"uses-permission", "uses-permission-sdk-23"}
        and element.get(f"{{{ANDROID_NS}}}name")
    })
    feature_declared = any(
        element.get(f"{{{ANDROID_NS}}}name") == "android.hardware.type.automotive"
        for element in root.findall("uses-feature")
    )
    metadata["automotive_feature_declared"] = feature_declared
    if include_aaos and not feature_declared:
        findings.append({
            "rule_id": "AAOS-FEATURE-UNCONFIRMED",
            "title": "AAOS compatibility not confirmed in manifest",
            "severity": "info",
            "summary": "The android.hardware.type.automotive declaration was not found; its absence does not prove incompatibility.",
            "recommendation": "Confirm distribution requirements and the AAOS device matrix; declare the feature when it is part of the app's contract.",
            "evidence": path,
            "source_path": path,
            "line": "1",
            "profile": "Manifest and AAOS",
        })

    application = root.find("application")
    component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
    components = [element for element in root.iter() if element.tag.rsplit("}", 1)[-1] in component_tags]
    for component in components:
        component_name = component.get(f"{{{ANDROID_NS}}}name", "(unnamed)")
        component_type = component.tag.rsplit("}", 1)[-1]
        filters = component.findall("intent-filter")
        exported = component.get(f"{{{ANDROID_NS}}}exported")
        inferred = exported is None and bool(filters) and component_type in {"activity", "activity-alias", "service", "receiver"}
        metadata["components"].append({
            "name": component_name,
            "type": component_type,
            "exported": exported if exported is not None else ("inferred_true" if inferred else "unspecified"),
            "permission": component.get(f"{{{ANDROID_NS}}}permission", ""),
            "role": component_role(_filter_infos(filters)) or "",
        })
        for intent_filter in filters:
            actions = {element.get(f"{{{ANDROID_NS}}}name") for element in intent_filter.findall("action")}
            categories = {element.get(f"{{{ANDROID_NS}}}name") for element in intent_filter.findall("category")}
            if "android.intent.action.VIEW" in actions and "android.intent.category.BROWSABLE" in categories:
                for data in intent_filter.findall("data"):
                    metadata["deep_links"].append({
                        "component": component_name,
                        "scheme": data.get(f"{{{ANDROID_NS}}}scheme", ""),
                        "host": data.get(f"{{{ANDROID_NS}}}host", ""),
                        "path": data.get(f"{{{ANDROID_NS}}}path") or data.get(f"{{{ANDROID_NS}}}pathPrefix") or data.get(f"{{{ANDROID_NS}}}pathPattern", ""),
                    })
    if application is not None:
        metadata["allow_backup"] = application.get(f"{{{ANDROID_NS}}}allowBackup")
        if application.get(f"{{{ANDROID_NS}}}debuggable", "false").lower() == "true":
            findings.append({
                "rule_id": "ANDROID-DEBUGGABLE",
                "title": "Manifest allows debugging",
                "severity": "high",
                "summary": "android:debuggable is set to true in the source manifest.",
                "recommendation": "Confirm the per-variant manifests and disable debug in distribution builds.",
                "evidence": path,
                "source_path": path,
                "line": "1",
                "profile": "Manifest and AAOS",
            })
        if application.get(f"{{{ANDROID_NS}}}testOnly", "false").lower() == "true":
            findings.append({
                "rule_id": "ANDROID-TEST-ONLY",
                "title": "Manifest marked as testOnly",
                "severity": "medium",
                "summary": "android:testOnly=true indicates a test build; it must not reach distribution and signals a development configuration.",
                "recommendation": "Confirm the attribute comes only from development builds and not from the main manifest.",
                "evidence": f"{path}: application android:testOnly",
                "source_path": path,
                "line": "1",
                "profile": "Manifest and AAOS",
            })
        if application.get(f"{{{ANDROID_NS}}}usesCleartextTraffic", "false").lower() == "true":
            findings.append({
                "rule_id": "ANDROID-CLEARTEXT",
                "title": "Manifest permits cleartext traffic",
                "severity": "high",
                "summary": "android:usesCleartextTraffic=true permits cleartext; it does not prove that an HTTP endpoint is used.",
                "recommendation": "Restrict cleartext and review networkSecurityConfig for the final manifests.",
                "evidence": path,
                "source_path": path,
                "line": "1",
                "profile": "Network security",
            })
        if application.get(f"{{{ANDROID_NS}}}allowBackup", "true").lower() == "true":
            backup_rules = application.get(f"{{{ANDROID_NS}}}fullBackupContent") or application.get(f"{{{ANDROID_NS}}}dataExtractionRules")
            findings.append({
                "rule_id": "ANDROID-BACKUP-ENABLED",
                "title": "Manifest allows backups",
                "severity": "medium",
                "summary": "The manifest allows data backup according to Android/device policies; this does not prove that secrets are included." + (" Backup rules were declared and need review." if backup_rules else " No backup rules configuration was declared."),
                "recommendation": "Review and test the backup rules per Android version; exclude credentials and sensitive data according to the threat model.",
                "evidence": f"{path}: application android:allowBackup",
                "source_path": path,
                "line": "1",
                "profile": "Data storage",
            })
        for component in components:
            component_name = component.get(f"{{{ANDROID_NS}}}name", "(unnamed)")
            component_type = component.tag.rsplit("}", 1)[-1]
            filters = component.findall("intent-filter")
            exported = component.get(f"{{{ANDROID_NS}}}exported")
            component_permission = component.get(f"{{{ANDROID_NS}}}permission") or application.get(f"{{{ANDROID_NS}}}permission", "")
            requires_explicit_export = component_type in {"activity", "activity-alias", "service", "receiver"}
            if filters and exported is None and requires_explicit_export:
                findings.append({
                    "rule_id": "ANDROID-EXPORTED-IMPLICIT",
                    "title": "Component with intent-filter and no explicit exported",
                    "severity": "medium",
                    "summary": f"{component_type} {component_name} has an intent-filter without android:exported; validate the target SDK and the merged manifest.",
                    "recommendation": "Declare android:exported explicitly and confirm callers/permissions in the variant's merged manifest.",
                    "evidence": f"{path}: component {component_name}",
                    "source_path": path,
                    "line": "1",
                    "profile": "Manifest and AAOS",
                })
            inferred_exported = exported.lower() == "true" if exported else bool(filters and requires_explicit_export)
            if (
                component_type == "provider"
                and component.get(f"{{{ANDROID_NS}}}grantUriPermissions", "false").lower() == "true"
                and (exported or "").lower() == "true"
            ):
                findings.append({
                    "rule_id": "ANDROID-PROVIDER-GRANT-URI",
                    "title": "Provider exported with grantUriPermissions",
                    "severity": "medium",
                    "summary": f"The provider {component_name} is exported and allows granting temporary access to URIs; without path-permission or validation, it may expose more data than intended.",
                    "recommendation": "Make the provider non-exported, restrict it with <grant-uri-permission> to specific paths, and validate the URIs received.",
                    "evidence": f"{path}: provider {component_name}",
                    "source_path": path,
                    "line": "1",
                    "profile": "Manifest and AAOS",
                })
            filter_infos = _filter_infos(filters)
            role = component_role(filter_infos)
            if role and include_aaos and (exported or "").lower() != "false":
                review_point = role_finding(role, component_type, component_name)
                if review_point:
                    findings.append({**review_point, "evidence": f"{path}: component {component_name}", "source_path": path, "line": "1", "profile": "Manifest and AAOS"})
            unverified_hosts = unverified_web_link_hosts(filter_infos)
            if unverified_hosts:
                findings.append({
                    **unverified_link_finding(component_type, component_name, unverified_hosts),
                    "evidence": f"{path}: component {component_name}", "source_path": path, "line": "1", "profile": "Manifest and AAOS",
                })
            if inferred_exported and not component_permission and not role:
                findings.append({
                    "rule_id": "ANDROID-EXPORTED-UNGUARDED",
                    "title": "Component potentially exported without effective permission",
                    "severity": "medium",
                    "summary": f"{component_type} {component_name} may be reachable by other apps; no permission was found on the component or on the application.",
                    "recommendation": "Confirm exported and effective protection in the merged manifest; restrict exposure or require an appropriate permission when needed.",
                    "evidence": f"{path}: component {component_name}",
                    "source_path": path,
                    "line": "1",
                    "profile": "Manifest and AAOS",
                })
    return findings, metadata


def analyze_source_directory(files: dict[str, bytes], profile: str = "aaos", project_name: str | None = None) -> dict[str, Any]:
    """Inspect a bounded, in-memory source snapshot; never extract or execute project files."""
    if profile not in {"android_app", "aaos"}:
        raise ValueError("Invalid profile. Choose android_app or aaos.")
    if not files:
        raise ValueError("Select a directory with Android code or configuration files.")
    if len(files) > 500:
        raise ValueError("The directory exceeds the 500-file analysis limit.")

    normalized: dict[str, bytes] = {}
    for raw_path, data in files.items():
        path = raw_path.replace("\\", "/")
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or ":" in path or any(part in {"", ".", ".."} for part in parsed.parts):
            raise ValueError("The directory contains an invalid file path.")
        if any(part.lower() in IGNORED_PARTS for part in parsed.parts):
            continue
        if parsed.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        if len(data) > MAX_SOURCE_FILE_BYTES:
            raise ValueError(f"The file {path} exceeds 1 MB.")
        normalized[path] = data
    if not normalized:
        raise ValueError("No supported Android files found (.kt, .java, .xml, .gradle, .kts, .properties or .pro).")

    findings: list[dict[str, str]] = []
    aaos_api_references: set[tuple[str, str, str]] = set()
    car_app_references: set[tuple[str, str, str]] = set()
    manifests = [path for path in normalized if PurePosixPath(path).name == "AndroidManifest.xml"]
    manifest_metadata: dict[str, Any] = {"package_name": "Android project", "target_sdk": "See Gradle configuration"}
    component_inventory: list[dict[str, str]] = []
    deep_link_inventory: list[dict[str, str]] = []
    manifest_targets_by_module: dict[str, set[str]] = {}
    manifest_packages: set[str] = set()
    gradle_application_ids: set[str] = set()
    gradle_namespaces: set[str] = set()
    manifest_permissions: set[str] = set()
    for manifest_path in manifests:
        source = normalized[manifest_path].decode("utf-8", errors="replace")
        manifest_findings, metadata = _inspect_manifest(manifest_path, source, include_aaos=profile == "aaos")
        findings.extend(manifest_findings)
        module_key = _module_key(manifest_path)
        for component in metadata.pop("components", []):
            component["module"] = module_key
            component["manifest"] = manifest_path
            component_inventory.append(component)
        deep_link_inventory.extend(metadata.pop("deep_links", []))
        if metadata.get("target_sdk") not in {None, "Unknown"}:
            manifest_targets_by_module.setdefault(module_key, set()).add(str(metadata["target_sdk"]))
        package_name = metadata.get("package_name")
        if package_name and package_name != "Unknown":
            manifest_packages.add(str(package_name))
        manifest_permissions.update(metadata.pop("permissions", []))
        manifest_metadata.update(metadata)
    if len(manifest_packages) == 1:
        manifest_metadata["package_name"] = next(iter(manifest_packages))
    elif len(manifest_packages) > 1:
        manifest_metadata["package_name"] = "Multiple modules"
    manifest_metadata["components"] = component_inventory
    manifest_metadata["deep_links"] = deep_link_inventory

    for path, data in normalized.items():
        if PurePosixPath(path).name == "AndroidManifest.xml":
            continue
        suffix = PurePosixPath(path).suffix.lower()
        source = data.decode("utf-8", errors="replace")
        for line_number, line in enumerate(mask_comments(source, suffix).splitlines(), start=1):
            for match in AAOS_API_PATTERN.finditer(line):
                aaos_api_references.add((path, str(line_number), match.group(0)))
            for match in CAR_APP_PATTERN.finditer(line):
                car_app_references.add((path, str(line_number), match.group(0)))
        masked = mask_comments(source, suffix)
        block_index: BlockIndex | None = None
        for rule in RULES:
            if rule.get("suffixes") and suffix not in rule["suffixes"]:
                continue
            text = source if rule.get("scan_comments") else masked
            if rule.get("mask_blocks"):
                text = rule["mask_blocks"].sub(lambda found: "".join(ch if ch in "\r\n" else " " for ch in found.group(0)), text)
            examined = 0
            for match in rule["pattern"].finditer(text):
                examined += 1
                if examined > MAX_MATCHES_EXAMINED:
                    break  # a pathological file must not turn context checks into a slowdown
                if rule.get("skip_in_blocks"):
                    block_index = block_index or BlockIndex(masked)
                    if any(rule["skip_in_blocks"].search(header) for header in block_index.headers_at(match.start())):
                        continue
                line_number = source.count("\n", 0, match.start()) + 1
                line_start = source.rfind("\n", 0, match.start()) + 1
                line_end = source.find("\n", match.start())
                line = source[line_start:line_end if line_end >= 0 else len(source)]
                findings.append(_finding(rule, path, line_number, line))
                if sum(item["rule_id"] == rule["id"] and item["source_path"] == path for item in findings) >= 10:
                    break

    dependencies, dependency_warnings = parse_gradle_dependencies(normalized)
    for dependency in dependencies:
        if dependency["version_state"] != "dynamic":
            continue
        coordinate = f"{dependency['group']}:{dependency['name']}:{dependency['version']}"
        findings.append({
            "rule_id": "ANDROID-DEPENDENCY-DYNAMIC-VERSION",
            "title": "Dependency with a dynamic version",
            "severity": "low",
            "summary": f"{coordinate} in {dependency['declared_in']} uses a dynamic version (+, range, latest or SNAPSHOT); builds are not reproducible and a compromised release is pulled in automatically.",
            "recommendation": "Pin an exact version, use a version catalog and Gradle dependency locking or verification, and update deliberately.",
            "evidence": f"{dependency['declared_in']}:{dependency['line']}",
            "source_path": dependency["declared_in"],
            "line": dependency["line"],
            "profile": "Build and dependencies",
            "_anchor": coordinate,
        })

    car_permissions = privileged_car_permissions(manifest_permissions)
    if profile == "aaos" and car_permissions:
        findings.append(privileged_car_permission_finding(car_permissions, manifests[0] if manifests else ""))
    egress_signals = data_egress_signals(manifest_permissions)
    if profile == "aaos" and egress_signals:
        findings.append(data_egress_finding(egress_signals, manifests[0] if manifests else ""))

    if profile == "aaos" and aaos_api_references:
        first_path, first_line, _ = sorted(aaos_api_references)[0]
        findings.append({
            "rule_id": "AAOS-VEHICLE-API-REVIEW",
            "title": "Android Automotive APIs found",
            "severity": "info",
            "summary": "The code references android.car/vehicle APIs; access and availability depend on the API level, permission, property and device/OEM configuration.",
            "recommendation": "Validate permissions per API/property, AAOS version and OEM policies on an authorized emulator or isolated bench; do not test on a road vehicle.",
            "evidence": f"{first_path}:{first_line} ({len(aaos_api_references)} references)",
            "source_path": first_path,
            "line": first_line,
            "profile": "AAOS vehicle APIs",
        })
    if car_app_references:
        first_path, first_line, _ = sorted(car_app_references)[0]
        findings.append({
            "rule_id": "AAOS-CAR-APP-LIBRARY",
            "title": "AndroidX Car App Library found",
            "severity": "info",
            "summary": "The project uses the AndroidX Car App Library; confirm whether the functional target is Android Auto, Android Automotive OS or both, since the environments and requirements differ.",
            "recommendation": "Validate the distribution matrix and supported templates for each intended host/platform.",
            "evidence": f"{first_path}:{first_line} ({len(car_app_references)} references)",
            "source_path": first_path,
            "line": first_line,
            "profile": "AAOS and car app compatibility",
        })

    if not manifests:
        findings.append({
            "rule_id": "AAOS-MANIFEST-MISSING",
            "title": "AndroidManifest.xml not found in the selected directory",
            "severity": "medium",
            "summary": "The scanner did not find the manifest; the directory may be incomplete or the manifest may be generated or live in another module.",
            "recommendation": "Select the correct project root and confirm manifests per module/variant.",
            "evidence": "AndroidManifest.xml missing from the selection",
            "source_path": "",
            "line": "",
            "profile": "Manifest and AAOS",
        })
    gradle_files = [path for path in normalized if PurePosixPath(path).name in {"build.gradle", "build.gradle.kts"}]
    if not gradle_files:
        findings.append({
            "rule_id": "ANDROID-BUILD-CONFIG-MISSING",
            "title": "Gradle configuration not found",
            "severity": "info",
            "summary": "No build.gradle/build.gradle.kts was found among the supported files.",
            "recommendation": "Confirm the Android project root was selected and include the relevant Gradle configuration.",
            "evidence": "build.gradle/build.gradle.kts missing from the selection",
            "source_path": "",
            "line": "",
            "profile": "Build and dependencies",
        })
    else:
        gradle_modules: dict[str, dict[str, Any]] = {}
        for gradle_path in gradle_files:
            gradle_source = normalized[gradle_path].decode("utf-8", errors="replace")
            target_match = re.search(r"\btargetSdk(?:Version)?\s*(?:=\s*)?(\d+)", gradle_source)
            compile_match = re.search(r"\bcompileSdk(?:Version)?\s*(?:=\s*)?(\d+)", gradle_source)
            namespace_match = re.search(r"\bnamespace\s*(?:=\s*)?[\"']([^\"']+)[\"']", gradle_source)
            app_id_match = re.search(r"\bapplicationId\s*(?:=\s*)?[\"']([^\"']+)[\"']", gradle_source)
            module_key = _module_key(gradle_path)
            module_data = gradle_modules.setdefault(module_key, {"module": module_key, "build_file": gradle_path})
            if target_match:
                target_sdk_value = int(target_match.group(1))
                module_data["target_sdk"] = str(target_sdk_value)
                if int(target_match.group(1)) < 31:
                    findings.append({
                        "rule_id": "ANDROID-OLD-TARGET-SDK",
                        "title": "Target SDK below API 31",
                        "severity": "medium",
                        "summary": f"Module {module_key} declares targetSdk {target_match.group(1)}; the effects depend on the version and the final configuration.",
                        "recommendation": "Evaluate updating the target SDK and validate behavior on the supported AAOS versions.",
                        "evidence": f"{gradle_path}:{gradle_source.count(chr(10), 0, target_match.start()) + 1}",
                        "source_path": gradle_path,
                        "line": str(gradle_source.count("\n", 0, target_match.start()) + 1),
                        "profile": "Build and dependencies",
                    })
            if compile_match:
                module_data["compile_sdk"] = int(compile_match.group(1))
            if namespace_match or app_id_match:
                module_data["package_name"] = (app_id_match or namespace_match).group(1)
                if app_id_match:
                    gradle_application_ids.add(app_id_match.group(1))
                elif namespace_match:
                    gradle_namespaces.add(namespace_match.group(1))

        module_summaries: list[dict[str, Any]] = []
        components_by_module: dict[str, list[dict[str, str]]] = {}
        for component in component_inventory:
            components_by_module.setdefault(component.get("module", "."), []).append(component)
        all_modules = set(gradle_modules) | set(manifest_targets_by_module)
        for module_key in sorted(all_modules):
            module_data = gradle_modules.setdefault(module_key, {"module": module_key, "build_file": ""})
            manifest_targets = manifest_targets_by_module.get(module_key, set())
            manifest_target = next(iter(manifest_targets)) if len(manifest_targets) == 1 else None
            manifest_target_status = (
                manifest_target if manifest_target is not None
                else "conflicting variants" if len(manifest_targets) > 1
                else "unavailable"
            )
            effective_target = module_data.get("target_sdk") or manifest_target
            module_data["manifest_target_sdk"] = manifest_target_status
            module_data["effective_target_sdk"] = effective_target or "unresolved"
            module_summaries.append(module_data)
            if effective_target and str(effective_target).isdigit() and int(effective_target) < 31 and not module_data.get("target_sdk"):
                manifest_path = next((path for path in manifests if _module_key(path) == module_key), "")
                findings.append({
                    "rule_id": "ANDROID-OLD-TARGET-SDK",
                    "title": "Target SDK below API 31",
                    "severity": "medium",
                    "summary": f"The manifest of module {module_key} declares targetSdk {effective_target}; the effects depend on the version and the final configuration.",
                    "recommendation": "Evaluate a phased target SDK update and validate on the supported Android/AAOS versions.",
                    "evidence": manifest_path,
                    "source_path": manifest_path,
                    "line": "1",
                    "profile": "Build and dependencies",
                })
            if effective_target and str(effective_target).isdigit() and int(effective_target) >= 31:
                for component in components_by_module.get(module_key, []):
                    if component.get("exported") != "inferred_true":
                        continue
                    manifest_path = component.get("manifest", "")
                    existing = next((
                        finding for finding in findings
                        if finding["rule_id"] == "ANDROID-EXPORTED-IMPLICIT"
                        and finding["source_path"] == manifest_path
                        and component["name"] in finding["evidence"]
                    ), None)
                    if existing:
                        existing.update({
                            "rule_id": "ANDROID-EXPORTED-BUILD-ERROR",
                            "title": "Possible build error: exported required",
                            "severity": "high",
                            "summary": f"Module {module_key} targets targetSdk {effective_target}; Android 12+ requires an explicit android:exported on components with an intent-filter.",
                            "recommendation": "Declare android:exported explicitly and confirm the variant's merged manifest.",
                            "profile": "Build and dependencies",
                        })
            compile_value = module_data.get("compile_sdk")
            if effective_target and str(effective_target).isdigit() and compile_value is not None and compile_value < int(effective_target):
                gradle_path = module_data["build_file"]
                findings.append({
                    "rule_id": "ANDROID-COMPILE-SDK-BELOW-TARGET",
                    "title": "compileSdk lower than targetSdk",
                    "severity": "high",
                    "summary": f"Module {module_key} shows compileSdk {compile_value} and targetSdk {effective_target}; confirm whether the effective build configuration fails.",
                    "recommendation": "Use compileSdk equal to or higher than targetSdk and confirm the module/variant's effective configuration.",
                    "evidence": gradle_path,
                    "source_path": gradle_path,
                    "line": "1",
                    "profile": "Build and dependencies",
                })
        manifest_metadata["gradle_modules"] = module_summaries
    module_summaries = manifest_metadata.get("gradle_modules", [])
    if module_summaries:
        effective_targets = [str(item.get("effective_target_sdk", "unresolved")) for item in module_summaries]
        if len(effective_targets) == 1 and effective_targets[0].isdigit():
            manifest_metadata["target_sdk"] = effective_targets[0]
        else:
            manifest_metadata["target_sdk"] = "Per module"
    else:
        all_manifest_targets = {target for targets in manifest_targets_by_module.values() for target in targets}
        if len(all_manifest_targets) == 1 and len(manifest_targets_by_module) == 1:
            manifest_metadata["target_sdk"] = next(iter(all_manifest_targets))
        elif all_manifest_targets:
            manifest_metadata["target_sdk"] = "Per module"

    if len(gradle_application_ids) == 1 and manifest_metadata.get("package_name") in {"Android project", "Unknown"}:
        manifest_metadata["package_name"] = next(iter(gradle_application_ids))
    elif len(gradle_application_ids) > 1:
        manifest_metadata["package_name"] = "Multiple modules"
    elif not gradle_application_ids and len(gradle_namespaces) == 1 and manifest_metadata.get("package_name") in {"Android project", "Unknown"}:
        # AGP 7+ projects often omit manifest package and declare only a namespace.
        manifest_metadata["package_name"] = next(iter(gradle_namespaces))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order.get(item["severity"], 9), item["rule_id"], item.get("source_path", ""), item.get("line", "")))
    severity_counts = {severity: sum(item["severity"] == severity for item in findings) for severity in order}
    risk_level = "elevated" if severity_counts["critical"] or severity_counts["high"] else "review" if severity_counts["medium"] else "informational"
    digest = sha256()
    for path, data in sorted(normalized.items()):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    enrich_findings(findings)
    profiles = [
        "Manifest", "Build and dependencies", "Network security", "WebView", "IPC and intents",
        "Data storage", "Secrets hygiene", "Cryptography", "Code quality and input",
    ]
    if profile == "aaos":
        profiles.extend(["AAOS vehicle APIs", "AAOS and car app compatibility"])
    return {
        "report_type": "source_directory",
        "analysis_profile": profile,
        "profile_label": "Android app · MASVS/MSTG-inspired" if profile == "android_app" else "Android Automotive · app baseline + AAOS",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "project_name": project_name or next((PurePosixPath(path).parts[0] for path in normalized if len(PurePosixPath(path).parts) > 1), "Android project"),
        "package_name": manifest_metadata.get("package_name", "Android project"),
        "version_name": "Directory analysis",
        "version_code": "—",
        "min_sdk": "See Gradle configuration",
        "target_sdk": manifest_metadata.get("target_sdk", "See Gradle configuration"),
        "automotive_feature_declared": manifest_metadata.get("automotive_feature_declared", False),
        "components": manifest_metadata.get("components", []),
        "component_count": len(manifest_metadata.get("components", [])),
        "exported_component_count": sum(
            component["exported"] in {"true", "inferred_true"}
            for component in manifest_metadata.get("components", [])
        ),
        "native_libraries": [],
        "deep_links": manifest_metadata.get("deep_links", []),
        "permissions": sorted(manifest_permissions),
        "permission_count": len(manifest_permissions),
        "gradle_modules": manifest_metadata.get("gradle_modules", []),
        "aaos_api_references": [
            {"path": path, "line": line, "api": api}
            for path, line, api in sorted(aaos_api_references)
        ],
        "car_app_library_references": [
            {"path": path, "line": line, "api": api}
            for path, line, api in sorted(car_app_references)
        ],
        "source_file_count": len(normalized),
        "source_bytes": sum(len(data) for data in normalized.values()),
        "source_sha256": digest.hexdigest(),
        "car_permissions": classify_car_permissions(manifest_permissions),
        "dependencies": dependencies,
        "dependency_summary": dependency_summary(dependencies),
        "dependency_warnings": dependency_warnings,
        "profiles_run": profiles,
        "severity_counts": severity_counts,
        "risk_level": risk_level,
        "masvs_summary": masvs_summary(findings),
        "findings": findings,
        "analysis_scope": "Static analysis of the selected source code/configuration. It does not compile, run, or test the vehicle. Coverage is limited to the documented rules.",
    }
