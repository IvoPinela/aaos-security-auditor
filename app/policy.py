"""Project policy: settings and justified suppressions from `aaos.toml`, plus inline ignores.

Teams only keep a scanner when they can silence known false positives *without hiding the decision*.
Every suppression therefore needs a reason, can expire, is reported back, and is flagged when stale.

Example `aaos.toml`:

    [settings]
    profile = "aaos"
    fail_on = "high"
    min_severity = "low"
    ignore_paths = ["**/src/test/**", "**/src/androidTest/**"]
    disabled_rules = ["ANDROID-HTTP-URL"]

    [[suppress]]
    rule = "ANDROID-WEAK-HASH"
    path = "app/src/main/java/ImageCache.kt"
    reason = "MD5 is only used for cache keys, never for security"
    author = "ivo"
    expires = 2027-01-01

Inline form, on the flagged line or the line above (a reason is required):

    // aaos-ignore[ANDROID-WEAK-HASH]: MD5 used for cache keys only
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from datetime import date, datetime
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any

from app.masvs import masvs_summary

CONFIG_NAME = "aaos.toml"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
PROFILES = {"aaos", "android_app"}
KNOWN_SETTINGS = {"profile", "fail_on", "min_severity", "ignore_paths", "disabled_rules"}
MIN_REASON_LENGTH = 8
INLINE_IGNORE = re.compile(r"aaos-ignore(?:\[(?P<rules>[A-Za-z0-9_*,\-\s]+)\])?\s*:?\s*(?P<reason>.*)$")
COMMENT_TAIL = re.compile(r"\s*(?:-->|\*/)\s*$")


@dataclass
class Suppression:
    rule: str
    reason: str
    path: str = ""
    line: int | None = None
    evidence_contains: str = ""
    author: str = ""
    expires: date | None = None
    used: int = 0

    def describe(self) -> str:
        scope = self.path or "any path"
        return f"{self.rule} @ {scope}" + (f":{self.line}" if self.line else "")


@dataclass
class Policy:
    settings: dict[str, Any] = field(default_factory=dict)
    suppressions: list[Suppression] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _as_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def _string_list(value: Any, name: str, warnings: list[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        warnings.append(f"settings.{name} must be a list of non-empty strings; ignored.")
        return []
    return list(value)


def parse_policy(text: str) -> Policy:
    """Parse and validate `aaos.toml`. Invalid TOML raises ValueError; bad entries become warnings."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{CONFIG_NAME} is not valid TOML: {exc}") from exc

    policy = Policy()
    raw_settings = document.get("settings", {})
    if not isinstance(raw_settings, dict):
        policy.warnings.append("[settings] must be a table; ignored.")
        raw_settings = {}
    for key in raw_settings:
        if key not in KNOWN_SETTINGS:
            policy.warnings.append(f"Unknown setting '{key}' ignored.")

    profile = raw_settings.get("profile")
    if profile is not None:
        if profile in PROFILES:
            policy.settings["profile"] = profile
        else:
            policy.warnings.append("settings.profile must be 'aaos' or 'android_app'; ignored.")
    for key, allowed in (("fail_on", ("none", *SEVERITY_ORDER)), ("min_severity", SEVERITY_ORDER)):
        value = raw_settings.get(key)
        if value is not None:
            if value in allowed:
                policy.settings[key] = value
            else:
                policy.warnings.append(f"settings.{key} must be one of {', '.join(allowed)}; ignored.")
    policy.settings["ignore_paths"] = _string_list(raw_settings.get("ignore_paths"), "ignore_paths", policy.warnings)
    policy.settings["disabled_rules"] = _string_list(raw_settings.get("disabled_rules"), "disabled_rules", policy.warnings)

    entries = document.get("suppress", [])
    if not isinstance(entries, list):
        policy.warnings.append("[[suppress]] must be an array of tables; ignored.")
        entries = []
    for index, entry in enumerate(entries, start=1):
        label = f"suppress #{index}"
        if not isinstance(entry, dict):
            policy.warnings.append(f"{label}: not a table; skipped.")
            continue
        rule, reason = entry.get("rule"), entry.get("reason")
        if not isinstance(rule, str) or not rule.strip():
            policy.warnings.append(f"{label}: missing 'rule'; skipped.")
            continue
        if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON_LENGTH:
            policy.warnings.append(f"{label} ({rule}): a 'reason' of at least {MIN_REASON_LENGTH} characters is required; skipped.")
            continue
        line = entry.get("line")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            policy.warnings.append(f"{label} ({rule}): 'line' must be a positive integer; skipped.")
            continue
        expires = _as_date(entry.get("expires")) if "expires" in entry else None
        if "expires" in entry and expires is None:
            policy.warnings.append(f"{label} ({rule}): 'expires' must be a date such as 2027-01-31; skipped.")
            continue
        policy.suppressions.append(Suppression(
            rule=rule.strip(),
            reason=reason.strip(),
            path=str(entry.get("path", "")).strip(),
            line=line,
            evidence_contains=str(entry.get("evidence_contains", "")),
            author=str(entry.get("author", "")).strip(),
            expires=expires,
        ))
    return policy


def find_policy_file(files: dict[str, bytes]) -> str | None:
    """Return the path of the shallowest aaos.toml in a file snapshot, if any."""
    candidates = [path for path in files if PurePosixPath(path).name == CONFIG_NAME]
    return min(candidates, key=lambda path: (len(PurePosixPath(path).parts), path)) if candidates else None


def _glob(path: str, pattern: str) -> bool:
    if fnmatchcase(path, pattern):
        return True
    # "**/x/**" should also match a top-level "x/..." path.
    return pattern.startswith("**/") and fnmatchcase(path, pattern[3:])


def _relative(path: str, root_prefix: str) -> str:
    return path[len(root_prefix):] if root_prefix and path.startswith(root_prefix) else path


def _inline_ignore(files: dict[str, bytes], path: str, line: str, rule_id: str, warnings: list[str]) -> str | None:
    """Return the reason of an `aaos-ignore` comment covering this finding, or None."""
    if not path or not line.isdigit() or path not in files:
        return None
    lines = files[path].decode("utf-8", errors="replace").splitlines()
    number = int(line)
    if path.endswith(".xml") and number == 1:
        # Manifest findings are file-level (line 1 is a placeholder): an ignore comment anywhere in the file applies.
        candidates = range(len(lines))
    else:
        candidates = (number - 1, number - 2)  # the flagged line, then the line above
    for index in candidates:
        if not 0 <= index < len(lines):
            continue
        match = INLINE_IGNORE.search(lines[index])
        if not match:
            continue
        rules = [item.strip() for item in (match.group("rules") or "*").split(",") if item.strip()]
        if not any(fnmatchcase(rule_id, pattern) for pattern in rules):
            continue
        reason = COMMENT_TAIL.sub("", match.group("reason") or "").strip()
        if len(reason) < MIN_REASON_LENGTH:
            warnings.append(f"Inline ignore at {path}:{index + 1} has no reason; not applied.")
            return None
        return reason
    return None


def refresh_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Recompute counts, heuristic risk level and MASVS summary after the findings changed."""
    findings = report.get("findings", [])
    counts = {severity: sum(item.get("severity") == severity for item in findings) for severity in SEVERITY_ORDER}
    report["severity_counts"] = counts
    report["risk_level"] = "elevated" if counts["critical"] or counts["high"] else "review" if counts["medium"] else "informational"
    report["masvs_summary"] = masvs_summary(findings)
    return report


def apply_policy(
    report: dict[str, Any],
    policy: Policy,
    files: dict[str, bytes] | None = None,
    root_prefix: str = "",
    config_path: str = "",
    today: date | None = None,
) -> dict[str, Any]:
    """Move suppressed findings to `suppressed_findings` and describe what the policy did."""
    today = today or date.today()
    active = [item for item in policy.suppressions if item.expires is None or item.expires >= today]
    expired = [item for item in policy.suppressions if item.expires is not None and item.expires < today]
    warnings = list(policy.warnings)
    disabled = policy.settings.get("disabled_rules", [])
    ignored_paths = policy.settings.get("ignore_paths", [])

    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    by_kind = {"config": 0, "inline": 0, "ignored_path": 0, "disabled_rule": 0}
    for finding in report.get("findings", []):
        rule_id = str(finding.get("rule_id", ""))
        path = str(finding.get("source_path", ""))
        relative = _relative(path, root_prefix)
        decision: dict[str, str] | None = None

        if any(fnmatchcase(rule_id, pattern) for pattern in disabled):
            decision = {"kind": "disabled_rule", "reason": f"Rule disabled in {CONFIG_NAME}"}
        elif relative and any(_glob(relative, pattern) for pattern in ignored_paths):
            decision = {"kind": "ignored_path", "reason": f"Path ignored in {CONFIG_NAME}"}
        else:
            for item in active:
                if not fnmatchcase(rule_id, item.rule):
                    continue
                if item.path and not (relative and _glob(relative, item.path)):
                    continue
                if item.line is not None and str(finding.get("line", "")) != str(item.line):
                    continue
                if item.evidence_contains and item.evidence_contains not in str(finding.get("evidence", "")):
                    continue
                item.used += 1
                decision = {"kind": "config", "reason": item.reason, "author": item.author,
                            "expires": item.expires.isoformat() if item.expires else ""}
                break
            if decision is None and files:
                reason = _inline_ignore(files, path, str(finding.get("line", "")), rule_id, warnings)
                if reason:
                    decision = {"kind": "inline", "reason": reason}

        if decision is None:
            kept.append(finding)
            continue
        by_kind[decision["kind"]] += 1
        suppressed.append({**finding, "suppression": decision})

    report["findings"] = kept
    report["suppressed_findings"] = suppressed
    report["policy"] = {
        "config": config_path,
        "suppressed": len(suppressed),
        "by_kind": by_kind,
        "expired": [{"suppression": item.describe(), "expired_on": item.expires.isoformat() if item.expires else ""} for item in expired],
        "unused": [item.describe() for item in active if item.used == 0],
        "warnings": warnings,
    }
    return refresh_summary(report)


def load_project_policy(files: dict[str, bytes]) -> tuple[Policy | None, str, str]:
    """Find and parse the project's aaos.toml. Returns (policy, config_path, root_prefix).

    Raises ValueError when the file exists but is not valid TOML.
    """
    path = find_policy_file(files)
    if path is None:
        return None, "", ""
    policy = parse_policy(files[path].decode("utf-8", errors="replace"))
    return policy, path, path[: -len(CONFIG_NAME)]
