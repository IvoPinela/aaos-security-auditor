"""Stable finding identities that survive line shifts and never depend on secret values.

A fingerprint is used to compare reports (baselines), to deduplicate, and as the SARIF
`partialFingerprints` value so GitHub code scanning does not reopen alerts when code moves.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any
import re

# Rules whose matched line can contain a credential: hash their location only, never their text.
CONTENT_FREE_RULES = {"ANDROID-SECRET-LITERAL", "ANDROID-KNOWN-SECRET-FORMAT"}
LINE_SUFFIX = re.compile(r":\d+\b")
FINGERPRINT_LENGTH = 24


def _normalize(text: Any) -> str:
    return " ".join(str(text).split())


def _anchor(finding: dict[str, Any]) -> str:
    """Text that identifies the finding independently of its line number."""
    matched_line = finding.pop("_anchor", None)  # transient: the matched source line, never stored
    if str(finding.get("rule_id", "")) in CONTENT_FREE_RULES:
        return ""
    if matched_line is not None:
        return _normalize(matched_line)
    return _normalize(LINE_SUFFIX.sub("", str(finding.get("evidence", ""))))


def assign_fingerprints(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Set `fingerprint` on each finding in place; identical anchors get an occurrence suffix."""
    seen: dict[str, int] = {}
    for finding in findings:
        anchor = _anchor(finding)  # always pops the transient anchor, even when already fingerprinted
        if finding.get("fingerprint"):
            continue
        material = f"{finding.get('rule_id', '')}\0{finding.get('source_path', '')}\0{anchor}"
        base = sha256(material.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]
        occurrence = seen.get(base, 0)
        seen[base] = occurrence + 1
        finding["fingerprint"] = base if occurrence == 0 else f"{base}-{occurrence}"
    return findings
