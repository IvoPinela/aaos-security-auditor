"""MASWE mapping: every ID must exist in the verified table, and reports must carry it."""

from aaos_auditor.exporters import to_markdown, to_sarif
from aaos_auditor.masvs import MASWE_TITLES, RULE_MASWE, enrich_findings, maswe_for_rule
from aaos_auditor.rules_catalog import known_rule_ids, rule_catalog


def test_every_mapped_weakness_is_in_the_verified_table():
    for rule_id, weaknesses in RULE_MASWE.items():
        for weakness in weaknesses:
            assert weakness in MASWE_TITLES, (rule_id, weakness)
    assert all(key.startswith("MASWE-") and len(key) == 10 for key in MASWE_TITLES)


def test_mapped_rules_exist_and_platform_rules_are_unmapped():
    ids = known_rule_ids()
    for pattern in RULE_MASWE:
        if "*" in pattern:
            assert any(item.startswith(pattern.rstrip("*")) for item in ids), pattern
        else:
            assert pattern in ids, pattern
    assert not any(maswe_for_rule(item) for item in ids if item.startswith("PLATFORM-"))


def test_glob_and_exact_lookup():
    assert maswe_for_rule("ANDROID-PERM-READ_SMS") == ["MASWE-0066"]
    assert maswe_for_rule("ANDROID-PERM-SYSTEM_ALERT_WINDOW") == ["MASWE-0039", "MASWE-0066"]
    assert maswe_for_rule("ANDROID-DEBUGGABLE") == ["MASWE-0063"]
    assert maswe_for_rule("UNKNOWN-RULE") == []


def test_findings_catalog_and_exports_carry_maswe():
    findings = enrich_findings([{"rule_id": "ANDROID-BACKUP-ENABLED", "title": "t", "severity": "medium",
                                 "summary": "s", "recommendation": "r", "evidence": "AndroidManifest.xml:3"}])
    assert findings[0]["maswe"] == ["MASWE-0006"]
    assert next(r for r in rule_catalog() if r["id"] == "ANDROID-BACKUP-ENABLED")["maswe"] == ["MASWE-0006"]
    report = {"project_name": "p", "findings": findings, "severity_counts": {}, "risk_level": "medium", "report_type": "source_directory"}
    sarif = to_sarif(report)
    assert "MASWE-0006" in sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "MASWE-0006" in to_markdown(report)
