from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from aaos_auditor import knowledge
from aaos_auditor.cli import main as cli_main
from aaos_auditor.directory_scanner import RULES, analyze_source_directory
from aaos_auditor.exporters import compare_with_baseline, to_markdown, to_sarif
from aaos_auditor.knowledge import (
    _load_documents,
    notes_for_rule,
    reload_knowledge_base,
    retrieve_context,
    search_notes,
    validate_knowledge_base,
)
from aaos_auditor.main import app
from aaos_auditor.masvs import masvs_for_rule
from aaos_auditor.pentest_plan import build_pentest_plan
from aaos_auditor.rules_catalog import known_rule_ids, rule_catalog
from aaos_auditor.scanner import ANDROID_NS


def request(method: str, url: str, **kwargs: object) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, url, **kwargs)

    return asyncio.run(send())


def rule_ids_for(files: dict[str, bytes], profile: str = "aaos") -> set[str]:
    return {finding["rule_id"] for finding in analyze_source_directory(files, profile=profile)["findings"]}


# --- New source rules -------------------------------------------------------

def test_new_code_rules_detect_crypto_sql_exec_and_dynamic_loading() -> None:
    code = b'''
val c1 = Cipher.getInstance("AES")
val c2 = Cipher.getInstance("DES/CBC/PKCS5Padding")
val ok = Cipher.getInstance("AES/GCM/NoPadding")
val md = MessageDigest.getInstance("MD5")
val iv = IvParameterSpec(ByteArray(16))
db.rawQuery("SELECT * FROM users WHERE name = '$name'", null)
db.execSQL("DELETE FROM t WHERE id = " + id)
Runtime.getRuntime().exec(cmd)
val loader = DexClassLoader(path, dir, null, parent)
'''
    report = analyze_source_directory({"app/src/main/java/Crypto.kt": code})
    by_rule: dict[str, list[dict[str, str]]] = {}
    for finding in report["findings"]:
        by_rule.setdefault(finding["rule_id"], []).append(finding)

    assert len(by_rule["ANDROID-WEAK-CIPHER"]) == 2  # AES/GCM must not match
    assert {"ANDROID-WEAK-HASH", "ANDROID-STATIC-IV", "ANDROID-RUNTIME-EXEC", "ANDROID-DYNAMIC-CODE-LOADING"} <= set(by_rule)
    assert len(by_rule["ANDROID-SQL-CONCAT"]) == 2
    assert by_rule["ANDROID-WEAK-HASH"][0]["masvs"] == ["MASVS-CRYPTO-1"]


def test_kotlin_property_syntax_and_webview_tls_rules() -> None:
    code = b'''
webView.settings.javaScriptEnabled = true
webView.settings.allowUniversalAccessFromFileURLs = true
override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
    handler?.proceed()
}
'''
    ids = rule_ids_for({"app/src/Web.kt": code})
    assert {"ANDROID-WEBVIEW-JS", "ANDROID-WEBVIEW-UNIVERSAL-FILE", "ANDROID-WEBVIEW-SSL-PROCEED"} <= ids


def test_xml_rules_only_apply_to_xml_files() -> None:
    nsc = b'''<network-security-config>
  <base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user" /></trust-anchors></base-config>
</network-security-config>'''
    paths = b'<paths><root-path name="root" path="." /></paths>'
    ids = rule_ids_for({"app/src/main/res/xml/network_security_config.xml": nsc, "app/src/main/res/xml/file_paths.xml": paths})
    assert {"ANDROID-NSC-CLEARTEXT", "ANDROID-NSC-USER-CERTS", "ANDROID-FILEPROVIDER-ROOT"} <= ids

    # The same text in Kotlin is a string, not configuration.
    assert "ANDROID-FILEPROVIDER-ROOT" not in rule_ids_for({"app/src/Doc.kt": b'val doc = "<root-path name=\\"x\\" />"'})


def test_known_secret_formats_are_reported_without_value() -> None:
    secret = "AKIA" + "ABCDEFGHIJKLMNOP"
    report = analyze_source_directory({"app/src/Keys.kt": f'val key = "{secret}"'.encode()})
    finding = next(item for item in report["findings"] if item["rule_id"] == "ANDROID-KNOWN-SECRET-FORMAT")
    assert finding["evidence"] == "app/src/Keys.kt:1"
    assert secret not in json.dumps(report)


def test_http_url_rule_ignores_namespaces_and_loopback() -> None:
    code = b'''val a = "http://api.example.test/v1"
val b = "http://10.0.2.2:8080"
val c = "http://schemas.android.com/apk/res/android"
'''
    report = analyze_source_directory({"app/src/Net.kt": code})
    http = [item for item in report["findings"] if item["rule_id"] == "ANDROID-HTTP-URL"]
    assert [item["line"] for item in http] == ["1"]


def test_gradle_release_hardening_rules() -> None:
    gradle = b'''android {
  namespace = "org.example.car"
  buildTypes { release { isMinifyEnabled = false; signingConfig = signingConfigs.getByName("debug") } }
}'''
    report = analyze_source_directory({"app/build.gradle.kts": gradle})
    ids = {item["rule_id"] for item in report["findings"]}
    assert {"ANDROID-RELEASE-NOT-MINIFIED", "ANDROID-DEBUG-SIGNING"} <= ids
    assert report["package_name"] == "org.example.car"


def test_manifest_test_only_shared_uid_and_car_permissions() -> None:
    manifest = f'''<manifest xmlns:android="{ANDROID_NS}" package="com.oem.climate" android:sharedUserId="android.uid.system">
  <uses-permission android:name="android.car.permission.CONTROL_CAR_CLIMATE" />
  <uses-permission android:name="android.car.permission.CAR_VENDOR_EXTENSION" />
  <uses-permission android:name="android.car.permission.CAR_SPEED" />
  <application android:testOnly="true" />
</manifest>'''.encode()
    files = {"app/src/main/AndroidManifest.xml": manifest}
    aaos = analyze_source_directory(files, profile="aaos")
    ids = {item["rule_id"] for item in aaos["findings"]}
    assert {"ANDROID-TEST-ONLY", "ANDROID-SHARED-USER-ID", "AAOS-PRIVILEGED-CAR-PERMISSION"} <= ids
    car = next(item for item in aaos["findings"] if item["rule_id"] == "AAOS-PRIVILEGED-CAR-PERMISSION")
    assert "CONTROL_CAR_CLIMATE" in car["summary"] and "CAR_SPEED" not in car["summary"]
    assert "AAOS-PRIVILEGED-CAR-PERMISSION" not in rule_ids_for(files, profile="android_app")


def test_reports_include_masvs_summary() -> None:
    report = analyze_source_directory({"app/src/Web.kt": b"settings.setJavaScriptEnabled(true)"})
    assert report["masvs_summary"].get("MASVS-PLATFORM-2") == 1
    assert "Cryptography" in report["profiles_run"]


def test_rule_patterns_stay_linear_on_long_adversarial_lines() -> None:
    import time

    size = 50_000
    inputs = ['"' + "a" * size, '"http://' + "a" * size, "Log.d(" * (size // 6), "(" * size, " " * size]
    for rule in RULES:
        started = time.perf_counter()
        for text in inputs:
            for _ in rule["pattern"].finditer(text):
                pass
        assert time.perf_counter() - started < 1.0, f"{rule['id']} is too slow on long lines"


# --- MASVS mapping and catalog ---------------------------------------------

def test_masvs_mapping_supports_exact_and_family_patterns() -> None:
    assert masvs_for_rule("ANDROID-CLEARTEXT") == ["MASVS-NETWORK-1"]
    assert masvs_for_rule("ANDROID-PERM-READ_SMS") == ["MASVS-PRIVACY-1"]
    assert masvs_for_rule("ANDROID-WEBVIEW-SSL-PROCEED") == ["MASVS-NETWORK-1", "MASVS-PLATFORM-2"]
    assert masvs_for_rule("SEMGREP-whatever") == []


def test_rule_catalog_covers_every_regex_rule_once() -> None:
    catalog = rule_catalog()
    ids = [entry["id"] for entry in catalog]
    assert len(ids) == len(set(ids))
    assert {rule["id"] for rule in RULES} <= set(ids)
    # Every security rule (not project-shape notices) should map to MASVS.
    unmapped = {
        entry["id"] for entry in catalog
        if not entry["masvs"] and entry["id"] not in {
            "AAOS-CAR-APP-LIBRARY", "AAOS-FEATURE-UNCONFIRMED", "AAOS-MANIFEST-MISSING",
            "ANDROID-BUILD-CONFIG-MISSING", "ANDROID-MANIFEST-XML",
        }
    }
    assert unmapped == set()


def test_every_finding_check_in_pentest_plan_is_a_known_rule() -> None:
    from aaos_auditor.pentest_plan import FINDING_CHECKS

    assert set(FINDING_CHECKS) <= known_rule_ids()
    plan = build_pentest_plan([{"rule_id": "ANDROID-WEAK-CIPHER"}, {"rule_id": "ANDROID-STATIC-IV"}])
    assert [check["id"] for check in plan["checks"]].count("PT-CRYPTO") == 1


# --- Knowledge base ---------------------------------------------------------

def test_shipped_knowledge_base_is_valid_and_references_known_rules() -> None:
    assert validate_knowledge_base(known_rule_ids()) == []


def test_every_rule_has_knowledge_note() -> None:
    reload_knowledge_base()
    missing = {rule_id for rule_id in known_rule_ids() if not notes_for_rule(rule_id)}
    assert missing == set()


def test_retrieval_ranks_high_severity_notes_first_and_supports_globs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    notes = [
        {"id": "general", "title": "General", "rule_ids": ["*"], "content": "g" * 50},
        {"id": "low-note", "title": "Low", "rule_ids": ["RULE-LOW"], "content": "l" * 200},
        {"id": "high-note", "title": "High", "rule_ids": ["RULE-HIGH"], "masvs": ["MASVS-NETWORK-1"], "content": "h" * 200},
        {"id": "family", "title": "Family", "rule_ids": ["SEMGREP-*"], "content": "f" * 20},
    ]
    notes_file = tmp_path / "notes.json"
    notes_file.write_text(json.dumps(notes), encoding="utf-8")
    monkeypatch.setenv("AAOS_KNOWLEDGE_FILE", str(notes_file))
    monkeypatch.setattr(knowledge, "MAX_CONTEXT_CHARS", 400)
    _load_documents.cache_clear()
    try:
        context, sources = retrieve_context([
            {"rule_id": "RULE-LOW", "severity": "low"},
            {"rule_id": "RULE-HIGH", "severity": "high"},
        ])
        assert [source["id"] for source in sources] == ["general", "high-note"]
        assert "(MASVS-NETWORK-1)" in context

        _, family_sources = retrieve_context([{"rule_id": "SEMGREP-java.crypto", "severity": "medium"}])
        assert "family" in {source["id"] for source in family_sources}
    finally:
        monkeypatch.delenv("AAOS_KNOWLEDGE_FILE")
        _load_documents.cache_clear()


def test_validate_knowledge_base_reports_problems(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    notes_file = tmp_path / "notes.json"
    notes_file.write_text(json.dumps([
        {"id": "a", "title": "A", "rule_ids": ["X-UNKNOWN"], "content": "ok"},
        {"id": "a", "title": "", "rule_ids": [], "content": ""},
    ]), encoding="utf-8")
    monkeypatch.setenv("AAOS_KNOWLEDGE_FILE", str(notes_file))
    problems = validate_knowledge_base({"X-KNOWN"})
    text = "\n".join(problems)
    assert "unknown rule 'X-UNKNOWN'" in text
    assert "duplicate id" in text
    assert "missing 'title'" in text and "missing 'content'" in text and "rule_ids" in text


def test_search_notes_ranks_title_matches() -> None:
    reload_knowledge_base()
    results = search_notes("cryptography")
    assert results and results[0]["id"] == "weak-cryptography"
    assert search_notes("   ") == []


# --- Exporters and baseline -------------------------------------------------

def sample_report() -> dict[str, object]:
    return analyze_source_directory({
        "app/src/Web.kt": b"settings.setJavaScriptEnabled(true)\nval md = MessageDigest.getInstance(\"SHA-1\")",
    }, profile="android_app")


def test_sarif_export_is_valid_shape_without_snippets() -> None:
    report = sample_report()
    sarif = to_sarif(report)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
    webview = next(result for result in run["results"] if result["ruleId"] == "ANDROID-WEBVIEW-JS")
    assert webview["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "app/src/Web.kt"}, "region": {"startLine": 1}}
    assert "setJavaScriptEnabled" not in json.dumps(sarif)
    rule = run["tool"]["driver"]["rules"][rule_ids.index("ANDROID-WEBVIEW-JS")]
    assert "MASVS-PLATFORM-2" in rule["properties"]["tags"]


def test_markdown_export_escapes_cells() -> None:
    report = sample_report()
    report["findings"][0]["title"] = "A | B"
    markdown = to_markdown(report)
    assert "A \\| B" in markdown
    assert "## OWASP MASVS coverage" in markdown


def test_baseline_comparison_splits_new_and_resolved() -> None:
    old = {"findings": [{"rule_id": "R1", "evidence": "a:1"}, {"rule_id": "R2", "evidence": "b:2"}]}
    new = {"findings": [{"rule_id": "R2", "evidence": "b:2"}, {"rule_id": "R3", "evidence": "c:3"}]}
    comparison = compare_with_baseline(new, old)
    assert comparison["new_count"] == 1 and comparison["new"][0]["rule_id"] == "R3"
    assert comparison["resolved_count"] == 1 and comparison["resolved"][0]["rule_id"] == "R1"
    assert comparison["unchanged_count"] == 1


# --- CLI --------------------------------------------------------------------

def make_project(root: Path) -> Path:
    source = root / "Proj" / "app" / "src" / "main" / "java"
    source.mkdir(parents=True)
    (source / "Web.kt").write_text("settings.setJavaScriptEnabled(true)\n", encoding="utf-8")
    return root / "Proj"


def test_cli_fail_on_gate_and_formats(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    project = make_project(tmp_path)

    assert cli_main([str(project), "--fail-on", "high"]) == 0
    capsys.readouterr()
    assert cli_main([str(project), "--fail-on", "medium"]) == 1
    assert "Gate failed" in capsys.readouterr().err

    sarif_path = tmp_path / "out.sarif"
    assert cli_main([str(project), "--format", "sarif", "-o", str(sarif_path)]) == 0
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"

    assert cli_main([str(project), "--format", "markdown"]) == 0
    assert "# AAOS Security Auditor Report" in capsys.readouterr().out


def test_cli_baseline_only_gates_on_new_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    project = make_project(tmp_path)
    baseline = tmp_path / "baseline.json"
    assert cli_main([str(project), "-o", str(baseline)]) == 0

    assert cli_main([str(project), "--baseline", str(baseline), "--fail-on", "medium"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["baseline_comparison"]["new_count"] == 0

    (project / "app" / "src" / "main" / "java" / "Net.kt").write_text('val u = "http://api.example.test"\n', encoding="utf-8")
    assert cli_main([str(project), "--baseline", str(baseline), "--fail-on", "low"]) == 1


def test_cli_min_severity_list_rules_and_check_knowledge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    project = make_project(tmp_path)
    assert cli_main([str(project), "--min-severity", "high"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []

    assert cli_main(["--list-rules"]) == 0
    assert "ANDROID-WEAK-CIPHER" in capsys.readouterr().out

    assert cli_main(["--check-knowledge"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


# --- API --------------------------------------------------------------------

def test_rules_and_knowledge_endpoints() -> None:
    rules = request("GET", "/api/rules")
    assert rules.status_code == 200
    assert any(rule["id"] == "ANDROID-NSC-CLEARTEXT" for rule in rules.json()["rules"])
    assert "MASVS-NETWORK-1" in rules.json()["masvs_controls"]

    by_rule = request("GET", "/api/knowledge", params={"rule_id": "ANDROID-WEAK-CIPHER"})
    assert by_rule.status_code == 200
    assert by_rule.json()["notes"][0]["id"] == "weak-cryptography"
    assert request("GET", "/api/knowledge").status_code == 400


def test_export_endpoint_returns_sarif_and_markdown() -> None:
    report = sample_report()
    sarif = request("POST", "/api/export/sarif", content=json.dumps(report))
    assert sarif.status_code == 200
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    assert sarif.json()["runs"][0]["tool"]["driver"]["version"] == app.version

    markdown = request("POST", "/api/export/markdown", content=json.dumps(report))
    assert markdown.status_code == 200 and "## Findings" in markdown.text

    assert request("POST", "/api/export/pdf", content="{}").status_code == 404
    assert request("POST", "/api/export/sarif", content="not json").status_code == 422
    assert request("POST", "/api/export/sarif", content="{}").status_code == 422
