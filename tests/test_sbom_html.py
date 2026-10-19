from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import httpx
import pytest

from app.ai_context import build_ai_context
from app.cli import main as cli_main
from app.directory_scanner import analyze_source_directory
from app.html_report import to_html
from app.main import app
from app.sbom import dependency_summary, parse_gradle_dependencies, parse_version_catalog, purl, to_cyclonedx
from app.threat_model import build_threat_model

CATALOG = b'''
[versions]
okhttp = "4.12.0"
coroutines = { strictly = "1.7.3" }

[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
androidx-core-ktx = "androidx.core:core-ktx:1.12.0"
kotlinx-coroutines = { group = "org.jetbrains.kotlinx", name = "kotlinx-coroutines-android", version.ref = "coroutines" }
compose-bom = { module = "androidx.compose:compose-bom", version = "2024.02.00" }
compose-ui = { module = "androidx.compose.ui:ui" }
'''

APP_GRADLE = b'''
dependencies {
    implementation(libs.okhttp)
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation("com.google.code.gson:gson:2.+")
    // implementation("com.commented:out:1.0")
    testImplementation("junit:junit:4.13.2")
    kapt("com.google.dagger:dagger-compiler:$daggerVersion")
    implementation("androidx.room:room-runtime:2.6.1@aar")
    debugImplementation("com.facebook.flipper:flipper:0.+")
}
'''

LEGACY_GRADLE = b'''
dependencies {
    compile group: 'org.apache.commons', name: 'commons-lang3', version: '3.12.0'
    implementation 'com.squareup.retrofit2:retrofit:2.9.0'
}
'''

FILES = {"gradle/libs.versions.toml": CATALOG, "app/build.gradle.kts": APP_GRADLE, "legacy/build.gradle": LEGACY_GRADLE}


def by_name(dependencies: list[dict], name: str) -> dict:
    return next(dep for dep in dependencies if dep["name"] == name)


# --- version catalog and Gradle parsing ----------------------------------------------

def test_version_catalog_resolves_refs_modules_and_accessors() -> None:
    catalog, warnings = parse_version_catalog(CATALOG.decode())
    assert warnings == []
    assert catalog["okhttp"] == {"group": "com.squareup.okhttp3", "name": "okhttp", "version": "4.12.0"}
    assert catalog["androidx.core.ktx"]["version"] == "1.12.0"  # androidx-core-ktx is libs.androidx.core.ktx
    assert catalog["kotlinx.coroutines"]["version"] == "1.7.3"  # strictly = ...
    assert catalog["compose.ui"]["version"] is None  # managed by a BOM


def test_broken_catalog_is_a_warning_not_a_crash() -> None:
    dependencies, warnings = parse_gradle_dependencies({"gradle/libs.versions.toml": b"[versions\n", "app/build.gradle": b"implementation 'a:b:1'"})
    assert any("not valid TOML" in warning for warning in warnings)
    assert by_name(dependencies, "b")["version"] == "1"


def test_parser_handles_catalog_string_map_and_legacy_notation() -> None:
    dependencies, _ = parse_gradle_dependencies(FILES)
    assert by_name(dependencies, "okhttp")["version"] == "4.12.0"
    assert by_name(dependencies, "core-ktx")["version"] == "1.12.0"
    assert by_name(dependencies, "kotlinx-coroutines-android")["version"] == "1.7.3"
    assert by_name(dependencies, "commons-lang3")["version"] == "3.12.0"  # map notation with the legacy "compile"
    assert by_name(dependencies, "retrofit")["configuration"] == "implementation"
    assert by_name(dependencies, "room-runtime")["version"] == "2.6.1"  # @aar stripped


def test_parser_ignores_commented_out_dependencies() -> None:
    dependencies, _ = parse_gradle_dependencies(FILES)
    assert not any(dep["name"] == "out" for dep in dependencies)


def test_parser_classifies_scope_and_version_state() -> None:
    dependencies, _ = parse_gradle_dependencies(FILES)
    assert by_name(dependencies, "junit")["scope"] == "test"
    assert by_name(dependencies, "flipper")["scope"] == "debug-only"
    assert by_name(dependencies, "dagger-compiler")["scope"] == "build-time"
    assert by_name(dependencies, "gson")["version_state"] == "dynamic"
    assert by_name(dependencies, "flipper")["version_state"] == "dynamic"
    dagger = by_name(dependencies, "dagger-compiler")
    assert dagger["version_state"] == "unresolved" and dagger["version"] is None and dagger["version_expression"] == "$daggerVersion"
    ui = by_name(dependencies, "ui")
    assert ui["version_state"] == "unresolved" and ui["version"] is None


def test_platform_entries_are_marked_as_boms() -> None:
    dependencies, _ = parse_gradle_dependencies(FILES)
    assert by_name(dependencies, "compose-bom")["bom"] is True
    assert by_name(dependencies, "okhttp")["bom"] is False


def test_dependency_summary_counts() -> None:
    dependencies, _ = parse_gradle_dependencies(FILES)
    summary = dependency_summary(dependencies)
    assert summary["total"] == len(dependencies) and summary["dynamic"] == 2 and summary["test_only"] == 1


def test_purl_encodes_and_omits_unknown_versions() -> None:
    assert purl({"group": "com.squareup.okhttp3", "name": "okhttp", "version": "4.12.0"}) == "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
    assert purl({"group": "g", "name": "a", "version": None}) == "pkg:maven/g/a"


# --- scanner integration ---------------------------------------------------------------

def scan(files: dict[str, bytes]) -> dict:
    return analyze_source_directory(files, profile="android_app")


def test_scan_reports_dependencies_and_dynamic_version_findings() -> None:
    report = scan(FILES)
    assert report["dependency_summary"]["total"] >= 10
    dynamic = [item for item in report["findings"] if item["rule_id"] == "ANDROID-DEPENDENCY-DYNAMIC-VERSION"]
    assert {item["source_path"] for item in dynamic} == {"app/build.gradle.kts"} and len(dynamic) == 2
    assert all(item["masvs"] == ["MASVS-CODE-3"] and item["fingerprint"] for item in dynamic)
    assert all("2.+" in item["summary"] or "0.+" in item["summary"] for item in dynamic)


def test_dynamic_version_fingerprint_survives_line_shifts() -> None:
    first = scan({"app/build.gradle": b"dependencies {\n implementation 'g:a:1.+'\n}"})
    second = scan({"app/build.gradle": b"\n\n\ndependencies {\n implementation 'g:a:1.+'\n}"})
    fp = lambda report: next(i["fingerprint"] for i in report["findings"] if i["rule_id"] == "ANDROID-DEPENDENCY-DYNAMIC-VERSION")
    assert fp(first) == fp(second)


def test_insecure_repository_is_reported_with_cwe() -> None:
    report = scan({"build.gradle": b'repositories { maven { url "http://repo.example.com/maven" } }'})
    finding = next(item for item in report["findings"] if item["rule_id"] == "ANDROID-GRADLE-INSECURE-REPO")
    assert finding["severity"] == "high" and finding["cwe"] == ["CWE-319"] and "MASVS-CODE-3" in finding["masvs"]


def test_threat_model_marks_the_supply_chain_surface_and_threat() -> None:
    report = scan({**FILES, "build.gradle": b'repositories { maven { url "http://repo.example.com" } }'})
    model = build_threat_model(report)
    assert next(surface for surface in model["surfaces"] if surface["id"] == "supply")["present"]
    assert "T-SUPPLY" in {threat["id"] for threat in model["threats"]}


def test_ai_context_mentions_dependencies_and_missing_advisory_data() -> None:
    context = build_ai_context(scan(FILES), include_locations=False)
    assert "**Dependencies:**" in context and "no advisory data imported" in context


# --- CycloneDX --------------------------------------------------------------------------

def test_cyclonedx_structure_and_determinism() -> None:
    report = scan(FILES)
    bom = to_cyclonedx(report)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["serialNumber"] == to_cyclonedx(report)["serialNumber"]  # same input, same serial
    purls = [component["purl"] for component in bom["components"]]
    assert "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0" in purls
    assert not any("compose-bom" in value for value in purls)  # BOM entries only manage versions
    assert len(purls) == len(set(f"{c['purl']}|{c['scope']}" for c in bom["components"]))
    junit = next(component for component in bom["components"] if component["name"] == "junit")
    assert junit["scope"] == "excluded"
    unresolved = next(component for component in bom["components"] if component["name"] == "ui")
    assert "version" not in unresolved and unresolved["purl"].endswith("/ui")
    state = {p["name"]: p["value"] for p in unresolved["properties"]}
    assert state["aaos:version-state"] == "unresolved"
    assert "declared dependencies only" in bom["metadata"]["properties"][0]["value"]
    gson = next(component for component in bom["components"] if component["name"] == "gson")
    assert "version" not in gson and gson["purl"].endswith("/gson")  # "2.+" is not a release
    assert {"name": "aaos:declared-version", "value": "2.+"} in gson["properties"]


# --- HTML report ----------------------------------------------------------------------------

HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'


def hostile_report() -> dict:
    report = scan({"app/src/Main.kt": b'val k = Cipher.getInstance("DES")', **FILES})
    report["project_name"] = HOSTILE
    report["findings"][0]["title"] = HOSTILE
    report["findings"][0]["evidence"] = HOSTILE
    report["suppressed_findings"] = [{"rule_id": HOSTILE, "evidence": HOSTILE, "suppression": {"kind": "config", "reason": HOSTILE, "expires": ""}}]
    report["policy"] = {"suppressed": 1, "expired": [{"suppression": HOSTILE, "expired_on": HOSTILE}], "unused": [HOSTILE], "warnings": [HOSTILE]}
    report["threat_model"] = build_threat_model(report)
    return report


def test_html_escapes_every_hostile_value() -> None:
    page = to_html(hostile_report())
    assert "<script>" not in page.lower().replace("script-src", "")
    assert "onerror=alert(1)>" not in page and "&lt;script&gt;" in page


def test_html_is_self_contained_and_blocks_network_and_scripts() -> None:
    page = to_html(hostile_report())
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert not re.search(r"<script|<link|<iframe|<object", page, re.IGNORECASE)
    assert not re.search(r'(?:src|href)\s*=\s*["\']https?:', page, re.IGNORECASE)


def test_html_contains_the_sections_a_reader_needs() -> None:
    page = to_html(scan({"app/src/Main.kt": b'val k = Cipher.getInstance("DES")', **FILES}))
    for text in ("<h2>Findings</h2>", "Weak cipher algorithm or mode", "OWASP MASVS coverage", "Applicable threats", "Phased validation plan",
                 "Not covered by this analysis", "Declared dependencies", "heuristic level, not a certification", "CWE-327"):
        assert text in page, text


def test_html_handles_an_empty_report() -> None:
    page = to_html({"findings": []})
    assert "No findings from the rules that ran" in page and "<html" in page


# --- CLI and API -------------------------------------------------------------------------------

def make_project(root: Path) -> Path:
    project = root / "Proj"
    (project / "gradle").mkdir(parents=True)
    (project / "app" / "src" / "main" / "java").mkdir(parents=True)
    (project / "gradle" / "libs.versions.toml").write_bytes(CATALOG)
    (project / "app" / "build.gradle.kts").write_bytes(APP_GRADLE)
    (project / "app" / "src" / "main" / "java" / "Main.kt").write_text('val k = Cipher.getInstance("DES")', encoding="utf-8")
    return project


def test_cli_sbom_and_html_formats(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    project = make_project(tmp_path)
    assert cli_main([str(project), "--format", "sbom"]) == 0
    bom = json.loads(capsys.readouterr().out)
    assert bom["bomFormat"] == "CycloneDX" and any(c["name"] == "okhttp" for c in bom["components"])

    target = tmp_path / "report.html"
    assert cli_main([str(project), "--format", "html", "-o", str(target)]) == 0
    assert "<h2>Findings</h2>" in target.read_text(encoding="utf-8")


def test_export_api_html_and_sbom() -> None:
    report = scan(FILES)

    def post(kind: str) -> httpx.Response:
        async def send() -> httpx.Response:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
                return await client.post(f"/api/export/{kind}", content=json.dumps(report))

        return asyncio.run(send())

    sbom = post("sbom")
    assert sbom.status_code == 200 and sbom.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert sbom.json()["bomFormat"] == "CycloneDX"
    html = post("html")
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert "<h2>Findings</h2>" in html.text
    assert post("pdf").status_code == 404
