from __future__ import annotations

import asyncio
import hashlib
import json
import os
import zipfile
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

import httpx
import pytest

from app import scanner
from app import ai_advisor
from app.connectors import import_static_report
from app.cli import collect_source_files
from app.cli import main as cli_main
from app import main as main_module
from app.main import app
from app.directory_scanner import analyze_source_directory
from app.knowledge import _load_documents, knowledge_base_status, retrieve_context
from app.pentest_plan import build_pentest_plan
from app.scanner import ANDROID_NS, analyze_apk


def post_analyze(**kwargs: object) -> httpx.Response:
    async def send_request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/api/analyze", **kwargs)

    return asyncio.run(send_request())


def post_directory(*, authorized: bool = True, profile: str = "aaos", files: list[tuple[str, bytes]], paths: list[str]) -> httpx.Response:
    async def send_request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        upload_files = [("files", (name, data, "application/octet-stream")) for name, data in files]
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(
                "/api/analyze-directory",
                data={"authorized": str(authorized).lower(), "profile": profile, "paths": json.dumps(paths)},
                files=upload_files,
            )

    return asyncio.run(send_request())


def post_connector(filename: str, data: bytes, *, authorized: bool = True) -> httpx.Response:
    async def send_request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(
                "/api/connectors/import-static-report",
                data={"authorized": str(authorized).lower()},
                files={"file": (filename, data, "application/json")},
            )

    return asyncio.run(send_request())


def make_zip(*, include_manifest: bool = True, native_libraries: tuple[str, ...] = ()) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        if include_manifest:
            archive.writestr("AndroidManifest.xml", b"placeholder parsed by fake androguard")
        for library in native_libraries:
            archive.writestr(library, b"native binary fixture")
    return buffer.getvalue()


def fake_manifest() -> ElementTree.Element:
    return ElementTree.fromstring(
        f'''<manifest xmlns:android="{ANDROID_NS}">
          <uses-feature android:name="android.hardware.type.automotive" />
          <application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true">
            <activity android:name=".OpenActivity" android:exported="true" />
            <service android:name=".ProtectedService" android:exported="true" android:permission="com.example.ACCESS" />
                        <activity android:name=".DeepLinkActivity">
                            <intent-filter>
                                <action android:name="android.intent.action.VIEW" />
                                <category android:name="android.intent.category.DEFAULT" />
                                <category android:name="android.intent.category.BROWSABLE" />
                                <data android:scheme="https" android:host="example.test" android:pathPrefix="/open" />
                            </intent-filter>
                        </activity>
          </application>
        </manifest>'''
    )


class FakeAPK:
    def __init__(self, path: str) -> None:
        self.path = path

    def get_android_manifest_xml(self) -> ElementTree.Element:
        return fake_manifest()

    def get_permissions(self) -> list[str]:
        return ["android.permission.RECORD_AUDIO", "android.permission.RECORD_AUDIO"]

    def get_package(self) -> str:
        return "com.example.carapp"

    def get_target_sdk_version(self) -> str:
        return "30"

    def get_min_sdk_version(self) -> str:
        return "26"

    def get_androidversion_name(self) -> str:
        return "1.2.3"

    def get_androidversion_code(self) -> str:
        return "12"


def test_rejects_non_zip_input() -> None:
    with pytest.raises(ValueError, match="valid APK/ZIP"):
        analyze_apk(b"not an apk")


def test_rejects_zip_without_manifest() -> None:
    with pytest.raises(ValueError, match="AndroidManifest.xml"):
        analyze_apk(make_zip(include_manifest=False))


def test_reports_manifest_findings_and_removes_temporary_apk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "APK", FakeAPK)

    report = analyze_apk(make_zip())

    assert report["package_name"] == "com.example.carapp"
    assert report["automotive_feature_declared"] is True
    assert report["permission_count"] == 1
    assert report["component_count"] == 3
    assert report["exported_component_count"] == 3
    assert report["components"][0]["name"] == ".OpenActivity"
    assert report["components"][2]["exported"] == "inferred_true"
    assert report["deep_links"] == [{
        "component": ".DeepLinkActivity",
        "scheme": "https",
        "host": "example.test",
        "path": "/open",
    }]
    assert report["native_libraries"] == []
    assert report["apk_sha256"] == hashlib.sha256(make_zip()).hexdigest()
    assert report["apk_size_bytes"] > 0
    assert "analyzed_at" in report
    assert report["risk_level"] == "elevated"
    assert report["severity_counts"]["high"] == 2
    assert {finding["rule_id"] for finding in report["findings"]} >= {
        "ANDROID-DEBUGGABLE",
        "ANDROID-CLEARTEXT",
        "ANDROID-BACKUP-ENABLED",
        "ANDROID-EXPORTED-UNGUARDED",
        "ANDROID-EXPORTED-IMPLICIT",
        "ANDROID-OLD-TARGET-SDK",
        "ANDROID-PERM-RECORD_AUDIO",
    }
    assert "AAOS-FEATURE-UNCONFIRMED" not in {finding["rule_id"] for finding in report["findings"]}


def test_reports_native_library_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "APK", FakeAPK)

    report = analyze_apk(make_zip(native_libraries=("lib/arm64-v8a/libvehicle.so", "lib/x86_64/libcodec.so")))

    assert report["native_libraries"] == ["lib/arm64-v8a/libvehicle.so", "lib/x86_64/libcodec.so"]


def test_removes_temporary_apk_when_analysis_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    class BrokenAPK:
        def __init__(self, path: str) -> None:
            paths.append(path)
            raise RuntimeError("parser error")

    monkeypatch.setattr(scanner, "APK", BrokenAPK)
    with pytest.raises(ValueError, match="Failed to analyze"):
        analyze_apk(make_zip())
    assert paths and not os.path.exists(paths[0])


def test_analysis_endpoint_requires_authorization() -> None:
    response = post_analyze(files={"file": ("app.apk", make_zip())})

    assert response.status_code == 400


def test_knowledge_retrieval_includes_matching_and_general_notes() -> None:
    context, sources = retrieve_context([{
        "rule_id": "ANDROID-CLEARTEXT",
        "title": "Cleartext",
        "severity": "high",
        "summary": "HTTP may be permitted",
        "recommendation": "Validate network policy",
        "evidence": "not sent to AI",
    }])

    source_ids = {source["id"] for source in sources}
    assert {"scope-aaos", "cleartext-networking"} <= source_ids
    assert "application-backup" not in source_ids
    assert "does not show that any endpoint uses HTTP" in context
    assert "not sent to AI" not in context

    export_context, export_sources = retrieve_context([{"rule_id": "ANDROID-EXPORTED-IMPLICIT"}])
    assert {"implicit-export-defaults", "deep-link-validation"} <= {source["id"] for source in export_sources}
    assert "Providers have different default rules" in export_context

    aaos_context, aaos_sources = retrieve_context([{"rule_id": "AAOS-VEHICLE-API-REVIEW"}])
    assert any(source["id"] == "aaos-vehicle-apis" for source in aaos_sources)
    assert "nor interact with CAN/ECUs" in aaos_context


def test_knowledge_base_loads_lazily_and_caches_documents() -> None:
    _load_documents.cache_clear()
    assert knowledge_base_status() == {"loaded": False, "document_count": 0}

    retrieve_context([{"rule_id": "ANDROID-CLEARTEXT"}])

    status = knowledge_base_status()
    assert status["loaded"] is True
    assert status["document_count"] >= 1


def test_pentest_plan_is_manual_and_tailored_to_findings() -> None:
    plan = build_pentest_plan([{"rule_id": "ANDROID-EXPORTED-UNGUARDED"}])
    check_ids = {check["id"] for check in plan["checks"]}

    assert plan["mode"] == "manual_checklist_only"
    assert plan["execution_status"] == "not_executed"
    assert {"PT-SCOPE", "PT-INPUTS", "PT-EXPORTED"} <= check_ids
    assert any("dedicated emulator" in check["method"] for check in plan["checks"] if check["id"] == "PT-EXPORTED")


def test_pentest_plan_adds_deep_link_validation_only_when_present() -> None:
    plan = build_pentest_plan([], [{"component": ".LinkActivity", "scheme": "https"}])

    assert any(check["id"] == "PT-DEEPLINKS" for check in plan["checks"])
    assert not any(check["id"] == "PT-DEEPLINKS" for check in build_pentest_plan([])["checks"])


def test_source_directory_detects_aaos_and_code_risks_without_source_evidence() -> None:
    manifest = f'''<manifest xmlns:android="{ANDROID_NS}" package="com.example.aaos">
      <uses-sdk android:targetSdkVersion="30" />
      <application android:debuggable="true" android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity"><intent-filter><action android:name="android.intent.action.VIEW" /></intent-filter></activity>
      </application>
    </manifest>'''.encode()
    code = b'''webView.getSettings().setJavaScriptEnabled(true)
val manager: android.car.hardware.property.CarPropertyManager? = null
Log.d("auth", "access_token=" + accessToken)
val api_key = "VERY_LONG_TEST_SECRET_VALUE_123"
'''
    report = analyze_source_directory({
        "CarApp/app/src/main/AndroidManifest.xml": manifest,
        "CarApp/app/build.gradle.kts": b'android { namespace = "com.example.aaos"; targetSdk = 30 }',
        "CarApp/app/src/main/java/Main.kt": code,
        "CarApp/app/build/intermediates/ignored.kt": b"setJavaScriptEnabled(true)",
    })

    rule_ids = {finding["rule_id"] for finding in report["findings"]}
    assert report["report_type"] == "source_directory"
    assert report["package_name"] == "com.example.aaos"
    assert report["target_sdk"] == "30"
    assert report["source_file_count"] == 3
    assert report["component_count"] == 1
    assert report["exported_component_count"] == 1
    assert {
        "AAOS-FEATURE-UNCONFIRMED",
        "ANDROID-DEBUGGABLE",
        "ANDROID-CLEARTEXT",
        "ANDROID-EXPORTED-IMPLICIT",
        "ANDROID-OLD-TARGET-SDK",
        "ANDROID-WEBVIEW-JS",
        "ANDROID-LOG-SENSITIVE",
        "ANDROID-SECRET-LITERAL",
        "AAOS-VEHICLE-API-REVIEW",
    } <= rule_ids
    assert all("VERY_LONG_TEST_SECRET_VALUE" not in finding["evidence"] for finding in report["findings"])
    assert not any("ignored.kt" in finding["evidence"] for finding in report["findings"])


def test_source_directory_profile_can_focus_general_android_app_checks() -> None:
    manifest = f'<manifest xmlns:android="{ANDROID_NS}" package="org.example"><application /></manifest>'.encode()
    code = b"val manager: android.car.hardware.property.CarPropertyManager? = null"

    android_report = analyze_source_directory({"app/AndroidManifest.xml": manifest, "app/src/Main.kt": code}, profile="android_app")
    aaos_report = analyze_source_directory({"app/AndroidManifest.xml": manifest, "app/src/Main.kt": code}, profile="aaos")

    assert android_report["analysis_profile"] == "android_app"
    assert "AAOS-FEATURE-UNCONFIRMED" not in {item["rule_id"] for item in android_report["findings"]}
    assert "AAOS-VEHICLE-API-REVIEW" not in {item["rule_id"] for item in android_report["findings"]}
    assert "AAOS-VEHICLE-API-REVIEW" in {item["rule_id"] for item in aaos_report["findings"]}


def test_source_directory_rejects_path_traversal_and_oversized_files() -> None:
    with pytest.raises(ValueError, match="invalid file path"):
        analyze_source_directory({"../secret.kt": b"class A"})
    with pytest.raises(ValueError, match="exceeds 1 MB"):
        analyze_source_directory({"src/Main.kt": b"x" * 1_000_001})


def test_source_directory_reports_android_12_manifest_build_blocker_and_sdk_mismatch() -> None:
        manifest = f'''<manifest xmlns:android="{ANDROID_NS}" package="org.example">
            <application><activity android:name=".Main"><intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.test" />
            </intent-filter></activity></application>
        </manifest>'''.encode()
        report = analyze_source_directory({
                "app/src/main/AndroidManifest.xml": manifest,
                "app/build.gradle": b'android { compileSdk = 30; defaultConfig { targetSdk = 35 } }',
        })

        findings = {finding["rule_id"] for finding in report["findings"]}
        assert "ANDROID-EXPORTED-BUILD-ERROR" in findings
        assert "ANDROID-COMPILE-SDK-BELOW-TARGET" in findings
        assert report["risk_level"] == "elevated"


def test_source_directory_skips_binaries_and_reports_missing_project_files() -> None:
    with pytest.raises(ValueError, match="supported Android files"):
        analyze_source_directory({"README.txt": b"documentation only", "image.png": b"binary"})

    report = analyze_source_directory({"src/Main.kt": b"class Main"})
    assert "AAOS-MANIFEST-MISSING" in {finding["rule_id"] for finding in report["findings"]}
    assert "ANDROID-BUILD-CONFIG-MISSING" in {finding["rule_id"] for finding in report["findings"]}


def test_directory_analysis_api_requires_authorization_and_returns_report(monkeypatch: pytest.MonkeyPatch) -> None:
    unauthorized = post_directory(authorized=False, files=[("app/src/Main.kt", b"class Main")], paths=["app/src/Main.kt"])
    assert unauthorized.status_code == 400
    monkeypatch.setattr(main_module, "ai_is_configured", lambda: False)

    response = post_directory(
        files=[("AndroidManifest.xml", b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>'), ("build.gradle", b'android { namespace = "org.demo" }')],
        paths=["Demo/app/src/main/AndroidManifest.xml", "Demo/app/build.gradle"],
    )

    assert response.status_code == 200
    report = response.json()
    assert report["report_type"] == "source_directory"
    assert report["package_name"] == "org.demo"
    assert report["pentest_plan"]["execution_status"] == "not_executed"


def test_directory_analysis_api_rejects_traversal_and_total_size(monkeypatch: pytest.MonkeyPatch) -> None:
    traversal = post_directory(files=[("x.kt", b"class Main")], paths=["../x.kt"])
    assert traversal.status_code == 422

    monkeypatch.setattr(main_module, "MAX_DIRECTORY_UPLOAD_BYTES", 3)
    oversized = post_directory(files=[("x.kt", b"class Main")], paths=["Demo/x.kt"])
    assert oversized.status_code == 413


def test_local_cli_reads_only_supported_source_and_emits_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "Project"
    source_dir = root / "app" / "src" / "main"
    build_dir = root / "app" / "build"
    source_dir.mkdir(parents=True)
    build_dir.mkdir(parents=True)
    (source_dir / "Main.kt").write_text('fun main() { val manager = "android.car.CarPropertyManager" }', encoding="utf-8")
    (build_dir / "Generated.kt").write_text("not included", encoding="utf-8")
    (root / "README.md").write_text("documentation", encoding="utf-8")

    files = collect_source_files(root)
    assert list(files) == ["app/src/main/Main.kt"]

    exit_code = cli_main([str(root), "--profile", "aaos"])
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert exit_code == 0
    assert report["report_type"] == "source_directory"
    assert report["source_file_count"] == 1
    assert report["analysis_profile"] == "aaos"


def test_directory_analysis_api_accepts_selected_general_profile() -> None:
    manifest = f'<manifest xmlns:android="{ANDROID_NS}" package="org.example"><application /></manifest>'.encode()
    response = post_directory(
        profile="android_app",
        files=[("AndroidManifest.xml", manifest)],
        paths=["Demo/app/src/main/AndroidManifest.xml"],
    )
    assert response.status_code == 200
    assert response.json()["analysis_profile"] == "android_app"


def test_semgrep_connector_imports_rule_and_path_without_message_or_source() -> None:
    data = json.dumps({"results": [{
        "check_id": "java.lang.security.audit.crypto",
        "path": "app/src/Main.kt",
        "start": {"line": 17},
        "extra": {"severity": "ERROR", "message": "Contains FAKE_SECRET_CONTENT"},
    }]}).encode()

    imported = import_static_report(data, "results.json")

    assert imported["connector"] == "Semgrep"
    finding = imported["findings"][0]
    assert finding["severity"] == "high"
    assert finding["evidence"] == "app/src/Main.kt:17"
    assert "FAKE_SECRET_CONTENT" not in str(imported)


def test_sarif_connector_import_and_authorization() -> None:
    sarif = json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Semgrep", "rules": []}},
            "results": [{
                "ruleId": "android.webview",
                "level": "warning",
                "message": {"text": "Sensitive code excerpt must not be imported"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/Main.java"},
                    "region": {"startLine": 24},
                }}],
            }],
        }],
    }).encode()
    unauthorized = post_connector("findings.sarif", sarif, authorized=False)
    authorized = post_connector("findings.sarif", sarif)

    assert unauthorized.status_code == 400
    assert authorized.status_code == 200
    finding = authorized.json()["findings"][0]
    assert finding["severity"] == "medium"
    assert finding["evidence"] == "src/Main.java:24"
    assert "Sensitive code excerpt" not in str(authorized.json())


def test_connector_endpoint_rejects_unsupported_format_invalid_json_and_large_report(monkeypatch: pytest.MonkeyPatch) -> None:
    unsupported = post_connector("results.txt", b"{}")
    malformed = post_connector("results.json", b"not json")
    assert unsupported.status_code == 415
    assert malformed.status_code == 422

    monkeypatch.setattr(main_module, "MAX_CONNECTOR_REPORT_BYTES", 3)
    oversized = post_connector("results.json", b'{"results":[]}')
    assert oversized.status_code == 413


def test_analysis_endpoint_rejects_non_apk_filename() -> None:
    response = post_analyze(
        data={"authorized": "true"},
        files={"file": ("app.zip", make_zip())},
    )

    assert response.status_code == 415


def test_authorized_analysis_endpoint_returns_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "APK", FakeAPK)
    monkeypatch.setattr(main_module, "ai_is_configured", lambda: False)
    monkeypatch.setattr(main_module, "explain_findings", lambda findings, knowledge_context="": asyncio.sleep(0, result=None))

    response = post_analyze(
        data={"authorized": "true"},
        files={"file": ("app.apk", make_zip(native_libraries=("lib/arm64-v8a/libvehicle.so",)))},
    )

    assert response.status_code == 200
    report = response.json()
    assert report["component_count"] == 3
    assert report["exported_component_count"] == 3
    assert report["native_libraries"] == ["lib/arm64-v8a/libvehicle.so"]
    assert report["ai_context_sources"] == []
    assert report["pentest_plan"]["execution_status"] == "not_executed"
    assert any(check["id"] == "PT-EXPORTED" for check in report["pentest_plan"]["checks"])
    assert any(check["id"] == "PT-DEEPLINKS" for check in report["pentest_plan"]["checks"])


def test_analysis_endpoint_enforces_upload_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "MAX_UPLOAD_BYTES", 3)

    response = post_analyze(
        data={"authorized": "true"},
        files={"file": ("app.apk", b"1234")},
    )

    assert response.status_code == 413


def test_ai_advisor_sends_only_summarized_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": "Review the permission with the team."}}]}

    class FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            assert timeout > 0

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def post(self, url: str, *, json: dict[str, object], headers: dict[str, str]) -> FakeResponse:
            captured["url"] = url
            captured["payload"] = json
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setenv("AI_BASE_URL", "http://ai.local/v1")
    monkeypatch.setenv("AI_MODEL", "local-model")
    monkeypatch.setenv("AI_PROVIDER", "openai-compatible")
    monkeypatch.setattr(ai_advisor.httpx, "AsyncClient", FakeAsyncClient)

    response = asyncio.run(ai_advisor.explain_findings([{
        "rule_id": "ANDROID-TEST",
        "title": "Test",
        "severity": "medium",
        "summary": "Finding summary",
        "recommendation": "Review",
        "evidence": "sensitive evidence not sent",
    }]))

    assert response == "Review the permission with the team."
    assert captured["url"] == "http://ai.local/v1/chat/completions"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    serialized = str(payload)
    assert "sensitive evidence not sent" not in serialized
    assert "ANDROID-TEST" in serialized


def test_claude_uses_anthropic_messages_api(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"content": [{"type": "text", "text": "Review the backup configuration."}]}

    class FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            assert timeout == 20.0

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def post(self, url: str, *, json: dict[str, object], headers: dict[str, str]) -> FakeResponse:
            captured["url"] = url
            captured["payload"] = json
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("AI_MODEL", "claude-test-model")
    monkeypatch.setenv("AI_API_KEY", "test-api-key")
    monkeypatch.setenv("AI_BASE_URL", "")
    monkeypatch.setattr(ai_advisor.httpx, "AsyncClient", FakeAsyncClient)

    response = asyncio.run(ai_advisor.explain_findings([{
        "rule_id": "ANDROID-TEST",
        "title": "Backup",
        "severity": "medium",
        "summary": "Backup allowed",
        "recommendation": "Review rules",
        "evidence": "must not be sent",
    }], knowledge_context="Curated context: validate backup rules."))

    assert response == "Review the backup configuration."
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"] == {
        "Content-Type": "application/json",
        "x-api-key": "test-api-key",
        "anthropic-version": "2023-06-01",
    }
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["model"] == "claude-test-model"
    assert "system" in payload
    assert "must not be sent" not in str(payload)
    assert "Curated context: validate backup rules." in str(payload)
