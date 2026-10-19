"""The APK path against the real Androguard parser, using compiled binary manifests (see tests/axml.py).

Everything else in the suite fakes the parser; these tests make sure the real library, real binary XML and the
scanner agree, including the attribute and namespace handling that fakes cannot reveal.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import zipfile

import httpx
import pytest

from aaos_auditor.main import app
from aaos_auditor.scanner import analyze_apk
from tests.axml import build_apk, build_axml

MANIFEST = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.oem.climate"
    android:versionCode="42" android:versionName="2.5.1">
  <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="34"/>
  <uses-feature android:name="android.hardware.type.automotive" android:required="true"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
  <uses-permission android:name="android.car.permission.CONTROL_CAR_CLIMATE"/>
  <uses-permission android:name="android.car.permission.CAR_SPEED"/>
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
    <activity android:name=".LinkActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="oem.example" android:pathPrefix="/open"/>
      </intent-filter>
    </activity>
    <service android:name=".NavService" android:exported="true">
      <intent-filter><action android:name="androidx.car.app.CarAppService"/></intent-filter>
    </service>
    <service android:name=".OpenService" android:exported="true"/>
    <service android:name=".GuardedService" android:exported="true" android:permission="com.oem.PERM"/>
    <provider android:name=".Docs" android:authorities="com.oem.docs" android:exported="true" android:grantUriPermissions="true"/>
  </application>
</manifest>'''


@pytest.fixture(scope="module")
def apk() -> bytes:
    return build_apk(MANIFEST, {"lib/arm64-v8a/libvehicle.so": b"binary", "classes.dex": b"dex"})


@pytest.fixture(scope="module")
def report(apk: bytes) -> dict:
    return analyze_apk(apk)


def rule_ids(report: dict) -> list[str]:
    return [finding["rule_id"] for finding in report["findings"]]


# --- metadata read by the real parser ------------------------------------------------------------

def test_real_parser_reads_package_versions_and_sdks(report: dict, apk: bytes) -> None:
    assert report["package_name"] == "com.oem.climate"
    assert report["version_name"] == "2.5.1" and str(report["version_code"]) == "42"
    assert str(report["min_sdk"]) == "29" and str(report["target_sdk"]) == "34"
    assert report["apk_sha256"] == hashlib.sha256(apk).hexdigest()
    assert report["automotive_feature_declared"] is True
    assert report["native_libraries"] == ["lib/arm64-v8a/libvehicle.so"]


def test_real_parser_reads_permissions_and_classifies_car_permissions(report: dict) -> None:
    assert {"android.permission.INTERNET", "android.car.permission.CONTROL_CAR_CLIMATE", "android.car.permission.CAR_SPEED"} <= set(report["permissions"])
    levels = {item["permission"].rsplit(".", 1)[-1]: item["protection_level"] for item in report["car_permissions"]}
    assert levels == {"CONTROL_CAR_CLIMATE": "signature|privileged", "CAR_SPEED": "dangerous"}


# --- findings from boolean attributes in the binary manifest ------------------------------------------

def test_boolean_attributes_in_binary_xml_become_findings(report: dict) -> None:
    found = set(rule_ids(report))
    assert {"ANDROID-DEBUGGABLE", "ANDROID-CLEARTEXT", "ANDROID-BACKUP-ENABLED"} <= found
    debuggable = next(f for f in report["findings"] if f["rule_id"] == "ANDROID-DEBUGGABLE")
    assert debuggable["severity"] == "high" and debuggable["masvs"] and debuggable["cwe"] == ["CWE-489"]


def test_component_inventory_and_exported_values(report: dict) -> None:
    components = {component["name"]: component for component in report["components"]}
    assert {".MainActivity", ".LinkActivity", ".NavService", ".OpenService", ".GuardedService", ".Docs"} <= set(components)
    assert components[".OpenService"]["exported"] == "true"
    assert components[".GuardedService"]["permission"] == "com.oem.PERM"
    assert components[".MainActivity"]["role"] == "launcher" and components[".NavService"]["role"] == "car-app-service"
    assert report["exported_component_count"] >= 5


def test_exported_noise_is_gone_but_real_exposure_remains(report: dict) -> None:
    unguarded = [f["evidence"] for f in report["findings"] if f["rule_id"] == "ANDROID-EXPORTED-UNGUARDED"]
    assert any(".OpenService" in evidence for evidence in unguarded)
    assert not any(".MainActivity" in evidence or ".NavService" in evidence or ".GuardedService" in evidence for evidence in unguarded)


def test_role_review_points_and_unverified_link_from_a_real_apk(report: dict) -> None:
    found = set(rule_ids(report))
    assert {"AAOS-CAR-APP-HOST-VALIDATION", "ANDROID-DEEPLINK-UNVERIFIED", "ANDROID-PROVIDER-GRANT-URI"} <= found


def test_deep_links_and_aaos_findings(report: dict) -> None:
    assert report["deep_links"] == [{"component": ".LinkActivity", "scheme": "https", "host": "oem.example", "path": "/open"}]
    found = set(rule_ids(report))
    assert "AAOS-PRIVILEGED-CAR-PERMISSION" in found and "AAOS-DATA-EGRESS-REVIEW" in found
    assert "AAOS-FEATURE-UNCONFIRMED" not in found  # the automotive feature is declared


def test_every_finding_has_the_enrichment_fields(report: dict) -> None:
    for finding in report["findings"]:
        assert finding["fingerprint"] and "masvs" in finding and "cwe" in finding
    assert report["masvs_summary"]
    assert len({f["fingerprint"] for f in report["findings"]}) == len(report["findings"])


def test_apk_fingerprints_are_stable_across_rebuilds(apk: bytes) -> None:
    first = analyze_apk(apk)
    second = analyze_apk(build_apk(MANIFEST, {"classes.dex": b"different content"}))
    assert {f["fingerprint"] for f in first["findings"]} == {f["fingerprint"] for f in second["findings"]}


# --- robustness ----------------------------------------------------------------------------------------------

def test_minimal_apk_without_application_element() -> None:
    report = analyze_apk(build_apk('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b"/>'))
    assert report["package_name"] == "a.b" and report["components"] == []


def test_apk_with_a_corrupt_binary_manifest_fails_cleanly() -> None:
    corrupt = io.BytesIO()
    with zipfile.ZipFile(corrupt, "w") as archive:
        archive.writestr("AndroidManifest.xml", build_axml(MANIFEST)[:60])
    with pytest.raises(ValueError, match="Failed to analyze the APK|Could not parse"):
        analyze_apk(corrupt.getvalue())


def test_temporary_apk_file_is_removed_after_a_real_analysis(apk: bytes) -> None:
    import glob
    import tempfile

    before = set(glob.glob(f"{tempfile.gettempdir()}/aaos-audit-*.apk"))
    analyze_apk(apk)
    assert set(glob.glob(f"{tempfile.gettempdir()}/aaos-audit-*.apk")) == before


def test_real_apk_through_the_upload_api(apk: bytes) -> None:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
            return await client.post("/api/analyze", data={"authorized": "true"}, files={"file": ("climate.apk", apk, "application/vnd.android.package-archive")})

    response = asyncio.run(send())
    assert response.status_code == 200
    body = response.json()
    assert body["package_name"] == "com.oem.climate" and body["threat_model"]["threats"]
    assert "T-VEHICLE" in {threat["id"] for threat in body["threat_model"]["threats"]}
    assert json.dumps(body)  # serializable end to end
