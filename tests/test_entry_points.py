"""Entry points exported by design (launcher, Car App, media) and web links without verification."""

from __future__ import annotations

from xml.etree import ElementTree

import pytest

from app import scanner
from app.directory_scanner import analyze_source_directory
from app.entry_points import FilterInfo, component_role, unverified_web_link_hosts
from app.scanner import ANDROID_NS, analyze_apk

LAUNCHER = '''<activity android:name=".MainActivity" android:exported="true">
  <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
</activity>'''
CAR_APP = '''<service android:name=".NavService" android:exported="true">
  <intent-filter><action android:name="androidx.car.app.CarAppService"/><category android:name="androidx.car.app.category.NAVIGATION"/></intent-filter>
</service>'''
MEDIA = '''<service android:name=".MediaService" android:exported="true">
  <intent-filter><action android:name="android.media.browse.MediaBrowserService"/></intent-filter>
</service>'''
PLAIN = '<service android:name=".Internal" android:exported="true"/>'
WEB_LINK = '''<activity android:name=".LinkActivity" android:exported="true">
  <intent-filter{verify}><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="{scheme}" android:host="oem.example"/></intent-filter>
</activity>'''


def manifest(*components: str) -> bytes:
    return f'''<manifest xmlns:android="{ANDROID_NS}" package="com.oem.app"><application>{"".join(components)}</application></manifest>'''.encode()


def findings_for(*components: str, profile: str = "aaos") -> list[dict]:
    return analyze_source_directory({"app/src/main/AndroidManifest.xml": manifest(*components)}, profile=profile)["findings"]


def rules(findings: list[dict]) -> list[str]:
    return [finding["rule_id"] for finding in findings]


# --- role detection ----------------------------------------------------------------------

def test_component_role_detection() -> None:
    main = FilterInfo(actions={"android.intent.action.MAIN"}, categories={"android.intent.category.LAUNCHER"})
    assert component_role([main]) == "launcher"
    assert component_role([FilterInfo(actions={"android.intent.action.MAIN"}, categories={"android.intent.category.CAR_LAUNCHER"})]) == "launcher"
    assert component_role([FilterInfo(actions={"androidx.car.app.CarAppService"})]) == "car-app-service"
    assert component_role([FilterInfo(actions={"androidx.media3.session.MediaSessionService"})]) == "media-browser"
    assert component_role([FilterInfo(actions={"android.intent.action.VIEW"})]) is None
    assert component_role([]) is None


# --- the exported-without-permission noise --------------------------------------------------

def test_launcher_activity_is_not_reported_as_unguarded() -> None:
    assert "ANDROID-EXPORTED-UNGUARDED" not in rules(findings_for(LAUNCHER))


def test_launcher_is_not_reported_in_any_profile() -> None:
    for profile in ("aaos", "android_app"):
        found = rules(findings_for(LAUNCHER, profile=profile))
        assert not any(rule.startswith(("ANDROID-EXPORTED-UNGUARDED", "AAOS-CAR-APP", "AAOS-MEDIA")) for rule in found), profile


def test_ordinary_exported_component_is_still_reported() -> None:
    assert rules(findings_for(PLAIN)).count("ANDROID-EXPORTED-UNGUARDED") == 1


def test_car_app_service_gets_a_host_validation_review_point_instead() -> None:
    found = findings_for(CAR_APP)
    assert "ANDROID-EXPORTED-UNGUARDED" not in rules(found)
    point = next(finding for finding in found if finding["rule_id"] == "AAOS-CAR-APP-HOST-VALIDATION")
    assert point["severity"] == "info" and "HostValidator" in point["recommendation"]
    assert point["masvs"] == ["MASVS-PLATFORM-1"] and point["cwe"] == ["CWE-940"]


def test_media_service_gets_a_caller_validation_review_point() -> None:
    found = findings_for(MEDIA)
    assert "ANDROID-EXPORTED-UNGUARDED" not in rules(found)
    assert "AAOS-MEDIA-BROWSER-CALLER-VALIDATION" in rules(found)


def test_review_points_are_aaos_profile_only_but_the_exemption_is_not() -> None:
    found = rules(findings_for(CAR_APP, MEDIA, profile="android_app"))
    assert "AAOS-CAR-APP-HOST-VALIDATION" not in found and "AAOS-MEDIA-BROWSER-CALLER-VALIDATION" not in found
    assert "ANDROID-EXPORTED-UNGUARDED" not in found


def test_non_exported_car_service_has_no_review_point() -> None:
    private = CAR_APP.replace('android:exported="true"', 'android:exported="false"')
    assert "AAOS-CAR-APP-HOST-VALIDATION" not in rules(findings_for(private))


def test_inventory_records_the_role() -> None:
    report = analyze_source_directory({"app/src/main/AndroidManifest.xml": manifest(LAUNCHER, CAR_APP, MEDIA, PLAIN)}, profile="aaos")
    roles = {component["name"]: component["role"] for component in report["components"]}
    assert roles == {".MainActivity": "launcher", ".NavService": "car-app-service", ".MediaService": "media-browser", ".Internal": ""}


# --- web links ----------------------------------------------------------------------------------

def test_unverified_https_link_is_reported() -> None:
    found = findings_for(WEB_LINK.format(verify="", scheme="https"))
    link = next(finding for finding in found if finding["rule_id"] == "ANDROID-DEEPLINK-UNVERIFIED")
    assert link["severity"] == "low" and "oem.example" in link["summary"] and link["cwe"] == ["CWE-939"]


def test_verified_link_and_custom_scheme_link_are_not_reported() -> None:
    assert "ANDROID-DEEPLINK-UNVERIFIED" not in rules(findings_for(WEB_LINK.format(verify=' android:autoVerify="true"', scheme="https")))
    assert "ANDROID-DEEPLINK-UNVERIFIED" not in rules(findings_for(WEB_LINK.format(verify="", scheme="myapp")))


def test_unverified_link_helper_ignores_non_browsable_filters() -> None:
    not_browsable = FilterInfo(actions={"android.intent.action.VIEW"}, schemes={"https"}, hosts={"x.test"})
    assert unverified_web_link_hosts([not_browsable]) == []


# --- the same behavior from a compiled APK ------------------------------------------------------------

class FakeAPK:
    xml = ""

    def __init__(self, path: str) -> None:
        self.path = path

    def get_android_manifest_xml(self):
        return ElementTree.fromstring(self.xml)

    def get_permissions(self) -> list[str]:
        return []

    def get_package(self) -> str:
        return "com.oem.app"

    def get_target_sdk_version(self) -> str:
        return "34"

    def get_min_sdk_version(self) -> str:
        return "29"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"


def apk_zip() -> bytes:
    from io import BytesIO
    import zipfile

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"placeholder parsed by the fake")
    return buffer.getvalue()


def test_apk_scanner_applies_the_same_role_logic(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeAPK.xml = manifest(LAUNCHER, CAR_APP, MEDIA, PLAIN, WEB_LINK.format(verify="", scheme="https")).decode()
    monkeypatch.setattr(scanner, "APK", FakeAPK)
    report = analyze_apk(apk_zip())
    found = [finding["rule_id"] for finding in report["findings"]]
    assert found.count("ANDROID-EXPORTED-UNGUARDED") == 2  # the plain service and the web link activity only
    assert {"AAOS-CAR-APP-HOST-VALIDATION", "AAOS-MEDIA-BROWSER-CALLER-VALIDATION", "ANDROID-DEEPLINK-UNVERIFIED"} <= set(found)
    roles = {component["name"]: component["role"] for component in report["components"]}
    assert roles[".MainActivity"] == "launcher" and roles[".NavService"] == "car-app-service"
