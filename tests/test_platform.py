"""Platform profile: build properties, SELinux, init scripts, privileged permissions, Soong."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from aaos_auditor.ai_context import build_ai_context
from aaos_auditor.cli import collect_platform_files
from aaos_auditor.cli import main as cli_main
from aaos_auditor.exporters import to_markdown, to_sarif
from aaos_auditor.html_report import to_html
from aaos_auditor.main import app
from aaos_auditor.pentest_plan import build_pentest_plan
from aaos_auditor.platform_scanner import (
    PLATFORM_RULES,
    analyze_platform_directory,
    parse_properties,
    platform_file_kind,
)
from aaos_auditor.policy import apply_policy, parse_policy
from aaos_auditor.rules_catalog import rule_catalog
from aaos_auditor.threat_model import build_threat_model

DIR = "device/oem/car"


def scan(files: dict[str, str] | dict[str, bytes]) -> dict:
    encoded = {path: (data.encode() if isinstance(data, str) else data) for path, data in files.items()}
    return analyze_platform_directory(encoded, project_name="oem-car")


def ids(report: dict) -> list[str]:
    return [finding["rule_id"] for finding in report["findings"]]


def one(name: str, text: str, **extra: str) -> list[str]:
    return ids(scan({f"{DIR}/{name}": text, **extra}))


# --- build properties -------------------------------------------------------------------------------

def test_parse_properties_reads_both_formats_and_the_last_definition_wins() -> None:
    entries = parse_properties("# c\nro.debuggable=1\nro.debuggable=0\n[ro.secure]: [0]\nimport x\n\nro.build.tags = release-keys\n")
    assert {(key, value) for _, key, value, _ in entries} == {("ro.debuggable", "0"), ("ro.secure", "0"), ("ro.build.tags", "release-keys")}


@pytest.mark.parametrize("line,rule", [
    ("ro.debuggable=1", "PLATFORM-PROP-DEBUGGABLE"),
    ("ro.secure=0", "PLATFORM-PROP-INSECURE-ADBD"),
    ("ro.adb.secure=0", "PLATFORM-PROP-ADB-UNAUTHENTICATED"),
    ("ro.build.tags=test-keys", "PLATFORM-PROP-TEST-KEYS"),
    ("ro.build.tags=dev-keys,test-keys", "PLATFORM-PROP-TEST-KEYS"),
    ("ro.build.type=eng", "PLATFORM-PROP-BUILD-TYPE"),
    ("ro.build.type=userdebug", "PLATFORM-PROP-BUILD-TYPE"),
    ("persist.sys.usb.config=mtp,adb", "PLATFORM-PROP-ADB-ENABLED"),
    ("persist.service.adb.enable=1", "PLATFORM-PROP-ADB-ENABLED"),
    ("service.adb.root=1", "PLATFORM-PROP-ADB-ROOT"),
    ("ro.allow.mock.location=1", "PLATFORM-PROP-MOCK-LOCATION"),
    ("ro.boot.verifiedbootstate=orange", "PLATFORM-PROP-VERIFIED-BOOT"),
    ("ro.boot.flash.locked=0", "PLATFORM-PROP-VERIFIED-BOOT"),
    ("ro.boot.veritymode=disabled", "PLATFORM-PROP-VERIFIED-BOOT"),
    ("ro.boot.selinux=permissive", "PLATFORM-PROP-SELINUX-PERMISSIVE"),
    ("ro.control_privapp_permissions=log", "PLATFORM-PROP-PRIVAPP-LOG"),
])
def test_insecure_properties_are_flagged(line: str, rule: str) -> None:
    assert rule in one("build.prop", line + "\n")


@pytest.mark.parametrize("line", [
    "ro.debuggable=0", "ro.secure=1", "ro.adb.secure=1", "ro.build.tags=release-keys", "ro.build.type=user",
    "persist.sys.usb.config=mtp", "service.adb.root=0", "ro.allow.mock.location=0", "ro.boot.verifiedbootstate=green",
    "ro.boot.flash.locked=1", "ro.boot.veritymode=enforcing", "ro.control_privapp_permissions=enforce", "ro.product.model=Car1",
    "# ro.debuggable=1",
])
def test_secure_properties_are_not_flagged(line: str) -> None:
    assert one("build.prop", line + "\n") == []


def test_property_overridden_later_in_the_same_file_is_judged_by_its_final_value() -> None:
    assert one("build.prop", "ro.debuggable=1\nro.debuggable=0\n") == []
    assert "PLATFORM-PROP-DEBUGGABLE" in one("build.prop", "ro.debuggable=0\nro.debuggable=1\n")


def test_build_type_severity_depends_on_the_value() -> None:
    severity = lambda value: next(f["severity"] for f in scan({f"{DIR}/build.prop": f"ro.build.type={value}\n"})["findings"])
    assert severity("eng") == "high" and severity("userdebug") == "medium"


def test_getprop_dump_of_a_unit_is_understood() -> None:
    assert "PLATFORM-PROP-DEBUGGABLE" in one("getprop.prop", "[ro.debuggable]: [1]\n[ro.product.model]: [Car1]\n")


# --- .mk ---------------------------------------------------------------------------------------------------

def test_makefile_signing_avb_cmdline_and_property_overrides() -> None:
    mk = (
        "BOARD_AVB_ENABLE := false\n"
        "PRODUCT_DEFAULT_DEV_CERTIFICATE := build/make/target/product/security/testkey\n"
        "BOARD_KERNEL_CMDLINE += androidboot.selinux=permissive\n"
        "PRODUCT_PROPERTY_OVERRIDES += \\\n    ro.adb.secure=0 \\\n    ro.product.name=car\n"
    )
    found = one("BoardConfig.mk", mk)
    assert {"PLATFORM-MK-AVB-DISABLED", "PLATFORM-MK-TEST-KEYS", "PLATFORM-PROP-SELINUX-PERMISSIVE", "PLATFORM-PROP-ADB-UNAUTHENTICATED"} <= set(found)


def test_makefile_safe_configuration_and_commented_lines() -> None:
    mk = (
        "BOARD_AVB_ENABLE := true\n"
        "PRODUCT_DEFAULT_DEV_CERTIFICATE := vendor/oem/security/release\n"
        "# BOARD_AVB_ENABLE := false\n"
        "ro.adb.secure=0\n"  # not inside a PRODUCT_*PROPERT* assignment
    )
    assert one("BoardConfig.mk", mk) == []


# --- SELinux -------------------------------------------------------------------------------------------------

def test_sepolicy_flags_permissive_unconfined_wildcards_and_capabilities() -> None:
    te = (
        "permissive hal_x;\n"
        "unconfined_domain(hal_y)\n"
        "allow hal_x hal_x_data:file *;\n"
        "allow hal_x self:capability { sys_admin net_admin };\n"
        "allow hal_x self:capability sys_module;\n"
        "allow hal_x self:capability2 dac_override;\n"
    )
    found = one("sepolicy/hal_x.te", te)
    assert found.count("PLATFORM-SEPOLICY-DANGEROUS-CAPABILITY") == 3  # sys_admin, sys_module, dac_override
    assert {"PLATFORM-SEPOLICY-PERMISSIVE", "PLATFORM-SEPOLICY-UNCONFINED", "PLATFORM-SEPOLICY-ALLOW-ALL"} <= set(found)


def test_sepolicy_ignores_userdebug_blocks_comments_and_narrow_rules() -> None:
    te = (
        "# permissive in a comment: permissive hal_c;\n"
        "userdebug_or_eng(`\n  permissive hal_dev;\n  allow hal_dev self:capability sys_admin;\n  userdebug_or_eng(`nested')\n')\n"
        "allow hal_x vendor_file:file { read open getattr };\n"
        "allow hal_x self:capability net_admin;\n"
        "neverallow { domain -hal_x } hal_x_data:file *;\n"
        "dontaudit hal_x self:capability sys_admin;\n"
    )
    assert one("sepolicy/hal_x.te", te) == []


def test_sepolicy_rule_after_a_userdebug_block_is_still_checked() -> None:
    te = "userdebug_or_eng(`\n  permissive a;\n')\npermissive b;\n"
    report = scan({f"{DIR}/x.te": te})
    assert [f["line"] for f in report["findings"]] == ["4"]


def test_sepolicy_multiline_rule_and_line_numbers() -> None:
    te = "\n\nallow hal_x self:capability {\n    sys_ptrace\n    net_admin\n};\n"
    finding = scan({f"{DIR}/x.te": te})["findings"][0]
    assert finding["rule_id"] == "PLATFORM-SEPOLICY-DANGEROUS-CAPABILITY" and finding["line"] == "3" and "sys_ptrace" in finding["title"]


# --- init ------------------------------------------------------------------------------------------------------

INIT = """
service carhal /vendor/bin/carhal
    class hal
    user root
service implicit /vendor/bin/implicit
    class hal
service good /vendor/bin/good
    user system
    group system
service restricted /vendor/bin/restricted
    capabilities NET_BIND_SERVICE
service sulike /system/bin/x
    user system
    seclabel u:r:su:s0
on boot
    chmod 0777 /data/vendor/car
    chmod 0660 /data/vendor/safe
    chmod 0666 /dev/null
    mkdir /data/vendor/open 0777
    mkdir /data/vendor/closed 0750
    write /proc/sys/kernel/kptr_restrict 0
    write /proc/sys/kernel/kptr_restrict 2
    exec - root -- /system/bin/setenforce 0
    write /sys/fs/selinux/enforce 0
    setprop persist.sys.usb.config adb
on property:ro.debuggable=1
    setenforce 0
    chmod 0777 /data/local
service dbg /system/bin/dbg
"""


def test_init_findings_cover_each_pattern() -> None:
    report = scan({f"{DIR}/init.car.rc": INIT})
    found = ids(report)
    assert found.count("PLATFORM-INIT-ROOT-SERVICE") == 3  # carhal, implicit and the service after the debuggable trigger section
    assert found.count("PLATFORM-INIT-SELINUX-DISABLED") == 2
    assert found.count("PLATFORM-INIT-WORLD-ACCESSIBLE") == 2  # chmod 0777 and mkdir 0777
    assert {"PLATFORM-INIT-SU-SERVICE", "PLATFORM-INIT-KERNEL-HARDENING-OFF", "PLATFORM-INIT-ADB-ENABLED"} <= set(found)


def test_init_precision_good_services_standard_nodes_and_debug_triggers() -> None:
    titles = " | ".join(f["title"] for f in scan({f"{DIR}/init.car.rc": INIT})["findings"])
    assert "Service good" not in titles  # runs as an explicit non-root user
    assert "Service restricted" not in titles and "/dev/null" not in titles and "/data/local" not in titles


def test_init_root_service_message_distinguishes_explicit_and_implicit_root() -> None:
    findings = {f["title"]: f["summary"] for f in scan({f"{DIR}/init.rc": INIT})["findings"] if f["rule_id"] == "PLATFORM-INIT-ROOT-SERVICE"}
    assert "declares user root" in findings["Service carhal runs as root"]
    assert "defaults to root" in findings["Service implicit runs as root"]


@pytest.mark.parametrize("socket,flagged", [
    ("socket carhal stream 0666 system system", True),
    ("socket carhal stream 666 system system", True),
    ("socket carhal stream 0660 system system", False),
    ("socket logdw dgram+passcred 0222 logd logd", False),  # write-only sockets (logging) are by design
    ("socket carhal stream 0664 system system", False),
])
def test_init_socket_modes(socket: str, flagged: bool) -> None:
    text = f"service x /bin/x\n    user system\n    {socket}\n"
    assert ("PLATFORM-INIT-WORLD-ACCESSIBLE" in one("init.rc", text)) is flagged


def test_init_comments_are_ignored() -> None:
    assert one("init.rc", "on boot\n    # setenforce 0\n    # chmod 0777 /data/x\n") == []


# --- privileged and default permissions -------------------------------------------------------------------------

PRIVAPP = """<permissions>
  <privapp-permissions package="com.oem.climate">
    <permission name="android.permission.INSTALL_PACKAGES"/>
    <permission name="android.car.permission.CONTROL_CAR_CLIMATE"/>
    <permission name="android.permission.REBOOT"/>
    <permission name="android.permission.UNUSED_ONE"/>
    <deny-permission name="android.permission.READ_FRAME_BUFFER"/>
  </privapp-permissions>
</permissions>"""
MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.oem.climate">
  <uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
  <uses-permission android:name="android.car.permission.CONTROL_CAR_CLIMATE"/>
  <uses-permission android:name="android.car.permission.CAR_DIAGNOSTICS"/>
  <uses-permission android:name="android.car.permission.CAR_SPEED"/>
  <uses-permission android:name="android.permission.REBOOT"/>
  <uses-permission android:name="android.permission.READ_FRAME_BUFFER"/>
</manifest>"""


def privapp_report(manifest: str | None = MANIFEST) -> dict:
    files = {f"{DIR}/permissions/privapp-permissions-oem.xml": PRIVAPP}
    if manifest is not None:
        files[f"{DIR}/apps/climate/AndroidManifest.xml"] = manifest
    return scan(files)


def test_privapp_flags_powerful_grants_and_vehicle_control() -> None:
    report = privapp_report()
    titles = [f["title"] for f in report["findings"] if f["rule_id"] == "PLATFORM-PRIVAPP-POWERFUL-PERMISSION"]
    assert "com.oem.climate is allowed to install any app" in titles and "com.oem.climate is allowed to reboot the device" in titles
    assert "PLATFORM-PRIVAPP-VEHICLE-CONTROL" in ids(report)


def test_privapp_cross_check_with_the_manifest() -> None:
    report = privapp_report()
    unused = [f["title"] for f in report["findings"] if f["rule_id"] == "PLATFORM-PRIVAPP-UNUSED-GRANT"]
    assert unused == ["com.oem.climate is allow-listed for a permission it does not request"] and "UNUSED_ONE" in report["findings"][
        [f["rule_id"] for f in report["findings"]].index("PLATFORM-PRIVAPP-UNUSED-GRANT")]["summary"]
    missing = [f for f in report["findings"] if f["rule_id"] == "PLATFORM-PRIVAPP-MISSING-GRANT"]
    assert len(missing) == 1 and "CAR_DIAGNOSTICS" in missing[0]["title"]  # CAR_SPEED is dangerous-level, not system-only
    assert "Android 9" in missing[0]["summary"]


def test_privapp_deny_entry_counts_as_a_decision() -> None:
    manifest = MANIFEST.replace("android.car.permission.CAR_DIAGNOSTICS", "android.car.permission.CAR_ENERGY")
    deny = PRIVAPP.replace("</privapp-permissions>", '<deny-permission name="android.car.permission.CAR_DIAGNOSTICS"/></privapp-permissions>')
    report = scan({f"{DIR}/permissions/privapp-permissions-oem.xml": deny, f"{DIR}/AndroidManifest.xml": manifest.replace("CAR_ENERGY", "CAR_DIAGNOSTICS")})
    assert "PLATFORM-PRIVAPP-MISSING-GRANT" not in ids(report)


def test_privapp_without_a_manifest_only_reviews_the_grants() -> None:
    found = ids(privapp_report(manifest=None))
    assert "PLATFORM-PRIVAPP-POWERFUL-PERMISSION" in found
    assert "PLATFORM-PRIVAPP-UNUSED-GRANT" not in found and "PLATFORM-PRIVAPP-MISSING-GRANT" not in found


def test_privapp_xml_with_entities_or_garbage_is_ignored_safely() -> None:
    bomb = '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "x">]><permissions><privapp-permissions package="p"><permission name="android.permission.INSTALL_PACKAGES"/></privapp-permissions></permissions>'
    assert one("permissions/privapp-permissions-x.xml", bomb) == []
    assert one("permissions/privapp-permissions-y.xml", "<permissions><oops") == []


def test_default_permissions_sensitive_grants() -> None:
    xml = """<exceptions><exception package="com.oem.nav">
      <permission name="android.permission.ACCESS_FINE_LOCATION" fixed="true"/>
      <permission name="android.permission.RECORD_AUDIO" fixed="false"/>
      <permission name="android.permission.VIBRATE" fixed="true"/></exception></exceptions>"""
    report = scan({f"{DIR}/permissions/default-permissions-oem.xml": xml})
    severity = {f["title"].split()[3]: f["severity"] for f in report["findings"]}
    assert severity == {"ACCESS_FINE_LOCATION": "medium", "RECORD_AUDIO": "low"}
    assert "cannot revoke" in next(f["title"] for f in report["findings"] if f["severity"] == "medium")


# --- Soong ---------------------------------------------------------------------------------------------------------

def test_soong_platform_signed_apps_and_inventory() -> None:
    bp = (
        'android_app {\n    name: "OemClimate",\n    certificate: "platform",\n    privileged: true,\n    platform_apis: true,\n}\n'
        'android_app { name: "Plain", certificate: "PRESIGNED" }\n'
        '// android_app { name: "Commented", certificate: "platform" }\n'
        '/* android_app { name: "Block", certificate: "platform" } */\n'
    )
    report = scan({f"{DIR}/apps/climate/Android.bp": bp})
    assert [f["title"] for f in report["findings"]] == ["OemClimate is signed with the platform certificate"]
    assert "also privileged" in report["findings"][0]["summary"]
    assert {m["name"] for m in report["platform_apps"]} == {"OemClimate", "Plain"}
    assert report["platform_apps"][0]["privileged"] is True and report["platform_apps"][0]["platform_apis"] is True


# --- file selection and limits -----------------------------------------------------------------------------------

def test_file_kinds() -> None:
    kinds = {
        "device/x/build.prop": "prop", "system/default.prop": "prop", "a/getprop.prop": "prop", "a/BoardConfig.mk": "mk",
        "sepolicy/a.te": "sepolicy", "init.car.rc": "init", "etc/permissions/privapp-permissions-oem.xml": "privapp",
        "etc/default-permissions/default-permissions-oem.xml": "default-permissions", "apps/Android.bp": "soong",
        "apps/AndroidManifest.xml": "manifest", "apps/Main.kt": None, "README.md": None,
    }
    assert {path: platform_file_kind(path) for path in kinds} == kinds


def test_irrelevant_ignored_and_invalid_paths() -> None:
    report = scan({f"{DIR}/build.prop": "ro.debuggable=1\n", "out/target/build.prop": "ro.debuggable=1\n", ".git/x/build.prop": "ro.debuggable=1\n", "README.md": "hello"})
    assert report["source_file_count"] == 1 and len(report["findings"]) == 1
    with pytest.raises(ValueError, match="invalid file path"):
        scan({"../build.prop": "ro.debuggable=1\n"})
    with pytest.raises(ValueError, match="No platform files found"):
        scan({"README.md": "x", "Main.kt": "class A"})
    with pytest.raises(ValueError, match="exceeds 1 MB"):
        analyze_platform_directory({"build.prop": b"a" * 1_000_001})


def test_findings_per_rule_per_file_are_bounded() -> None:
    text = "".join(f"permissive d{i};\n" for i in range(100))
    assert len(scan({f"{DIR}/x.te": text})["findings"]) == 25


# --- report shape, fingerprints, policy --------------------------------------------------------------------------

def test_report_has_the_shape_the_rest_of_the_tool_expects() -> None:
    report = scan({f"{DIR}/build.prop": "ro.debuggable=1\nro.build.tags=test-keys\n"})
    assert report["report_type"] == "source_directory" and report["analysis_profile"] == "platform"
    assert report["risk_level"] == "elevated" and report["severity_counts"]["high"] == 2
    assert report["platform_files"] == {"prop": 1} and report["source_sha256"]
    for finding in report["findings"]:
        assert finding["fingerprint"] and finding["cwe"] and finding["masvs"] == [] and "_anchor" not in finding
        assert finding["evidence"] == f"{finding['source_path']}:{finding['line']}"


def test_fingerprints_survive_line_shifts() -> None:
    first = scan({f"{DIR}/build.prop": "ro.debuggable=1\n"})["findings"][0]["fingerprint"]
    second = scan({f"{DIR}/build.prop": "# a\n# b\n\nro.debuggable=1\n"})["findings"][0]["fingerprint"]
    assert first == second


def test_project_policy_applies_to_platform_reports_including_inline_ignores() -> None:
    files = {
        f"{DIR}/build.prop": b"ro.debuggable=1\nro.build.type=userdebug\n",
        f"{DIR}/init.rc": b"service legacy /bin/legacy\n    # aaos-ignore[PLATFORM-INIT-ROOT-SERVICE]: legacy daemon, migration tracked in the vendor backlog\n",
    }
    report = analyze_platform_directory(files)
    policy = parse_policy(
        '[settings]\nfail_on = "high"\n[[suppress]]\nrule = "PLATFORM-PROP-BUILD-TYPE"\npath = "device/oem/car/build.prop"\n'
        'reason = "bench fleet image, never shipped"\n'
    )
    apply_policy(report, policy, files)
    assert "PLATFORM-PROP-BUILD-TYPE" not in ids(report) and "PLATFORM-PROP-DEBUGGABLE" in ids(report)
    assert report["policy"]["by_kind"]["config"] == 1


def test_platform_rules_are_in_the_catalog_with_cwe_where_known() -> None:
    catalog = {entry["id"]: entry for entry in rule_catalog()}
    assert {rule["id"] for rule in PLATFORM_RULES} <= set(catalog)
    assert all(catalog[rule["id"]]["scope"] == "platform" for rule in PLATFORM_RULES)
    assert catalog["PLATFORM-PROP-TEST-KEYS"]["cwe"] == ["CWE-321"]


SAMPLE = {
    f"{DIR}/build.prop": "ro.debuggable=1\nro.secure=0\nro.adb.secure=0\nro.build.tags=test-keys\nro.build.type=userdebug\npersist.sys.usb.config=adb\n"
                         "service.adb.root=1\nro.allow.mock.location=1\nro.boot.verifiedbootstate=orange\nro.boot.selinux=permissive\nro.control_privapp_permissions=log\n",
    f"{DIR}/BoardConfig.mk": "BOARD_AVB_ENABLE := false\nPRODUCT_DEFAULT_DEV_CERTIFICATE := build/make/target/product/security/testkey\n",
    f"{DIR}/x.te": "permissive a;\nunconfined_domain(b)\nallow c d:file *;\nallow e self:capability sys_admin;\n",
    f"{DIR}/init.rc": INIT,
    f"{DIR}/permissions/privapp-permissions-oem.xml": PRIVAPP,
    f"{DIR}/apps/climate/AndroidManifest.xml": MANIFEST,
    f"{DIR}/permissions/default-permissions-oem.xml": '<exceptions><exception package="a"><permission name="android.permission.CAMERA" fixed="true"/></exception></exceptions>',
    f"{DIR}/apps/climate/Android.bp": 'android_app { name: "A", certificate: "platform" }',
}


def test_every_platform_rule_is_demonstrated_by_the_sample_set() -> None:
    produced = set(ids(scan(SAMPLE)))
    missing = {rule["id"] for rule in PLATFORM_RULES} - produced
    assert missing == set(), f"no sample produces: {sorted(missing)}"


# --- threat model, plan and exports ------------------------------------------------------------------------------------

def test_threat_model_and_plan_for_a_platform_report() -> None:
    report = scan(SAMPLE)
    report["pentest_plan"] = build_pentest_plan(report["findings"], [], "platform")
    model = build_threat_model(report)
    assert {"T-PLATFORM-BUILD", "T-PLATFORM-MAC", "T-PLATFORM-PRIVILEGE", "T-PLATFORM-HARDENING"} <= {t["id"] for t in model["threats"]}
    assert next(s for s in model["surfaces"] if s["id"] == "platform")["present"]
    assert any("Binaries and native code" in item for item in model["not_assessed"])
    assert not any("Dependencies and CVEs" in item for item in model["not_assessed"])
    check_ids = {check["id"] for check in report["pentest_plan"]["checks"]}
    assert {"PT-SCOPE", "PT-PLATFORM-BUILD", "PT-PLATFORM-MAC", "PT-PLATFORM-PRIVILEGE"} <= check_ids
    assert "PT-INPUTS" not in check_ids and "PT-DATA" not in check_ids  # app-only checks do not apply
    phases = {phase["id"] for phase in model["validation_phases"]}
    assert "8-platform" in phases


def test_every_exporter_handles_a_platform_report() -> None:
    report = scan(SAMPLE)
    assert "PLATFORM-PROP-DEBUGGABLE" in to_markdown(report)
    assert "PLATFORM-SEPOLICY-PERMISSIVE" in to_html(report)
    sarif = to_sarif(report)
    assert any(result["ruleId"] == "PLATFORM-PROP-TEST-KEYS" for result in sarif["runs"][0]["results"])
    assert all(result.get("partialFingerprints") for result in sarif["runs"][0]["results"])
    briefing = build_ai_context(report, include_locations=False)
    assert "PLATFORM-PROP-DEBUGGABLE" in briefing and "T-PLATFORM-BUILD" in briefing and "build.prop" not in briefing


# --- CLI and API ----------------------------------------------------------------------------------------------------------

def make_tree(root: Path) -> Path:
    tree = root / "aosp"
    files = {
        "device/oem/car/build.prop": "ro.debuggable=1\n",
        "device/oem/car/init.car.rc": "on boot\n    chmod 0777 /data/x\n",
        "out/target/product/build.prop": "ro.debuggable=1\n",
        "vendor/app/Main.kt": "class A",
    }
    for relative, text in files.items():
        target = tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return tree


def test_collect_platform_files_selects_only_relevant_files_and_skips_ignored_trees(tmp_path: Path) -> None:
    assert sorted(collect_platform_files(make_tree(tmp_path))) == ["device/oem/car/build.prop", "device/oem/car/init.car.rc"]
    with pytest.raises(ValueError, match="not a directory"):
        collect_platform_files(tmp_path / "nope")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="No platform files found"):
        collect_platform_files(empty)


def test_cli_platform_profile_and_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree = make_tree(tmp_path)
    assert cli_main([str(tree), "--profile", "platform", "--fail-on", "high"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["analysis_profile"] == "platform" and report["project_name"] == "aosp" and report["source_file_count"] == 2
    assert report["threat_model"]["threats"] and "8-platform" in {p["id"] for p in report["threat_model"]["validation_phases"]}
    assert cli_main([str(tree), "--profile", "platform", "--fail-on", "critical"]) == 0


def test_cli_picks_the_platform_profile_from_aaos_toml(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree = make_tree(tmp_path)
    (tree / "aaos.toml").write_text(
        '[settings]\nprofile = "platform"\n[[suppress]]\nrule = "PLATFORM-INIT-WORLD-ACCESSIBLE"\nreason = "temporary data directory in a lab image"\n',
        encoding="utf-8",
    )
    assert cli_main([str(tree)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["analysis_profile"] == "platform" and report["policy"]["suppressed"] == 1
    assert "PLATFORM-INIT-WORLD-ACCESSIBLE" not in ids(report)


def test_cli_list_rules_includes_platform_rules(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["--list-rules"]) == 0
    assert "PLATFORM-SEPOLICY-PERMISSIVE" in capsys.readouterr().out


def test_cli_platform_reports_a_clear_error_for_a_tree_without_platform_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "Main.kt").write_text("class A", encoding="utf-8")
    assert cli_main([str(tmp_path), "--profile", "platform"]) == 2
    assert "No platform files found" in capsys.readouterr().err


def test_directory_api_accepts_the_platform_profile() -> None:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
            return await client.post(
                "/api/analyze-directory",
                data={"authorized": "true", "profile": "platform", "paths": json.dumps(["Car/build.prop", "Car/sepolicy/a.te"])},
                files=[("files", ("build.prop", b"ro.debuggable=1\n", "text/plain")), ("files", ("a.te", b"permissive a;\n", "text/plain"))],
            )

    response = asyncio.run(send())
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_profile"] == "platform" and {"PLATFORM-PROP-DEBUGGABLE", "PLATFORM-SEPOLICY-PERMISSIVE"} <= set(ids(body))
    assert body["threat_model"]["threats"] and "PT-PLATFORM-BUILD" in {c["id"] for c in body["pentest_plan"]["checks"]}
