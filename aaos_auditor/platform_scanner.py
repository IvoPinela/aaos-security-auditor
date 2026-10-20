"""Static review of Android platform and AAOS image sources.

The application scanners look at one app. A vehicle also ships an operating system: build properties, SELinux
policy, init scripts, the allow-list of privileged permissions, and Soong module definitions. A single
`ro.debuggable=1` or a `permissive` domain in a production image undoes the security of every app on it.

Scope and limits, stated plainly:
* It reads text files that already exist in a source tree or a device configuration. It does not build, boot,
  unpack or run anything, and it never touches a device or a vehicle.
* It analyzes configuration, not binaries or native code (HALs, services written in C++ or Rust).
* A tree that omits files cannot be fully judged; findings describe what the selected files show.
* Rules inside `userdebug_or_eng(...)` and init triggers conditioned on `ro.debuggable=1` are skipped because
  they do not exist in user builds.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any
from xml.etree import ElementTree

from aaos_auditor.car_permissions import PREFIX as CAR_PREFIX
from aaos_auditor.car_permissions import is_system_only, protection_level
from aaos_auditor.masvs import enrich_findings, masvs_summary

MAX_FILES = 5_000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_FINDINGS_PER_RULE_PER_FILE = 25
IGNORED_PARTS = {".git", ".repo", "out", "prebuilts", "node_modules", "__pycache__"}
PROFILE_LABEL = "Android platform · AAOS image sources"
PROFILES_RUN = ["Build properties", "SELinux policy", "Init scripts", "Privileged permissions", "Default permissions", "Soong modules"]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PROFILE = "Platform image"

PROPERTY_FILE_NAMES = {"build.prop", "default.prop", "system.prop", "vendor.prop", "product.prop", "odm.prop", "system_ext.prop", "prop.default"}
# Standard AOSP device nodes that are world-accessible by design.
STANDARD_WORLD_NODES = {
    "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/ptmx", "/dev/tty", "/dev/binder",
    "/dev/hwbinder", "/dev/vndbinder", "/dev/ashmem", "/dev/kmsg",
}


# Catalog entries for rules_catalog (severity is the highest the rule can produce).
PLATFORM_RULES: tuple[dict[str, str], ...] = (
    {"id": "PLATFORM-PROP-DEBUGGABLE", "severity": "high", "title": "Image is debuggable (ro.debuggable=1)", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-INSECURE-ADBD", "severity": "high", "title": "adb runs as root (ro.secure=0)", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-ADB-UNAUTHENTICATED", "severity": "high", "title": "adb accepts connections without authorization", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-TEST-KEYS", "severity": "high", "title": "Image is signed with the public AOSP test keys", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-BUILD-TYPE", "severity": "medium", "title": "Image is an eng or userdebug build", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-ADB-ENABLED", "severity": "medium", "title": "adb is enabled by default", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-ADB-ROOT", "severity": "high", "title": "adbd restarted as root (service.adb.root=1)", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-MOCK-LOCATION", "severity": "medium", "title": "Mock locations are allowed", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-VERIFIED-BOOT", "severity": "high", "title": "Verified boot is off or the bootloader is unlocked", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-SELINUX-PERMISSIVE", "severity": "high", "title": "SELinux is permissive on the kernel command line", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PROP-PRIVAPP-LOG", "severity": "medium", "title": "Privileged permission violations are only logged", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-MK-TEST-KEYS", "severity": "high", "title": "Default signing certificate is the public test key", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-MK-AVB-DISABLED", "severity": "high", "title": "Android Verified Boot is disabled in the board configuration", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-SEPOLICY-PERMISSIVE", "severity": "high", "title": "SELinux domain is permissive", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-SEPOLICY-UNCONFINED", "severity": "high", "title": "SELinux domain is unconfined", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-SEPOLICY-ALLOW-ALL", "severity": "high", "title": "SELinux rule allows every permission", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-SEPOLICY-DANGEROUS-CAPABILITY", "severity": "medium", "title": "SELinux rule grants a powerful capability", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-INIT-SELINUX-DISABLED", "severity": "high", "title": "Init script switches SELinux off", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-INIT-SU-SERVICE", "severity": "high", "title": "Service runs in the su SELinux domain", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-INIT-WORLD-ACCESSIBLE", "severity": "medium", "title": "Socket, file or directory accessible by everyone", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-INIT-KERNEL-HARDENING-OFF", "severity": "medium", "title": "Kernel hardening switched off", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-INIT-ADB-ENABLED", "severity": "medium", "title": "Init script enables adb or adb root", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-INIT-ROOT-SERVICE", "severity": "low", "title": "Service runs as root", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PRIVAPP-POWERFUL-PERMISSION", "severity": "medium", "title": "App is allow-listed for a powerful permission", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PRIVAPP-VEHICLE-CONTROL", "severity": "low", "title": "App is allow-listed to control vehicle functions", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PRIVAPP-UNUSED-GRANT", "severity": "low", "title": "Allow-list grants a permission the app does not request", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-PRIVAPP-MISSING-GRANT", "severity": "medium", "title": "App requests a privileged permission without an allow-list entry", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-DEFAULT-GRANT-SENSITIVE", "severity": "medium", "title": "Sensitive runtime permission granted by default", "profile": "Platform image", "scope": "platform"},
    {"id": "PLATFORM-BP-PLATFORM-SIGNED", "severity": "low", "title": "App is signed with the platform certificate", "profile": "Platform image", "scope": "platform"},
)


def platform_file_kind(path: str) -> str | None:
    """Classify a path as one of the files this scanner understands."""
    name = PurePosixPath(path).name
    lower = name.lower()
    if lower in PROPERTY_FILE_NAMES or lower.endswith(".prop"):
        return "prop"
    if lower.endswith(".mk"):
        return "mk"
    if lower.endswith(".te"):
        return "sepolicy"
    if lower.endswith(".rc"):
        return "init"
    if lower.startswith("privapp-permissions") and lower.endswith(".xml"):
        return "privapp"
    if lower.startswith("default-permissions") and lower.endswith(".xml"):
        return "default-permissions"
    if name == "Android.bp":
        return "soong"
    if name == "AndroidManifest.xml":
        return "manifest"
    return None


def _finding(
    rule_id: str, severity: str, title: str, summary: str, recommendation: str,
    path: str, line: int, anchor: str,
) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "summary": summary,
        "recommendation": recommendation,
        "evidence": f"{path}:{line}",
        "source_path": path,
        "line": str(line),
        "profile": PROFILE,
        "_anchor": anchor,
    }


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_text(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start:end if end >= 0 else len(text)]


def _blank(text: str) -> str:
    return "".join(ch if ch in "\r\n" else " " for ch in text)


def _strip_hash_comments(text: str) -> str:
    """Blank `# ...` comments (init, SELinux and property files use them) keeping offsets and line numbers."""
    return re.sub(r"(?m)(?:^|(?<=\s))#.*$", lambda match: _blank(match.group(0)), text)


def _mask_macro(text: str, macro: str) -> str:
    """Blank the argument block of a macro such as userdebug_or_eng(...), including nested parentheses."""
    out = list(text)
    for match in re.finditer(rf"\b{re.escape(macro)}\s*\(", text):
        depth, index = 1, match.end()
        while index < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[index], 0)
            index += 1
        for position in range(match.start(), index):
            if out[position] not in "\r\n":
                out[position] = " "
    return "".join(out)


def _safe_xml(text: str) -> ElementTree.Element | None:
    """Parse XML that may come from an untrusted tree; refuse DOCTYPE and ENTITY."""
    head = text[:65536].upper()
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        return None
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None


# --- build properties ------------------------------------------------------------------------------

PROP_LINE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.\-]+)\s*=\s*(?P<value>.*?)\s*$")
GETPROP_LINE = re.compile(r"^\s*\[(?P<key>[^\]]+)\]\s*:\s*\[(?P<value>.*)\]\s*$")
MK_PROPERTY = re.compile(r"(?P<key>(?:ro|persist|service)\.[A-Za-z0-9_.\-]+)\s*=\s*(?P<value>[^\s\\#]+)")


def parse_properties(text: str) -> list[tuple[int, str, str, str]]:
    """Return (line, key, value, raw line) from key=value files and from `getprop` dumps; the last definition wins."""
    entries: dict[str, tuple[int, str, str, str]] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "import ")):
            continue
        match = GETPROP_LINE.match(raw) or PROP_LINE.match(raw)
        if match:
            entries[match.group("key")] = (number, match.group("key"), match.group("value"), raw.strip())
    return sorted(entries.values())


def _mk_properties(text: str) -> list[tuple[int, str, str, str]]:
    """Properties set through PRODUCT_*PROPERT* assignments in .mk files, including continuation lines."""
    entries: dict[str, tuple[int, str, str, str]] = {}
    in_assignment = False
    for number, raw in enumerate(text.splitlines(), start=1):
        code = raw.split("#", 1)[0]
        if "PRODUCT_" in code and "PROPERT" in code:
            in_assignment = True
        if in_assignment:
            for match in MK_PROPERTY.finditer(code):
                entries[match.group("key")] = (number, match.group("key"), match.group("value"), raw.strip())
        if in_assignment and not code.rstrip().endswith("\\"):
            in_assignment = False
    return sorted(entries.values())


def _property_findings(path: str, entries: list[tuple[int, str, str, str]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    def add(number: int, raw: str, rule_id: str, severity: str, title: str, summary: str, recommendation: str) -> None:
        findings.append(_finding(rule_id, severity, title, summary, recommendation, path, number, raw))

    for number, key, value, raw in entries:
        lowered = value.lower()
        if key == "ro.debuggable" and value == "1":
            add(number, raw, "PLATFORM-PROP-DEBUGGABLE", "high", "Image is debuggable (ro.debuggable=1)",
                "A debuggable image lets adb run as root and allows debugging of every app. It must never ship in a production vehicle.",
                "Build the release with the user variant (ro.debuggable=0) and read the property back from the final image.")
        elif key == "ro.secure" and value == "0":
            add(number, raw, "PLATFORM-PROP-INSECURE-ADBD", "high", "adb runs as root (ro.secure=0)",
                "With ro.secure=0 the adb daemon keeps root, so anyone with adb access owns the device.",
                "Use ro.secure=1 in production and keep root out of the release image.")
        elif key == "ro.adb.secure" and value == "0":
            add(number, raw, "PLATFORM-PROP-ADB-UNAUTHENTICATED", "high", "adb accepts connections without authorization (ro.adb.secure=0)",
                "With ro.adb.secure=0 a host does not need to be approved before it gets an adb shell.",
                "Set ro.adb.secure=1 and keep adb disabled on production vehicles.")
        elif key == "ro.build.tags" and "test-keys" in lowered:
            add(number, raw, "PLATFORM-PROP-TEST-KEYS", "high", "Image is signed with the public AOSP test keys",
                "test-keys means the platform, OTA and apps are signed with keys published in AOSP, so anyone can produce updates and apps the device will trust.",
                "Sign release builds with your own protected release keys and confirm ro.build.tags is release-keys.")
        elif key == "ro.build.type" and lowered in {"eng", "userdebug"}:
            add(number, raw, "PLATFORM-PROP-BUILD-TYPE", "high" if lowered == "eng" else "medium",
                f"Image is a {lowered} build",
                f"A {lowered} build enables developer features (root adb, extra debugging) that a production vehicle should not have.",
                "Ship the user build type and keep userdebug for engineering and test fleets only.")
        elif key == "persist.sys.usb.config" and "adb" in lowered:
            add(number, raw, "PLATFORM-PROP-ADB-ENABLED", "medium", "adb is enabled by default",
                "The default USB configuration exposes adb, which gives a debugging channel to anyone who can reach the port.",
                "Remove adb from the default USB configuration in production images.")
        elif key == "persist.service.adb.enable" and value == "1":
            add(number, raw, "PLATFORM-PROP-ADB-ENABLED", "medium", "adb is enabled by default",
                "persist.service.adb.enable=1 starts adb by default.",
                "Remove it from production images.")
        elif key == "service.adb.root" and value == "1":
            add(number, raw, "PLATFORM-PROP-ADB-ROOT", "high", "adbd restarted as root (service.adb.root=1)",
                "service.adb.root=1 gives adb a root shell.",
                "Remove it from production images.")
        elif key == "ro.allow.mock.location" and value == "1":
            add(number, raw, "PLATFORM-PROP-MOCK-LOCATION", "medium", "Mock locations are allowed",
                "Mock locations let an app feed false positions to navigation and safety features.",
                "Disable mock locations in production images.")
        elif key == "ro.boot.verifiedbootstate" and lowered == "orange":
            add(number, raw, "PLATFORM-PROP-VERIFIED-BOOT", "high", "Verified boot reports an unlocked bootloader",
                "verifiedbootstate=orange means the boot chain is not verified.",
                "Lock the bootloader and keep verified boot enforced in production.")
        elif key == "ro.boot.flash.locked" and value == "0":
            add(number, raw, "PLATFORM-PROP-VERIFIED-BOOT", "high", "Bootloader is unlocked (ro.boot.flash.locked=0)",
                "An unlocked bootloader allows flashing arbitrary images.",
                "Lock the bootloader before the vehicle leaves the factory.")
        elif key == "ro.boot.veritymode" and lowered == "disabled":
            add(number, raw, "PLATFORM-PROP-VERIFIED-BOOT", "high", "dm-verity is disabled",
                "With verity disabled, modified system partitions are not detected at boot.",
                "Keep dm-verity enabled in production images.")
        elif key == "ro.boot.selinux" and lowered == "permissive":
            add(number, raw, "PLATFORM-PROP-SELINUX-PERMISSIVE", "high", "SELinux is permissive on the kernel command line",
                "androidboot.selinux=permissive logs violations instead of blocking them for the whole system.",
                "Boot enforcing in production and fix the denials instead of disabling enforcement.")
        elif key == "ro.control_privapp_permissions" and lowered == "log":
            add(number, raw, "PLATFORM-PROP-PRIVAPP-LOG", "medium", "Privileged permission violations are only logged",
                "ro.control_privapp_permissions=log reports apps that hold privileged permissions outside the allow-list instead of enforcing it.",
                "Use enforce in production once every privileged app is allow-listed.")
    return findings


def _mk_findings(path: str, text: str) -> list[dict[str, str]]:
    findings = _property_findings(path, _mk_properties(text))
    code = _strip_hash_comments(text)
    for match in re.finditer(r"(?m)^[ \t]*PRODUCT_DEFAULT_DEV_CERTIFICATE[ \t]*[:+?]?=[ \t]*(?P<value>\S*testkey\S*)", code):
        findings.append(_finding(
            "PLATFORM-MK-TEST-KEYS", "high", "Default signing certificate is the public test key",
            "PRODUCT_DEFAULT_DEV_CERTIFICATE points at the AOSP test key, which everyone has.",
            "Use your own release certificate and keep its private key off build machines that are not controlled.",
            path, _line_of(code, match.start()), _line_text(text, match.start()).strip(),
        ))
    for match in re.finditer(r"(?m)^[ \t]*BOARD_AVB_ENABLE[ \t]*[:+?]?=[ \t]*false\b", code):
        findings.append(_finding(
            "PLATFORM-MK-AVB-DISABLED", "high", "Android Verified Boot is disabled in the board configuration",
            "BOARD_AVB_ENABLE := false builds an image whose partitions are not verified at boot.",
            "Enable AVB, sign vbmeta with your release key, and lock the bootloader.",
            path, _line_of(code, match.start()), _line_text(text, match.start()).strip(),
        ))
    for match in re.finditer(r"androidboot\.selinux=permissive", code):
        findings.append(_finding(
            "PLATFORM-PROP-SELINUX-PERMISSIVE", "high", "SELinux is permissive on the kernel command line",
            "androidboot.selinux=permissive logs violations instead of blocking them for the whole system.",
            "Boot enforcing in production and fix the denials instead of disabling enforcement.",
            path, _line_of(code, match.start()), _line_text(text, match.start()).strip(),
        ))
    return findings


# --- SELinux ----------------------------------------------------------------------------------------

ALLOW_RULE = re.compile(
    r"(?m)^[ \t]*allow[ \t]+(?P<src>\{[^}]*\}|[\w~*.-]+)[ \t]+(?P<tgt>\{[^}]*\}|[\w~*.-]+)[ \t]*:[ \t]*"
    r"(?P<cls>\{[^}]*\}|[\w*]+)[ \t]+(?P<perms>\{[^}]*\}|[\w~*-]+)[ \t]*;"
)
PERMISSIVE_RULE = re.compile(r"(?m)^[ \t]*permissive[ \t]+(?P<domain>\w+)[ \t]*;")
UNCONFINED_RULE = re.compile(r"\bunconfined_domain\s*\(\s*(?P<domain>\w+)\s*\)")
DANGEROUS_CAPABILITIES = {
    "sys_module": ("high", "load kernel modules"),
    "sys_admin": ("medium", "perform a wide range of administrative operations, including mounts"),
    "sys_rawio": ("medium", "access raw I/O and memory"),
    "sys_ptrace": ("medium", "trace and inspect other processes"),
    "dac_override": ("medium", "bypass file permission checks"),
    "dac_read_search": ("medium", "bypass read and directory search permission checks"),
}


def _words(group: str) -> set[str]:
    return set(re.findall(r"[\w*~-]+", group))


def _sepolicy_findings(path: str, text: str) -> list[dict[str, str]]:
    code = _mask_macro(_strip_hash_comments(text), "userdebug_or_eng")
    findings: list[dict[str, str]] = []

    for match in PERMISSIVE_RULE.finditer(code):
        domain = match.group("domain")
        findings.append(_finding(
            "PLATFORM-SEPOLICY-PERMISSIVE", "high", f"SELinux domain {domain} is permissive",
            f"permissive {domain}; makes SELinux log violations of this domain instead of blocking them, so a compromise of it is not contained.",
            "Remove the permissive statement and fix the denials with specific allow rules. Keep permissive only inside userdebug_or_eng() for bring-up.",
            path, _line_of(code, match.start()), _line_text(text, match.start()).strip(),
        ))
    for match in UNCONFINED_RULE.finditer(code):
        domain = match.group("domain")
        findings.append(_finding(
            "PLATFORM-SEPOLICY-UNCONFINED", "high", f"SELinux domain {domain} is unconfined",
            f"unconfined_domain({domain}) grants the domain broad access, defeating the purpose of mandatory access control for it.",
            "Write the narrow rules the domain needs and remove unconfined_domain.",
            path, _line_of(code, match.start()), _line_text(text, match.start()).strip(),
        ))
    for match in ALLOW_RULE.finditer(code):
        perms, classes = _words(match.group("perms")), _words(match.group("cls"))
        line, anchor = _line_of(code, match.start()), " ".join(_line_text(text, match.start()).split())
        if "*" in perms:
            findings.append(_finding(
                "PLATFORM-SEPOLICY-ALLOW-ALL", "high", "SELinux rule allows every permission",
                "A wildcard permission set grants the source domain everything on the target class, which is almost never the intent.",
                "List the specific permissions needed.",
                path, line, anchor,
            ))
        elif classes & {"capability", "capability2"}:
            for capability in sorted(perms & set(DANGEROUS_CAPABILITIES)):
                severity, effect = DANGEROUS_CAPABILITIES[capability]
                findings.append(_finding(
                    "PLATFORM-SEPOLICY-DANGEROUS-CAPABILITY", severity, f"SELinux rule grants the {capability} capability",
                    f"The {capability} capability lets a process {effect}. Few domains need it, and a compromised one becomes much more powerful.",
                    "Confirm the domain really needs it, keep it out of app domains and network-facing daemons, and prefer a narrower design.",
                    path, line, f"{anchor}#{capability}",
                ))
    return findings


# --- init scripts --------------------------------------------------------------------------------------

SECTION_START = re.compile(r"^(on|service|import)\b")
SELINUX_OFF = re.compile(r"\bsetenforce\s+(?:0|permissive)\b|\bwrite\s+/sys/fs/selinux/enforce\s+0\b", re.IGNORECASE)
KERNEL_HARDENING = re.compile(
    r"\bwrite\s+/proc/sys/(?P<name>kernel/kptr_restrict|kernel/dmesg_restrict|kernel/randomize_va_space)\s+0\b"
    r"|\bwrite\s+/proc/sys/(?P<paranoid>kernel/perf_event_paranoid)\s+-1\b"
)
DEBUG_TRIGGER = re.compile(r"ro\.debuggable=1|ro\.build\.type=(?:userdebug|eng)|service\.adb\.root=1")


def _octal(value: str) -> int | None:
    try:
        return int(value, 8) if re.fullmatch(r"0?[0-7]{3,4}", value) else None
    except ValueError:
        return None


def _init_sections(code: str) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for number, raw in enumerate(code.splitlines(), start=1):
        if not raw.strip():
            continue
        if SECTION_START.match(raw):
            current = {"header": raw.strip(), "line": number, "lines": []}
            sections.append(current)
        elif current is not None:
            current["lines"].append((number, raw.strip(), raw))
    return sections


def _init_findings(path: str, text: str) -> list[dict[str, str]]:
    code = _strip_hash_comments(text)
    findings: list[dict[str, str]] = []
    original_lines = text.splitlines()

    def raw_of(number: int) -> str:
        return " ".join(original_lines[number - 1].split()) if 0 < number <= len(original_lines) else ""

    for section in _init_sections(code):
        header = section["header"]
        if DEBUG_TRIGGER.search(header):
            continue  # only runs on debuggable builds, which are reported through the build properties
        is_service = header.startswith("service ")
        options = {"user": None, "capabilities": False, "seclabel": None}
        for number, line, _ in section["lines"]:
            keyword, _, rest = line.partition(" ")
            rest = rest.strip()
            if is_service:
                if keyword == "user":
                    options["user"] = rest
                elif keyword == "capabilities":
                    options["capabilities"] = True
                elif keyword == "seclabel":
                    options["seclabel"] = rest
                    if re.fullmatch(r"u:r:su:s0", rest):
                        findings.append(_finding(
                            "PLATFORM-INIT-SU-SERVICE", "high", "Service runs in the su SELinux domain",
                            "The su domain is the root-shell domain used on development builds. In production it makes the service unconfined root.",
                            "Give the service its own domain with only the permissions it needs.",
                            path, number, raw_of(number),
                        ))
                elif keyword == "socket":
                    parts = rest.split()
                    mode = _octal(parts[2]) if len(parts) >= 3 else None
                    if mode is not None and mode & 0o006 == 0o006:
                        findings.append(_finding(
                            "PLATFORM-INIT-WORLD-ACCESSIBLE", "medium", f"Socket {parts[0]} is readable and writable by everyone",
                            f"The socket mode {parts[2]} lets every process on the system connect and read, which is rarely intended for a privileged service.",
                            "Restrict the mode and give the socket to the user and group that need it.",
                            path, number, raw_of(number),
                        ))
            if SELINUX_OFF.search(line):
                findings.append(_finding(
                    "PLATFORM-INIT-SELINUX-DISABLED", "high", "Init script switches SELinux off",
                    "Setting SELinux to permissive (or writing 0 to selinux/enforce) disables mandatory access control for the whole system.",
                    "Remove it, boot enforcing, and fix the denials with narrow rules.",
                    path, number, raw_of(number),
                ))
            chmod = re.match(r"chmod\s+(?P<mode>[0-7]{3,4})\s+(?P<target>\S+)", line)
            if chmod:
                mode, target = _octal(chmod.group("mode")), chmod.group("target")
                if mode is not None and mode & 0o002 and target not in STANDARD_WORLD_NODES:
                    findings.append(_finding(
                        "PLATFORM-INIT-WORLD-ACCESSIBLE", "medium", f"{target} is made writable by everyone",
                        f"chmod {chmod.group('mode')} lets any process write to {target}.",
                        "Use the narrowest mode and set the owner and group that need access.",
                        path, number, raw_of(number),
                    ))
            mkdir = re.match(r"mkdir\s+(?P<target>\S+)\s+(?P<mode>[0-7]{3,4})\b", line)
            if mkdir:
                mode = _octal(mkdir.group("mode"))
                if mode is not None and mode & 0o002:
                    findings.append(_finding(
                        "PLATFORM-INIT-WORLD-ACCESSIBLE", "medium", f"Directory {mkdir.group('target')} is created writable by everyone",
                        f"mkdir with mode {mkdir.group('mode')} lets any process create and replace files in it.",
                        "Use a mode such as 0750 or 0770 with the right owner and group.",
                        path, number, raw_of(number),
                    ))
            hardening = KERNEL_HARDENING.search(line)
            if hardening:
                name = hardening.group("name") or hardening.group("paranoid")
                findings.append(_finding(
                    "PLATFORM-INIT-KERNEL-HARDENING-OFF", "medium", f"Kernel hardening switched off ({name})",
                    f"Writing the weakest value to {name} exposes kernel addresses, logs or randomization to unprivileged code.",
                    "Keep the default hardening in production images.",
                    path, number, raw_of(number),
                ))
            if re.match(r"setprop\s+service\.adb\.root\s+1\b", line) or re.match(r"setprop\s+persist\.sys\.usb\.config\s+\S*adb", line):
                findings.append(_finding(
                    "PLATFORM-INIT-ADB-ENABLED", "medium", "Init script enables adb or adb root",
                    "Enabling adb (or adb root) from an init script exposes a debugging channel on every boot.",
                    "Remove it from production images.",
                    path, number, raw_of(number),
                ))
        if is_service:
            name = header.split()[1] if len(header.split()) > 1 else "service"
            user = options["user"]
            if (user is None or user == "root") and not options["capabilities"]:
                findings.append(_finding(
                    "PLATFORM-INIT-ROOT-SERVICE", "low", f"Service {name} runs as root",
                    f"Service {name} " + ("declares user root" if user else "has no user option, and init defaults to root") +
                    ". A bug in it gives an attacker root, and SELinux is then the only barrier.",
                    "Run it as a dedicated user and group, add only the capabilities it needs, and give it its own SELinux domain.",
                    path, section["line"], raw_of(section["line"]),
                ))
    return findings


# --- privileged and default permissions ----------------------------------------------------------------------

POWERFUL_PERMISSIONS = {
    "android.permission.INSTALL_PACKAGES": ("medium", "install any app"),
    "android.permission.GRANT_RUNTIME_PERMISSIONS": ("medium", "grant runtime permissions to other apps"),
    "android.permission.REVOKE_RUNTIME_PERMISSIONS": ("medium", "revoke runtime permissions from other apps"),
    "android.permission.INJECT_EVENTS": ("medium", "inject input events into other apps"),
    "android.permission.READ_FRAME_BUFFER": ("medium", "read what is on screen"),
    "android.permission.WRITE_SECURE_SETTINGS": ("medium", "change secure system settings"),
    "android.permission.MASTER_CLEAR": ("medium", "factory reset the device"),
    "android.permission.INTERACT_ACROSS_USERS_FULL": ("medium", "act across all users, which matters in multi-user cars"),
    "android.permission.MANAGE_USERS": ("low", "create, remove and manage users"),
    "android.permission.MANAGE_DEVICE_ADMINS": ("low", "manage device administrators"),
    "android.permission.MANAGE_APP_OPS_MODES": ("low", "change app operation modes"),
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE": ("low", "enable and disable components of other apps"),
    "android.permission.DELETE_PACKAGES": ("low", "uninstall apps"),
    "android.permission.REBOOT": ("low", "reboot the device"),
}
SENSITIVE_DEFAULT_GRANTS = {
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.READ_CONTACTS", "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG",
}


def _line_for(text: str, package: str, permission: str | None = None) -> int:
    start = text.find(f'package="{package}"')
    if start < 0:
        return 1
    if permission:
        found = text.find(f'name="{permission}"', start)
        if found >= 0:
            return _line_of(text, found)
    return _line_of(text, start)


def _privapp_entries(path: str, text: str) -> dict[str, dict[str, set[str]]]:
    root = _safe_xml(text)
    result: dict[str, dict[str, set[str]]] = {}
    if root is None:
        return result
    for element in root.iter("privapp-permissions"):
        package = element.get("package") or ""
        if not package:
            continue
        entry = result.setdefault(package, {"grant": set(), "deny": set()})
        entry["grant"].update(child.get("name") or "" for child in element.findall("permission"))
        entry["deny"].update(child.get("name") or "" for child in element.findall("deny-permission"))
    return result


def _privapp_findings(path: str, text: str, manifests: dict[str, set[str]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for package, entry in sorted(_privapp_entries(path, text).items()):
        for permission in sorted(entry["grant"] - {""}):
            level = POWERFUL_PERMISSIONS.get(permission)
            line = _line_for(text, package, permission)
            if level:
                severity, effect = level
                findings.append(_finding(
                    "PLATFORM-PRIVAPP-POWERFUL-PERMISSION", severity, f"{package} is allowed to {effect}",
                    f"The allow-list grants {permission} to {package}, which lets it {effect}. A compromise of that app inherits the ability.",
                    "Confirm the app needs it, keep the list as short as possible, and review that app's exported components and update path.",
                    path, line, f"{package}|{permission}",
                ))
            elif permission.startswith(f"{CAR_PREFIX}CONTROL_"):
                findings.append(_finding(
                    "PLATFORM-PRIVAPP-VEHICLE-CONTROL", "low", f"{package} can control vehicle functions",
                    f"The allow-list grants {permission} to {package}. Vehicle control is the most safety-relevant capability on AAOS.",
                    "Keep an inventory of apps that can control the vehicle, validate driving state in each, and test them only on an emulator or isolated bench.",
                    path, line, f"{package}|{permission}",
                ))
        requested = manifests.get(package)
        if requested is not None:
            for permission in sorted(entry["grant"] - requested - {""}):
                findings.append(_finding(
                    "PLATFORM-PRIVAPP-UNUSED-GRANT", "low", f"{package} is allow-listed for a permission it does not request",
                    f"The allow-list grants {permission} to {package}, but the app's manifest does not request it. Unused grants widen the blast radius of a compromise.",
                    "Remove the entry, or add the use-permission if the app really needs it.",
                    path, _line_for(text, package, permission), f"{package}|{permission}",
                ))
            for permission in sorted(requested):
                if permission.startswith(CAR_PREFIX) and is_system_only(protection_level(permission)) \
                        and permission not in entry["grant"] and permission not in entry["deny"]:
                    findings.append(_finding(
                        "PLATFORM-PRIVAPP-MISSING-GRANT", "medium", f"{package} requests {permission.rsplit('.', 1)[-1]} without an allow-list entry",
                        f"{package} requests {permission}, a signature or privileged permission, but the allow-list neither grants nor denies it. "
                        "On Android 9 and later an unlisted privileged permission is a violation, and with enforcement the device does not boot.",
                        "Add a permission or deny-permission entry for it in the allow-list of that partition.",
                        path, _line_for(text, package), f"{package}|{permission}",
                    ))
    return findings


def _default_permission_findings(path: str, text: str) -> list[dict[str, str]]:
    root = _safe_xml(text)
    findings: list[dict[str, str]] = []
    if root is None:
        return findings
    for exception in root.iter("exception"):
        package = exception.get("package") or "(unknown package)"
        for permission in exception.findall("permission"):
            name = permission.get("name") or ""
            if name not in SENSITIVE_DEFAULT_GRANTS:
                continue
            fixed = (permission.get("fixed") or "").lower() == "true"
            findings.append(_finding(
                "PLATFORM-DEFAULT-GRANT-SENSITIVE", "medium" if fixed else "low",
                f"{package} is granted {name.rsplit('.', 1)[-1]} by default" + (" and the user cannot revoke it" if fixed else ""),
                f"default-permissions grants {name} to {package} without asking" + (", and fixed=true stops the user from taking it back." if fixed else "."),
                "Grant sensitive runtime permissions only when a feature needs them, avoid fixed=true, and document why.",
                path, _line_for(text, package, name), f"{package}|{name}",
            ))
    return findings


# --- Soong ------------------------------------------------------------------------------------------------------

BP_MODULE = re.compile(r"\b(?P<type>android_app|android_app_import)\s*\{")


def _soong_modules(path: str, text: str) -> list[dict[str, Any]]:
    code = re.sub(r"//[^\n]*|/\*.*?\*/", lambda match: _blank(match.group(0)), text, flags=re.DOTALL)
    modules = []
    for match in BP_MODULE.finditer(code):
        depth, index = 1, match.end()
        while index < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[index], 0)
            index += 1
        body = code[match.end():index]
        name = re.search(r'\bname:\s*"([^"]+)"', body)
        certificate = re.search(r'\bcertificate:\s*"([^"]+)"', body)
        modules.append({
            "name": name.group(1) if name else "(unnamed)",
            "type": match.group("type"),
            "certificate": certificate.group(1) if certificate else "",
            "privileged": bool(re.search(r"\bprivileged:\s*true\b", body)),
            "platform_apis": bool(re.search(r"\bplatform_apis:\s*true\b", body)),
            "path": path,
            "line": _line_of(code, match.start()),
        })
    return modules


def _soong_findings(modules: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings = []
    for module in modules:
        if module["certificate"] != "platform":
            continue
        findings.append(_finding(
            "PLATFORM-BP-PLATFORM-SIGNED", "low", f"{module['name']} is signed with the platform certificate",
            f"{module['name']} uses certificate: \"platform\", so it runs with the platform signature and typically the system UID, "
            "the highest trust an app can have. Any exported component or injectable input becomes a platform-level entry point."
            + (" It is also privileged." if module["privileged"] else ""),
            "Keep platform-signed apps minimal, avoid exporting components, validate all input, and review them first.",
            module["path"], module["line"], f"{module['name']}|platform",
        ))
    return findings


# --- manifests (for cross-checks) ----------------------------------------------------------------------------------

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _manifest_permissions(text: str) -> tuple[str, set[str]] | None:
    root = _safe_xml(text)
    if root is None:
        return None
    package = root.get("package")
    if not package:
        return None
    requested = {
        element.get(f"{{{ANDROID_NS}}}name", "")
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] in {"uses-permission", "uses-permission-sdk-23"}
    }
    return package, requested - {""}


# --- orchestration --------------------------------------------------------------------------------------------------

def analyze_platform_directory(files: dict[str, bytes], project_name: str | None = None) -> dict[str, Any]:
    """Analyze the platform-relevant files of a source tree or a device configuration snapshot."""
    selected: dict[str, bytes] = {}
    for raw_path, data in files.items():
        path = raw_path.replace("\\", "/")
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or ":" in path or any(part in {"", ".", ".."} for part in parsed.parts):
            raise ValueError("The directory contains an invalid file path.")
        if set(parsed.parts) & IGNORED_PARTS or platform_file_kind(path) is None:
            continue
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(f"The file {path} exceeds 1 MB.")
        selected[path] = data
    if not selected:
        raise ValueError("No platform files found (build.prop, *.te, *.rc, privapp-permissions*.xml, default-permissions*.xml, Android.bp, *.mk).")
    if len(selected) > MAX_FILES:
        raise ValueError(f"The selection exceeds the {MAX_FILES}-file limit for platform analysis.")
    if sum(len(data) for data in selected.values()) > MAX_TOTAL_BYTES:
        raise ValueError("The selected files exceed the total size limit for platform analysis.")

    texts = {path: data.decode("utf-8", errors="replace") for path, data in selected.items()}
    kinds = {path: platform_file_kind(path) for path in texts}

    manifests: dict[str, set[str]] = {}
    for path, text in texts.items():
        if kinds[path] == "manifest":
            parsed_manifest = _manifest_permissions(text)
            if parsed_manifest:
                manifests.setdefault(parsed_manifest[0], set()).update(parsed_manifest[1])

    findings: list[dict[str, str]] = []
    platform_apps: list[dict[str, Any]] = []
    for path, text in sorted(texts.items()):
        kind = kinds[path]
        if kind == "prop":
            findings += _property_findings(path, parse_properties(text))
        elif kind == "mk":
            findings += _mk_findings(path, text)
        elif kind == "sepolicy":
            findings += _sepolicy_findings(path, text)
        elif kind == "init":
            findings += _init_findings(path, text)
        elif kind == "privapp":
            findings += _privapp_findings(path, text, manifests)
        elif kind == "default-permissions":
            findings += _default_permission_findings(path, text)
        elif kind == "soong":
            platform_apps += _soong_modules(path, text)
    findings += _soong_findings(platform_apps)

    # Bound the report: many identical findings in one file add noise, not information.
    counts: dict[tuple[str, str], int] = {}
    bounded = []
    for finding in findings:
        key = (finding["rule_id"], finding["source_path"])
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= MAX_FINDINGS_PER_RULE_PER_FILE:
            bounded.append(finding)
    findings = bounded

    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["rule_id"], item["source_path"], int(item["line"])))
    enrich_findings(findings)
    severity_counts = {severity: sum(item["severity"] == severity for item in findings) for severity in SEVERITY_ORDER}
    risk_level = "elevated" if severity_counts["critical"] or severity_counts["high"] else "review" if severity_counts["medium"] else "informational"
    digest = sha256()
    for path, data in sorted(selected.items()):
        digest.update(path.encode("utf-8") + b"\0" + data + b"\0")

    by_kind: dict[str, int] = {}
    for kind in kinds.values():
        by_kind[kind or "other"] = by_kind.get(kind or "other", 0) + 1
    return {
        "report_type": "source_directory",
        "analysis_profile": "platform",
        "profile_label": PROFILE_LABEL,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "project_name": project_name or next((PurePosixPath(p).parts[0] for p in selected if len(PurePosixPath(p).parts) > 1), "Platform sources"),
        "package_name": "Platform image sources",
        "version_name": "Platform analysis",
        "version_code": "-",
        "min_sdk": "n/a",
        "target_sdk": "n/a",
        "automotive_feature_declared": False,
        "components": [],
        "component_count": 0,
        "exported_component_count": 0,
        "native_libraries": [],
        "deep_links": [],
        "permissions": [],
        "permission_count": 0,
        "gradle_modules": [],
        "aaos_api_references": [],
        "car_app_library_references": [],
        "car_permissions": [],
        "dependencies": [],
        "dependency_summary": {"total": 0, "pinned": 0, "dynamic": 0, "unresolved": 0, "test_only": 0},
        "dependency_warnings": [],
        "platform_apps": platform_apps,
        "platform_files": by_kind,
        "source_file_count": len(selected),
        "source_bytes": sum(len(data) for data in selected.values()),
        "source_sha256": digest.hexdigest(),
        "profiles_run": PROFILES_RUN,
        "severity_counts": severity_counts,
        "risk_level": risk_level,
        "masvs_summary": masvs_summary(findings),
        "findings": findings,
        "analysis_scope": (
            "Static review of platform configuration files (build properties, SELinux, init, privileged permissions, Soong). "
            "It does not build, boot or unpack an image, and it does not analyze binaries or native code. "
            "A tree that omits files cannot be fully reviewed."
        ),
    }
