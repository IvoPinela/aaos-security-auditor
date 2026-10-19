"""Declared Gradle dependencies and a CycloneDX SBOM, derived statically from build files.

What this sees: dependencies that are *declared* in `build.gradle`, `build.gradle.kts` and a
`libs.versions.toml` version catalog (string and map notation, catalog references, platform/BOM
entries). What it cannot see: transitive dependencies, versions that only a BOM or a dynamic
resolution decides, and variant-specific wiring. Such entries are kept, with an honest
`version_state`, instead of being guessed.
"""

from __future__ import annotations

import re
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from app import __version__
from app.source_mask import mask_comments

CONFIGURATION = (
    r"(?:[a-z][A-Za-z]*(?:Implementation|Api|CompileOnly|RuntimeOnly|Kapt|Ksp|AnnotationProcessor)"
    r"|implementation|api|compileOnly|runtimeOnly|kapt|ksp|annotationProcessor|classpath|coreLibraryDesugaring|lintChecks"
    r"|compile|testCompile|androidTestCompile|runtime)"
)
PLATFORM = r"(?P<platform>(?:enforced)?[Pp]latform\s*\(\s*)?"
STRING_NOTATION = re.compile(
    rf"\b(?P<cfg>{CONFIGURATION})\b\s*\(?\s*{PLATFORM}[\"'](?P<gav>[^\"':\s]+:[^\"':\s]+(?::[^\"'\s]+)?)[\"']"
)
MAP_NOTATION = re.compile(
    rf"\b(?P<cfg>{CONFIGURATION})\b\s*\(?\s*group\s*[:=]\s*[\"'](?P<group>[^\"']+)[\"']\s*,\s*name\s*[:=]\s*[\"'](?P<name>[^\"']+)[\"']"
    r"(?:\s*,\s*version\s*[:=]\s*[\"'](?P<version>[^\"']+)[\"'])?"
)
CATALOG_REF = re.compile(rf"\b(?P<cfg>{CONFIGURATION})\b\s*\(?\s*{PLATFORM}libs\.(?P<alias>[A-Za-z0-9_.]+)")
DYNAMIC_VERSION = re.compile(r"\+|^[\[(]|latest\.(?:release|integration)|^SNAPSHOT$|-SNAPSHOT$", re.IGNORECASE)
TEST_PREFIXES = ("test", "androidTest")
OPTIONAL_CONFIGS = {"compileOnly", "kapt", "ksp", "annotationProcessor", "classpath", "lintChecks"}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _scope(configuration: str) -> str:
    lowered = configuration[0].lower() + configuration[1:]
    if lowered.startswith(TEST_PREFIXES):
        return "test"
    if lowered.startswith("debug"):
        return "debug-only"
    if lowered in OPTIONAL_CONFIGS or lowered.endswith(("CompileOnly", "Kapt", "Ksp", "AnnotationProcessor")):
        return "build-time"
    return "required"


def _version_state(version: str | None) -> str:
    if not version:
        return "unresolved"
    if "$" in version or "{" in version:
        return "unresolved"  # taken from a variable we do not evaluate
    if DYNAMIC_VERSION.search(version):
        return "dynamic"
    return "pinned"


def _split_gav(gav: str) -> tuple[str, str, str | None]:
    parts = gav.split(":")
    group, name = parts[0], parts[1]
    version = parts[2].split("@")[0] if len(parts) > 2 and parts[2] else None
    return group, name, version


def parse_version_catalog(text: str) -> tuple[dict[str, dict[str, str | None]], list[str]]:
    """Return {accessor: {group, name, version}} from a libs.versions.toml, plus warnings."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return {}, [f"Version catalog is not valid TOML: {exc}"]
    versions = document.get("versions", {}) if isinstance(document.get("versions"), dict) else {}
    libraries = document.get("libraries", {}) if isinstance(document.get("libraries"), dict) else {}

    def resolve(spec: Any) -> str | None:
        if isinstance(spec, str):
            return spec
        if isinstance(spec, dict):
            if isinstance(spec.get("ref"), str):
                value = versions.get(spec["ref"])
                return value if isinstance(value, str) else (value.get("strictly") or value.get("require") if isinstance(value, dict) else None)
            return spec.get("strictly") or spec.get("require") or spec.get("prefer")
        return None

    catalog: dict[str, dict[str, str | None]] = {}
    for alias, entry in libraries.items():
        group = name = None
        version: str | None = None
        if isinstance(entry, str):
            group, name, version = _split_gav(entry) if entry.count(":") >= 1 else (None, None, None)
        elif isinstance(entry, dict):
            if isinstance(entry.get("module"), str) and ":" in entry["module"]:
                group, name = entry["module"].split(":", 1)
            else:
                group, name = entry.get("group"), entry.get("name")
            version = resolve(entry.get("version"))
        if group and name:
            accessor = re.sub(r"[-_]", ".", alias)  # libs.androidx.core.ktx is declared as androidx-core-ktx
            catalog[accessor] = {"group": group, "name": name, "version": version}
    return catalog, []


def parse_gradle_dependencies(files: dict[str, bytes]) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract declared dependencies from every Gradle build file and version catalog in the snapshot."""
    warnings: list[str] = []
    catalog: dict[str, dict[str, str | None]] = {}
    for path, data in files.items():
        if PurePosixPath(path).name.endswith(".versions.toml"):
            parsed, catalog_warnings = parse_version_catalog(data.decode("utf-8", errors="replace"))
            catalog.update(parsed)
            warnings += [f"{path}: {message}" for message in catalog_warnings]

    found: dict[tuple, dict[str, Any]] = {}

    def record(path: str, line: int, configuration: str, group: str, name: str, version: str | None, platform: bool) -> None:
        state = _version_state(version)
        key = (path, configuration, group, name, version)
        found.setdefault(key, {
            "group": group,
            "name": name,
            "version": None if state == "unresolved" else version,
            "version_expression": version if state == "unresolved" and version else "",
            "version_state": state,
            "configuration": configuration,
            "scope": _scope(configuration),
            "bom": platform,
            "declared_in": path,
            "line": str(line),
        })

    for path, data in sorted(files.items()):
        if PurePosixPath(path).name not in {"build.gradle", "build.gradle.kts"}:
            continue
        text = mask_comments(data.decode("utf-8", errors="replace"), ".gradle")
        for match in STRING_NOTATION.finditer(text):
            group, name, version = _split_gav(match.group("gav"))
            record(path, _line_of(text, match.start()), match.group("cfg"), group, name, version, bool(match.group("platform")))
        for match in MAP_NOTATION.finditer(text):
            record(path, _line_of(text, match.start()), match.group("cfg"), match.group("group"), match.group("name"), match.group("version"), False)
        for match in CATALOG_REF.finditer(text):
            alias = re.sub(r"\.(?:get|asProvider)$", "", match.group("alias"))
            entry = catalog.get(alias)
            if entry is None:
                continue  # a bundle, plugin accessor or an alias we cannot resolve
            record(path, _line_of(text, match.start()), match.group("cfg"), str(entry["group"]), str(entry["name"]), entry["version"], bool(match.group("platform")))
    return sorted(found.values(), key=lambda dep: (dep["declared_in"], dep["group"], dep["name"], dep["configuration"])), warnings


def purl(dependency: dict[str, Any]) -> str:
    base = f"pkg:maven/{quote(dependency['group'], safe='')}/{quote(dependency['name'], safe='')}"
    # Only an exact, pinned version identifies a release; "2.+" or a range would mislead vulnerability scanners.
    pinned = dependency.get("version") and dependency.get("version_state", "pinned") == "pinned"
    return f"{base}@{quote(dependency['version'], safe='')}" if pinned else base


def dependency_summary(dependencies: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(dependencies),
        "pinned": sum(dep["version_state"] == "pinned" for dep in dependencies),
        "dynamic": sum(dep["version_state"] == "dynamic" for dep in dependencies),
        "unresolved": sum(dep["version_state"] == "unresolved" for dep in dependencies),
        "test_only": sum(dep["scope"] == "test" for dep in dependencies),
    }


def to_cyclonedx(report: dict[str, Any]) -> dict[str, Any]:
    """CycloneDX 1.5 JSON for the declared dependencies; deterministic for the same input."""
    dependencies = [dep for dep in report.get("dependencies", []) if isinstance(dep, dict) and not dep.get("bom")]
    seed = str(report.get("source_sha256") or report.get("package_name") or "aaos")
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dep in dependencies:
        identity = f"{purl(dep)}|{dep['scope']}"
        if identity in seen:
            continue
        seen.add(identity)
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": identity,
            "group": dep["group"],
            "name": dep["name"],
            "purl": purl(dep),
            "scope": {"required": "required", "build-time": "optional", "debug-only": "optional", "test": "excluded"}[dep["scope"]],
            "properties": [
                {"name": "aaos:configuration", "value": dep["configuration"]},
                {"name": "aaos:declared-in", "value": dep["declared_in"]},
                {"name": "aaos:version-state", "value": dep["version_state"]},
            ],
        }
        if dep.get("version") and dep["version_state"] == "pinned":
            component["version"] = dep["version"]
        elif dep.get("version"):
            component["properties"].append({"name": "aaos:declared-version", "value": str(dep["version"])})
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}",
        "version": 1,
        "metadata": {
            "timestamp": str(report.get("analyzed_at") or datetime.now(timezone.utc).isoformat()),
            "tools": {"components": [{"type": "application", "name": "AAOS Security Auditor", "version": __version__}]},
            "component": {"type": "application", "name": str(report.get("package_name") or "android-app")},
            "properties": [{"name": "aaos:completeness", "value": "declared dependencies only; transitive dependencies and BOM-managed versions are not resolved"}],
        },
        "components": components,
    }
