"""Packaging: the entry points, the data files a wheel must carry, and consistency between the dependency lists."""

from __future__ import annotations

import importlib.resources as resources
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import aaos_auditor
from aaos_auditor.main import LOOPBACK_HOSTS, build_server_parser, serve

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def requirement_names(lines: list[str]) -> dict[str, str]:
    result = {}
    for line in lines:
        line = line.split("#")[0].strip()
        if line and not line.startswith("-"):
            name = re.split(r"[<>=!~\[ ]", line, maxsplit=1)[0].lower()
            result[name] = line
    return result


def test_requirements_txt_matches_pyproject_dependencies() -> None:
    """Two lists drift silently. They must agree on package and version range."""
    from_requirements = requirement_names((ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines())
    from_pyproject = requirement_names(PYPROJECT["project"]["dependencies"])
    assert from_requirements == from_pyproject


def test_dev_requirements_match_the_dev_extra() -> None:
    dev = requirement_names((ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines())
    assert dev == requirement_names(PYPROJECT["project"]["optional-dependencies"]["dev"])


def test_version_is_read_from_the_package() -> None:
    assert "version" in PYPROJECT["project"]["dynamic"]
    assert PYPROJECT["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "aaos_auditor.__version__"}
    assert re.fullmatch(r"\d+\.\d+\.\d+", aaos_auditor.__version__)


def test_console_scripts_point_at_real_callables() -> None:
    scripts = PYPROJECT["project"]["scripts"]
    assert set(scripts) == {"aaos-audit", "aaos-web"}
    for target in scripts.values():
        module, function = target.split(":")
        imported = __import__(module, fromlist=[function])
        assert callable(getattr(imported, function)), target


def test_package_data_is_inside_the_package() -> None:
    files = resources.files("aaos_auditor")
    assert (files / "static" / "index.html").is_file()
    assert (files / "static" / "app.js").is_file()
    assert (files / "knowledge" / "security_notes.json").is_file()
    assert PYPROJECT["tool"]["setuptools"]["package-data"]["aaos_auditor"] == ["static/*", "knowledge/*.json"]


def test_nothing_still_refers_to_the_old_package_name() -> None:
    offenders = []
    for path in list((ROOT / "aaos_auditor").rglob("*.py")) + list((ROOT / "tests").rglob("*.py")):
        if path.name == "test_package.py":
            continue  # this file contains the patterns it searches for
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(?:from|import) app\b", text, re.MULTILINE) or "-m app." in text:
            offenders.append(path.name)
    assert offenders == []


def test_python_dash_m_runs_the_cli() -> None:
    result = subprocess.run([sys.executable, "-m", "aaos_auditor", "--check-knowledge"], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and '"valid": true' in result.stdout


# --- the web launcher --------------------------------------------------------------------------

def test_web_launcher_defaults_to_localhost_only() -> None:
    args = build_server_parser().parse_args([])
    assert args.host == "127.0.0.1" and args.port == 8000
    assert args.host in LOOPBACK_HOSTS


def test_web_launcher_warns_when_exposed_and_stays_quiet_on_localhost(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import uvicorn

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda application, **kwargs: calls.append(kwargs))

    assert serve(["--port", "9001"]) == 0
    assert capsys.readouterr().err == "" and calls[-1]["host"] == "127.0.0.1" and calls[-1]["port"] == 9001

    assert serve(["--host", "0.0.0.0"]) == 0
    warning = capsys.readouterr().err
    assert "no authentication" in warning and "0.0.0.0" in warning
    assert calls[-1]["host"] == "0.0.0.0"
