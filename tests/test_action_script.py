"""Tests for scripts/run_action.sh, the logic behind the GitHub Action.

The script is plain bash driven by INPUT_* variables, so it can be tested without GitHub. It is skipped on
Windows (paths and bash flavors differ there); the Linux CI job runs it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_action.sh"
FIXTURE = "tests/ui/fixtures/Climate"

# On Windows it only runs when AAOS_TEST_ACTION=1 and `bash` is Git Bash (WSL bash cannot read these paths).
pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or (sys.platform == "win32" and not os.getenv("AAOS_TEST_ACTION")),
    reason="the action script is tested on Linux and macOS (set AAOS_TEST_ACTION=1 to run it with Git Bash on Windows)",
)


def run_action(tmp_path: Path, **inputs: str) -> tuple[subprocess.CompletedProcess, dict[str, str], Path]:
    out_dir = tmp_path / "out"
    output_file = tmp_path / "github_output"
    summary_file = tmp_path / "summary.md"
    output_file.touch()
    env = {
        **os.environ,
        "GITHUB_WORKSPACE": str(ROOT),
        "OUT_DIR": str(out_dir),
        "GITHUB_OUTPUT": str(output_file),
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "PYTHON": sys.executable,
        **{f"INPUT_{name.upper()}": value for name, value in inputs.items()},
    }
    result = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    outputs = dict(line.split("=", 1) for line in output_file.read_text().splitlines() if "=" in line)
    return result, outputs, out_dir


def test_gate_fails_but_all_artifacts_are_still_produced(tmp_path: Path) -> None:
    result, outputs, out_dir = run_action(tmp_path, path=FIXTURE, fail_on="high", no_config="true")
    assert result.returncode == 0, result.stderr  # the script reports the gate; the Action step enforces it
    assert outputs["gate"] == "failed"
    for name in ("report.json", "results.sarif", "report.md", "sbom.cdx.json", "report.html"):
        assert (out_dir / name).stat().st_size > 0, name
    assert json.loads((out_dir / "results.sarif").read_text())["version"] == "2.1.0"
    assert json.loads((out_dir / "sbom.cdx.json").read_text())["bomFormat"] == "CycloneDX"
    assert "<h2>Findings</h2>" in (out_dir / "report.html").read_text()
    assert "Gate (`fail-on: high`): **failed**" in (tmp_path / "summary.md").read_text()


def test_gate_passes_when_the_threshold_is_not_reached(tmp_path: Path) -> None:
    result, outputs, _ = run_action(tmp_path, path=FIXTURE, fail_on="critical", no_config="true")
    assert result.returncode == 0 and outputs["gate"] == "passed"


def test_project_policy_is_applied_by_default(tmp_path: Path) -> None:
    _, _, out_dir = run_action(tmp_path, path=FIXTURE, fail_on="none")
    report = json.loads((out_dir / "report.json").read_text())
    assert report["policy"]["suppressed"] == 1


def test_no_config_ignores_the_policy(tmp_path: Path) -> None:
    _, _, out_dir = run_action(tmp_path, path=FIXTURE, fail_on="none", no_config="true")
    assert "policy" not in json.loads((out_dir / "report.json").read_text())


def test_invalid_inputs_fail_with_a_clear_error(tmp_path: Path) -> None:
    result, _, _ = run_action(tmp_path, path=FIXTURE, fail_on="banana")
    assert result.returncode == 2 and "fail-on must be" in result.stdout
    result, _, _ = run_action(tmp_path, path="does/not/exist")
    assert result.returncode == 2 and "is not a directory" in result.stdout


def test_imports_accept_relative_and_absolute_paths_and_skip_blank_lines(tmp_path: Path) -> None:
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text(json.dumps([{"RuleID": "generic-api-key", "File": "app/A.kt", "StartLine": 3, "Secret": "X"}]))
    relative = ROOT / ".tmp-action-import.json"
    relative.write_text(gitleaks.read_text())
    try:
        _, _, out_dir = run_action(tmp_path, path=FIXTURE, fail_on="none", imports=f"\n{gitleaks}\n  \n.tmp-action-import.json\n")
    finally:
        relative.unlink()
    report = json.loads((out_dir / "report.json").read_text())
    assert [item["connector"] for item in report["imported_reports"]] == ["Gitleaks", "Gitleaks"]
    assert any(finding["rule_id"].startswith("GITLEAKS-") for finding in report["findings"])


def test_baseline_makes_the_gate_count_only_new_findings(tmp_path: Path) -> None:
    for name in ("first", "plain", "second"):
        (tmp_path / name).mkdir()
    _, _, first_dir = run_action(tmp_path / "first", path=FIXTURE, fail_on="none", no_config="true")
    baseline = tmp_path / "baseline.json"
    baseline.write_text((first_dir / "report.json").read_text())

    _, outputs_without, _ = run_action(tmp_path / "plain", path=FIXTURE, fail_on="low", no_config="true")
    assert outputs_without["gate"] == "failed"  # findings of severity low or higher exist

    _, outputs, _ = run_action(tmp_path / "second", path=FIXTURE, fail_on="low", no_config="true", baseline=str(baseline))
    assert outputs["gate"] == "passed"  # nothing is new since the baseline
