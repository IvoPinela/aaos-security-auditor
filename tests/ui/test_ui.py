"""Real-browser tests of the web UI.

They start the app on a free port, drive it with Playwright, and are skipped when Playwright is not
installed, so a plain `pytest` keeps working for contributors without a browser.

    pip install -r requirements-dev.txt
    playwright install chromium          # or set UI_BROWSER_CHANNEL=msedge / chrome to use an installed browser
    pytest tests/ui
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, sync_playwright  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "Climate"
BROWSER_CHANNEL = os.getenv("UI_BROWSER_CHANNEL") or None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def base_url():
    port = _free_port()
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{url}/api/health", timeout=1):
                    break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError("The app server did not start")
        yield url
    finally:
        server.terminate()
        server.wait(timeout=10)


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True)
        yield instance
        instance.close()


@pytest.fixture
def page(browser, base_url):
    context = browser.new_context(accept_downloads=True, viewport={"width": 1280, "height": 1400})
    page = context.new_page()
    errors: list[str] = []
    page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: errors.append(f"pageerror: {error}"))
    page.goto(base_url)
    yield page
    context.close()
    # Failed requests we trigger on purpose (400/422) and the favicon are not application errors.
    real = [e for e in errors if "favicon" not in e.lower() and "status of 4" not in e]
    assert not real, f"JavaScript errors in the console: {real}"


@pytest.fixture
def report_page(page: Page) -> Page:
    """The page after analyzing the fixture project."""
    page.click('button[data-mode="directory"]')
    page.set_input_files("#directory-files", str(FIXTURE))
    page.check('input[name="authorized"]')
    page.click('button[type="submit"]')
    page.wait_for_selector("#results .result-header", timeout=30_000)
    return page


def download(page: Page, action: str, tmp_path: Path) -> tuple[str, str]:
    with page.expect_download() as info:
        page.click(f'[data-action="{action}"]')
    target = tmp_path / action
    info.value.save_as(str(target))
    return info.value.suggested_filename, target.read_text(encoding="utf-8-sig")


# --- home -------------------------------------------------------------------

def test_home_is_in_english(page: Page) -> None:
    assert page.title() == "AAOS Security Auditor"
    assert page.get_attribute("html", "lang") == "en"
    assert "Security first" in page.inner_text("h1")
    page.click('button[data-mode="directory"]')
    assert page.is_visible("#profile-select")


def test_footer_shows_the_app_version(page: Page) -> None:
    from app import __version__

    page.wait_for_function(f"document.querySelector('#app-version').textContent === '{__version__}'")


# --- analysis and policy ------------------------------------------------------

def test_report_applies_the_project_policy(report_page: Page) -> None:
    text = report_page.inner_text("#results")
    assert "SOURCE CODE REPORT" in text and "com.oem.climate" in text
    note = report_page.locator("#results p.privacy-note").first.inner_text()
    assert "1 finding(s) suppressed with a recorded reason" in note
    assert "1 suppression(s) expired and active again" in note
    assert "1 stale" in note

    findings = report_page.inner_text("#finding-list")
    assert "Weak hash function" not in findings  # suppressed with a reason
    assert "JavaScript enabled in WebView" in findings  # suppression expired
    assert "HTTP URL without TLS" not in findings  # rule disabled in aaos.toml
    assert "MASVS-" in findings


def test_aaos_findings_show_protection_levels(report_page: Page) -> None:
    findings = report_page.inner_text("#finding-list")
    assert "Sensitive vehicle permissions requested" in findings
    assert "CONTROL_CAR_CLIMATE [signature|privileged]" in findings
    assert "Vehicle/location data with network access" in findings


def test_report_buttons_are_in_english(report_page: Page) -> None:
    actions = report_page.inner_text(".report-actions")
    for label in ("Download JSON", "Export findings CSV", "Export SARIF", "Export Markdown", "AI briefing", "Import external report", "Set baseline"):
        assert label in actions


def test_threat_model_validation_phases_and_checklist(report_page: Page) -> None:
    report_page.click('details[data-lazy="pentest"] summary')
    report_page.wait_for_selector('details[data-lazy="pentest"] .pentest-check')
    report_page.click("details.threat-model summary")
    model = report_page.inner_text("details.threat-model")
    assert "T-VEHICLE" in model and "Validation phases" in model and "Not covered" in model

    report_page.locator(".pentest-check input").first.check()
    report_page.wait_for_function("document.querySelector('.pentest-progress').textContent.includes('1 of')")
    assert "in this session" in report_page.inner_text(".pentest-progress")


def test_inventory_panel_loads_lazily(report_page: Page) -> None:
    report_page.click('details[data-lazy="inventory"] summary')
    report_page.wait_for_function(
        "!document.querySelector('details[data-lazy=\"inventory\"] .lazy-content').textContent.includes('Open this section')"
    )
    assert "Components in manifests" in report_page.inner_text('details[data-lazy="inventory"]')


def test_search_and_severity_filters(report_page: Page) -> None:
    report_page.fill("#finding-search", "zzzz-no-match")
    assert report_page.is_visible("#filter-empty")
    report_page.fill("#finding-search", "")
    total = report_page.locator(".finding-card").count()
    report_page.select_option("#severity-filter", "high")
    assert 0 < report_page.locator(".finding-card:visible").count() < total


# --- exports --------------------------------------------------------------------

def test_exports_sarif_markdown_briefing_and_csv(report_page: Page, tmp_path: Path) -> None:
    name, body = download(report_page, "export-sarif", tmp_path)
    sarif = json.loads(body)
    results = sarif["runs"][0]["results"]
    assert name.endswith(".sarif") and sarif["version"] == "2.1.0"
    assert all(result.get("partialFingerprints") for result in results)
    suppressed = [result for result in results if result.get("suppressions")]
    assert suppressed and "cache keys" in suppressed[0]["suppressions"][0]["justification"]

    name, body = download(report_page, "export-markdown", tmp_path)
    assert name.endswith(".md") and "## Policy decisions" in body and "## Applicable threats" in body

    name, body = download(report_page, "export-ai-context", tmp_path)
    assert "briefing for AI-assisted analysis" in body and "## Decisions already made by the team" in body
    assert "```json" in body and "## Suggested triage order" in body

    name, body = download(report_page, "csv", tmp_path)
    assert name.endswith(".csv") and "masvs" in body.splitlines()[0]


# --- connectors and baseline ------------------------------------------------------

def test_import_external_report_never_shows_secret_values(report_page: Page, tmp_path: Path) -> None:
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text(json.dumps([{
        "RuleID": "generic-api-key", "File": "app/src/main/java/com/oem/climate/ImageCache.kt",
        "StartLine": 3, "Secret": "TOPSECRETVALUE",
    }]), encoding="utf-8")
    report_page.set_input_files("#connector-file", str(gitleaks))
    report_page.wait_for_function("document.querySelector('#results').textContent.includes('findings imported')", timeout=15_000)
    assert "Secret detected by Gitleaks" in report_page.inner_text("#finding-list")
    assert "Messages and code excerpts are not imported" in report_page.inner_text("#results")
    assert "TOPSECRETVALUE" not in report_page.content()
    assert "suppressed with a recorded reason" in report_page.inner_text("#results")  # policy note survives re-render


def test_baseline_comparison(report_page: Page) -> None:
    report_page.click('[data-action="baseline"]')
    report_page.click('[data-action="compare"]')
    comparison = report_page.inner_text("#comparison-box")
    assert "Comparison:" in comparison and "New (0)" in comparison and "Resolved (0)" in comparison


# --- errors -------------------------------------------------------------------------

def test_invalid_apk_shows_an_english_error(page: Page) -> None:
    page.set_input_files("#apk-file", {"name": "x.apk", "mimeType": "application/octet-stream", "buffer": b"not an apk"})
    page.check('input[name="authorized"]')
    page.click('button[type="submit"]')
    page.wait_for_selector("#error:not([hidden])", timeout=15_000)
    assert "valid APK/ZIP" in page.inner_text("#error")
