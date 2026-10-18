"""HTTP API and minimal web UI for the AAOS security auditor MVP."""

from __future__ import annotations

import os
import json
import asyncio
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.ai_advisor import ai_is_configured, ai_provider_name, explain_findings
from app.ai_context import build_ai_context
from app.connectors import SUPPORTED_FORMATS, import_static_report
from app.directory_scanner import MAX_SOURCE_FILE_BYTES, analyze_source_directory
from app.exporters import to_markdown, to_sarif
from app.knowledge import knowledge_base_status, notes_for_rule, retrieve_context, search_notes
from app.masvs import MASVS_CONTROLS, MASVS_VERSION, enrich_findings
from app.pentest_plan import build_pentest_plan
from app.policy import apply_policy, load_project_policy
from app.rules_catalog import rule_catalog
from app.scanner import analyze_apk
from app.threat_model import build_threat_model

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_EXPORT_BYTES = 10 * 1024 * 1024
MAX_DIRECTORY_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_DIRECTORY_FILES = 500
MAX_CONNECTOR_REPORT_BYTES = 5 * 1024 * 1024
APK_PARSE_LIMITER = asyncio.Semaphore(2)
BASE_DIR = os.path.dirname(__file__)
load_dotenv(Path(BASE_DIR).parent / ".env")

app = FastAPI(
    title="AAOS Security Auditor",
    description="Authorized, static-first Android Automotive application security assessment.",
    version=__version__,
)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


@app.get("/", include_in_schema=False)
async def home() -> FileResponse:
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.get("/api/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "version": __version__,
        "ai_enabled": ai_is_configured(),
        "ai_provider": ai_provider_name(),
        "knowledge_base": knowledge_base_status(),
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...), authorized: bool = Form(False)) -> dict[str, object]:
    if not authorized:
        raise HTTPException(status_code=400, detail="Confirm that you are authorized to analyze this application.")
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=415, detail="Upload an APK file.")

    try:
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="The APK exceeds the 50 MB limit.")
        async with APK_PARSE_LIMITER:
            report = await run_in_threadpool(analyze_apk, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        await file.close()

    report["ai_advice"] = None
    report["ai_context_sources"] = []
    report["pentest_plan"] = build_pentest_plan(report["findings"], report.get("deep_links", []))
    report["threat_model"] = build_threat_model(report)
    if report["findings"] and ai_is_configured():
        knowledge_context, context_sources = retrieve_context(report["findings"])
        briefing = build_ai_context(report, knowledge_context, include_locations=False, max_chars=12_000)
        report["ai_advice"] = await explain_findings(report["findings"], knowledge_context, briefing)
        report["ai_context_sources"] = context_sources
    return report


@app.post("/api/analyze-directory")
async def analyze_directory(
    files: list[UploadFile] = File(...),
    paths: str = Form(...),
    profile: str = Form("aaos"),
    authorized: bool = Form(False),
) -> dict[str, object]:
    if not authorized:
        raise HTTPException(status_code=400, detail="Confirm that you are authorized to analyze this project.")
    if len(files) > MAX_DIRECTORY_FILES:
        raise HTTPException(status_code=413, detail=f"The limit is {MAX_DIRECTORY_FILES} files per analysis.")
    try:
        relative_paths = json.loads(paths)
        if not isinstance(relative_paths, list) or len(relative_paths) != len(files) or not all(isinstance(path, str) for path in relative_paths):
            raise ValueError("The directory path list is invalid.")
        normalized_paths = [path.replace("\\", "/") for path in relative_paths]
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError("The directory contains duplicate paths.")
        source_files: dict[str, bytes] = {}
        total_bytes = 0
        for relative_path, upload in zip(normalized_paths, files, strict=True):
            data = await upload.read(MAX_SOURCE_FILE_BYTES + 1)
            if len(data) > MAX_SOURCE_FILE_BYTES:
                raise HTTPException(status_code=413, detail=f"A file exceeds the {MAX_SOURCE_FILE_BYTES // 1_000_000} MB limit.")
            total_bytes += len(data)
            if total_bytes > MAX_DIRECTORY_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="The directory exceeds the 20 MB total limit.")
            source_files[relative_path] = data
        report = analyze_source_directory(source_files, profile=profile)
        try:
            policy, policy_path, policy_root = load_project_policy(source_files)
        except ValueError as exc:
            # A broken policy must not hide findings: report it and keep every finding.
            report["policy"] = {"config": "aaos.toml", "suppressed": 0, "by_kind": {}, "expired": [], "unused": [], "warnings": [str(exc)]}
        else:
            if policy:
                apply_policy(report, policy, source_files, root_prefix=policy_root, config_path=policy_path)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="The directory path list is not valid JSON.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        for upload in files:
            await upload.close()

    report["ai_advice"] = None
    report["ai_context_sources"] = []
    report["pentest_plan"] = build_pentest_plan(report["findings"], report.get("deep_links", []))
    report["threat_model"] = build_threat_model(report)
    if report["findings"] and ai_is_configured():
        # Source findings include paths only as evidence; snippets and source files stay local.
        ai_findings = report["findings"][:50]
        knowledge_context, context_sources = retrieve_context(ai_findings)
        briefing = build_ai_context(report, knowledge_context, include_locations=False, max_chars=12_000)
        report["ai_advice"] = await explain_findings(ai_findings, knowledge_context, briefing)
        report["ai_context_sources"] = context_sources
    return report


@app.get("/api/rules")
async def list_rules() -> dict[str, object]:
    """Expose the deterministic rule catalog with MASVS mapping for docs and triage."""
    return {"masvs_version": MASVS_VERSION, "masvs_controls": MASVS_CONTROLS, "rules": rule_catalog()}


@app.get("/api/knowledge")
async def knowledge_lookup(
    rule_id: str = Query("", max_length=120),
    q: str = Query("", max_length=200),
) -> dict[str, object]:
    """Look up curated notes by rule ID or keywords; returns local notes only, never calls AI."""
    if not rule_id and not q:
        raise HTTPException(status_code=400, detail="Provide rule_id or q.")
    notes = notes_for_rule(rule_id) if rule_id else search_notes(q)
    return {
        "notes": [
            {key: note.get(key) for key in ("id", "title", "rule_ids", "masvs", "content") if key in note}
            for note in notes
        ],
    }


@app.post("/api/export/{export_format}")
async def export_report(
    export_format: str,
    request: Request,
    locations: bool = Query(True, description="ai-context: include path:line (for local use by the assistant)"),
) -> Response:
    """Convert a report JSON produced by this app to SARIF 2.1.0, Markdown or an AI briefing."""
    if export_format not in {"sarif", "markdown", "ai-context"}:
        raise HTTPException(status_code=404, detail="Unknown format. Use sarif, markdown or ai-context.")
    body = await request.body()
    if len(body) > MAX_EXPORT_BYTES:
        raise HTTPException(status_code=413, detail="The report exceeds the 10 MB export limit.")
    try:
        report = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail="The body is not a valid JSON report.") from exc
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise HTTPException(status_code=422, detail="The report must contain a 'findings' list.")
    report["findings"] = [finding for finding in report["findings"] if isinstance(finding, dict)]
    if export_format == "sarif":
        return JSONResponse(to_sarif(report, app.version), media_type="application/sarif+json")
    if export_format == "ai-context":
        return PlainTextResponse(build_ai_context(report, include_locations=locations), media_type="text/markdown; charset=utf-8")
    return PlainTextResponse(to_markdown(report), media_type="text/markdown; charset=utf-8")


@app.post("/api/threat-model")
async def threat_model(request: Request) -> dict[str, object]:
    """Recompute the derived threat model for a report (for example after importing external findings)."""
    body = await request.body()
    if len(body) > MAX_EXPORT_BYTES:
        raise HTTPException(status_code=413, detail="The report exceeds the 10 MB limit.")
    try:
        report = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail="The body is not a valid JSON report.") from exc
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise HTTPException(status_code=422, detail="The report must contain a 'findings' list.")
    report["findings"] = [finding for finding in report["findings"] if isinstance(finding, dict)]
    report["pentest_plan"] = build_pentest_plan(report["findings"], report.get("deep_links", []))
    return {"threat_model": build_threat_model(report), "pentest_plan": report["pentest_plan"]}


@app.get("/api/connectors")
async def list_connectors() -> dict[str, object]:
    """Describe the external report formats that can be imported and how to produce each."""
    return {"formats": list(SUPPORTED_FORMATS)}


@app.post("/api/connectors/import-static-report")
async def import_connector_report(
    file: UploadFile = File(...),
    authorized: bool = Form(False),
) -> dict[str, object]:
    if not authorized:
        raise HTTPException(status_code=400, detail="Confirm that you are authorized to import this report.")
    filename = file.filename or ""
    if not filename.lower().endswith((".sarif", ".json", ".xml")):
        await file.close()
        raise HTTPException(status_code=415, detail="Use a Semgrep, SARIF, Gitleaks, OSV-Scanner, Trivy, MobSF (JSON) or Android Lint (XML) report.")
    try:
        data = await file.read(MAX_CONNECTOR_REPORT_BYTES + 1)
        if len(data) > MAX_CONNECTOR_REPORT_BYTES:
            raise HTTPException(status_code=413, detail="The external report exceeds the 5 MB limit.")
        imported = import_static_report(data, filename)
        enrich_findings(imported["findings"])
        return imported
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        await file.close()
