"""Read-only command-line entry point for local Android source audits."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from app.ai_context import build_ai_context
from app.connectors import import_static_report, merge_imported_findings
from app.directory_scanner import ALLOWED_SUFFIXES, IGNORED_PARTS, MAX_SOURCE_FILE_BYTES, analyze_source_directory
from app.exporters import SEVERITY_ORDER, compare_with_baseline, filter_by_severity, to_markdown, to_sarif
from app.knowledge import validate_knowledge_base
from app.pentest_plan import build_pentest_plan
from app.rules_catalog import known_rule_ids, rule_catalog
from app.threat_model import build_threat_model

MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_SOURCE_FILES = 500
MAX_WALK_ENTRIES = 20_000


def collect_source_files(root: Path) -> dict[str, bytes]:
    """Read only supported regular files; don't follow symlinks or execute project content."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("The path provided is not a directory.")

    files: dict[str, bytes] = {}
    total_bytes = 0
    visited_entries = 0
    for current, directory_names, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directory_names[:] = sorted(
            name for name in directory_names
            if name.lower() not in IGNORED_PARTS and not (current_path / name).is_symlink()
        )
        for filename in sorted(filenames):
            visited_entries += 1
            if visited_entries > MAX_WALK_ENTRIES:
                raise ValueError(f"The directory exceeds the limit of {MAX_WALK_ENTRIES} visited entries.")
            path = current_path / filename
            if path.is_symlink() or path.suffix.lower() not in ALLOWED_SUFFIXES:
                continue
            size = path.stat().st_size
            if size > MAX_SOURCE_FILE_BYTES:
                raise ValueError(f"The file {path.relative_to(root).as_posix()} exceeds 1 MB.")
            if len(files) >= MAX_SOURCE_FILES:
                raise ValueError(f"The limit is {MAX_SOURCE_FILES} accepted files per analysis.")
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("The directory exceeds the 20 MB total limit.")
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    if not files:
        raise ValueError("No supported Android files found in the directory.")
    return files


def _print_rules() -> None:
    for entry in rule_catalog():
        masvs = ",".join(entry["masvs"]) or "-"
        print(f"{entry['id']:<40} {entry['severity']:<8} {entry['scope']:<16} {masvs:<40} {entry['title']}")


def _load_baseline(path: Path) -> dict[str, Any]:
    baseline: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(baseline, dict) or not isinstance(baseline.get("findings"), list):
        raise ValueError("The baseline must be a JSON report from this auditor (with 'findings').")
    return baseline


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only static Android/AAOS source audit")
    parser.add_argument("directory", type=Path, nargs="?", help="Authorized Android project directory")
    parser.add_argument("--profile", choices=("android_app", "aaos"), default="aaos")
    parser.add_argument("--format", choices=("json", "sarif", "markdown", "ai-context"), default="json", help="Output format; ai-context is a Markdown briefing for an AI assistant")
    parser.add_argument(
        "--import", dest="imports", action="append", type=Path, default=[], metavar="REPORT",
        help="Merge an external report (Semgrep, SARIF, Gitleaks, OSV-Scanner, Trivy, MobSF JSON or Android Lint XML); repeatable",
    )
    parser.add_argument("--no-locations", action="store_true", help="ai-context: omit path:line (use when the briefing leaves your machine)")
    parser.add_argument("--list-connectors", action="store_true", help="Print supported external report formats and exit")
    parser.add_argument("--output", "-o", type=Path, help="Write the report to this file instead of stdout")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="info", help="Hide findings below this severity")
    parser.add_argument(
        "--fail-on", choices=("none", *SEVERITY_ORDER), default="none",
        help="Exit with code 1 when a finding at or above this severity exists (only new findings with --baseline)",
    )
    parser.add_argument("--baseline", type=Path, help="Earlier JSON report; adds new/resolved comparison")
    parser.add_argument("--list-rules", action="store_true", help="Print the rule catalog and exit")
    parser.add_argument("--check-knowledge", action="store_true", help="Validate knowledge/security_notes.json and exit")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        # Windows consoles default to cp1252; reports are UTF-8 (Portuguese text, JSON consumers).
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    if args.list_rules:
        _print_rules()
        return 0
    if args.list_connectors:
        from app.connectors import SUPPORTED_FORMATS

        for entry in SUPPORTED_FORMATS:
            print(f"{entry['label']:<18} {entry['produces']:<38} {entry['how_to']}")
        return 0
    if args.check_knowledge:
        problems = validate_knowledge_base(known_rule_ids())
        for problem in problems:
            print(problem, file=sys.stderr)
        print(json.dumps({"valid": not problems, "problems": len(problems)}, ensure_ascii=False))
        return 1 if problems else 0
    if args.directory is None:
        parser.error("provide the directory to analyze (or use --list-rules / --check-knowledge)")

    try:
        source_files = collect_source_files(args.directory)
        report = analyze_source_directory(source_files, profile=args.profile)
        import_summaries = []
        for import_path in args.imports:
            imported = import_static_report(import_path.read_bytes(), import_path.name)
            merge_imported_findings(report, imported["findings"])
            import_summaries.append({"file": import_path.name, "connector": imported["connector"], **imported["stats"]})
        if import_summaries:
            report["imported_reports"] = import_summaries
        report["pentest_plan"] = build_pentest_plan(report["findings"], report.get("deep_links", []))
        report["threat_model"] = build_threat_model(report)
        if args.baseline:
            report["baseline_comparison"] = compare_with_baseline(report, _load_baseline(args.baseline))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2

    gate_findings = report["baseline_comparison"]["new"] if args.baseline else report["findings"]
    gate_failed = args.fail_on != "none" and bool(filter_by_severity(gate_findings, args.fail_on))

    if args.min_severity != "info":
        report["findings"] = filter_by_severity(report["findings"], args.min_severity)
    if args.format == "sarif":
        output = json.dumps(to_sarif(report), ensure_ascii=False, indent=2)
    elif args.format == "markdown":
        output = to_markdown(report)
    elif args.format == "ai-context":
        output = build_ai_context(report, include_locations=not args.no_locations)
    else:
        output = json.dumps(report, ensure_ascii=False, indent=2)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if gate_failed:
        print(f"Gate failed: findings exist with severity >= {args.fail_on}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
