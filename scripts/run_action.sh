#!/usr/bin/env bash
# Runs the auditor for the GitHub Action. All inputs arrive as INPUT_* environment variables so the
# logic can be tested outside GitHub. Writes reports to $OUT_DIR and outputs to $GITHUB_OUTPUT.
set -euo pipefail

ROOT="${AAOS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"
OUT_DIR="${OUT_DIR:-${RUNNER_TEMP:-/tmp}/aaos-security-auditor}"
OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/null}"
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-/dev/null}"
PYTHON="${PYTHON:-python}"

PROJECT_PATH="${INPUT_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
mkdir -p "$OUT_DIR"

case "$FAIL_ON" in none|info|low|medium|high|critical) ;; *) echo "::error::fail-on must be none, info, low, medium, high or critical (got '$FAIL_ON')"; exit 2;; esac

# Inputs may be relative to the workspace or absolute (for example ${{ runner.temp }}/report.json).
resolve() { case "$1" in /*|[A-Za-z]:*) echo "$1";; *) echo "$WORKSPACE/$1";; esac; }

target="$(resolve "$PROJECT_PATH")"
[ -d "$target" ] || { echo "::error::path '$PROJECT_PATH' is not a directory in the workspace"; exit 2; }

args=()
[ -n "${INPUT_PROFILE:-}" ] && args+=(--profile "$INPUT_PROFILE")
[ -n "${INPUT_CONFIG:-}" ] && args+=(--config "$(resolve "$INPUT_CONFIG")")
[ "${INPUT_NO_CONFIG:-false}" = "true" ] && args+=(--no-config)
[ -n "${INPUT_BASELINE:-}" ] && args+=(--baseline "$(resolve "$INPUT_BASELINE")")
while IFS= read -r report; do
  report="$(echo "$report" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$report" ] && args+=(--import "$(resolve "$report")")
done <<< "${INPUT_IMPORTS:-}"

cd "$ROOT"
# Produce every artifact without gating, so reports and SARIF exist even when the gate trips.
for format in json sarif markdown sbom html; do
  case "$format" in
    json) file="report.json";; sarif) file="results.sarif";; markdown) file="report.md";;
    sbom) file="sbom.cdx.json";; html) file="report.html";;
  esac
  "$PYTHON" -m app.cli "$target" ${args[@]+"${args[@]}"} --fail-on none --format "$format" -o "$OUT_DIR/$file"
done

# The gate is evaluated separately so its exit code can be reported as an output.
set +e
"$PYTHON" -m app.cli "$target" ${args[@]+"${args[@]}"} --fail-on "$FAIL_ON" --format json -o /dev/null 2> "$OUT_DIR/gate.log"
code=$?
set -e
if [ "$code" -eq 0 ]; then gate="passed"; elif [ "$code" -eq 1 ]; then gate="failed"; else cat "$OUT_DIR/gate.log" >&2; exit "$code"; fi

{
  echo "report-file=$OUT_DIR/report.json"
  echo "sarif-file=$OUT_DIR/results.sarif"
  echo "markdown-file=$OUT_DIR/report.md"
  echo "sbom-file=$OUT_DIR/sbom.cdx.json"
  echo "html-file=$OUT_DIR/report.html"
  echo "gate=$gate"
} >> "$OUTPUT_FILE"

{ echo "## AAOS Security Auditor"; echo; echo "Gate (\`fail-on: $FAIL_ON\`): **$gate**"; echo; cat "$OUT_DIR/report.md"; } >> "$SUMMARY_FILE"
echo "Gate: $gate"
