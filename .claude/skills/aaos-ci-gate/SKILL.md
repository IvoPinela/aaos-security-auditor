---
name: aaos-ci-gate
description: Use when the user wants the AAOS Security Auditor to run automatically in CI (GitHub Actions, GitLab CI, Azure DevOps, Jenkins) or as a pre-commit/pre-push check on their own Android/AAOS repository — "add this scanner to CI", "fail the build on high findings", "upload SARIF to GitHub code scanning", "only fail on new findings". Writes pipeline config; does not push or trigger pipelines without asking.
---

# AAOS CI Gate

Wire the read-only CLI into a pipeline so new risky findings block merges and results show up as code-scanning alerts.

## CLI flags that matter

```
python -m app.cli <project-dir> --profile aaos|android_app
    --format json|sarif|markdown   # sarif for code scanning, markdown for PR comments
    -o <file>                      # write instead of stdout
    --fail-on none|info|low|medium|high|critical   # exit 1 at/above this severity
    --baseline <old-report.json>   # gate only on findings not in the baseline
    --min-severity <sev>           # hide noise in the output (gate still sees all)
    --config <aaos.toml> / --no-config   # policy file (auto-discovered at the project root)
    --import <report>              # merge Semgrep/SARIF/Gitleaks/OSV/Trivy/MobSF/Lint results (repeatable)
    --format ai-context            # Markdown briefing for an assistant
```

Exit codes: `0` ok · `1` gate failed · `2` input error (bad path, limits exceeded). Treat `2` as a pipeline error, not a pass.

## Workflow

1. Ask (or infer from the repo) the CI system, the Android project root inside the repo, the profile, and the threshold. Defaults: `--fail-on high`, profile `aaos` if the manifest declares `android.hardware.type.automotive`, else `android_app`.
2. Decide how the auditor is obtained: vendored path, git submodule, or a pinned git checkout of this repo at a tag/commit. **Pin a commit**, don't track a branch.
3. Recommend a **baseline** for existing projects so the gate doesn't fail on day one: generate `security-baseline.json` once on the default branch, commit it, and gate PRs on `--baseline security-baseline.json`. Explain that the baseline should shrink over time and be regenerated deliberately, not to silence new findings.
4. Write the pipeline file. Keep permissions minimal (`contents: read`, plus `security-events: write` only for the SARIF upload job).
5. Show the user the file and the one command to test it locally before they commit. Don't push, open PRs, or trigger runs unless asked.

## GitHub Actions template

```yaml
name: aaos-security-audit
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # SARIF upload only
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: <owner>/aaos-security-auditor
          ref: <pinned-commit-sha>
          path: .auditor
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r .auditor/requirements.txt
      - name: Scan (SARIF)
        working-directory: .auditor
        run: python -m app.cli "$GITHUB_WORKSPACE/<android-root>" --profile aaos --format sarif -o "$GITHUB_WORKSPACE/aaos.sarif"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aaos.sarif
          category: aaos-security-auditor
      - name: Gate on new high findings
        working-directory: .auditor
        run: python -m app.cli "$GITHUB_WORKSPACE/<android-root>" --profile aaos --baseline "$GITHUB_WORKSPACE/security-baseline.json" --fail-on high --format markdown -o "$GITHUB_WORKSPACE/aaos.md"
      - if: always()
        run: cat aaos.md >> "$GITHUB_STEP_SUMMARY"
```

Adapt the same three steps (scan → upload SARIF → gate) for GitLab (`artifacts:reports:sast` does not accept SARIF directly; publish the Markdown/JSON as artifacts instead), Azure DevOps or Jenkins.

## Pre-commit hook (local)

```yaml
- repo: local
  hooks:
    - id: aaos-audit
      name: AAOS security audit
      entry: python -m app.cli . --profile aaos --fail-on high --min-severity medium --format markdown
      language: system
      pass_filenames: false
```

This only works when run from the auditor checkout, so prefer CI unless the user vendors the auditor.

## Limits to state

- The gate covers only this auditor's static rules. It is not a MASVS assessment, does not scan dependencies for CVEs, and does not see the merged manifest. Suggest pairing with dependency scanning and an Android lint job.
- The CLI has limits of 500 files / 20 MB / 1 MB per file. Large monorepos need the Android module path, not the repo root.
- Never point CI at devices, emulators connected to vehicles, CAN buses or production backends.
