---
name: aaos-source-audit
description: Use whenever the user asks Claude Code to inspect an authorized Android or Android Automotive source directory with this AAOS Security Auditor project. Runs its local read-only static scanner, explains findings with file/line evidence, distinguishes Android app versus AAOS profile, and lists what needs validation on an isolated emulator. Do not silently run active pentests or vehicle tests.
---

# AAOS Source Directory Review

Use this workflow only when Claude Code is working in the `aaos-security-auditor` project and the user explicitly identifies an authorized Android project directory.

## Workflow

1. Confirm the exact target directory and authorization. Do not scan the whole workspace or adjacent ESP32/vehicle projects by default.
2. Choose the profile from the user's target:
   - `aaos` for an Android Automotive OS application; includes general Android checks and AAOS-specific manifest/API review.
   - `android_app` for a general Android app where AAOS checks are not in scope.
   Ask if the target platform is genuinely unclear.
3. Use the local static scanner from the `aaos-security-auditor` project root with `python -m app.cli <authorized-project-directory> --profile <aaos|android_app>`. Treat its JSON output as candidate static evidence, not a certification. Useful flags: `--format markdown` for a readable summary, `--min-severity medium` to cut noise, `--baseline <old.json>` to show only new/resolved findings, `--list-rules` to see what is covered, `--import <report>` (repeatable; Semgrep, SARIF, Gitleaks, OSV-Scanner, Trivy, MobSF, Android Lint) to merge external results, and `--format ai-context` for a Markdown briefing. Each finding carries `masvs` controls and the report has a `masvs_summary`.
4. For each finding, check the cited file and line in the target tree. Check the relevant module/variant when reviewing Gradle or source manifests. Do not copy secret literals into the report.
5. Explain severity, what the source proves, what remains uncertain, and one practical remediation. Separate build blockers from security risks and informational observations.
6. If the user supplies Semgrep JSON or SARIF 2.1 results, import them with `--import <file>` on the CLI or the app's **Import external report** button. Keep original scanner messages and source snippets out of AI prompts and summaries.
7. Produce a concise report with: scope/profile, files reviewed, verified static findings, likely risks, positive controls, external evidence needed, and safe next steps.

## Related skills

- `aaos-finding-triage`: classify and prioritize the findings from step 3 (false positives, needs-runtime).
- `aaos-threat-model`: merge external scanner reports, derive threats and a phased manual validation plan.
- `aaos-remediation`: apply fixes in the target project and prove them with a baseline re-scan.
- `aaos-ci-gate`: run this scan automatically in CI with SARIF upload and a severity gate.
- `aaos-rule-authoring`: add or tune a rule in this repository when coverage is missing.

## Limits and safety

- The CLI reads only supported text/config files and skips symlinks, generated/build/vendor trees and binaries. It does not execute Gradle, project scripts, app binaries, or external analyzers.
- Static checks can miss code paths, variants, merged-manifest changes, dependency CVEs, server-side flaws, and runtime-only behavior. Do not claim that the app is safe or exploitable based on a pattern match alone.
- Runtime verification, if separately authorized, belongs on a dedicated emulator or isolated bench. Never interact with a road vehicle, CAN bus, ECU, production service, or third-party target.
- Follow OWASP MASVS/MASTG as guidance, not as a claim of formal assessment or compliance.
