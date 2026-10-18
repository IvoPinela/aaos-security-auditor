---
name: aaos-finding-triage
description: Use when the user has an AAOS Security Auditor JSON report (from the web UI download or `python -m app.cli`) and wants findings triaged, deduplicated, prioritized, or classified as true positive / false positive / needs runtime evidence. Also use for "which findings matter", "explain this report", "is this a false positive", or MASVS-oriented summaries. Read-only; never runs the target app or tests a vehicle.
---

# AAOS Finding Triage

Turn a raw auditor report into a short, defensible priority list. The scanner is deliberately conservative and pattern-based, so triage is where context gets added — not where certainty gets invented.

## Inputs

- A report JSON produced by this project (`report_type: "source_directory"` or an APK report with `apk_sha256`).
- Ideally, read access to the same authorized source tree so cited `source_path:line` can be checked.
- If only the JSON is available, say so in the output: every verdict becomes "unverified".

## Workflow

1. **Confirm scope.** Note package, profile (`aaos` vs `android_app`), `source_sha256`/`apk_sha256`, and `analyzed_at`. Don't triage a report against a different tree than the one it hashed — if the tree has changed, re-run `python -m app.cli <dir> --profile <p> --baseline <old.json>` and triage the `baseline_comparison.new` list instead.
2. **Respect recorded decisions.** Read `suppressed_findings` and `policy` first: suppressed findings carry a team-written reason, so do not re-raise them unless the reason is weak or no longer true. Report expired and stale suppressions.
3. **Group before judging.** Collapse findings by `rule_id`; one root cause across 10 lines is one item. Use `masvs_summary` to show which MASVS areas are affected.
4. **Verify each group** by opening the cited file/line:
   - Is the code reachable in release (not a `debug`/`test` source set, not dead code, not a comment or string)?
   - For Gradle rules (`ANDROID-RELEASE-NOT-MINIFIED`, `ANDROID-DEBUG-SIGNING`), is the match inside the `release` build type?
   - For manifest rules, does the **merged** manifest likely differ (library manifests, `tools:node`, flavors)?
   - For data-flow rules (`ANDROID-SQL-CONCAT`, `ANDROID-RUNTIME-EXEC`), does the concatenated value come from an external source (intent extras, deep link, provider, network)?
   - For crypto/hash rules, what is being protected? MD5 for a cache key is not a crypto finding.
   - For secret rules, confirm whether it is a real credential **without reproducing the value**.
5. **Classify** each group as exactly one of:
   - `confirmed` — static evidence is sufficient (e.g. `root-path` in the packaged FileProvider XML).
   - `likely` — pattern matches and is reachable, but impact depends on runtime/backend context.
   - `needs-runtime` — only an authorized emulator/bench test can decide (list the check from `pentest_plan`).
   - `false-positive` — explain why in one line (test source set, debug block, comment, non-crypto use).
6. **Prioritize** with the scanner severity as the starting point, then adjust one step up or down with a stated reason (reachability, data sensitivity, AAOS vehicle impact, exposure to other apps). Never upgrade to `critical` without a demonstrated path.
7. **Look up guidance** for each rule in `knowledge/security_notes.json` (or `GET /api/knowledge?rule_id=<ID>` if the server is running) and use it for wording and caveats.

## Output format

```
Scope: <package> · profile <p> · <sha256[:12]> · <n> findings → <m> groups

| # | Priority | Rule | Verdict | Where | Why / next step |
|---|----------|------|---------|-------|-----------------|

False positives (n): <rule — one-line reason>
Needs runtime evidence: <PT-* check ids from pentest_plan>
Not covered by this scan: <merged manifest, dependencies/CVEs, backend, native libs…>
```

Keep it to what a developer can act on this week. Put the full table first; prose after.

## Safety

- Never copy secret values, tokens or private keys into the triage output — cite path and line only.
- Do not write exploit payloads or step-by-step attack instructions. Describe the fix and the safe validation.
- Runtime confirmation belongs on a dedicated emulator or isolated bench, with authorization. Never a road vehicle, CAN bus, ECU, or third-party service.
- Don't conclude "the app is secure"; conclude "these rules found these items".
