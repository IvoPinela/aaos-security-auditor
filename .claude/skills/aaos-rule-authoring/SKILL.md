---
name: aaos-rule-authoring
description: Use when adding, changing, or tuning a detection rule in this AAOS Security Auditor repository — e.g. "add a rule for X", "this rule has false positives", "detect Kotlin syntax too", "map rule to MASVS". Covers the regex table, manifest/APK checks, MASVS mapping, knowledge notes, pentest checklist, tests, and README, so a rule is never added half-wired.
---

# Authoring Auditor Rules

A rule in this project is more than a regex. A rule is complete only when all of these agree. The test suite enforces most of them.

| Piece | File | Enforced by |
|---|---|---|
| Detection | `app/directory_scanner.py` `RULES` (source regex) or `_inspect_manifest` / `app/scanner.py` (manifest/APK) | your new test |
| Catalog entry (structural rules only) | `app/rules_catalog.py` `STRUCTURAL_RULES` | `test_rule_catalog_covers_every_regex_rule_once` |
| MASVS + CWE mapping | `app/masvs.py` `RULE_MASVS`, `RULE_CWE` (use only unambiguous CWE ids) | `test_rule_catalog_covers_every_regex_rule_once` (no unmapped security rules) |
| Knowledge note | `knowledge/security_notes.json` | `test_every_rule_has_knowledge_note`, `python -m app.cli --check-knowledge` |
| Threat link (optional) | `app/threat_model.py` `THREATS` (add the rule ID/glob to the threat it supports) | `tests/test_connectors_context.py` |
| Manual check (optional) | `app/pentest_plan.py` `FINDING_CHECKS` | `test_every_finding_check_in_pentest_plan_is_a_known_rule` |
| Docs | `README.md` rule list | review |

## Step by step

1. **Pick the ID.** `ANDROID-<AREA>-<THING>` for generic Android, `AAOS-<THING>` for automotive-specific. Never rename an existing ID: baselines and SARIF history depend on it.
2. **Write the detector.**
   - Source regex → add a dict to `RULES` with `id, pattern, severity, title, summary, recommendation, profile`, and `suffixes` to restrict file types (`{".kt", ".java"}` for code, `{".xml"}` for resources, `{".gradle", ".kts"}` for build files). Without `suffixes` the rule runs on every supported file, including `.properties` and `.toml`.
   - Cover **both Java and Kotlin** syntax (`setX(true)` and `.x = true`).
   - Avoid catastrophic backtracking: no nested quantifiers like `(a+)+`; bound open spans (`[^}]{0,400}?`, `[^;\n]*`). Files can be up to 1 MB.
   - Manifest/APK checks → add to `_inspect_manifest` (source) **and** `analyze_apk` (APK) when both can observe it, then add a row to `STRUCTURAL_RULES`.
   - AAOS-only checks must be gated on `profile == "aaos"` in the source scanner.
3. **Wording rules** (all user-facing strings are English):
   - `summary` says what the match shows **and what it doesn't prove** ("may be…", "confirm…").
   - `recommendation` is one concrete fix.
   - Severity: `high` only when the static match alone is a strong signal (e.g. TLS validation disabled, `root-path`); `medium` when impact needs context; `low`/`info` for hygiene or inventory.
4. **Evidence stays path:line.** `_finding()` already does this — never put the matched text, a code excerpt, or a secret into `evidence`, `summary`, or `title`.
5. **Map to MASVS v2** in `RULE_MASVS` (exact ID, or extend a `FAMILY-*` glob). Only use control IDs listed in `MASVS_CONTROLS`.
6. **Add or extend a knowledge note.** Either append the ID to an existing note's `rule_ids` or add a note with `id, title, rule_ids, masvs, content`. Content is guidance for the AI advisor: caveats, false-positive patterns, remediation. No secrets or customer data.
7. **Optional manual check** in `FINDING_CHECKS` — emulator/bench-only wording, no exploitation steps.
8. **Test** in `tests/test_features.py` (or a new file):
   - at least one positive sample per syntax variant,
   - at least one near-miss negative (the secure variant, e.g. `AES/GCM/NoPadding`),
   - for XML/Gradle rules, a test that the same text in a `.kt` file does **not** match if `suffixes` is set,
   - for secret-like rules, `assert secret not in json.dumps(report)`.
9. **Run** `python -m pytest -q` and `python -m app.cli --check-knowledge`, then `python -m app.cli --list-rules` to eyeball the catalog row.
10. **README**: add the rule to the profile list in "What is implemented".

## Tuning an existing rule

- Reproduce the false positive as a failing negative test first, then tighten the regex.
- Prefer narrowing with `suffixes` or a negative lookahead over lowering severity.
- If the rule is fundamentally context-dependent, keep the match and improve `summary` + knowledge note instead of silencing it.

## Out of scope

Rules must stay static and offline. Don't add checks that run Gradle, execute project code, call the network, decompile binaries, or interact with devices/vehicles.
