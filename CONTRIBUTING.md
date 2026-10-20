# Contributing

Thanks for helping. Good contributions here are usually **rules**, **false-positive reports** and **AAOS knowledge**.

## Set up

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest                                                   # unit, API and corpus tests
playwright install chromium && pytest tests/ui           # optional: real-browser UI tests
```

Python 3.11 or newer is required.

## Reporting a false positive or a missed issue

Open an issue with the **false positive** template. The most useful report contains the smallest code or manifest
snippet that shows the problem, the rule ID, and what you expected. **Remove real secrets and customer code first.**

## Adding or changing a rule

A rule is more than a regex. It is complete only when all of these agree, and the test suite enforces most of them:

| Piece | Where |
| --- | --- |
| Detector | `aaos_auditor/directory_scanner.py` (`RULES`) or the manifest and APK checks |
| Catalog entry (structural rules) | `aaos_auditor/rules_catalog.py` |
| MASVS and CWE | `aaos_auditor/masvs.py` |
| Knowledge note | `aaos_auditor/knowledge/security_notes.json` |
| Threat link (optional) | `aaos_auditor/threat_model.py` |
| **Vulnerable and safe samples** | `tests/test_rule_corpus.py` (app rules) or `tests/test_platform.py` (platform rules, which also need an entry in the sample set) |
| README mention | the coverage table |

Rules for rules:

1. **Evidence stays `path:line`.** Never put matched text, code excerpts or secret values in a finding.
2. **Add safe samples, not only vulnerable ones.** A rule that cannot tell the secure variant apart is not finished.
3. **Say what the match does not prove** in the summary.
4. **Avoid catastrophic backtracking.** Bound open spans; the corpus and performance tests will notice.
5. Static and offline only: no network calls, no running project code, no device or vehicle interaction.

If you use Claude Code, the `aaos-rule-authoring` skill in `.claude/skills/` walks through every step.

## Pull requests

- Keep a change focused; add or update tests; run `pytest` and `python -m aaos_auditor.cli --check-knowledge`.
- Describe the behavior change and why. For rules, include the sample that motivated it.
- New user-facing text is in English.
- Do not commit secrets, real customer code or real keys, not even in tests. Build fake keys from two parts so that no
  full key-shaped literal exists in the repository.

## Security issues

Please follow [SECURITY.md](SECURITY.md) and do not open a public issue for vulnerabilities.

## License

By contributing you agree that your contribution is released under the [MIT License](LICENSE).
