# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0] - 2026-10-19

### Added
- **GitHub Action** (`action.yml`): one-line use in other repositories, with SARIF upload, a severity gate, baselines,
  imports, and outputs for every report.
- **CycloneDX SBOM** (`--format sbom`, `POST /api/export/sbom`) from declared Gradle dependencies, including version
  catalogs, platform/BOM entries and honest version states (pinned, dynamic, unresolved).
- **Self-contained HTML report** (`--format html`, `POST /api/export/html`): one file, no JavaScript, strict
  Content-Security-Policy, fully escaped.
- Rules `ANDROID-GRADLE-INSECURE-REPO` and `ANDROID-DEPENDENCY-DYNAMIC-VERSION`; a supply chain surface in the threat model.
- Precision corpus: vulnerable and safe samples for every regex rule, plus documented limitations.
- `SECURITY.md`, `CONTRIBUTING.md`, issue and pull request templates.

### Changed
- Rules ignore comments (string literals are kept) and know their enclosing block, so `debug {}` build types,
  `BuildConfig.DEBUG` guards and `<debug-overrides>` no longer produce findings. Commented-out credentials are still reported.
- Fewer false positives: `RSA/ECB/OAEP` is not block-cipher ECB, `tokenizer` is not a token, templates and resource
  references are not secrets, a bare `.data` is not an intent URL.
- Fewer false negatives: Kotlin `registerReceiver` without a semicolon, typed secret declarations, hostname verifiers
  that always return true.
- The CLI keeps the real project name; exporters compute the threat model when it is missing.

## [0.3.0] - 2026-10-18

### Added
- `aaos.toml` project policy: settings and suppressions that require a reason, can expire, and are reported when
  stale or expired; inline `aaos-ignore` comments. A broken policy never hides findings.
- Stable finding fingerprints (line-shift safe, independent of secret values) used by baselines and SARIF `partialFingerprints`.
- `android.car` protection levels from the AOSP Car service manifest, so findings explain what a permission request means.
- AI briefing: project facts, changes since the baseline, recorded team decisions, a suggested triage order,
  a machine-readable summary and a size estimate.
- Continuous integration (tests on Python 3.11 to 3.13 and Windows, browser tests, self-scan) and Dependabot.

### Fixed
- The threat model panel was unstyled in the browser; the footer version is now a single source of truth.

## [0.2.0]

### Added
- 54 rules mapped to OWASP MASVS and CWE; connectors for Semgrep, SARIF, Gitleaks, OSV-Scanner, Trivy, MobSF and
  Android Lint; derived threat model; Markdown AI briefing; SARIF and Markdown export; knowledge base; Claude Code skills.
