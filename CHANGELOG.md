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
- Rules `AAOS-CAR-APP-ALLOW-ALL-HOSTS`, `AAOS-CAR-APP-HOST-VALIDATION`, `AAOS-MEDIA-BROWSER-CALLER-VALIDATION` and `ANDROID-DEEPLINK-UNVERIFIED`.
- The APK path is tested against the real Androguard parser with compiled binary manifests, and in the browser.
- Rules `ANDROID-GRADLE-INSECURE-REPO` and `ANDROID-DEPENDENCY-DYNAMIC-VERSION`; a supply chain surface in the threat model.
- Precision corpus: vulnerable and safe samples for every regex rule, plus documented limitations.
- `SECURITY.md`, `CONTRIBUTING.md`, issue and pull request templates.

### Packaging
- **Installable**: `pipx install git+https://github.com/IvoPinela/aaos-security-auditor` gives the `aaos-audit` command
  and the `aaos-web` launcher (localhost only unless you choose another host, with a warning). A `pyproject.toml` builds a wheel
  that includes the web interface and the knowledge notes.
- The Python package is now `aaos_auditor` (it was `app`, a name that cannot be published). Use `python -m aaos_auditor`
  or `aaos-audit`. The notes moved to `aaos_auditor/knowledge/security_notes.json`.

### Changed
- Exported-component noise: launcher activities are no longer reported as "exported without permission", and Car App and
  media browser services get precise review points about validating the host or caller (AAOS profile).
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
