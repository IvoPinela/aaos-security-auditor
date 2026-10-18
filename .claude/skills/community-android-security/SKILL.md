---
name: community-android-security
description: Static Android security-review guidance for authorized Kotlin/Java projects. Use when reviewing manifests, component exposure, cleartext/network configuration, WebViews, local storage, hardcoded-secret patterns, or build security posture. Prefer evidence from files and distinguish verified facts from likely risks and controls requiring runtime evidence.
---

# Community Android Security Review

This project-local skill adapts the static-review guidance from Felix Graeber's `claude-android-audit-skill` Android security skill. Its downloaded, unmodified source is retained in `UPSTREAM-SKILL.md`; the MIT license is in `LICENSE`.

## Review method

1. Confirm the user is authorized to review the selected project and keep the review within the explicitly supplied source root.
2. Read `UPSTREAM-SKILL.md` for the upstream security principles. Apply them as review guidance, not as proof of a vulnerability.
3. Prefer the local AAOS auditor's deterministic report for supported manifests, Gradle, Kotlin, Java, and configuration checks. Inspect referenced source locations only to verify context.
4. Report each item as a verified static fact, a conditional risk, or a question requiring runtime/external evidence. Don't turn a grep match or missing control into a confirmed exploit without a demonstrated path.
5. Treat pinning, Play Integrity, obfuscation, permissions, and release hardening as threat-model dependent; describe operational tradeoffs rather than demanding them universally.
6. Never copy secret values into a response or report. Refer to the file and line only; recommend rotation when a live credential is confirmed, without reproducing it.

## Safety boundary

This skill is for read-only review and remediation advice. Do not run builds, project scripts, Frida/objection, fuzzers, network probes, app installs, or tests against a vehicle. Any runtime verification must be separately authorized and performed on an isolated emulator or bench.

## Limitations

The upstream skill is generic Android guidance, not AAOS-specific certification. Use the sibling `aaos-source-audit` skill for this repository's bounded scanner workflow and AAOS-specific caveats. Static source review cannot prove merged-manifest behavior, backend authorization, runtime reachability, OEM permissions, or vehicle impact.
