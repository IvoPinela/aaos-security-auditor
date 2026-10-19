# Security policy

AAOS Security Auditor is a security tool, so its own security matters. It reads files and reports that come from
projects and third-party scanners you may not fully trust, and it can show their content in a browser and send a
summary to an AI model.

## Supported versions

Only the latest release on the `main` branch receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead: open the repository's **Security** tab and choose **Report a vulnerability**
(<https://github.com/IvoPinela/aaos-security-auditor/security/advisories/new>). Include:

- what you found and why it matters,
- a minimal project, report or request that reproduces it,
- the version (`/api/health` shows it) and your environment.

You can expect an acknowledgement within a few days. Fixes are released as soon as they are verified, and you will be
credited unless you prefer otherwise.

## What is in scope

- Code execution, file access outside the selected directory, or path traversal while analyzing a project or importing a report.
- Script injection (XSS) in the web UI or in the HTML report, or a way to make the HTML report load external resources.
- Regular-expression denial of service or other inputs that make an analysis hang or exhaust memory despite the size limits.
- Ways to make secret values, source code, paths or lines reach the AI advisor or an exported briefing that should not contain them.
- Bypasses of the prompt-injection protections in the AI briefing.
- A broken `aaos.toml` or imported report hiding findings instead of reporting an error.

## What is not in scope

- Wrong or missing findings (false positives and false negatives). Please file those as normal issues, ideally with the
  `false positive` template; they are expected in a pattern-based scanner.
- Vulnerabilities in the projects you analyze.
- Running the server on a public network without authentication, TLS and rate limits. The README says not to.

## How the tool protects itself

- It never runs the analyzed app, Gradle, project scripts or external scanners.
- It reads only a bounded set of text files, ignores symlinks, and enforces limits on file count, file size and total size.
- Imported reports drop messages, code excerpts, matched text and secret values; paths are reduced to project-relative form.
- XML from scanners that contains `DOCTYPE` or `ENTITY` is refused.
- The HTML report has no JavaScript and a Content-Security-Policy that forbids scripts and network loads; every value is escaped.
- Text that can come from a project or a scanner is treated as untrusted before it enters an AI briefing.

## Using the tool responsibly

Run it only on software you are authorized to assess. It performs static analysis only and must not be pointed at
vehicles, CAN buses, ECUs or third-party systems.
