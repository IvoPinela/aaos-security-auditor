---
name: aaos-remediation
description: Use when the user wants findings from the AAOS Security Auditor fixed in their own authorized Android/AAOS project — "fix these findings", "patch the manifest", "make the WebView safe", "remove cleartext". Produces minimal, reviewable code/config changes per finding, then re-runs the scanner with a baseline to prove the finding is gone. Edits only the target project the user names.
---

# AAOS Remediation

Fix findings with the smallest change that removes the risk without breaking behavior, then prove it with a re-scan.

## Before editing

1. Confirm the **target directory** and that the user owns it or is authorized to modify it. Never edit files outside it, and never edit this auditor's own code as part of a remediation.
2. Save a baseline: `python -m aaos_auditor.cli <target> --profile <aaos|android_app> -o baseline.json` (from the auditor root). Write it outside the target tree or confirm it's git-ignored.
3. For each finding, open the cited file/line and confirm it is real and reachable (see the `aaos-finding-triage` skill). Don't "fix" false positives — note them instead.
4. If a fix changes behavior (e.g. disabling cleartext breaks a dev server, removing `exported` breaks a launcher), **ask** before applying, and offer the variant-scoped alternative.

## Fix patterns

Prefer these idioms. Adjust to the project's language (Kotlin/Java), style, and minSdk.

| Rule | Preferred fix |
|---|---|
| `ANDROID-CLEARTEXT`, `ANDROID-NSC-CLEARTEXT` | Remove `usesCleartextTraffic="true"`; add `res/xml/network_security_config.xml` with `<base-config cleartextTrafficPermitted="false">`. If a dev host needs HTTP, put a `domain-config` for that host in `src/debug/res/xml/` only. |
| `ANDROID-NSC-USER-CERTS` | Move `<certificates src="user"/>` inside `<debug-overrides>`. |
| `ANDROID-TRUST-ALL-CERTS`, `ANDROID-WEBVIEW-SSL-PROCEED` | Delete the custom TrustManager/HostnameVerifier; use platform defaults. In `onReceivedSslError`, call `handler.cancel()`. For test CAs use NSC `debug-overrides`. |
| `ANDROID-DEBUGGABLE`, `ANDROID-TEST-ONLY` | Remove the attribute from `src/main` manifest; AGP sets it per build type. |
| `ANDROID-BACKUP-ENABLED` | Set `android:allowBackup="false"`, or keep backups and add `dataExtractionRules` (API 31+) + `fullBackupContent` excluding tokens/DBs. |
| `ANDROID-EXPORTED-*` | Add explicit `android:exported`. `false` unless another app must call it; if `true`, add `android:permission` with a `signature` protection level custom permission. Keep the launcher activity `exported="true"`. |
| `ANDROID-PENDINGINTENT-MUTABLE` | `FLAG_IMMUTABLE` unless a fill-in is required (inline reply, bubbles); then use an explicit Intent (set component/package). |
| `ANDROID-DYNAMIC-RECEIVER` | `ContextCompat.registerReceiver(ctx, r, filter, ContextCompat.RECEIVER_NOT_EXPORTED)`. |
| `ANDROID-WEBVIEW-*` | Disable `allowFileAccess`/`allowUniversalAccessFromFileURLs`; serve local content with `WebViewAssetLoader`; gate `setWebContentsDebuggingEnabled` on `BuildConfig.DEBUG`; restrict `addJavascriptInterface` to trusted origins or replace with `WebMessageListener` + allowed origin list. |
| `ANDROID-FILEPROVIDER-ROOT` | Replace `<root-path>` with `<files-path name="shared" path="shared/"/>` (or `cache-path`) and move shared files there. |
| `ANDROID-WEAK-CIPHER`, `ANDROID-STATIC-IV` | `AES/GCM/NoPadding` with a Keystore key; let `cipher.init(ENCRYPT_MODE, key)` generate the IV and store `cipher.iv` with the ciphertext. Flag that existing data needs migration. |
| `ANDROID-WEAK-HASH` | `SHA-256` for integrity; PBKDF2/Argon2 for passwords. Leave non-crypto uses and annotate them. |
| `ANDROID-SQL-CONCAT` | `rawQuery("… WHERE name = ?", arrayOf(name))` / `execSQL(sql, arrayOf(args))`, or Room `@Query` parameters. |
| `ANDROID-SECRET-LITERAL`, `ANDROID-KNOWN-SECRET-FORMAT` | Remove from source; read from a git-ignored `local.properties` → `BuildConfig` for non-secret config, or move the call to a backend for real secrets. **Tell the user to rotate the credential** — removal doesn't un-leak it. Never echo the value. |
| `ANDROID-LOG-SENSITIVE` | Remove the value from the log or wrap in `if (BuildConfig.DEBUG)`; strip `Log.d/v` in release via R8 `-assumenosideeffects`. |
| `ANDROID-RELEASE-NOT-MINIFIED`, `ANDROID-DEBUG-SIGNING` | In `release {}`: `isMinifyEnabled = true`, `isShrinkResources = true`, a release `signingConfig` whose passwords come from env/gradle properties. |
| `ANDROID-OLD-TARGET-SDK`, `ANDROID-COMPILE-SDK-BELOW-TARGET` | Propose the bump as its own change with the behavior-change checklist; don't bundle it with security fixes. |
| `AAOS-PRIVILEGED-CAR-PERMISSION` | Remove permissions the feature doesn't use; for the rest, document why and ensure control operations check driving state/UX restrictions. |

## After editing

1. Re-scan: `python -m aaos_auditor.cli <target> --profile <p> --baseline baseline.json --format markdown`.
2. Report: fixed (in `baseline_comparison.resolved`), still present (with reason), and **any new findings the fix introduced**, which must be zero or explained.
3. List what still needs runtime confirmation on an emulator (merged manifest, NSC actually packaged, WebView behavior).
4. Do not run Gradle, install the app, or start emulators unless the user explicitly asks. Never touch a vehicle, CAN bus or ECU.

## Change hygiene

- One finding group per logical change; keep diffs reviewable.
- Match the project's existing style (Kotlin DSL vs Groovy, property vs setter syntax).
- Don't add new dependencies for a fix without asking.
