"""Precision corpus: every regex rule must flag its vulnerable samples and leave its safe samples alone.

`vulnerable` samples must produce the rule. `safe` samples must not. `limitations` document behavior we
know is imperfect (a pattern-based scanner cannot be perfect); they are asserted so that any change is a
deliberate decision, not an accident.
"""

from __future__ import annotations

import pytest

from app.directory_scanner import RULES, analyze_source_directory

AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"  # split on purpose: no full key-shaped literal in the repository

KT = "app/src/main/java/Sample.kt"
JAVA = "app/src/main/java/Sample.java"
XML = "app/src/main/res/xml/sample.xml"
GRADLE_KTS = "app/build.gradle.kts"
GRADLE = "app/build.gradle"

# rule id -> {file, vulnerable[], safe[], limitations[(sample, "flagged" | "missed", why)]}
CORPUS: dict[str, dict] = {
    "AAOS-CLEARTEXT": {
        "file": XML,
        "vulnerable": ['<application android:usesCleartextTraffic="true"/>'],
        "safe": ['<application android:usesCleartextTraffic="false"/>', '<!-- android:usesCleartextTraffic="true" -->'],
    },
    "ANDROID-WEBVIEW-JS": {
        "file": KT,
        "vulnerable": ["webView.settings.javaScriptEnabled = true", "settings.setJavaScriptEnabled(true)", "webView.getSettings().setJavaScriptEnabled(true);"],
        "safe": ["webView.settings.javaScriptEnabled = false", "settings.setJavaScriptEnabled(false)", "// settings.setJavaScriptEnabled(true) disabled for security", "/* webView.settings.javaScriptEnabled = true */"],
    },
    "ANDROID-WEBVIEW-JS-BRIDGE": {
        "file": KT,
        "vulnerable": ['webView.addJavascriptInterface(Bridge(), "bridge")', 'webView.addJavascriptInterface(new Bridge(), "bridge");'],
        "safe": ['webView.removeJavascriptInterface("bridge")', "// webView.addJavascriptInterface(Bridge(), \"b\")"],
    },
    "ANDROID-WEBVIEW-FILE-ACCESS": {
        "file": KT,
        "vulnerable": ["settings.allowFileAccess = true", "settings.setAllowFileAccess(true)", "settings.setAllowFileAccessFromFileURLs(true);"],
        "safe": ["settings.allowFileAccess = false", "settings.setAllowFileAccess(false)"],
    },
    "ANDROID-WEBVIEW-DEBUG": {
        "file": KT,
        "vulnerable": ["WebView.setWebContentsDebuggingEnabled(true)", "WebView.setWebContentsDebuggingEnabled(true);"],
        "safe": [
            "WebView.setWebContentsDebuggingEnabled(false)",
            "WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)",
            "if (BuildConfig.DEBUG) {\n    WebView.setWebContentsDebuggingEnabled(true)\n}",
        ],
    },
    "ANDROID-TRUST-ALL-CERTS": {
        "file": KT,
        "vulnerable": [
            "override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}",
            "public void checkServerTrusted(X509Certificate[] chain, String authType) {}",
            "HttpsURLConnection.setDefaultHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)",
            "builder.hostnameVerifier { _, _ -> true }",
            "public boolean verify(String hostname, SSLSession session) { return true; }",
        ],
        "safe": [
            "override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { delegate.checkServerTrusted(chain, authType) }",
            "override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { throw CertificateException() }",
            "builder.hostnameVerifier { host, session -> host == \"api.example.test\" && session.isValid }",
        ],
    },
    "ANDROID-PENDINGINTENT-MUTABLE": {
        "file": KT,
        "vulnerable": ["PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_MUTABLE)", "PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)"],
        "safe": ["PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_IMMUTABLE)", "PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)"],
        "limitations": [
            ("PendingIntent.getService(\n    ctx, 0, intent,\n    PendingIntent.FLAG_MUTABLE)", "missed", "calls split over several lines are not matched"),
        ],
    },
    "ANDROID-DYNAMIC-RECEIVER": {
        "file": KT,
        "vulnerable": ["registerReceiver(receiver, filter)", "registerReceiver(receiver, filter);", "ContextCompat.registerReceiver(ctx, receiver, filter, ContextCompat.RECEIVER_EXPORTED)"],
        "safe": ["unregisterReceiver(receiver)", "ContextCompat.registerReceiver(ctx, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)", "// registerReceiver(receiver, filter)"],
    },
    "ANDROID-WORLD-READABLE": {
        "file": KT,
        "vulnerable": ['openFileOutput("a", Context.MODE_WORLD_READABLE)', 'getSharedPreferences("p", MODE_WORLD_WRITEABLE)'],
        "safe": ['openFileOutput("a", Context.MODE_PRIVATE)'],
    },
    "ANDROID-EXTERNAL-STORAGE": {
        "file": KT,
        "vulnerable": ["val dir = Environment.getExternalStorageDirectory()", "Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)"],
        "safe": ["context.getExternalFilesDir(null)", "Environment.getExternalStorageState()"],
    },
    "ANDROID-SECRET-LITERAL": {
        "file": KT,
        "vulnerable": [
            'val apiKey = "sk_live_ABCDEFGHIJKLMN"',
            'const val password: String = "SuperSecretPassw0rd"',
            'String API_KEY = "ABCDEFGHIJKLMNOPQRST";',
            '// val accessToken = "ABCDEFGHIJKLMNOPQRST"  (commented out, but still in the repository)',
        ],
        "safe": [
            "val apiKey = BuildConfig.API_KEY",
            'val password = ""',
            'val password = "changeit"',
            'val apiKey = "${System.getenv("KEY")}"',
            'val apiKey = "@string/maps_key_reference"',
        ],
    },
    "ANDROID-LOG-SENSITIVE": {
        "file": KT,
        "vulnerable": ['Log.d(TAG, "token=" + token)', 'Log.e(TAG, "login failed for password " + pw)', 'System.out.println("authorization: " + header);', "Log.i(TAG, \"accessToken=$accessToken\")"],
        "safe": ['Log.d(TAG, "tokenizer ready")', 'Log.d(TAG, "user logged in")', '// Log.d(TAG, "token=" + token)'],
    },
    "ANDROID-KNOWN-SECRET-FORMAT": {
        "file": KT,
        "vulnerable": [f'val k = "{AWS_KEY}"', '"-----BEGIN RSA PRIVATE KEY-----"', f'// old key {AWS_KEY}'],
        "safe": ['"-----BEGIN CERTIFICATE-----"', '"-----BEGIN PUBLIC KEY-----"', 'val k = "AKIA-not-a-key"'],
    },
    "ANDROID-WEBVIEW-UNIVERSAL-FILE": {
        "file": KT,
        "vulnerable": ["settings.allowUniversalAccessFromFileURLs = true", "settings.setAllowUniversalAccessFromFileURLs(true);"],
        "safe": ["settings.allowUniversalAccessFromFileURLs = false"],
    },
    "ANDROID-WEBVIEW-SSL-PROCEED": {
        "file": KT,
        "vulnerable": [
            "override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) { handler?.proceed() }",
            "public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError e) { handler.proceed(); }",
        ],
        "safe": ["override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) { handler?.cancel() }"],
        "limitations": [
            ("override fun onReceivedSslError(v: WebView?, h: SslErrorHandler?, e: SslError?) { if (BuildConfig.DEBUG) h?.proceed() else h?.cancel() }",
             "flagged", "a proceed() guarded only by a condition on the same line is still reported; review the guard"),
        ],
    },
    "ANDROID-NSC-CLEARTEXT": {
        "file": XML,
        "vulnerable": ['<base-config cleartextTrafficPermitted="true">', '<domain-config cleartextTrafficPermitted="true"><domain>x.test</domain></domain-config>'],
        "safe": ['<base-config cleartextTrafficPermitted="false">', '<!-- <base-config cleartextTrafficPermitted="true"> -->'],
    },
    "ANDROID-NSC-USER-CERTS": {
        "file": XML,
        "vulnerable": ['<base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config>'],
        "safe": [
            '<base-config><trust-anchors><certificates src="system"/></trust-anchors></base-config>',
            '<debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>',
            '<!-- <certificates src="user"/> -->',
        ],
    },
    "ANDROID-FILEPROVIDER-ROOT": {
        "file": XML,
        "vulnerable": ['<paths><root-path name="root" path="."/></paths>'],
        "safe": ['<paths><files-path name="shared" path="shared/"/></paths>', '<!-- <root-path name="r" path="."/> -->'],
    },
    "ANDROID-WEAK-CIPHER": {
        "file": KT,
        "vulnerable": ['Cipher.getInstance("AES")', 'Cipher.getInstance("DES/CBC/PKCS5Padding")', 'Cipher.getInstance("AES/ECB/PKCS5Padding")', 'Cipher.getInstance("RC4")', 'Cipher.getInstance("DESede/CBC/PKCS5Padding")'],
        "safe": ['Cipher.getInstance("AES/GCM/NoPadding")', 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")', 'Cipher.getInstance("ChaCha20-Poly1305")', '// Cipher.getInstance("DES")'],
    },
    "ANDROID-WEAK-HASH": {
        "file": KT,
        "vulnerable": ['MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-1")', 'MessageDigest.getInstance("SHA1")'],
        "safe": ['MessageDigest.getInstance("SHA-256")', 'MessageDigest.getInstance("SHA-512")'],
    },
    "ANDROID-STATIC-IV": {
        "file": KT,
        "vulnerable": ["IvParameterSpec(ByteArray(16))", "IvParameterSpec(byteArrayOf(0, 0, 0, 0))", 'IvParameterSpec("1234567890123456".toByteArray())', "new IvParameterSpec(new byte[16])", 'new IvParameterSpec("abcdefghijklmnop".getBytes())'],
        "safe": ["IvParameterSpec(iv)", "IvParameterSpec(cipher.iv)", "GCMParameterSpec(128, iv)"],
        "limitations": [
            ("IvParameterSpec(ByteArray(16).also { SecureRandom().nextBytes(it) })", "flagged", "an IV filled from SecureRandom right after allocation looks like a zeroed IV"),
        ],
    },
    "ANDROID-SQL-CONCAT": {
        "file": KT,
        "vulnerable": ['db.rawQuery("SELECT * FROM t WHERE a=" + id, null)', 'db.rawQuery("SELECT * FROM t WHERE a=$id", null)', "db.execSQL(\"DELETE FROM t WHERE id = '\" + id + \"'\")", 'db.rawQuery("SELECT * FROM t WHERE a=${id}", null)'],
        "safe": ['db.rawQuery("SELECT * FROM t WHERE a=?", arrayOf(id))', 'db.execSQL("CREATE TABLE t (id INTEGER)")'],
    },
    "ANDROID-RUNTIME-EXEC": {
        "file": KT,
        "vulnerable": ['Runtime.getRuntime().exec("ls")', 'val p = ProcessBuilder("ls", "-l").start()'],
        "safe": ["val helper = MyProcessBuilderHelper()", "// Runtime.getRuntime().exec(cmd)"],
    },
    "ANDROID-DYNAMIC-CODE-LOADING": {
        "file": KT,
        "vulnerable": ["val loader = DexClassLoader(path, dir, null, parent)", "InMemoryDexClassLoader(buffer, parent)"],
        "safe": ['Class.forName("com.example.Plugin")', "val cl = context.classLoader"],
    },
    "ANDROID-HTTP-URL": {
        "file": KT,
        "vulnerable": ['val u = "http://api.example.test/v1"', 'String BASE = "http://example.org";'],
        "safe": ['val u = "https://api.example.test/v1"', 'val d = "http://localhost:8080/"', 'val e = "http://10.0.2.2:8080/"', 'val ns = "http://schemas.android.com/apk/res/android"', "// see http://example.com for details"],
    },
    "ANDROID-WEBVIEW-LOADURL-UNTRUSTED": {
        "file": KT,
        "vulnerable": ['webView.loadUrl(intent.getStringExtra("url"))', 'webView.loadUrl(uri.getQueryParameter("u")!!)', "webView.loadUrl(intent.data.toString())", "webView.loadUrl(intent.dataString)"],
        "safe": ['webView.loadUrl("https://example.com")', "webView.loadUrl(BuildConfig.HOME_URL)", "webView.loadUrl(viewModel.data.url)"],
    },
    "ANDROID-PREFS-SENSITIVE": {
        "file": KT,
        "vulnerable": ['prefs.edit().putString("auth_token", token).apply()', 'editor.putString("password", pw)', 'prefs.edit().putString("user_secret", s)'],
        "safe": ['prefs.edit().putString("theme", "dark").apply()', 'editor.putString("language", "pt")'],
    },
    "ANDROID-INSECURE-RANDOM": {
        "file": KT,
        "vulnerable": ["val sessionToken = Random().nextInt().toString()", "String token = Long.toHexString((long) Math.random());", "val nonce = Random().nextLong()"],
        "safe": ["val token = SecureRandom().nextInt()", "val delay = Random().nextInt(100)"],
    },
    "AAOS-CAR-APP-ALLOW-ALL-HOSTS": {
        "file": KT,
        "vulnerable": [
            "override fun createHostValidator() = HostValidator.ALLOW_ALL_HOSTS_VALIDATOR",
            "return HostValidator.ALLOW_ALL_HOSTS_VALIDATOR;",
        ],
        "safe": [
            "override fun createHostValidator() = HostValidator.Builder(applicationContext).addAllowedHosts(R.array.hosts).build()",
            "// HostValidator.ALLOW_ALL_HOSTS_VALIDATOR is only for tests",
            "if (BuildConfig.DEBUG) {\n    return HostValidator.ALLOW_ALL_HOSTS_VALIDATOR\n}",
        ],
    },
    "ANDROID-GRADLE-INSECURE-REPO": {
        "file": GRADLE,
        "vulnerable": [
            'repositories { maven { url "http://repo.example.com/maven" } }',
            'repositories { maven { url = uri("http://repo.example.com/maven") } }',
            'repositories { maven("http://repo.example.com/maven") }',
            'repositories { maven { url = uri("https://repo.example.com"); isAllowInsecureProtocol = true } }',
            "repositories { maven { url 'https://repo.example.com'\n allowInsecureProtocol = true } }",
        ],
        "safe": [
            'repositories { maven { url "https://repo.example.com/maven" } }',
            'repositories { maven { url = uri("http://localhost:8081/repository") } }',
            'repositories { maven { url = uri("http://10.0.2.2:8081/repo") } }',
            'repositories { maven("https://jitpack.io") }',
            '// repositories { maven { url "http://old.example.com" } }',
        ],
    },
    "ANDROID-RELEASE-NOT-MINIFIED": {
        "file": GRADLE_KTS,
        "vulnerable": ["android { buildTypes { release { isMinifyEnabled = false } } }", "release {\n    minifyEnabled false\n}"],
        "safe": [
            "android { buildTypes { release { isMinifyEnabled = true } } }",
            "android { buildTypes { debug { isMinifyEnabled = false } } }",
            "buildTypes {\n  getByName(\"debug\") {\n    isMinifyEnabled = false\n  }\n}",
        ],
    },
    "ANDROID-DEBUG-SIGNING": {
        "file": GRADLE_KTS,
        "vulnerable": ['android { buildTypes { release { signingConfig = signingConfigs.getByName("debug") } } }', "release {\n    signingConfig signingConfigs.debug\n}"],
        "safe": [
            'android { buildTypes { release { signingConfig = signingConfigs.getByName("release") } } }',
            'android { buildTypes { debug { signingConfig = signingConfigs.getByName("debug") } } }',
        ],
    },
}


def rules_found(file: str, code: str) -> set[str]:
    report = analyze_source_directory({file: code.encode("utf-8")}, profile="aaos")
    return {finding["rule_id"] for finding in report["findings"]}


def test_corpus_covers_every_regex_rule() -> None:
    assert {rule["id"] for rule in RULES} == set(CORPUS), "every rule needs vulnerable and safe samples in the corpus"
    for rule_id, entry in CORPUS.items():
        assert entry["vulnerable"] and entry["safe"], f"{rule_id} needs both kinds of sample"


@pytest.mark.parametrize(
    "rule_id,sample",
    [(rule_id, sample) for rule_id, entry in CORPUS.items() for sample in entry["vulnerable"]],
)
def test_vulnerable_samples_are_flagged(rule_id: str, sample: str) -> None:
    assert rule_id in rules_found(CORPUS[rule_id]["file"], sample), f"{rule_id} missed:\n{sample}"


@pytest.mark.parametrize(
    "rule_id,sample",
    [(rule_id, sample) for rule_id, entry in CORPUS.items() for sample in entry["safe"]],
)
def test_safe_samples_are_not_flagged(rule_id: str, sample: str) -> None:
    assert rule_id not in rules_found(CORPUS[rule_id]["file"], sample), f"{rule_id} false positive on:\n{sample}"


@pytest.mark.parametrize(
    "rule_id,sample,outcome,why",
    [(rule_id, *item) for rule_id, entry in CORPUS.items() for item in entry.get("limitations", [])],
)
def test_documented_limitations_stay_as_documented(rule_id: str, sample: str, outcome: str, why: str) -> None:
    found = rule_id in rules_found(CORPUS[rule_id]["file"], sample)
    assert found == (outcome == "flagged"), f"behavior changed ({why}); update the corpus deliberately"


# --- the lexical helpers behind the precision gains ----------------------------------

def test_double_slash_inside_a_string_is_not_treated_as_a_comment() -> None:
    code = 'val url = "http://api.example.test/v1" // a real comment follows\n'
    assert "ANDROID-HTTP-URL" in rules_found(KT, code)


def test_line_numbers_stay_correct_after_masking_multiline_comments() -> None:
    code = "/*\n * header\n */\n\nval d = Environment.getExternalStorageDirectory()\n"
    report = analyze_source_directory({KT: code.encode()}, profile="aaos")
    finding = next(item for item in report["findings"] if item["rule_id"] == "ANDROID-EXTERNAL-STORAGE")
    assert finding["line"] == "5"


def test_release_rule_distinguishes_debug_and_release_blocks_in_one_file() -> None:
    gradle = "android { buildTypes {\n  debug { isMinifyEnabled = false }\n  release { isMinifyEnabled = false }\n} }\n"
    report = analyze_source_directory({GRADLE_KTS: gradle.encode()}, profile="aaos")
    lines = [item["line"] for item in report["findings"] if item["rule_id"] == "ANDROID-RELEASE-NOT-MINIFIED"]
    assert lines == ["3"]


def test_commented_out_secret_keeps_a_stable_fingerprint_independent_of_content() -> None:
    first = analyze_source_directory({KT: b'// val apiKey = "ABCDEFGHIJKLMNOPQRST"'}, profile="aaos")
    second = analyze_source_directory({KT: b'// val apiKey = "ZZZZZZZZZZZZZZZZZZZZZ"'}, profile="aaos")
    fp = lambda report: next(i["fingerprint"] for i in report["findings"] if i["rule_id"] == "ANDROID-SECRET-LITERAL")
    assert fp(first) == fp(second)
