package com.oem.climate
class ImageCache {
    fun key(url: String): String {
        val md = java.security.MessageDigest.getInstance("MD5")
        return url
    }
    fun web(webView: android.webkit.WebView) {
        webView.settings.javaScriptEnabled = true
        webView.loadUrl(intent.getStringExtra("u"))
    }
}
