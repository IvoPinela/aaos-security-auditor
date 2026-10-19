android { namespace = "com.oem.climate"; compileSdk = 34; defaultConfig { targetSdk = 34 } }

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.code.gson:gson:2.+")
    testImplementation("junit:junit:4.13.2")
}
