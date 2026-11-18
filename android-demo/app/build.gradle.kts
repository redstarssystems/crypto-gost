plugins {
    id("com.android.application")
}

android {
    namespace = "org.rssys.gost.demo"
    compileSdk = 34
    defaultConfig {
        applicationId = "org.rssys.gost.demo"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes {
        debug {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
    implementation(files(
        "libs/crypto-gost-core-release.aar",
        "libs/crypto-gost-pkix-release.aar",
        "libs/crypto-gost-tls13-release.aar",
        "libs/crypto-gost-jsse-release.aar",
    ))
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
