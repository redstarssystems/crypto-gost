plugins {
    id("com.android.library")
}

android {
    namespace = "org.rssys.gost.tls13"
    compileSdk = 34

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    defaultConfig {
        minSdk = 31
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":crypto-gost-core"))
    api(project(":crypto-gost-pkix"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}
