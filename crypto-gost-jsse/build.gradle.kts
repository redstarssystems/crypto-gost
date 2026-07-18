plugins {
    id("com.android.library")
}

android {
    namespace = "org.rssys.gost.jsse"
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

    buildTypes {
        release {
            consumerProguardFiles(
                "src/main/resources/META-INF/proguard/crypto-gost-jsse.pro"
            )
        }
    }

    sourceSets {
        getByName("main") {
            java.apply {
                (this as org.gradle.api.tasks.util.PatternFilterable).exclude(
                    "**/JdkHttpOcspFetcher.java",
                    "**/JdkHttpCrlFetcher.java"
                )
            }
        }
    }
}

dependencies {
    api(project(":crypto-gost-core"))
    api(project(":crypto-gost-pkix"))
    api(project(":crypto-gost-tls13"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}
