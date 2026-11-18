plugins {
    id("com.android.library")
}

android {
    namespace = "org.rssys.gost.pkix"
    compileSdk = 34

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    defaultConfig {
        minSdk = 34
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            consumerProguardFiles(
                "src/main/resources/META-INF/proguard/crypto-gost-pkix.pro"
            )
        }
    }

    sourceSets {
        getByName("main") {
            java.apply {
                (this as org.gradle.api.tasks.util.PatternFilterable).exclude(
                    "**/JdkHttpTspTransport.java",
                    // движок на java.net.http, которого нет на Android 14
                    "**/internal/net/JdkHttpFetch.java"
                )
            }
        }
    }
}

dependencies {
    api(project(":crypto-gost-core"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}
