pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "crypto-gost"
include(
    ":crypto-gost-core",
    ":crypto-gost-pkix",
    ":crypto-gost-tls13",
    ":crypto-gost-jsse",
)
