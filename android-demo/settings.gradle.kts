pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        maven {
            url = uri("https://registry.gitflic.ru/project/red-stars-systems/crypto-gost/package/-/maven")
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "android-demo"
include(":app")
