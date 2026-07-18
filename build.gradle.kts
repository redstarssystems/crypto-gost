import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension

plugins {
    id("com.android.library") version "9.2.1" apply false
}

subprojects {
    plugins.withId("com.android.library") {

        apply(plugin = "maven-publish")
        apply(plugin = "signing")

        extensions.configure<PublishingExtension> {
            publications {
                register<MavenPublication>("release") {
                    afterEvaluate { from(components["release"]) }
                    groupId = "org.rssys"
                    artifactId = "${project.name}-android"
                    version = CryptoGostVersion.resolve(project)
                    pom {
                        name = "crypto-gost — ${project.name}"
                        description =
                            "Android-модуль ${project.name} библиотеки ГОСТ-криптографии"
                        url = "https://gitflic.ru/project/red-stars-systems/crypto-gost"
                        licenses {
                            license {
                                name = "Открытая лицензия на ПО «Рэд старс системс»"
                                url = "https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE"
                            }
                        }
                        developers {
                            developer {
                                name = "Михаил Ананьев"
                                email = "mike1452@yandex.ru"
                            }
                        }
                        scm {
                            connection = "scm:git:https://gitflic.ru/project/red-stars-systems/crypto-gost.git"
                        }
                    }
                }
            }
            repositories {
                maven {
                    url = uri(MavenPublishUrl.resolve(project))
                    credentials {
                        val creds = MavenSettingsCredentials.resolve("gitflic")
                        username = creds.username
                        password = creds.password
                    }
                }
            }
        }

        // Имя ключа и бинарь — из профиля sign корневого pom.xml
        project.ext.set("signing.gnupg.keyName", GpgKeyName.resolve(project))
        project.ext.set("signing.gnupg.executable", "gpg2")

        extensions.configure<SigningExtension> {
            useGpgCmd()
            sign(
                extensions.getByType<PublishingExtension>()
                    .publications["release"]
            )
        }


    }
}
