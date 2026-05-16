package org.rssys.gost.jsse.examples.springboot;

import org.rssys.gost.jsse.RssysGostJsseProvider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

/**
 * Точка входа Spring Boot приложения с ГОСТ TLS 1.3.
 * <p>
 * Провайдер регистрируется в static-блоке, а не в main(), потому что
 * Spring Boot начинает конфигурировать встроенный Tomcat до того, как
 * контекст приложения полностью инициализирован. Если бы провайдер
 * регистрировался в @Bean-методе, SSLContext.getInstance("TLSv1.3", "RssysGostJsse")
 * мог бы упасть на "no such provider" при старте контейнера.
 * <p>
 * Исключаем Undertow auto-configuration: undertow-core есть на classpath
 * (из default-профиля), но undertow-servlet (DeploymentInfo) отсутствует,
 * и Spring Boot падает при попытке загрузить UndertowWebServerFactoryCustomizer.
 */
@SpringBootApplication(excludeName = {
        "org.springframework.boot.autoconfigure.web.embedded.EmbeddedWebServerFactoryCustomizerAutoConfiguration"
})
public class GostSpringBootApp {

    static {
        Security.addProvider(new RssysGostJsseProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(GostSpringBootApp.class, args);
    }
}
