package org.rssys.gost.pkix.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.pkix.LogCapture;

/**
 * Адрес запроса и перехода приходит от недоверенной стороны и может содержать учётные данные и
 * токены: в журнал движков он попадает без них.
 */
@DisplayName("Движки загрузки: адрес в журнале без учётных данных и параметров запроса")
class FetchLoggingTest {

    enum Engine {
        JDK_HTTP {
            @Override
            FetchOutcome run(FetchRequest request) throws Exception {
                return new JdkHttpFetch().execute(request);
            }
        },
        URL_CONNECTION {
            @Override
            FetchOutcome run(FetchRequest request) throws Exception {
                return UrlConnectionFetch.execute(request);
            }
        };

        abstract FetchOutcome run(FetchRequest request) throws Exception;
    }

    private SlowServers servers;
    private LogCapture log;

    @BeforeEach
    void setUp() throws Exception {
        servers = new SlowServers();
    }

    @AfterEach
    void tearDown() {
        if (log != null) {
            log.close();
        }
        servers.close();
    }

    /** Перехват на родителе логгеров pkix: оба движка пишут под ним, имя класса различает их. */
    private void capture() {
        log = LogCapture.start(LogCapture.PKIX);
    }

    private URI secretUri(String path) {
        return URI.create(
                servers.base.replace("http://", "http://user:pass@") + path + "?token=secret");
    }

    private FetchRequest request(String path, java.util.function.Predicate<URI> blocked) {
        return FetchRequest.crl(secretUri(path), Duration.ofSeconds(5), 262_144, blocked);
    }

    private void assertLoggedWithoutSecrets(String fragment) {
        List<String> lines = log.allMessages();
        assertEquals(
                List.of(),
                log.messagesAtOrAbove(java.util.logging.Level.WARNING),
                "отказ загрузки движок пишет на DEBUG, WARNING делает вызывающий");
        assertTrue(
                lines.stream().anyMatch(l -> l.contains(fragment)),
                "ожидалась запись «" + fragment + "», журнал: " + lines);
        for (String line : lines) {
            assertFalse(
                    line.contains("pass") || line.contains("secret"), "секреты в журнале: " + line);
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Заблокированный адрес")
    void blockedAddress(Engine engine) throws Exception {
        capture();

        engine.run(request("/ok", uri -> true));

        assertLoggedWithoutSecrets("address not allowed");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Ответ не 200")
    void nonOk(Engine engine) throws Exception {
        capture();

        engine.run(request("/err500big", uri -> false));

        assertLoggedWithoutSecrets("Fetch failed: HTTP");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Перенаправление не разрешено и слишком много перенаправлений")
    void redirects(Engine engine) throws Exception {
        capture();

        engine.run(request("/rfile", uri -> false));
        assertLoggedWithoutSecrets("redirect (HTTP 307) is not allowed");

        engine.run(request("/loop", uri -> false));
        assertLoggedWithoutSecrets("too many redirects");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Неожиданный Content-Type")
    void unexpectedContentType(Engine engine) throws Exception {
        capture();
        FetchRequest tsp =
                FetchRequest.tsp(
                        secretUri("/type-wrong"),
                        new byte[] {1},
                        Duration.ofSeconds(5),
                        262_144,
                        uri -> false);

        engine.run(tsp);

        assertLoggedWithoutSecrets("unexpected Content-Type");
    }
}
