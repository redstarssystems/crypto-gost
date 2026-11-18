package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.internal.net.FetchOutcome;
import org.rssys.gost.pkix.internal.net.FetchOutcome.Failure;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.internal.net.JdkHttpFetch;
import org.rssys.gost.pkix.internal.net.SlowServers;
import org.rssys.gost.pkix.util.DeadlineExceededException;

@DisplayName("TspFetchSupport: перевод исхода движка в IOException")
class TspFetchSupportTest {

    private static final String URL = "http://tsa.example/tsp?token=secret";

    private static IOException refusal(FetchTransport engine) {
        return assertThrows(
                IOException.class,
                () ->
                        TspFetchSupport.send(
                                new byte[] {1}, URL, Duration.ofSeconds(1), uri -> false, engine));
    }

    @Test
    @DisplayName("Понижение https до http: отдельный текст, адрес без параметров")
    void downgrade() {
        IOException e =
                refusal(
                        request ->
                                FetchOutcome.failure(
                                        Failure.DOWNGRADE,
                                        302,
                                        URI.create("http://tsa.example/next?token=secret"),
                                        true));

        assertEquals("Redirect downgrades https to http: http://tsa.example/next", e.getMessage());
    }

    @Test
    @DisplayName("Срок: «timed out» с адресом без параметров, причина сохранена")
    void deadline() {
        DeadlineExceededException cause = new DeadlineExceededException("deadline");

        IOException e =
                refusal(
                        request -> {
                            throw cause;
                        });

        assertEquals("TSP request timed out for http://tsa.example/tsp", e.getMessage());
        assertEquals(cause, e.getCause());
    }

    @Test
    @DisplayName("Исходный адрес с чужой схемой и переход с чужой схемой различаются текстом")
    void schemeMessages() {
        URI file = URI.create("file:///etc/x");

        assertEquals(
                "Unsupported TSP URL scheme: file",
                refusal(request -> FetchOutcome.failure(Failure.DISALLOWED_SCHEME, 0, file, false))
                        .getMessage());
        assertEquals(
                "Unsupported redirect URL scheme: file",
                refusal(request -> FetchOutcome.failure(Failure.DISALLOWED_SCHEME, 307, file, true))
                        .getMessage());
    }

    @Test
    @DisplayName(
            "Отказ TSA: исключение несёт код и адрес без параметров, журнал движка без WARNING")
    void refusalCarriesCauseAndEngineStaysQuiet() throws Exception {
        try (SlowServers servers = new SlowServers();
                LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            String url = servers.base + "/err500big?token=secret";

            IOException e =
                    assertThrows(
                            IOException.class,
                            () ->
                                    TspFetchSupport.send(
                                            new byte[] {1},
                                            url,
                                            Duration.ofSeconds(5),
                                            uri -> false,
                                            new JdkHttpFetch()));

            assertTrue(e.getMessage().contains("HTTP 500"), "код ответа в исключении");
            assertTrue(e.getMessage().contains(servers.base), "адрес в исключении");
            assertFalse(e.getMessage().contains("secret"), "параметры запроса не выводятся");
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отказ уже в исключении, движок его не дублирует на WARNING");
            assertTrue(
                    log.messages(Level.FINE).stream().anyMatch(m -> m.contains("HTTP 500")),
                    "ход загрузки виден на DEBUG: " + log.messages(Level.FINE));
        }
    }
}
