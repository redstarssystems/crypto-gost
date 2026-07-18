package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.util.GostLogger;

class GostSSLEngineLoggerTest {

    private static GostCertificate serverCert;
    private static GostCertificate rootCa;
    private static GostX509KeyManager serverKeyManager;

    private TestLogger testLogger;
    private GostLogger.LogSink originalLogger;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
    }

    @BeforeEach
    void captureLogger() {
        testLogger = new TestLogger();
        originalLogger = GostSSLEngine.setLoggerForTest(testLogger);
    }

    @AfterEach
    void restoreLogger() {
        GostSSLEngine.setLoggerForTest(originalLogger);
    }

    @Test
    @DisplayName("Лог: handshake start DEBUG при beginHandshake")
    void testHandshakeStartLogged() throws Exception {
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "example.com",
                        443,
                        true);

        clientEngine.beginHandshake();

        assertTrue(
                testLogger.containsLevel(GostLogger.Level.DEBUG),
                "Должен быть хотя бы один DEBUG лог");
        assertTrue(
                testLogger.containsMessage("Handshake started"),
                "Должен содержать 'Handshake started' в любом сообщении");
    }

    // Фрагмент именно handshake-предупреждения (отличается от создания "created WITHOUT")
    private static final String HANDSHAKE_NO_HOSTNAME =
            "Client TLS handshake without hostname verification";

    // сообщение при создании engine через session context флаг
    private static final String CREATED_NO_HOSTNAME =
            "Client SSLEngine created WITHOUT hostname verification";

    @Test
    @DisplayName("Лог: session context флаг — ровно один WARNING при создании, ноль при handshake")
    void testSessionContextFlagLogsOnceOnCreate() throws Exception {
        GostSSLSessionContext sc = new GostSSLSessionContext(null, 0);
        sc.setEndpointIdentificationDisabled(true);

        // создание engine — должен быть ровно 1 WARNING
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "example.com",
                        443,
                        sc);

        long creationWarnings =
                testLogger.entries().stream()
                        .filter(e -> e.level() == GostLogger.Level.WARNING)
                        .filter(
                                e ->
                                        e.message() != null
                                                && e.message().contains(CREATED_NO_HOSTNAME))
                        .count();
        assertEquals(
                1,
                creationWarnings,
                "Ровно один WARNING при создании engine через session context флаг");

        // handshake — не должен добавлять handshake-WARNING
        clientEngine.beginHandshake();

        long handshakeWarnings =
                testLogger.entries().stream()
                        .filter(
                                e ->
                                        e.message() != null
                                                && e.message().contains(HANDSHAKE_NO_HOSTNAME))
                        .count();
        assertEquals(
                0, handshakeWarnings, "Session context opt-out не должен давать handshake-WARNING");
    }

    @Test
    @DisplayName(
            "Лог: осознанный opt-out (createForClientNoHostnameCheck) не даёт handshake-WARNING")
    void testExplicitNoHostnameCheckSuppressesHandshakeWarning() throws Exception {
        // намерение объявлено разово при создании — повтор на каждом соединении избыточен
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClientNoHostnameCheck(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "example.com",
                        443,
                        null);

        clientEngine.beginHandshake();

        assertFalse(
                testLogger.containsMessage(HANDSHAKE_NO_HOSTNAME),
                "explicit opt-out не должен логировать handshake-WARNING о проверке hostname");
    }

    @Test
    @DisplayName("Лог: снятый safe-default (setSSLParameters null) даёт handshake-WARNING")
    void testClearedSafeDefaultWarnsPerHandshake() throws Exception {
        // safe-default HTTPS, затем очистка через setSSLParameters(null) — тревожный сигнал
        GostSSLEngine clientEngine =
                GostSSLEngine.createForContextClient(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "example.com",
                        443,
                        null,
                        null);
        javax.net.ssl.SSLParameters p = clientEngine.getSSLParameters();
        p.setEndpointIdentificationAlgorithm(null);
        clientEngine.setSSLParameters(p);

        clientEngine.beginHandshake();

        assertTrue(
                testLogger.containsMessage(HANDSHAKE_NO_HOSTNAME),
                "снятый safe-default должен логировать handshake-WARNING per-connection");
    }

    @Test
    @DisplayName("Лог: активная проверка hostname (safe-default) не даёт handshake-WARNING")
    void testActiveVerificationNoWarning() throws Exception {
        GostSSLEngine clientEngine =
                GostSSLEngine.createForContextClient(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "example.com",
                        443,
                        null,
                        null);

        clientEngine.beginHandshake();

        assertFalse(
                testLogger.containsMessage(HANDSHAKE_NO_HOSTNAME),
                "при активной проверке hostname handshake-WARNING не нужен");
    }

    private static final class TestLogger implements GostLogger.LogSink {
        private final List<LogEntry> entries = new ArrayList<>();

        record LogEntry(GostLogger.Level level, String message) {}

        @Override
        public void log(GostLogger.Level level, String msg, Throwable thrown) {
            entries.add(new LogEntry(level, msg));
        }

        @Override
        public void log(GostLogger.Level level, String format, Object... params) {
            entries.add(new LogEntry(level, format));
        }

        List<LogEntry> entries() {
            return entries;
        }

        boolean containsLevel(GostLogger.Level level) {
            return entries.stream().anyMatch(e -> e.level() == level);
        }

        boolean containsMessage(String fragment) {
            return entries.stream()
                    .anyMatch(e -> e.message() != null && e.message().contains(fragment));
        }
    }
}
