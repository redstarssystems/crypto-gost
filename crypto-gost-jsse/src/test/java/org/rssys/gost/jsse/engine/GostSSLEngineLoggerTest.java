package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.System.Logger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;

class GostSSLEngineLoggerTest {

    private static GostCertificate serverCert;
    private static GostCertificate rootCa;
    private static GostX509KeyManager serverKeyManager;

    private TestLogger testLogger;
    private System.Logger originalLogger;

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
                testLogger.containsLevel(Logger.Level.DEBUG), "Должен быть хотя бы один DEBUG лог");
        assertTrue(
                testLogger.containsMessage("Handshake started"),
                "Должен содержать 'Handshake started' в любом сообщении");
    }

    // Фрагмент именно handshake-предупреждения (отличается от создания "created WITHOUT")
    private static final String HANDSHAKE_NO_HOSTNAME =
            "Client TLS handshake without hostname verification";

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

    private static final class TestLogger implements System.Logger {
        private final List<LogEntry> entries = new ArrayList<>();

        record LogEntry(Level level, String message) {}

        @Override
        public String getName() {
            return "test";
        }

        @Override
        public boolean isLoggable(Level level) {
            return true;
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            entries.add(new LogEntry(level, msg));
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            entries.add(new LogEntry(level, format));
        }

        boolean containsLevel(Level level) {
            return entries.stream().anyMatch(e -> e.level() == level);
        }

        boolean containsMessage(String fragment) {
            return entries.stream()
                    .anyMatch(e -> e.message() != null && e.message().contains(fragment));
        }
    }
}
