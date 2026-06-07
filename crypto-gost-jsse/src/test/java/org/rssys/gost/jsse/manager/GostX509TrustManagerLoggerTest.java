package org.rssys.gost.jsse.manager;
import org.rssys.gost.jsse.RssysGostJsseProvider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.lang.System.Logger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.*;

class GostX509TrustManagerLoggerTest {

    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle leaf;
    private TestLogger testLogger;
    private System.Logger originalLogger;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        root = TlsTestHelper.createRootCA(params);
        leaf = TlsTestHelper.createCertSignedBy(params, root.priv,
                root.cert.getPublicKey(), root.subjectDn,
                "20240501120000Z", "21060101120000Z",
                new String[]{"localhost"}, (String[]) null,
                (byte[]) null, (String[]) null,
                false, null);
    }

    @BeforeEach
    void captureLogger() {
        testLogger = new TestLogger();
        originalLogger = GostX509TrustManager.setLoggerForTest(testLogger);
    }

    @AfterEach
    void restoreLogger() {
        GostX509TrustManager.setLoggerForTest(originalLogger);
    }

    @Test
    @DisplayName("Лог: cert validation failure WARNING")
    void testValidationFailureLogged() {
        GostX509TrustManager tm = new GostX509TrustManager(null, false);

        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        assertThrows(java.security.cert.CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, "wrong-host", false));

        assertTrue(testLogger.containsLevel(Logger.Level.WARNING),
                "При ошибке валидации должен быть WARNING лог");
    }

    private static final class TestLogger implements System.Logger {
        private final List<LogEntry> entries = new ArrayList<>();

        record LogEntry(Level level, String message) {}

        @Override
        public String getName() { return "test"; }

        @Override
        public boolean isLoggable(Level level) { return true; }

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
            return entries.stream().anyMatch(e -> e.message() != null && e.message().contains(fragment));
        }
    }
}
