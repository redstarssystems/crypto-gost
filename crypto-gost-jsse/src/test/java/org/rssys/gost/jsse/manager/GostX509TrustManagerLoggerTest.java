package org.rssys.gost.jsse.manager;

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
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.util.GostLogger;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

class GostX509TrustManagerLoggerTest {

    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle leaf;
    private TestLogger testLogger;
    private GostLogger.LogSink originalLogger;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        root = TlsTestHelper.createRootCA(params);
        leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
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

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        assertThrows(
                java.security.cert.CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, "wrong-host", false));

        assertTrue(
                testLogger.containsLevel(GostLogger.Level.WARNING),
                "При ошибке валидации должен быть WARNING лог");
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

        boolean containsLevel(GostLogger.Level level) {
            return entries.stream().anyMatch(e -> e.level() == level);
        }

        boolean containsMessage(String fragment) {
            return entries.stream()
                    .anyMatch(e -> e.message() != null && e.message().contains(fragment));
        }
    }
}
