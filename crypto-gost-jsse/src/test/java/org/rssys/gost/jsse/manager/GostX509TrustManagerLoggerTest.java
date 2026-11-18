package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

@DisplayName("GostX509TrustManager: записи журнала")
class GostX509TrustManagerLoggerTest {

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle leaf;
    private LogCapture log;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        root = PkixCertTestHelper.createRootCA(params);
        leaf =
                PkixCertTestHelper.createCertSignedBy(
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
        log = LogCapture.start(LogCapture.JSSE);
    }

    @AfterEach
    void restoreLogger() {
        log.close();
    }

    @Test
    @DisplayName("Отказ по сертификату собеседника: менеджер не пишет, причина в исключении")
    void testValidationFailureIsNotLoggedByManager() {
        GostX509TrustManager tm = GostX509TrustManager.insecureTrustAll();
        // Фабрика предупреждает об отключённой проверке; к отказу это отношения не имеет
        log.clear();

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        java.security.cert.CertificateException failure =
                assertThrows(
                        java.security.cert.CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, "wrong-host", false));

        assertInstanceOf(TlsException.class, failure.getCause(), "причина отказа сохранена");
        // Отказ по данным собеседника пишет движок на DEBUG (у него есть соединение и стадия);
        // менеджер, вызванный напрямую, записей не делает
        assertEquals(
                List.of(),
                log.allMessages("GostX509TrustManager"),
                "менеджер не дублирует отказ: причина в исключении");
        assertEquals(List.of(), log.thrown(), "исключение и стек в журнал не попадают");
    }

    @Test
    @DisplayName("Конструктор без якорей отвергается, insecureTrustAll сохраняет leaf-проверки")
    void nullAnchorsRejectedAndInsecureFactoryKeepsLeafChecks() throws Exception {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostX509TrustManager.fromTrustAnchors(null),
                "null-якоря должны отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.empty(), OcspPolicy.IF_PRESENT, null),
                "пустой список якорей должен отвергаться");

        GostX509TrustManager tm = GostX509TrustManager.insecureTrustAll();
        assertThrows(
                java.security.cert.CertificateException.class,
                () -> tm.validateChainWithOcsp(List.of(leaf.cert, root.cert), "wrong-host", false),
                "insecureTrustAll не должен отключать проверку hostname");
    }

    @Test
    @DisplayName(
            "checkClientTrusted при STAPLING_REQUIRED без staple -> успех и один WARNING на TrustManager")
    void clientOcspRequiredPolicyDoesNotBlockMtls() throws Exception {
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.STAPLING_REQUIRED, null);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        X509Certificate[] jcaChain = CertificateBridge.toJca(chain);

        assertDoesNotThrow(
                () -> tm.checkClientTrusted(jcaChain, "EC"),
                "STAPLING_REQUIRED относится к серверному сертификату, не к клиентскому");
        int warningCount = countMessages("Client certificate OCSP is not mandatory");
        assertTrue(warningCount > 0, "должен быть WARNING о мягкой клиентской OCSP-политике");

        assertDoesNotThrow(() -> tm.checkClientTrusted(jcaChain, "EC"));
        assertEquals(
                warningCount,
                countMessages("Client certificate OCSP is not mandatory"),
                "повторная проверка не должна дублировать WARNING");
    }

    @Test
    @DisplayName("validateClientChain: предупреждение «не обязателен» только при политике OFF")
    void clientOcspWarningSuppressedWhenPolicyRequestsStaple() throws Exception {
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.STAPLING_REQUIRED, null);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        assertDoesNotThrow(() -> tm.validateClientChain(chain, ClientOcspPolicy.REQUEST));
        assertEquals(
                0,
                countMessages("Client certificate OCSP is not mandatory"),
                "при REQUEST политика клиентского staple задана явно, предупреждение неуместно");

        assertDoesNotThrow(() -> tm.validateClientChain(chain, ClientOcspPolicy.OFF));
        assertTrue(
                countMessages("Client certificate OCSP is not mandatory") > 0,
                "при OFF предупреждение остаётся (контроль)");
    }

    private static GostCertificate leafWithStaple(
            java.util.function.Function<byte[], byte[]> staple) throws Exception {
        GostCertificate stapled =
                PkixCertTestHelper.createCertSignedBy(
                                ECParameters.tc26a256(),
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
                                null)
                        .cert;
        stapled.setOcspResponse(staple.apply(stapled.getSerialNumber()));
        return stapled;
    }

    @Test
    @DisplayName("trustAll через сборщик пишет одно предупреждение об отключённой проверке")
    void trustAllWarnsOnce() {
        org.rssys.gost.jsse.GostSsl.builder().trustAll().buildClientContext();

        assertEquals(
                1,
                countMessages("certificate chain validation DISABLED"),
                "одно предупреждение на создание, а не по одному от сборщика и от менеджера");
    }

    @Test
    @DisplayName("Принятый клиентский сертификат пишется на уровне DEBUG, а не INFO")
    void acceptedClientCertificateIsLoggedAtDebug() throws Exception {
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(root.cert));

        tm.validateClientChain(List.of(leaf.cert, root.cert), ClientOcspPolicy.OFF);

        assertTrue(
                log.messages(Level.FINE, "GostX509TrustManager").stream()
                        .anyMatch(m -> m.contains("Client certificate accepted")),
                "запись есть на уровне DEBUG");
        assertFalse(
                hasLevel(Level.INFO), "на уровне INFO имя субъекта клиента в журнал не попадает");
    }

    @Test
    @DisplayName(
            "Отозванный staple: код alert 44, причина PkixException(REVOKED), запись «отозван»")
    void revokedStapleIsReportedAsRevocation() throws Exception {
        GostCertificate stapled =
                leafWithStaple(
                        serial ->
                                GostOcspResponseBuilder.create(serial)
                                        .issuerDn(root.subjectDn)
                                        .thisUpdate(Instant.now())
                                        .noNextUpdate()
                                        .revoked("20250101000000Z")
                                        .sign(root.priv));
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.IF_PRESENT, null);

        java.security.cert.CertificateException failure =
                assertThrows(
                        java.security.cert.CertificateException.class,
                        () ->
                                tm.validateChainWithOcsp(
                                        List.of(stapled, root.cert), "localhost", false));

        TlsException tlsCause = assertInstanceOf(TlsException.class, failure.getCause());
        assertEquals(
                TlsConstants.ALERT_CERTIFICATE_REVOKED,
                tlsCause.getAlertCode(),
                "отзыв должен давать alert certificate_revoked");
        PkixException pkixCause = assertInstanceOf(PkixException.class, tlsCause.getCause());
        assertEquals(PkixException.Reason.REVOKED, pkixCause.reason(), "причина сохранена");
        assertTrue(
                containsMessage("Certificate revoked"),
                "отзыв сообщается отдельной записью журнала");
        String serialHex = new java.math.BigInteger(1, stapled.getSerialNumber()).toString(16);
        assertTrue(
                log.allMessages("GostX509TrustManager").stream()
                        .anyMatch(m -> m.contains(serialHex)),
                "в записи об отзыве есть серийный номер: "
                        + log.allMessages("GostX509TrustManager"));
    }

    @Test
    @DisplayName("Staple с неверной подписью: код bad_certificate, менеджер записи не делает")
    void invalidStapleIsNotReportedAsRevocation() throws Exception {
        PkixCertTestHelper.CertBundle foreignRoot =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        GostCertificate stapled =
                leafWithStaple(
                        serial ->
                                GostOcspResponseBuilder.create(serial)
                                        .issuerDn(root.subjectDn)
                                        .thisUpdate(Instant.now())
                                        .noNextUpdate()
                                        .sign(foreignRoot.priv));
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.IF_PRESENT, null);

        java.security.cert.CertificateException failure =
                assertThrows(
                        java.security.cert.CertificateException.class,
                        () ->
                                tm.validateChainWithOcsp(
                                        List.of(stapled, root.cert), "localhost", false));

        TlsException tlsCause = assertInstanceOf(TlsException.class, failure.getCause());
        assertEquals(
                TlsConstants.ALERT_BAD_CERTIFICATE,
                tlsCause.getAlertCode(),
                "ответ с неверной подписью не отзыв");
        assertFalse(
                containsMessage("Certificate revoked"),
                "запись «отозван» не должна появляться без отзыва");
        // Отказ по данным собеседника пишет движок на DEBUG (у него есть соединение и стадия);
        // менеджер, вызванный напрямую, записей не делает - причина в исключении
        assertEquals(
                List.of(),
                log.allMessages("GostX509TrustManager"),
                "менеджер не дублирует отказ: причина в исключении");
    }

    private boolean hasLevel(Level level) {
        return !log.messages(level, "GostX509TrustManager").isEmpty();
    }

    private boolean containsMessage(String fragment) {
        return countMessages(fragment) > 0;
    }

    private int countMessages(String fragment) {
        return (int)
                log.allMessages("GostX509TrustManager").stream()
                        .filter(m -> m.contains(fragment))
                        .count();
    }
}
