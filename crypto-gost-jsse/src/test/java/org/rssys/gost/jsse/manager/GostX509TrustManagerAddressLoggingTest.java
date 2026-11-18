package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.HexFormat;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.crl.CrlSizeLimitException;
import org.rssys.gost.jsse.ocsp.OcspFetchResult;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.jsse.testkit.LogSecrets;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.signature.ECParameters;

/**
 * Адрес из CDP и AIA сертификата приходит от недоверенной стороны и может содержать учётные
 * данные и токены: в журнал и сообщения исключений менеджера он попадает без них.
 */
@DisplayName("GostX509TrustManager: адреса CDP и AIA в журнале без учётных данных и параметров")
class GostX509TrustManagerAddressLoggingTest {

    private static final String CDP = LogSecrets.uri("http", "crl.example.com/root.crl");
    private static final String AIA = LogSecrets.uri("http", "ocsp.example.com/ocsp");

    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle root;

    private LogCapture log;

    @BeforeAll
    static void setUpCerts() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
    }

    @BeforeEach
    void captureLogger() {
        log = LogCapture.start(LogCapture.JSSE);
    }

    @AfterEach
    void restoreLogger() {
        log.close();
    }

    private static GostCertificate leaf(byte[] extension) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        extension)
                .cert;
    }

    private void assertNoSecrets(String where) {
        List<String> lines = log.allMessages();
        assertFalse(lines.isEmpty(), where + ": ожидалась запись в журнале");
        for (String line : lines) {
            assertFalse(LogSecrets.leaks(line), where + ": секреты в журнале: " + line);
        }
    }

    private GostX509TrustManager crlManager(CrlPolicy policy, CrlFetcher fetcher) {
        return GostX509TrustManager.fromTrustAnchors(
                TrustAnchors.ofCertificate(root.cert),
                OcspPolicy.IF_PRESENT,
                null,
                policy,
                fetcher);
    }

    @Test
    @DisplayName("CRL: зеркало недоступно, превышение размера и прерывание - без секретов")
    void crlMessagesHaveNoSecrets() throws Exception {
        GostCertificate leaf = leaf(PkixCertTestHelper.buildCdpExtension(CDP));
        List<GostCertificate> chain = List.of(leaf, root.cert);

        // Зеркало недоступно (IF_CDP_PRESENT: проверка пропускается, запись в журнале остаётся)
        crlManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            throw new IOException("CDP down");
                        })
                .validateChainWithOcsp(chain, null, false);
        assertNoSecrets("зеркало недоступно");
        List<String> unavailable =
                log.messages(Level.WARNING, "GostX509TrustManager").stream()
                        .filter(m -> m.contains("CRL mirror unavailable"))
                        .toList();
        assertEquals(1, unavailable.size(), "один поглощённый отказ - одна запись");
        assertTrue(unavailable.get(0).contains("NETWORK"), "причина перечислением");
        assertFalse(
                log.allMessages().stream().anyMatch(m -> m.contains("CDP down")),
                "текст исключения загрузчика в журнал не идёт");

        log.clear();
        CertificateException tooBig =
                assertThrows(
                        CertificateException.class,
                        () ->
                                crlManager(
                                                CrlPolicy.REQUIRE,
                                                uri -> {
                                                    throw new CrlSizeLimitException(
                                                            "CRL response exceeds 1 bytes", 1, 2);
                                                })
                                        .validateChainWithOcsp(chain, null, false));
        assertNoSecrets("превышение размера");
        assertEquals(
                1,
                log.messages(Level.WARNING, "GostX509TrustManager").stream()
                        .filter(m -> m.contains("exceeds size limit"))
                        .count(),
                "превышение размера пишется один раз и на WARNING");
        assertEquals(List.of(), log.messages(Level.SEVERE), "ERROR для обработанного отказа нет");
        assertFalse(LogSecrets.leaks(tooBig.getMessage()), tooBig.getMessage());

        log.clear();
        Thread.currentThread().interrupt();
        try {
            CertificateException interrupted =
                    assertThrows(
                            CertificateException.class,
                            () ->
                                    crlManager(
                                                    CrlPolicy.REQUIRE,
                                                    uri -> {
                                                        throw new IOException("interrupted");
                                                    })
                                            .validateChainWithOcsp(chain, null, false));
            assertFalse(
                    LogSecrets.leaks(interrupted.getMessage()),
                    "секреты в сообщении: " + interrupted.getMessage());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    @DisplayName("OCSP: ответ не получен - адрес в журнале без секретов")
    void ocspFailureHasNoSecrets() throws Exception {
        GostCertificate leaf = leaf(PkixCertTestHelper.buildAiaOcspExtension(AIA));
        List<GostCertificate> chain = List.of(leaf, root.cert);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        (certDer, issuerDer, uri) -> null);

        // Без ответа OCSP политика STAPLING_OR_FETCH отказывает, запись о неудаче уже в журнале
        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));

        assertNoSecrets("OCSP");
        assertTrue(
                log.allMessages().stream().anyMatch(l -> l.contains("ocsp.example.com/ocsp")),
                "путь адреса в журнале сохраняется");
    }

    @Test
    @DisplayName("OCSP: причина загрузчика и серийный номер в одной записи, текста исключения нет")
    void ocspFailureCarriesReasonAndSerial() throws Exception {
        GostCertificate leaf = leaf(PkixCertTestHelper.buildAiaOcspExtension(AIA));
        List<GostCertificate> chain = List.of(leaf, root.cert);
        OcspFetcher timedOut =
                new OcspFetcher() {
                    @Override
                    public byte[] fetch(byte[] certDer, byte[] issuerDer, String uri) {
                        return null;
                    }

                    @Override
                    public OcspFetchResult fetchWithNonce(
                            byte[] certDer, byte[] issuerDer, String uri) {
                        return OcspFetchResult.failed(FetchFailure.TIMEOUT);
                    }
                };
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        timedOut);

        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));

        List<String> failed =
                log.messages(Level.WARNING, "GostX509TrustManager").stream()
                        .filter(m -> m.contains("OCSP fetch failed"))
                        .toList();
        assertEquals(1, failed.size(), "один поглощённый отказ - одна запись: " + failed);
        String serialHex = HexFormat.of().formatHex(leaf.getSerialNumber());
        assertTrue(failed.get(0).contains(serialHex), "серийный номер сертификата: " + failed);
        assertTrue(failed.get(0).contains("TIMEOUT"), "причина перечислением: " + failed);
        assertNoSecrets("OCSP с причиной");
    }
}
