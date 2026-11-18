package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * {@link GostX509TrustManager#validateClientChain}: порядок «staple клиента -> fetch».
 * Обязательный staple фиксируется до сетевого запроса, поэтому ответ, полученный по сети,
 * политику {@link ClientOcspPolicy#REQUIRE} не выполняет.
 */
@DisplayName("GostX509TrustManager.validateClientChain: staple клиента и fetch")
class GostX509TrustManagerClientOcspTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static PkixCertTestHelper.CertBundle root;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
    }

    /** Счётчик обращений к «респондеру»; отвечает валидным ответом о статусе good. */
    private static final class CountingFetcher implements OcspFetcher {
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public byte[] fetch(byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
            calls.incrementAndGet();
            try {
                GostCertificate cert = new GostCertificate(certDer);
                return ocspFor(cert);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static byte[] ocspFor(GostCertificate cert) throws Exception {
        return GostOcspResponseBuilder.create(cert.getSerialNumber())
                .issuerDn(root.subjectDn)
                .thisUpdate(Instant.now())
                .noNextUpdate()
                .sign(root.priv);
    }

    /** Клиентский leaf с AIA-адресом OCSP, чтобы fetch вообще был возможен. */
    private static GostCertificate clientLeafWithAia() throws Exception {
        byte[] aia = PkixCertTestHelper.buildAiaOcspExtension("http://localhost:1/ocsp");
        return PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_CLIENT_AUTH},
                        false,
                        null,
                        aia)
                .cert;
    }

    private static GostX509TrustManager trust(CountingFetcher fetcher) {
        return GostX509TrustManager.fromTrustAnchors(
                TrustAnchors.ofCertificate(root.cert), OcspPolicy.STAPLING_OR_FETCH, fetcher);
    }

    @Test
    @DisplayName("REQUIRE без staple: отказ, сетевой запрос не выполняется")
    void requireRejectsWithoutStapleAndDoesNotFetch() throws Exception {
        CountingFetcher fetcher = new CountingFetcher();
        List<GostCertificate> chain = List.of(clientLeafWithAia(), root.cert);

        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () -> trust(fetcher).validateClientChain(chain, ClientOcspPolicy.REQUIRE),
                        "REQUIRE без присланного staple должен отклоняться");
        // engine берёт код alert'а из причины: без неё отказ ушёл бы с кодом по умолчанию
        TlsException cause = assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(
                TlsConstants.ALERT_BAD_CERTIFICATE,
                cause.getAlertCode(),
                "ожидался alert bad_certificate");
        assertEquals(
                0,
                fetcher.calls.get(),
                "отказ обязан наступить до fetch: ответ из сети не засчитывается");
    }

    @Test
    @DisplayName("REQUEST без staple: fetch выполняется и ответ принимается (контроль)")
    void requestWithoutStapleFetches() throws Exception {
        CountingFetcher fetcher = new CountingFetcher();
        List<GostCertificate> chain = List.of(clientLeafWithAia(), root.cert);

        assertDoesNotThrow(
                () -> trust(fetcher).validateClientChain(chain, ClientOcspPolicy.REQUEST));
        assertEquals(1, fetcher.calls.get(), "REQUEST сохраняет прежний best-effort fetch");
    }

    @Test
    @DisplayName("REQUIRE со staple: принимается без сетевого запроса")
    void requireWithStapleDoesNotFetch() throws Exception {
        CountingFetcher fetcher = new CountingFetcher();
        GostCertificate leaf = clientLeafWithAia();
        leaf.setOcspResponse(ocspFor(leaf));
        List<GostCertificate> chain = List.of(leaf, root.cert);

        assertDoesNotThrow(
                () -> trust(fetcher).validateClientChain(chain, ClientOcspPolicy.REQUIRE));
        assertEquals(0, fetcher.calls.get(), "при присланном staple fetch не нужен");
    }
}
