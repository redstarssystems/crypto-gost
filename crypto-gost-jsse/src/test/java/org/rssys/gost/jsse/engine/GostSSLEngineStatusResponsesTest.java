package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.ExtendedSSLSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Клиентская сессия отдаёт через {@code getStatusResponses()} OCSP-ответы, которые прислал сервер,
 * в порядке его цепочки. Ответ, полученный клиентом по сети, к ним не относится.
 */
@DisplayName("GostSSLEngine: клиентская getStatusResponses() отражает присланное сервером")
class GostSSLEngineStatusResponsesTest {

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;
    private static PkixCertTestHelper.CertBundle serverLeafWithAia;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf = leaf(null);
        serverLeafWithAia =
                leaf(PkixCertTestHelper.buildAiaOcspExtension("http://localhost:1/ocsp"));
    }

    private static PkixCertTestHelper.CertBundle leaf(byte[] aia) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                new String[] {"localhost"},
                (String[]) null,
                new byte[] {(byte) 0x80},
                null,
                false,
                null,
                aia);
    }

    private static byte[] ocspFor(GostCertificate cert) throws Exception {
        return GostOcspResponseBuilder.create(cert.getSerialNumber())
                .issuerDn(root.subjectDn)
                .thisUpdate(Instant.now())
                .noNextUpdate()
                .sign(root.priv);
    }

    private static GostSSLEngine server(PkixCertTestHelper.CertBundle bundle, byte[] staple)
            throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry(
                "default", CertificateBridge.toJca(List.of(bundle.cert, root.cert)), bundle.priv);
        GostSSLEngine engine =
                GostSSLEngine.createForServer(
                        km,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(CS));
        if (staple != null) {
            engine.setOcspResponse(staple);
        }
        return engine;
    }

    private static GostSSLEngine client(OcspPolicy policy, OcspFetcher fetcher) {
        return GostSSLEngine.createForClient(
                new GostX509KeyManager(),
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), policy, fetcher),
                "localhost",
                0,
                new GostSSLSessionContext(CS));
    }

    private static List<byte[]> statusResponsesOf(GostSSLEngine client) {
        return ((ExtendedSSLSession) client.getSession()).getStatusResponses();
    }

    @Test
    @DisplayName("Сервер со staple: клиентская сессия отдаёт [staple] (root без staple отброшен)")
    void clientSessionExposesServerStaple() throws Exception {
        byte[] staple = ocspFor(serverLeaf.cert);
        GostSSLEngine client = client(OcspPolicy.IF_PRESENT, null);
        GostSSLEngineLoopbackTest.doLoopback(
                client, server(serverLeaf, staple), InMemoryTlsTransport.newPair());

        List<byte[]> responses = statusResponsesOf(client);
        assertEquals(1, responses.size(), "хвостовая пустая запись корня должна быть отброшена");
        assertArrayEquals(staple, responses.get(0));
    }

    @Test
    @DisplayName("Сервер без staple: клиентская сессия отдаёт пустой список")
    void clientSessionEmptyWithoutServerStaple() throws Exception {
        GostSSLEngine client = client(OcspPolicy.IF_PRESENT, null);
        GostSSLEngineLoopbackTest.doLoopback(
                client, server(serverLeaf, null), InMemoryTlsTransport.newPair());

        assertTrue(statusResponsesOf(client).isEmpty());
    }

    @Test
    @DisplayName("Снимок: пустые записи в середине сохраняются, обрезаются только хвостовые")
    void snapshotTrimsOnlyTrailingEmptyEntries() throws Exception {
        GostCertificate withA = new GostCertificate(serverLeaf.cert.getEncoded());
        GostCertificate withB = new GostCertificate(serverLeaf.cert.getEncoded());
        GostCertificate none1 = new GostCertificate(serverLeaf.cert.getEncoded());
        GostCertificate none2 = new GostCertificate(serverLeaf.cert.getEncoded());
        byte[] a = {1};
        byte[] b = {2};
        withA.setOcspResponse(a);
        withB.setOcspResponse(b);

        List<byte[]> middle =
                GostSSLEngine.snapshotPeerStatusResponses(List.of(withA, none1, withB));
        assertEquals(3, middle.size());
        assertArrayEquals(a, middle.get(0));
        assertEquals(0, middle.get(1).length, "пустая запись в середине означает «ответа нет»");
        assertArrayEquals(b, middle.get(2));

        List<byte[]> trailing =
                GostSSLEngine.snapshotPeerStatusResponses(List.of(withA, none1, none2));
        assertEquals(1, trailing.size(), "хвостовые пустые записи отбрасываются");

        assertTrue(GostSSLEngine.snapshotPeerStatusResponses(List.of(none1, none2)).isEmpty());
    }

    @Test
    @DisplayName("Ответ, полученный клиентом по сети (STAPLING_OR_FETCH), в сессию не попадает")
    // Trust manager кладёт сетевой ответ в те же GostCertificate; снимок после валидации выдал бы
    // его за присланный сервером. Снимок обязан быть сделан до валидации.
    void fetchedResponseIsNotExposed() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        OcspFetcher fetcher =
                (certDer, issuerDer, uri) -> {
                    fetches.incrementAndGet();
                    try {
                        return ocspFor(new GostCertificate(certDer));
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                };
        GostSSLEngine client = client(OcspPolicy.STAPLING_OR_FETCH, fetcher);
        GostSSLEngineLoopbackTest.doLoopback(
                client, server(serverLeafWithAia, null), InMemoryTlsTransport.newPair());

        assertTrue(fetches.get() > 0, "клиент должен был получить ответ по сети");
        assertTrue(
                statusResponsesOf(client).isEmpty(),
                "сессия отражает только присланное сервером, а не полученное клиентом");
    }
}
