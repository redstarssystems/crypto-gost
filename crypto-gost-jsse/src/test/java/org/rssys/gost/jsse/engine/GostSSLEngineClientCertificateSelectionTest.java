package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Security;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Выбор клиентского сертификата в {@link GostSSLEngine} по CertificateRequest: клиент не выбирает
 * сертификат заранее, а делает это селектором на основе KeyManager, и сессия показывает то, что
 * реально отправлено (RFC 8446 §4.4.2, §4.4.3).
 */
@DisplayName("GostSSLEngine: выбор клиентского сертификата по CertificateRequest")
class GostSSLEngineClientCertificateSelectionTest {

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static PkixCertTestHelper.CertBundle serverRoot;
    private static PkixCertTestHelper.CertBundle serverLeaf;
    private static PkixCertTestHelper.CertBundle root256;
    private static PkixCertTestHelper.CertBundle root512;
    private static PkixCertTestHelper.CertBundle leaf256;
    private static PkixCertTestHelper.CertBundle leaf512;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        serverRoot = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        serverLeaf = leaf(ECParameters.tc26a256(), serverRoot, new String[] {"localhost"});
        root256 = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        root512 = PkixCertTestHelper.createRootCA(ECParameters.tc26a512());
        leaf256 = leaf(ECParameters.tc26a256(), root256, null);
        leaf512 = leaf(ECParameters.tc26a512(), root512, null);
    }

    private static PkixCertTestHelper.CertBundle leaf(
            ECParameters params, PkixCertTestHelper.CertBundle ca, String[] san) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                ca.priv,
                ca.cert.getPublicKey(),
                ca.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                san,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static void add(
            GostX509KeyManager km,
            String alias,
            PkixCertTestHelper.CertBundle leaf,
            PkixCertTestHelper.CertBundle ca)
            throws Exception {
        km.addKeyEntry(alias, CertificateBridge.toJca(List.of(leaf.cert, ca.cert)), leaf.priv);
    }

    private static GostX509TrustManager trust(PkixCertTestHelper.CertBundle... roots) {
        TrustAnchors anchors = TrustAnchors.ofCertificate(roots[0].cert);
        return GostX509TrustManager.fromTrustAnchors(anchors);
    }

    private static GostSSLEngine server(
            PkixCertTestHelper.CertBundle clientRoot, boolean requestAuth) throws Exception {
        GostSSLSessionContext context = new GostSSLSessionContext(CS);
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "server", serverLeaf, serverRoot);
        GostSSLEngine server =
                GostSSLEngine.createForServer(km, trust(clientRoot), "localhost", 0, context);
        if (requestAuth) {
            server.setNeedClientAuth(true);
        }
        return server;
    }

    private static GostSSLEngine client(GostX509KeyManager km) {
        GostSSLSessionContext context = new GostSSLSessionContext(CS);
        return GostSSLEngine.createForClient(km, trust(serverRoot), "localhost", 0, context);
    }

    @Test
    @DisplayName(
            "Только 512-битный сертификат: уходит на CertificateRequest, сессия его показывает")
    void only512CertificateIsSentAndReported() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "k512", leaf512, root512);
        GostSSLEngine client = client(km);
        GostSSLEngine server = server(root512, true);

        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        Certificate[] local = client.getSession().getLocalCertificates();
        assertNotNull(local, "сертификат был запрошен и отправлен");
        assertEquals(2, local.length, "отправлена цепочка из листа и корня");
        assertEquals(
                CertificateBridge.toJca(leaf512.cert),
                local[0],
                "в сессии лист, который реально ушёл серверу");
        assertEquals(
                CertificateBridge.toJca(leaf512.cert),
                server.getSession().getPeerCertificates()[0],
                "сервер принял именно 512-битный лист (CertificateVerify схемой 512)");
    }

    @Test
    @DisplayName("Сертификаты 256 и 512: сервер принимает все схемы, берётся первая запись")
    void bothCertificatesFirstFitWins() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "k256", leaf256, root256);
        add(km, "k512", leaf512, root512);
        GostSSLEngine client = client(km);
        GostSSLEngine server = server(root256, true);

        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        assertEquals(
                CertificateBridge.toJca(leaf256.cert),
                client.getSession().getLocalCertificates()[0],
                "первая подошедшая запись");
        assertEquals(
                CertificateBridge.toJca(leaf256.cert).getSubjectX500Principal(),
                client.getSession().getLocalPrincipal(),
                "локальный субъект совпадает с отправленным листом");
    }

    @Test
    @DisplayName("Сервер сертификат не запрашивал: getLocalCertificates() и принципал равны null")
    void noCertificateRequestMeansNoLocalCertificates() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "k256", leaf256, root256);
        GostSSLEngine client = client(km);
        GostSSLEngine server = server(root256, false);

        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        assertNull(client.getSession().getLocalCertificates(), "ничего не отправлялось");
        assertNull(client.getSession().getLocalPrincipal(), "и субъекта нет");
    }

    @Test
    @DisplayName("Исключение селектора: SSLException приложению и alert internal_error, не сырое")
    void selectorFailureBecomesInternalError() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "k256", leaf256, root256);
        GostSSLEngine client = client(km);
        client.setClientCertificateSelectorForTest(
                request -> {
                    throw new IllegalArgumentException("secret detail");
                });
        GostSSLEngine server = server(root256, true);

        RuntimeException failure =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                GostSSLEngineLoopbackTest.doLoopback(
                                        client, server, InMemoryTlsTransport.newPair()),
                        "сбой селектора роняет рукопожатие");

        SSLException sslFailure = assertInstanceOf(SSLException.class, failure.getCause());
        assertFalse(
                String.valueOf(sslFailure.getMessage()).contains("secret detail"),
                "текст исключения кода приложения в сообщение не попадает");
        TlsException tls = assertInstanceOf(TlsException.class, sslFailure.getCause());
        assertEquals(
                TlsConstants.ALERT_INTERNAL_ERROR,
                tls.getAlertCode(),
                "alert internal_error, а не handshake_failure");
        assertInstanceOf(
                IllegalArgumentException.class,
                tls.getCause(),
                "причина сохранена для диагностики");
    }

    @Test
    @DisplayName(
            "Staple чужого листа не прикладывается: сервер с политикой REQUEST не отвергает клиента")
    void foreignStapleIsNotAttachedToSelectedCertificate() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "k256", leaf256, root256);
        add(km, "k512", leaf512, root512);
        GostSSLEngine client = client(km);
        // Выбор зависит от сервера: уйдёт 256-битный лист, а staple выпущен для 512-битного
        client.setOcspResponse(
                GostOcspResponseBuilder.create(leaf512.cert.getSerialNumber())
                        .issuerDn(root512.subjectDn)
                        .thisUpdate(Instant.now())
                        .noNextUpdate()
                        .sign(root512.priv));
        GostSSLSessionContext serverContext = new GostSSLSessionContext(CS);
        serverContext.setClientOcspPolicy(ClientOcspPolicy.REQUEST);
        serverContext.setNeedClientAuth(true);
        GostX509KeyManager serverKm = new GostX509KeyManager();
        add(serverKm, "server", serverLeaf, serverRoot);
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        serverKm, trust(root256), "localhost", 0, serverContext);

        // Прикреплённый чужой staple сервер отверг бы (CertID другого сертификата)
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        assertEquals(
                CertificateBridge.toJca(leaf256.cert),
                client.getSession().getLocalCertificates()[0],
                "ушёл 256-битный лист без чужого staple");
    }
}
