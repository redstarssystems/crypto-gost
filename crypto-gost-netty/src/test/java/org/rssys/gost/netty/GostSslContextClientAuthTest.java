package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslHandler;
import java.time.Instant;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.netty.NettyTestSupport.Fixture;
import org.rssys.gost.netty.NettyTestSupport.Outcome;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * Аутентификация клиента через Netty: режимы {@code OPTIONAL} и {@code REQUIRE}, а также
 * сочетание HTTP/2 (ALPN), mTLS и обязательного OCSP-staple клиентского сертификата.
 */
@DisplayName("Netty: аутентификация клиента")
class GostSslContextClientAuthTest {

    private static final UnpooledByteBufAllocator ALLOC = UnpooledByteBufAllocator.DEFAULT;
    private static final String HOST = "localhost";

    private static Fixture fixture;

    @BeforeAll
    static void setUp() throws Exception {
        fixture = new Fixture();
    }

    private static GostSslContextBuilder serverBuilder(ClientAuth auth) throws Exception {
        return GostSslContextBuilder.forServer(fixture.serverKeyManager())
                .trustManager(fixture.rootTrust())
                .clientAuth(auth);
    }

    private static GostSslContext clientWithCert() throws Exception {
        return GostSslContextBuilder.forClient()
                .trustManager(fixture.rootTrust())
                .keyManager(fixture.clientKeyManager())
                .build();
    }

    private static GostSslContext clientWithoutCert() throws Exception {
        return GostSslContextBuilder.forClient().trustManager(fixture.rootTrust()).build();
    }

    // ========================================================================
    // OPTIONAL и REQUIRE
    // ========================================================================

    @Test
    @DisplayName(
            "OPTIONAL с клиентским сертификатом: рукопожатие проходит, сервер видит сертификат")
    void optionalWithCertificate() throws Exception {
        SslHandler cs = clientWithCert().newHandler(ALLOC, HOST, 0);
        SslHandler ss = serverBuilder(ClientAuth.OPTIONAL).build().newHandler(ALLOC, HOST, 0);

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertTrue(outcome.succeeded(), "рукопожатие должно пройти: " + outcome);
        assertTrue(
                ss.engine().getSession().getPeerCertificates().length > 0,
                "сервер должен получить клиентский сертификат");
    }

    @Test
    @DisplayName("OPTIONAL без клиентского сертификата: рукопожатие проходит, у сервера нет пира")
    void optionalWithoutCertificate() throws Exception {
        SslHandler cs = clientWithoutCert().newHandler(ALLOC, HOST, 0);
        SslHandler ss = serverBuilder(ClientAuth.OPTIONAL).build().newHandler(ALLOC, HOST, 0);

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertTrue(outcome.succeeded(), "анонимный клиент допустим при OPTIONAL: " + outcome);
        assertThrows(
                SSLPeerUnverifiedException.class,
                () -> ss.engine().getSession().getPeerCertificates(),
                "сертификата клиента у сервера быть не должно");
    }

    @Test
    @DisplayName("REQUIRE с клиентским сертификатом: рукопожатие проходит")
    void requireWithCertificate() throws Exception {
        SslHandler cs = clientWithCert().newHandler(ALLOC, HOST, 0);
        SslHandler ss = serverBuilder(ClientAuth.REQUIRE).build().newHandler(ALLOC, HOST, 0);

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertTrue(outcome.succeeded(), "рукопожатие должно пройти: " + outcome);
        assertTrue(ss.engine().getSession().getPeerCertificates().length > 0);
    }

    @Test
    @DisplayName("REQUIRE без клиентского сертификата: отказ, клиент получает алерт 116")
    void requireWithoutCertificateRejected() throws Exception {
        SslHandler cs = clientWithoutCert().newHandler(ALLOC, HOST, 0);
        SslHandler ss = serverBuilder(ClientAuth.REQUIRE).build().newHandler(ALLOC, HOST, 0);

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertFalse(outcome.succeeded(), "сервер должен отказать анонимному клиенту");
        assertInstanceOf(SSLException.class, outcome.serverFailure(), "сервер: SSL-отказ");
        assertTrue(
                outcome.clientSawAlert(TlsConstants.ALERT_CERTIFICATE_REQUIRED),
                "клиент должен получить certificate_required (116): " + outcome.clientFailure());
    }

    // ========================================================================
    // HTTP/2 + mTLS + клиентский OCSP-staple
    // ========================================================================

    private static GostSslContext h2MtlsStapleServer() throws Exception {
        return serverBuilder(ClientAuth.REQUIRE)
                .clientOcspPolicy(ClientOcspPolicy.REQUIRE)
                .applicationProtocols("h2", "http/1.1")
                .build();
    }

    private static GostSslContext h2MtlsClient() throws Exception {
        return GostSslContextBuilder.forClient()
                .trustManager(fixture.rootTrust())
                .keyManager(fixture.clientKeyManager())
                .applicationProtocols("h2", "http/1.1")
                .build();
    }

    private static byte[] clientStaple() throws Exception {
        return GostOcspResponseBuilder.create(fixture.clientCert.cert.getSerialNumber())
                .issuerDn(fixture.rootCa.subjectDn)
                .thisUpdate(Instant.now())
                .noNextUpdate()
                .sign(fixture.rootCa.priv);
    }

    @Test
    @DisplayName("h2 + mTLS + обязательный staple: клиент со staple проходит, h2 согласован")
    void h2MtlsWithClientStaple() throws Exception {
        SslHandler cs = h2MtlsClient().newHandler(ALLOC, HOST, 0);
        SslHandler ss = h2MtlsStapleServer().newHandler(ALLOC, HOST, 0);
        // staple задаётся на движке до добавления обработчика в канал: Netty начинает
        // рукопожатие при добавлении в активный канал
        ((GostSSLEngine) cs.engine()).setOcspResponse(clientStaple());

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertTrue(
                outcome.succeeded(),
                "при REQUIRE успех рукопожатия доказывает, что staple принят: " + outcome);
        assertEquals("h2", cs.applicationProtocol(), "клиентский протокол");
        assertEquals("h2", ss.applicationProtocol(), "серверный протокол");
        assertTrue(
                ss.engine().getSession().getPeerCertificates().length > 0,
                "сервер должен получить клиентский сертификат (mTLS, а не только ALPN)");
    }

    @Test
    @DisplayName(
            "h2 + mTLS + обязательный staple: клиент без staple получает алерт bad_certificate")
    void h2MtlsWithoutClientStapleRejected() throws Exception {
        SslHandler cs = h2MtlsClient().newHandler(ALLOC, HOST, 0);
        SslHandler ss = h2MtlsStapleServer().newHandler(ALLOC, HOST, 0);

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertFalse(outcome.succeeded(), "сервер должен отказать клиенту без staple");
        assertInstanceOf(SSLException.class, outcome.serverFailure(), "сервер: SSL-отказ");
        assertTrue(
                outcome.clientSawAlert(TlsConstants.ALERT_BAD_CERTIFICATE),
                "клиент должен получить bad_certificate (42): " + outcome.clientFailure());
    }
}
