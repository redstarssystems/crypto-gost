package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.GostSslBuilder;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Предел возраста {@code thisUpdate} OCSP-ответа, заданный в {@link GostSslBuilder}, доходит до
 * проверки приложенного ответа и на клиентской сборке (staple сервера), и на серверной
 * (staple клиента при mTLS). Без этого пользователь считал бы предел включённым, а проверки нет.
 */
@DisplayName("GostSslBuilder.maxThisUpdateAge: предел доходит до проверки staple (клиент и сервер)")
class GostSslBuilderThisUpdateAgeTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final Duration TWO_HOURS = Duration.ofHours(2);

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;
    private static PkixCertTestHelper.CertBundle clientLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf = leaf(new String[] {"localhost"});
        clientLeaf = leaf(null);
    }

    private static PkixCertTestHelper.CertBundle leaf(String[] san) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                san,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    /** Ответ со thisUpdate 5 ч назад и nextUpdate через 30 суток: годен, пока не задан предел. */
    private static byte[] oldStaple(GostCertificate cert) {
        return GostOcspResponseBuilder.create(cert.getSerialNumber())
                .issuerDn(root.subjectDn)
                .thisUpdate(Instant.now().minus(5, ChronoUnit.HOURS))
                .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                .sign(root.priv);
    }

    private static GostSslBuilder identity(PkixCertTestHelper.CertBundle bundle) {
        return GostSsl.builder()
                .certificate(bundle.cert.getEncoded(), GostDerCodec.encodePrivateKey(bundle.priv))
                .trustCa(root.cert.getEncoded());
    }

    private static GostSSLEngine engine(SSLContext ctx, boolean clientMode) {
        GostSSLEngine engine = (GostSSLEngine) ctx.createSSLEngine("localhost", 0);
        engine.setUseClientMode(clientMode);
        return engine;
    }

    private static void handshake(GostSSLEngine client, GostSSLEngine server) throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
    }

    // ------------------------------------------------------------------ клиентская сборка

    private static void clientHandshakeWithServerStaple(Duration limit) throws Exception {
        GostSSLEngine server = engine(identity(serverLeaf).buildServerContext(), false);
        server.setOcspResponse(oldStaple(serverLeaf.cert));
        GostSslBuilder clientBuilder = GostSsl.builder().trustCa(root.cert.getEncoded());
        if (limit != null) {
            clientBuilder.maxThisUpdateAge(limit);
        }
        handshake(engine(clientBuilder.buildClientContext(), true), server);
    }

    @Test
    @DisplayName("Клиент: без предела старый staple сервера принимается")
    void client_withoutLimit_accepted() {
        assertDoesNotThrow(() -> clientHandshakeWithServerStaple(null));
    }

    @Test
    @DisplayName(
            "Клиент: предел больше возраста staple (но заданный) -> принят: отказ зависит от значения")
    void client_limitLargerThanAge_accepted() {
        // Отличает отказ по значению предела от посторонней поломки при его включении
        assertDoesNotThrow(() -> clientHandshakeWithServerStaple(Duration.ofHours(10)));
    }

    @Test
    @DisplayName("Клиент: предел меньше возраста staple сервера -> handshake отвергнут")
    void client_limitEnforced() {
        RuntimeException ex =
                assertThrows(
                        RuntimeException.class,
                        () -> clientHandshakeWithServerStaple(TWO_HOURS),
                        "Предел, заданный в сборщике, должен действовать на staple сервера");
        // отказ должен быть именно TLS-отказом, а не истёкшим сроком или закрытым транспортом
        assertInstanceOf(SSLException.class, ex.getCause(), "ожидается отказ TLS-рукопожатия");
    }

    // ------------------------------------------------------------------ серверная сборка

    private static void serverHandshakeWithClientStaple(Duration limit) throws Exception {
        GostSslBuilder serverBuilder =
                identity(serverLeaf)
                        .needClientAuth(true)
                        .clientOcspPolicy(ClientOcspPolicy.REQUEST);
        if (limit != null) {
            serverBuilder.maxThisUpdateAge(limit);
        }
        GostSSLEngine server = engine(serverBuilder.buildServerContext(), false);
        GostSSLEngine client = engine(identity(clientLeaf).buildClientContext(), true);
        client.setOcspResponse(oldStaple(clientLeaf.cert));
        handshake(client, server);
    }

    @Test
    @DisplayName("Сервер (mTLS): без предела старый staple клиента принимается")
    void server_withoutLimit_accepted() {
        assertDoesNotThrow(() -> serverHandshakeWithClientStaple(null));
    }

    @Test
    @DisplayName("Сервер (mTLS): предел больше возраста staple (но заданный) -> принят")
    void server_limitLargerThanAge_accepted() {
        assertDoesNotThrow(() -> serverHandshakeWithClientStaple(Duration.ofHours(10)));
    }

    @Test
    @DisplayName("Сервер (mTLS): предел меньше возраста staple клиента -> handshake отвергнут")
    void server_limitEnforced() {
        assertThrows(
                RuntimeException.class,
                () -> serverHandshakeWithClientStaple(TWO_HOURS),
                "Предел, заданный в сборщике, должен действовать на staple клиента");
    }

    // ------------------------------------------------------------------ настройка

    @Test
    @DisplayName("Ноль и отрицательное значение отвергаются, null допустим и сбрасывает предел")
    void builder_validatesValue() {
        GostSslBuilder builder = GostSsl.builder();

        assertThrows(IllegalArgumentException.class, () -> builder.maxThisUpdateAge(Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.maxThisUpdateAge(Duration.ofSeconds(-1)));
        assertDoesNotThrow(() -> builder.maxThisUpdateAge(TWO_HOURS).maxThisUpdateAge(null));
    }

    @Test
    @DisplayName("trustAll() вместе с пределом -> IllegalStateException (клиент и сервер)")
    void trustAllWithLimit_rejected() {
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustAll()
                                .maxThisUpdateAge(TWO_HOURS)
                                .buildClientContext());
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustAll()
                                .maxThisUpdateAge(TWO_HOURS)
                                .buildServerContext());
    }
}
