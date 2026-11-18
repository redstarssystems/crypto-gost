package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.PskClientHelloFixture;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;

/**
 * Сквозной путь нарушения в PSK-расширениях ClientHello: {@code TlsException} движка tls13 доходит
 * до {@link AlertMapper} и становится {@link SSLHandshakeException} у пользователя
 * {@link GostSSLEngine}. {@code AlertMapperTest} проверяет саму таблицу, этот тест - что движок
 * действительно передаёт в неё алерт.
 */
@DisplayName("GostSSLEngine: нарушения PSK в ClientHello дают SSLHandshakeException")
class GostSSLEnginePskAlertTest {

    private static final int PORT = 443;
    private static final String HOST = "localhost";
    private static final int RECORD_HEADER = 5;
    private static final int KEY_LENGTH = 32;

    private static TlsCiphersuite suite;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {HOST},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
    }

    private static byte[] sequence(int base) {
        byte[] data = new byte[KEY_LENGTH];
        for (int i = 0; i < KEY_LENGTH; i++) {
            data[i] = (byte) (base + i);
        }
        return data;
    }

    /** ClientHello штатного клиента jsse как основа для конструктора: handshake-кадр без заголовка записи. */
    private static byte[] baseClientHelloFrame() throws Exception {
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        HOST,
                        PORT,
                        new GostSSLSessionContext(suite));
        client.beginHandshake();
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        byte[] record = new byte[net.remaining()];
        net.get(record);
        return Arrays.copyOfRange(record, RECORD_HEADER, record.length);
    }

    /** Подаёт серверу ClientHello, собранный конструктором, и возвращает исключение движка. */
    private static SSLException serverRejects(
            GostSSLSessionContext context, UnaryOperator<PskClientHelloFixture> violation)
            throws Exception {
        byte[] frame = violation.apply(new PskClientHelloFixture(baseClientHelloFrame())).build();
        byte[] record = TlsMessageBuilder.buildPlaintextRecord(TlsConstants.CT_HANDSHAKE, frame);
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        serverKm, GostX509TrustManager.insecureTrustAll(), HOST, PORT, context);
        server.beginHandshake();
        ByteBuffer src = ByteBuffer.wrap(record);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        return assertThrows(
                SSLException.class,
                () -> {
                    SSLEngineResult result = server.unwrap(src, dst);
                    throw new AssertionError("ClientHello принят: " + result);
                },
                "нарушение в ClientHello должно отвергаться");
    }

    private static GostSSLSessionContext emptyContext() {
        return new GostSSLSessionContext(suite);
    }

    @Test
    @DisplayName("Binder короче 32 байт (decode_error): SSLHandshakeException")
    void decodeErrorBecomesHandshakeException() throws Exception {
        SSLException ex =
                serverRejects(
                        emptyContext(),
                        f -> f.identity(sequence(0x10), 0, sequence(0xA0)).binderLength(0, 31));

        assertInstanceOf(SSLHandshakeException.class, ex, "decode_error: " + ex);
        assertInstanceOf(
                TlsException.class,
                ex.getCause(),
                "исходное нарушение стека должно быть причиной исключения");
    }

    @Test
    @DisplayName("Повтор pre_shared_key (illegal_parameter): SSLHandshakeException")
    void illegalParameterBecomesHandshakeException() throws Exception {
        SSLException ex =
                serverRejects(
                        emptyContext(),
                        f -> f.identity(sequence(0x10), 0, sequence(0xA0)).duplicatePsk());

        assertInstanceOf(SSLHandshakeException.class, ex, "illegal_parameter: " + ex);
    }

    @Test
    @DisplayName("Нет psk_key_exchange_modes (missing_extension): SSLHandshakeException")
    void missingExtensionBecomesHandshakeException() throws Exception {
        SSLException ex =
                serverRejects(
                        emptyContext(),
                        f -> f.identity(sequence(0x10), 0, sequence(0xA0)).withoutModes());

        assertInstanceOf(SSLHandshakeException.class, ex, "missing_extension: " + ex);
    }

    @Test
    @DisplayName("Неверный PSK binder известного тикета (decrypt_error): SSLHandshakeException")
    void wrongBinderBecomesHandshakeException() throws Exception {
        GostSSLSessionContext context = emptyContext();
        byte[] ticket = sequence(0x10);
        context.getPskStore()
                .onTicketReceived(
                        new PskEntry(
                                ticket,
                                3600,
                                0,
                                new byte[8],
                                sequence(0xA0),
                                System.currentTimeMillis(),
                                PskBinding.forServer(HOST),
                                PskEntry.NO_CERTIFICATE_BOUND));

        // binder посчитан по другому PSK
        SSLException ex = serverRejects(context, f -> f.identity(ticket, 0, sequence(0x55)));

        assertInstanceOf(SSLHandshakeException.class, ex, "decrypt_error: " + ex);
    }
}
