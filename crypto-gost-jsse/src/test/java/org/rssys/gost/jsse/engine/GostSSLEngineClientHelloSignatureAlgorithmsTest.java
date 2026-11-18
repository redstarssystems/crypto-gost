package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.PskClientHelloFixture;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Строгий разбор {@code signature_algorithms} в ClientHello на стороне {@link GostSSLEngine}:
 * ошибка разбора доходит до приложения исключением {@code SSLException} с причиной.
 */
@DisplayName("GostSSLEngine: signature_algorithms в ClientHello")
class GostSSLEngineClientHelloSignatureAlgorithmsTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int HEADER = TlsConstants.RECORD_HEADER_SIZE;

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    private static GostSSLEngine engine(SSLContext context, boolean clientMode) {
        GostSSLEngine engine = (GostSSLEngine) context.createSSLEngine("localhost", 0);
        engine.setUseClientMode(clientMode);
        return engine;
    }

    /** Рукопожатный кадр настоящего ClientHello клиента движка. */
    private static byte[] clientHelloFrame() throws Exception {
        GostSSLEngine client =
                engine(
                        GostSsl.builder().trustCa(root.cert.getEncoded()).buildClientContext(),
                        true);
        client.beginHandshake();
        ByteBuffer network =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), network);
        network.flip();
        byte[] record = new byte[network.remaining()];
        network.get(record);
        return java.util.Arrays.copyOfRange(record, HEADER, record.length);
    }

    private static SSLException serverRejects(byte[] handshakeFrame) throws Exception {
        GostSSLEngine server =
                engine(
                        GostSsl.builder()
                                .certificate(
                                        serverLeaf.cert.getEncoded(),
                                        GostDerCodec.encodePrivateKey(serverLeaf.priv))
                                .trustCa(root.cert.getEncoded())
                                .buildServerContext(),
                        false);
        byte[] record = new byte[HEADER + handshakeFrame.length];
        record[0] = TlsConstants.CT_HANDSHAKE;
        record[1] = 3;
        record[2] = 3;
        record[3] = (byte) (handshakeFrame.length >>> 8);
        record[4] = (byte) handshakeFrame.length;
        System.arraycopy(handshakeFrame, 0, record, HEADER, handshakeFrame.length);
        return assertThrows(
                SSLException.class,
                () ->
                        server.unwrap(
                                ByteBuffer.wrap(record),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)));
    }

    @Test
    @DisplayName("битый список схем: SSLException с причиной decode_error")
    void malformedListReachesApplication() throws Exception {
        byte[] frame =
                new PskClientHelloFixture(clientHelloFrame())
                        .withoutPskExtension()
                        .replaceBaseExtension(
                                TlsConstants.EXT_SIGNATURE_ALGORITHMS, new byte[] {0x00, 0x00})
                        .build();

        SSLException error = serverRejects(frame);

        assertTrue(
                error.getMessage().contains("signature_algorithms"),
                "Ожидалась ошибка разбора signature_algorithms: " + error.getMessage());
    }

    @Test
    @DisplayName("нет ни PSK, ни signature_algorithms: SSLException с причиной missing_extension")
    void absentWithoutPskReachesApplication() throws Exception {
        byte[] frame =
                new PskClientHelloFixture(clientHelloFrame())
                        .withoutPskExtension()
                        .withoutBaseExtension(TlsConstants.EXT_SIGNATURE_ALGORITHMS)
                        .build();

        SSLException error = serverRejects(frame);

        assertTrue(
                error.getMessage().contains("signature_algorithms"),
                "Ожидался отказ из-за отсутствия signature_algorithms: " + error.getMessage());
    }
}
