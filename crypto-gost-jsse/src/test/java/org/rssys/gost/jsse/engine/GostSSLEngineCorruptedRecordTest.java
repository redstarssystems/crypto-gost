package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Искажение записи с данными приложения после рукопожатия: стек сообщает о нём как о сбое проверки
 * записи ({@code bad_record_mac}, RFC 8446 §5.2), а {@link AlertMapper} превращает его в
 * {@link SSLException}, не в {@link SSLHandshakeException}: рукопожатие уже завершено.
 */
@DisplayName("GostSSLEngine: искажённая запись после рукопожатия -> SSLException (bad_record_mac)")
class GostSSLEngineCorruptedRecordTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int RECORD_HEADER_SIZE = 5;

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

    @Test
    @DisplayName("unwrap искажённой записи: SSLException, код bad_record_mac, не рукопожатие")
    void corruptedApplicationRecordIsNotHandshakeException() throws Exception {
        GostSSLEngine server =
                engine(
                        GostSsl.builder()
                                .certificate(
                                        serverLeaf.cert.getEncoded(),
                                        GostDerCodec.encodePrivateKey(serverLeaf.priv))
                                .trustCa(root.cert.getEncoded())
                                .buildServerContext(),
                        false);
        GostSSLEngine client =
                engine(
                        GostSsl.builder().trustCa(root.cert.getEncoded()).buildClientContext(),
                        true);
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        ByteBuffer network =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.wrap("искажение".getBytes(StandardCharsets.UTF_8)), network);
        network.flip();
        byte[] record = new byte[network.remaining()];
        network.get(record);
        record[RECORD_HEADER_SIZE + 4] ^= 0x42;

        ByteBuffer plaintext = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLException error =
                assertThrows(
                        SSLException.class,
                        () -> server.unwrap(ByteBuffer.wrap(record), plaintext),
                        "Искажённая запись должна отвергаться");

        assertFalse(
                error instanceof SSLHandshakeException,
                "Сбой проверки записи после рукопожатия не относится к рукопожатию: " + error);
        TlsException cause = assertInstanceOf(TlsException.class, error.getCause());
        assertEquals(
                TlsConstants.ALERT_BAD_RECORD_MAC,
                cause.getAlertCode(),
                "Сбой проверки записи должен нести код bad_record_mac");
    }
}
