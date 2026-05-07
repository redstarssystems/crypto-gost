package org.rssys.gost.tls13.message;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты TlsHandshakeMessage — кодирование/декодирование сообщений handshake TLS 1.3.
 * Проверяет формат: handshake_type(1) || length(3) || body.
 */
@DisplayName("TlsHandshakeMessage — сообщения handshake TLS 1.3")
class TlsHandshakeMessageTest {

    // -----------------------------------------------------------------------
    // Кодирование
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("encode ClientHello")
    void testEncodeClientHello() {
        byte[] body = new byte[]{0, 1, 2, 3, 4, 5};
        TlsHandshakeMessage msg = new TlsHandshakeMessage(
                TlsConstants.HT_CLIENT_HELLO, body);
        byte[] encoded = msg.encode();

        assertEquals(TlsConstants.HT_CLIENT_HELLO, encoded[0]);
        int len = ((encoded[1] & 0xFF) << 16) | ((encoded[2] & 0xFF) << 8) | (encoded[3] & 0xFF);
        assertEquals(6, len);
        assertArrayEquals(body, Arrays.copyOfRange(encoded, 4, 10));
    }

    @Test
    @DisplayName("encode ServerHello")
    void testEncodeServerHello() {
        byte[] body = new byte[10];
        Arrays.fill(body, (byte) 0xAB);
        TlsHandshakeMessage msg = new TlsHandshakeMessage(
                TlsConstants.HT_SERVER_HELLO, body);
        byte[] encoded = msg.encode();
        assertEquals(14, encoded.length);
        assertEquals(TlsConstants.HT_SERVER_HELLO, encoded[0]);
    }

    @Test
    @DisplayName("encode пустого тела")
    void testEncodeEmptyBody() {
        TlsHandshakeMessage msg = new TlsHandshakeMessage(
                TlsConstants.HT_FINISHED, new byte[0]);
        byte[] encoded = msg.encode();
        assertEquals(4, encoded.length);
        assertEquals(TlsConstants.HT_FINISHED, encoded[0]);
        assertEquals(0, ((encoded[1] & 0xFF) << 16) | ((encoded[2] & 0xFF) << 8) | (encoded[3] & 0xFF));
    }

    @Test
    @DisplayName("encode всех типов handshake")
    void testEncodeAllTypes() {
        byte[] body = "test".getBytes();
        byte[] types = {
                TlsConstants.HT_CLIENT_HELLO,
                TlsConstants.HT_SERVER_HELLO,
                TlsConstants.HT_ENCRYPTED_EXTENSIONS,
                TlsConstants.HT_CERTIFICATE,
                TlsConstants.HT_CERTIFICATE_VERIFY,
                TlsConstants.HT_FINISHED
        };
        for (byte type : types) {
            TlsHandshakeMessage msg = new TlsHandshakeMessage(type, body);
            byte[] encoded = msg.encode();
            assertEquals(type, encoded[0]);
            TlsHandshakeMessage decoded = TlsHandshakeMessage.decode(encoded);
            assertEquals(type, decoded.getType());
            assertArrayEquals(body, decoded.getBody());
        }
    }

    // -----------------------------------------------------------------------
    // Декодирование
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("decode Certificate")
    void testDecodeCertificate() {
        byte[] certBody = new byte[]{0, 1, 2, 3};
        byte[] encoded = new TlsHandshakeMessage(
                TlsConstants.HT_CERTIFICATE, certBody).encode();

        TlsHandshakeMessage decoded = TlsHandshakeMessage.decode(encoded);
        assertEquals(TlsConstants.HT_CERTIFICATE, decoded.getType());
        assertArrayEquals(certBody, decoded.getBody());
    }

    @Test
    @DisplayName("decode CertificateVerify")
    void testDecodeCertificateVerify() {
        byte[] signature = new byte[64];
        Arrays.fill(signature, (byte) 0x42);
        byte[] encoded = new TlsHandshakeMessage(
                TlsConstants.HT_CERTIFICATE_VERIFY, signature).encode();

        TlsHandshakeMessage decoded = TlsHandshakeMessage.decode(encoded);
        assertEquals(TlsConstants.HT_CERTIFICATE_VERIFY, decoded.getType());
        assertArrayEquals(signature, decoded.getBody());
    }

    @Test
    @DisplayName("decode с большим телом (32 КБ)")
    void testDecodeLargeBody() {
        byte[] body = new byte[32768];
        for (int i = 0; i < body.length; i++) {
            body[i] = (byte) (i & 0xFF);
        }
        byte[] encoded = new TlsHandshakeMessage(
                TlsConstants.HT_CERTIFICATE, body).encode();

        TlsHandshakeMessage decoded = TlsHandshakeMessage.decode(encoded);
        assertEquals(TlsConstants.HT_CERTIFICATE, decoded.getType());
        assertArrayEquals(body, decoded.getBody());
    }

    // -----------------------------------------------------------------------
    // Roundtrip
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("encode->decode roundtrip для разных типов")
    void testEncodeDecodeRoundtrip() {
        byte[][] bodies = {
                new byte[0],
                new byte[]{42},
                "Hello TLS 1.3 GOST".getBytes(),
                new byte[255],
                new byte[65535]
        };
        byte[] types = {
                TlsConstants.HT_CLIENT_HELLO,
                TlsConstants.HT_SERVER_HELLO,
                TlsConstants.HT_CERTIFICATE,
                TlsConstants.HT_FINISHED
        };
        for (byte[] body : bodies) {
            for (byte type : types) {
                TlsHandshakeMessage original = new TlsHandshakeMessage(type, body);
                TlsHandshakeMessage decoded = TlsHandshakeMessage.decode(original.encode());
                assertEquals(original, decoded, "Roundtrip failed for type=" + type + " len=" + body.length);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Ошибки
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("null тело в конструкторе")
    void testNullBodyThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, null));
    }

    @Test
    @DisplayName("decode null")
    void testDecodeNullThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> TlsHandshakeMessage.decode(null));
    }

    @Test
    @DisplayName("decode слишком коротких данных")
    void testDecodeTooShortThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> TlsHandshakeMessage.decode(new byte[]{1, 2, 3}));
    }

    @Test
    @DisplayName("decode с некорректной длиной (усечённое сообщение)")
    void testDecodeTruncatedThrows() {
        byte[] truncated = new byte[14];
        truncated[0] = TlsConstants.HT_CERTIFICATE;
        truncated[1] = 0;
        truncated[2] = 0;
        truncated[3] = 100;
        System.arraycopy(new byte[10], 0, truncated, 4, 10);

        assertThrows(IllegalArgumentException.class,
                () -> TlsHandshakeMessage.decode(truncated));
    }

    // -----------------------------------------------------------------------
    // equals / hashCode
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("equals и hashCode")
    void testEqualsAndHashCode() {
        byte[] body = "test body".getBytes();
        TlsHandshakeMessage m1 = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body);
        TlsHandshakeMessage m2 = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body);
        TlsHandshakeMessage m3 = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, body);

        assertEquals(m1, m2);
        assertEquals(m1.hashCode(), m2.hashCode());
        assertNotEquals(m1, m3);
        assertNotEquals(null, m1);
        assertNotEquals(m1, "string");
    }

    @Test
    @DisplayName("getBody возвращает копию")
    void testGetBodyReturnsCopy() {
        byte[] body = new byte[]{1, 2, 3};
        TlsHandshakeMessage msg = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body);
        byte[] retrieved = msg.getBody();
        assertArrayEquals(body, retrieved);
        retrieved[0] = 99;
        assertArrayEquals(new byte[]{1, 2, 3}, msg.getBody());
    }
}
