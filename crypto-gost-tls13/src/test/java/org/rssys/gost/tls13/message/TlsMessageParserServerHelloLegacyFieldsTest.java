package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Служебные поля ServerHello и HelloRetryRequest (RFC 8446 §4.1.3, §4.2.1, §4.2.11):
 * {@code legacy_session_id_echo}, {@code legacy_compression_method}, {@code legacy_version} и
 * {@code selected_identity} разбираются одним проходом.
 */
@DisplayName("TlsMessageParser: служебные поля ServerHello и HRR")
class TlsMessageParserServerHelloLegacyFieldsTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    private static final int TLS_12 = 0x0303;
    private static final int TLS_10 = 0x0301;

    private static byte[] selectedVersion() {
        return TlsMessageParserTest.encodeExt(
                TlsConstants.EXT_SUPPORTED_VERSIONS, new byte[] {0x03, 0x04});
    }

    private static byte[] preSharedKey(int length, int identity) {
        byte[] data = new byte[length];
        if (length >= 2) {
            data[0] = (byte) (identity >>> 8);
            data[1] = (byte) identity;
        }
        return TlsMessageParserTest.encodeExt(TlsConstants.EXT_PRE_SHARED_KEY, data);
    }

    private static byte[] body(
            int legacyVersion, byte[] random, byte[] sessionId, int compression, byte[]... ext)
            throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(out, legacyVersion);
        out.write(random, 0, random.length);
        out.write(sessionId.length);
        out.write(sessionId, 0, sessionId.length);
        TlsEncoding.encodeUint16(out, 0xC103);
        out.write(compression);
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        for (byte[] e : ext) {
            extensions.write(e, 0, e.length);
        }
        TlsEncoding.encodeUint16(out, extensions.size());
        out.write(extensions.toByteArray(), 0, extensions.size());
        return out.toByteArray();
    }

    private static byte[] ordinary() {
        return new byte[TlsConstants.RANDOM_LENGTH];
    }

    private static TlsException parseFails(byte[] body) {
        return assertThrows(
                TlsException.class,
                () -> TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT),
                "ServerHello должен отвергаться");
    }

    private static byte[] sessionId(int length) {
        byte[] id = new byte[length];
        for (int i = 0; i < length; i++) {
            id[i] = (byte) (0x40 + i);
        }
        return id;
    }

    // ------------------------------------------------------------ legacy_compression_method

    @Test
    @DisplayName("ServerHello и HRR: сжатие не 0 -> illegal_parameter")
    void compressionMustBeNull() throws Exception {
        for (byte[] random : new byte[][] {ordinary(), TlsMessageParser.HRR_RANDOM}) {
            byte[] body = body(TLS_12, random, new byte[0], 1, selectedVersion());
            assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, parseFails(body).getAlertCode());
        }
    }

    @Test
    @DisplayName("ServerHello и HRR: нулевое сжатие принимается")
    void nullCompressionIsAccepted() throws Exception {
        for (byte[] random : new byte[][] {ordinary(), TlsMessageParser.HRR_RANDOM}) {
            byte[] body = body(TLS_12, random, new byte[0], 0, selectedVersion());
            TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT);
        }
    }

    @Test
    @DisplayName("версия проверяется раньше сжатия: при двух дефектах код ошибки версии")
    void versionIsCheckedBeforeCompression() throws Exception {
        // supported_versions указывает не TLS 1.3, и сжатие тоже неверно (RFC 8446 §4.2.1)
        byte[] wrongVersion =
                TlsMessageParserTest.encodeExt(
                        TlsConstants.EXT_SUPPORTED_VERSIONS, new byte[] {0x03, 0x03});
        byte[] body = body(TLS_12, ordinary(), new byte[0], 1, wrongVersion);

        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, parseFails(body).getAlertCode());

        byte[] noVersion = body(TLS_12, ordinary(), new byte[0], 1);
        assertEquals(
                TlsConstants.ALERT_PROTOCOL_VERSION,
                parseFails(noVersion).getAlertCode(),
                "Без supported_versions раньше сжатия сообщается версия");
    }

    // ------------------------------------------------------------ legacy_session_id_echo

    @Test
    @DisplayName("эхо идентификатора читается копией: пустое и 32 байта")
    void echoIsExtracted() throws Exception {
        for (int length : new int[] {0, TlsConstants.SESSION_ID_LENGTH}) {
            byte[] id = sessionId(length);
            byte[] body = body(TLS_12, ordinary(), id, 0, selectedVersion());

            byte[] echo =
                    TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT)
                            .legacySessionIdEcho;

            assertArrayEquals(id, echo, "Эхо идентификатора длиной " + length);
        }
    }

    @Test
    @DisplayName("эхо длиннее 32 байт -> illegal_parameter")
    void echoLongerThanLimitIsRejected() throws Exception {
        for (byte[] random : new byte[][] {ordinary(), TlsMessageParser.HRR_RANDOM}) {
            byte[] body =
                    body(
                            TLS_12,
                            random,
                            sessionId(TlsConstants.SESSION_ID_LENGTH + 1),
                            0,
                            selectedVersion());
            assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, parseFails(body).getAlertCode());
        }
    }

    // ------------------------------------------------------------ selected_identity

    @Test
    @DisplayName("selected_identity читается; без pre_shared_key значение «нет»")
    void selectedIdentityIsExtracted() throws Exception {
        byte[] withPsk =
                body(TLS_12, ordinary(), new byte[0], 0, selectedVersion(), preSharedKey(2, 1));
        byte[] without = body(TLS_12, ordinary(), new byte[0], 0, selectedVersion());

        assertEquals(
                1,
                TlsMessageParser.parseServerHello(withPsk, SERVER_RESPONSE_TYPES_SENT)
                        .selectedPskIdentity);
        assertEquals(
                TlsMessageParser.ParsedServerHello.NO_PSK_IDENTITY,
                TlsMessageParser.parseServerHello(without, SERVER_RESPONSE_TYPES_SENT)
                        .selectedPskIdentity);
    }

    @Test
    @DisplayName("selected_identity не из двух байт -> decode_error")
    void selectedIdentityMalformed() throws Exception {
        for (int length : new int[] {0, 1, 3}) {
            byte[] body =
                    body(
                            TLS_12,
                            ordinary(),
                            new byte[0],
                            0,
                            selectedVersion(),
                            preSharedKey(length, 0));
            assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseFails(body).getAlertCode());
        }
    }

    // ------------------------------------------------------------ legacy_version

    @Test
    @DisplayName("legacy_version не 0x0303: PSK и key_share видны разбору так же, как при 0x0303")
    void legacyVersionIsIgnored() throws Exception {
        // RFC 8446 §4.2.1: при наличии supported_versions legacy_version игнорируется. Раньше
        // selected_identity читался отдельным проходом, который при чужой версии «не видел»
        // расширений, и клиент считал PSK не принятым
        for (int legacyVersion : new int[] {TLS_10, 0x0302, 0x0000, 0x7F1C}) {
            byte[] body =
                    body(
                            legacyVersion,
                            ordinary(),
                            new byte[0],
                            0,
                            selectedVersion(),
                            preSharedKey(2, 0));

            TlsMessageParser.ParsedServerHello parsed =
                    TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT);

            assertEquals(
                    0,
                    parsed.selectedPskIdentity,
                    "selected_identity при legacy_version 0x" + Integer.toHexString(legacyVersion));
        }
    }
}
