package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Таблица допустимости расширений RFC 8446 §4.2 в разборе ServerHello, HelloRetryRequest,
 * Certificate, CertificateRequest и NewSessionTicket.
 */
@DisplayName("Расширения по сообщениям: таблица RFC 8446 §4.2")
class TlsExtensionTableTest {

    private static final int GREASE_TYPE = 0x0A0A;
    private static final byte[] TLS13_VERSION = {0x03, 0x04};
    private static final Set<Integer> SENT_WITHOUT_PSK =
            Set.of(TlsConstants.EXT_SUPPORTED_VERSIONS, TlsConstants.EXT_KEY_SHARE);

    // ------------------------------------------------------------------
    // Сборка сообщений
    // ------------------------------------------------------------------

    private static byte[] extension(int type, byte... data) {
        byte[] ext = new byte[4 + data.length];
        ext[0] = (byte) (type >>> 8);
        ext[1] = (byte) type;
        ext[2] = (byte) (data.length >>> 8);
        ext[3] = (byte) data.length;
        System.arraycopy(data, 0, ext, 4, data.length);
        return ext;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static byte[] versionExtension() {
        return extension(TlsConstants.EXT_SUPPORTED_VERSIONS, TLS13_VERSION);
    }

    /** key_share ServerHello: group(2) || key_exchange_length(2) || key_exchange. */
    private static byte[] fullKeyShare() {
        return extension(
                TlsConstants.EXT_KEY_SHARE,
                (byte) 0x00,
                (byte) 0x23,
                (byte) 0x00,
                (byte) 0x02,
                (byte) 0xAA,
                (byte) 0xBB);
    }

    /** key_share HelloRetryRequest: только selected_group. */
    private static byte[] groupOnlyKeyShare() {
        return extension(TlsConstants.EXT_KEY_SHARE, (byte) 0x00, (byte) 0x23);
    }

    private static byte[] serverHello(boolean retryRequest, byte[]... extensions) {
        byte[] block = concat(extensions);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x03);
        out.write(0x03);
        byte[] random = new byte[TlsConstants.RANDOM_LENGTH];
        if (retryRequest) {
            random = TlsMessageParser.HRR_RANDOM.clone();
        } else {
            Arrays.fill(random, (byte) 0x11);
        }
        out.write(random, 0, random.length);
        out.write(0); // legacy_session_id_echo пуст
        out.write(0xC1);
        out.write(0x03); // cipher suite
        out.write(0); // legacy_compression_method
        out.write(block.length >>> 8);
        out.write(block.length);
        out.write(block, 0, block.length);
        return out.toByteArray();
    }

    private static int alertOf(org.junit.jupiter.api.function.Executable action) {
        return assertThrows(TlsException.class, action).getAlertCode();
    }

    // ------------------------------------------------------------------
    // ServerHello
    // ------------------------------------------------------------------

    @Test
    @DisplayName("ServerHello: версия, key_share и отправленный pre_shared_key принимаются")
    void serverHelloValidAccepted() throws Exception {
        Set<Integer> sent =
                Set.of(
                        TlsConstants.EXT_SUPPORTED_VERSIONS,
                        TlsConstants.EXT_KEY_SHARE,
                        TlsConstants.EXT_PRE_SHARED_KEY);
        TlsMessageParser.ParsedServerHello parsed =
                TlsMessageParser.parseServerHello(
                        serverHello(
                                false,
                                versionExtension(),
                                fullKeyShare(),
                                extension(
                                        TlsConstants.EXT_PRE_SHARED_KEY, (byte) 0x00, (byte) 0x00)),
                        sent);
        assertEquals(2, parsed.ecdhePublicKeyRaw.length);
        assertEquals(0, parsed.selectedPskIdentity);
    }

    @Test
    @DisplayName(
            "ServerHello: cookie -> illegal_parameter, даже если клиент отправил cookie во втором ClientHello")
    void cookieInServerHelloRejected() {
        // Второй ClientHello после HRR содержит cookie, поэтому «отправлено»: код различим только
        // при порядке «сначала допустимость в сообщении»
        Set<Integer> sent =
                Set.of(
                        TlsConstants.EXT_SUPPORTED_VERSIONS,
                        TlsConstants.EXT_KEY_SHARE,
                        TlsConstants.EXT_COOKIE);
        byte[] body =
                serverHello(
                        false,
                        versionExtension(),
                        fullKeyShare(),
                        extension(TlsConstants.EXT_COOKIE, (byte) 0x00, (byte) 0x01, (byte) 0x7F));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(() -> TlsMessageParser.parseServerHello(body, sent)));
    }

    @Test
    @DisplayName("ServerHello: cookie без запроса в первом ответе -> illegal_parameter")
    void cookieInFirstServerHelloRejected() {
        byte[] body =
                serverHello(
                        false,
                        versionExtension(),
                        fullKeyShare(),
                        extension(TlsConstants.EXT_COOKIE, (byte) 0x00, (byte) 0x01, (byte) 0x7F));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)));
    }

    @Test
    @DisplayName("ServerHello: key_share без отправленного key_share -> unsupported_extension")
    void keyShareNotSentRejected() {
        // Клиент отправил только supported_versions (как при setOmitKeyShare)
        Set<Integer> sent = Set.of(TlsConstants.EXT_SUPPORTED_VERSIONS);
        byte[] body = serverHello(false, versionExtension(), fullKeyShare());
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                alertOf(() -> TlsMessageParser.parseServerHello(body, sent)));
    }

    @Test
    @DisplayName("ServerHello: pre_shared_key без предложенного PSK -> unsupported_extension")
    void pskNotOfferedRejected() {
        byte[] body =
                serverHello(
                        false,
                        versionExtension(),
                        fullKeyShare(),
                        extension(TlsConstants.EXT_PRE_SHARED_KEY, (byte) 0x00, (byte) 0x00));
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)));
    }

    @Test
    @DisplayName("ServerHello: двухбайтовый key_share (форма HRR) -> decode_error")
    void hrrFormKeyShareInServerHelloRejected() {
        byte[] body = serverHello(false, versionExtension(), groupOnlyKeyShare());
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)),
                "код не зависит от того, предлагалась ли группа");
    }

    @Test
    @DisplayName("ServerHello: неизвестный тип без запроса -> unsupported_extension")
    void unknownTypeWithoutRequestRejected() {
        byte[] body =
                serverHello(false, versionExtension(), fullKeyShare(), extension(GREASE_TYPE));
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)));
    }

    @Test
    @DisplayName("ServerHello: известное расширение не из ServerHello -> illegal_parameter")
    void foreignKnownTypeRejected() {
        byte[] body =
                serverHello(
                        false,
                        versionExtension(),
                        fullKeyShare(),
                        extension(TlsConstants.EXT_SERVER_NAME));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)));
    }

    @Test
    @DisplayName("ServerHello без supported_versions с неизвестным типом -> protocol_version")
    void missingVersionBeatsTable() {
        // Сервер TLS 1.2 шлёт расширения, которых клиент не отправлял; версия проверяется раньше
        // таблицы, иначе вместо protocol_version вышел бы unsupported_extension
        byte[] body = serverHello(false, extension(GREASE_TYPE));
        assertEquals(
                TlsConstants.ALERT_PROTOCOL_VERSION,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)));
    }

    // ------------------------------------------------------------------
    // HelloRetryRequest
    // ------------------------------------------------------------------

    @Test
    @DisplayName("HRR: cookie принимается без запроса, key_share из двух байт принимается")
    void hrrCookieAcceptedWithoutRequest() throws Exception {
        byte[] cookie = {0x00, 0x02, 0x55, 0x66};
        TlsMessageParser.ParsedServerHello parsed =
                TlsMessageParser.parseServerHello(
                        serverHello(
                                true,
                                versionExtension(),
                                groupOnlyKeyShare(),
                                extension(TlsConstants.EXT_COOKIE, cookie)),
                        SENT_WITHOUT_PSK);
        assertNotNull(parsed.cookie);
        assertArrayEquals(new byte[] {0x55, 0x66}, parsed.cookie);
        assertEquals(0, parsed.ecdhePublicKeyRaw.length);
    }

    @Test
    @DisplayName("HRR: cookie с лишним байтом после значения -> decode_error")
    void hrrCookieWithTrailingBytesRejected() {
        // cookie<1..2^16-1>: длина 1, значение 1 байт и ещё один лишний байт
        byte[] body =
                serverHello(
                        true,
                        versionExtension(),
                        groupOnlyKeyShare(),
                        extension(
                                TlsConstants.EXT_COOKIE,
                                (byte) 0x00,
                                (byte) 0x01,
                                (byte) 0x55,
                                (byte) 0x66));
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)),
                "тело cookie - ровно cookie<1..2^16-1> (RFC 8446 §4.2.2)");
    }

    @Test
    @DisplayName("HRR: pre_shared_key -> illegal_parameter")
    void pskInHrrRejected() {
        Set<Integer> sent =
                Set.of(
                        TlsConstants.EXT_SUPPORTED_VERSIONS,
                        TlsConstants.EXT_KEY_SHARE,
                        TlsConstants.EXT_PRE_SHARED_KEY);
        byte[] body =
                serverHello(
                        true,
                        versionExtension(),
                        groupOnlyKeyShare(),
                        extension(TlsConstants.EXT_PRE_SHARED_KEY, (byte) 0x00, (byte) 0x00));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(() -> TlsMessageParser.parseServerHello(body, sent)),
                "pre_shared_key допустим в ServerHello, но не в HRR, даже отправленный клиентом");
    }

    @Test
    @DisplayName("HRR: полная запись key_share -> decode_error")
    void fullKeyShareInHrrRejected() {
        byte[] body = serverHello(true, versionExtension(), fullKeyShare());
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                alertOf(() -> TlsMessageParser.parseServerHello(body, SENT_WITHOUT_PSK)));
    }

    // ------------------------------------------------------------------
    // Certificate
    // ------------------------------------------------------------------

    private static byte[] certificateWithExtensionBlock(byte[] extensionBlock) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] certDer = bundle.cert.getEncoded();
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(entry, certDer.length);
        entry.write(certDer, 0, certDer.length);
        TlsEncoding.encodeUint16(entry, extensionBlock.length);
        entry.write(extensionBlock, 0, extensionBlock.length);
        byte[] entryBytes = entry.toByteArray();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0); // certificate_request_context
        TlsEncoding.encodeUint24(body, entryBytes.length);
        body.write(entryBytes, 0, entryBytes.length);
        return body.toByteArray();
    }

    private static byte[] statusRequestEntryExtension() {
        // CertificateStatus: status_type(1)=ocsp || uint24(len)=2 || OCSPResponse
        return extension(
                TlsConstants.EXT_STATUS_REQUEST,
                (byte) 0x01,
                (byte) 0x00,
                (byte) 0x00,
                (byte) 0x02,
                (byte) 0x30,
                (byte) 0x00);
    }

    @Test
    @DisplayName("Certificate: пустой блок расширений принимается при любом наборе запрошенного")
    void certificateWithoutExtensionsAccepted() throws Exception {
        byte[] body = certificateWithExtensionBlock(new byte[0]);
        assertEquals(1, TlsMessageParser.parseCertificate(body, Set.of()).size());
        assertEquals(
                1,
                TlsMessageParser.parseCertificate(body, Set.of(TlsConstants.EXT_STATUS_REQUEST))
                        .size());
    }

    @Test
    @DisplayName("Certificate: status_request по запросу принимается")
    void certificateStatusRequestRequestedAccepted() throws Exception {
        byte[] body = certificateWithExtensionBlock(statusRequestEntryExtension());
        assertEquals(
                1,
                TlsMessageParser.parseCertificate(body, Set.of(TlsConstants.EXT_STATUS_REQUEST))
                        .size());
    }

    @Test
    @DisplayName("Certificate: status_request без запроса -> unsupported_extension")
    void certificateStatusRequestUnsolicitedRejected() throws Exception {
        byte[] body = certificateWithExtensionBlock(statusRequestEntryExtension());
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                alertOf(() -> TlsMessageParser.parseCertificate(body, Set.of())));
    }

    @Test
    @DisplayName(
            "Certificate: key_share -> illegal_parameter, неизвестный тип -> unsupported_extension")
    void certificateForeignAndUnknownRejected() throws Exception {
        byte[] foreign =
                certificateWithExtensionBlock(
                        extension(TlsConstants.EXT_KEY_SHARE, (byte) 0, (byte) 0));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(
                        () ->
                                TlsMessageParser.parseCertificate(
                                        foreign, Set.of(TlsConstants.EXT_STATUS_REQUEST))));
        byte[] unknown = certificateWithExtensionBlock(extension(GREASE_TYPE));
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                alertOf(
                        () ->
                                TlsMessageParser.parseCertificate(
                                        unknown, Set.of(TlsConstants.EXT_STATUS_REQUEST))));
    }

    // ------------------------------------------------------------------
    // CertificateRequest
    // ------------------------------------------------------------------

    private static byte[] withAppendedExtension(byte[] certificateRequest, byte[] extension) {
        byte[] result = concat(certificateRequest, extension);
        int extLen = ((result[1] & 0xFF) << 8) | (result[2] & 0xFF);
        extLen += extension.length;
        result[1] = (byte) (extLen >>> 8);
        result[2] = (byte) extLen;
        return result;
    }

    @Test
    @DisplayName("CertificateRequest: key_share -> illegal_parameter")
    void certificateRequestForeignRejected() {
        byte[] body =
                withAppendedExtension(
                        TlsMessageBuilder.buildCertificateRequest(),
                        extension(TlsConstants.EXT_KEY_SHARE, (byte) 0, (byte) 0));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(() -> TlsMessageParser.parseCertificateRequest(body)));
    }

    @Test
    @DisplayName(
            "CertificateRequest: неизвестный тип (GREASE) игнорируется, status_request принимается")
    void certificateRequestUnknownIgnored() throws Exception {
        byte[] body =
                withAppendedExtension(
                        TlsMessageBuilder.buildCertificateRequest(null, true),
                        extension(GREASE_TYPE));
        assertTrue(TlsMessageParser.parseCertificateRequest(body).ocspRequested());
    }

    // ------------------------------------------------------------------
    // NewSessionTicket
    // ------------------------------------------------------------------

    /** lifetime(4) || age_add(4) || nonce(1+8) || ticket(2+3), без блока расширений. */
    private static byte[] ticketWithoutExtensionBlock() {
        return new byte[] {
            0x00, 0x00, 0x1C, 0x20, 0x01, 0x02, 0x03, 0x04, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x00,
            0x03, 0x0A, 0x0B, 0x0C
        };
    }

    private static byte[] ticketWithExtensionBlock(byte[] extensions) {
        byte[] block =
                concat(
                        new byte[] {(byte) (extensions.length >>> 8), (byte) extensions.length},
                        extensions);
        return concat(ticketWithoutExtensionBlock(), block);
    }

    @Test
    @DisplayName("NewSessionTicket: пустой блок расширений (00 00) принимается")
    void ticketEmptyExtensionBlockAccepted() throws Exception {
        TlsMessageParser.ParsedNewSessionTicket parsed =
                TlsMessageParser.parseNewSessionTicket(ticketWithExtensionBlock(new byte[0]));
        assertEquals(3, parsed.ticket.length);
    }

    @Test
    @DisplayName("NewSessionTicket: early_data и GREASE принимаются")
    void ticketEarlyDataAndGreaseAccepted() throws Exception {
        // early_data допустим в NewSessionTicket и без запроса (RFC 8446 §4.2): сервер вправе
        // слать расширения в этом сообщении по своему усмотрению
        byte[] extensions =
                concat(
                        extension(
                                TlsConstants.EXT_EARLY_DATA,
                                (byte) 0,
                                (byte) 0,
                                (byte) 0x40,
                                (byte) 0),
                        extension(GREASE_TYPE));
        assertEquals(
                3,
                TlsMessageParser.parseNewSessionTicket(ticketWithExtensionBlock(extensions))
                        .ticket
                        .length);
    }

    @Test
    @DisplayName("NewSessionTicket: key_share -> illegal_parameter")
    void ticketForeignExtensionRejected() {
        byte[] body =
                ticketWithExtensionBlock(extension(TlsConstants.EXT_KEY_SHARE, (byte) 0, (byte) 0));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                alertOf(() -> TlsMessageParser.parseNewSessionTicket(body)));
    }

    @Test
    @DisplayName("NewSessionTicket: нет блока расширений или хвост за ним -> decode_error")
    void ticketMalformedExtensionBlockRejected() {
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                alertOf(
                        () ->
                                TlsMessageParser.parseNewSessionTicket(
                                        ticketWithoutExtensionBlock())),
                "поле extensions обязательно (RFC 8446 §4.6.1)");
        byte[] trailing = concat(ticketWithExtensionBlock(new byte[0]), new byte[] {0x01});
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                alertOf(() -> TlsMessageParser.parseNewSessionTicket(trailing)),
                "хвост за блоком расширений не принадлежит ни одному полю");
    }
}
