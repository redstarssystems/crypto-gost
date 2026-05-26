package org.rssys.gost.tls13.message;

import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;
import org.rssys.gost.tls13.crypto.TlsSignatureCodec;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * Сборка handshake-сообщений TLS 1.3 (RFC 8446 §4, RFC 9367).
 * <p>
 * Отдельный класс по SRP: {@link TlsSession} управляет состоянием и потоком,
 * а сборка wire-формата сообщений вынесена сюда.
 * Парсинг, соответственно, в {@link TlsMessageParser}.
 * <p>
 * Конструктору передаются параметры, выбранные при инициализации сессии:
 * cipher suite, именованная группа, схема подписи, ключи и сертификат.
 * Это позволяет собирать сообщения без доступа к полному состоянию TlsSession.
 */
public final class TlsMessageBuilder {

    private final TlsCiphersuite ciphersuite;
    private final List<Integer> offeredCipherSuiteIds;
    private final int selectedNamedGroup;
    private int selectedSigScheme;
    private final PrivateKeyParameters ourPrivateKey;
    private final List<TlsCertificate> ourCertificateChain;
    private final int hashLen;

    // ALPN (RFC 7301): список протоколов клиента для включения в ClientHello
    private List<String> clientAlpnProtocols;

    // Расширение supported_versions для ClientHello:
    // — вместо new byte[] + BAOS в buildCommonExtensions
    private static final byte[] SV_CLIENT = new byte[]{
            0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04
    };

    // Расширение supported_versions для ServerHello (без 0x02):
    // — отдельная константа, чтобы не аллоцировать byte[2] и не писать encodeExtension
    private static final byte[] SV_SERVER = new byte[]{
            0x00, 0x2B, 0x00, 0x02, 0x03, 0x04
    };

    // Весь extension supported_groups в сборе (тип+длина+тело).
    // Список из 7 групп ГОСТ фиксирован — незачем собирать его через BAOS каждый раз.
    private static final byte[] SUPPORTED_GROUPS_EXT = new byte[]{
            0x00, 0x0A, 0x00, 0x10,
            0x00, 0x0E,
            0x00, 0x22, 0x00, 0x23, 0x00, 0x24, 0x00, 0x25,
            0x00, 0x26, 0x00, 0x27, 0x00, 0x28
    };

    // Тело signature_algorithms (длина+список схем) без заголовка расширения.
    // Нужен отдельно для buildCertificateRequest, где используется encodeExtension.
    private static final byte[] SIG_ALG_BODY = new byte[]{
            0x00, 0x0E,
            0x07, 0x09, 0x07, 0x0A, 0x07, 0x0B, 0x07, 0x0C,
            0x07, 0x0D, 0x07, 0x0E, 0x07, 0x0F
    };

    // Весь extension signature_algorithms в сборе — чтобы не аллоцировать
    // BAOS + toByteArray() для семи uint16 на каждый handshake (вызывается 2 раза).
    private static final byte[] SIG_ALG_EXT = new byte[]{
            0x00, 0x0D, 0x00, 0x10,
            0x00, 0x0E,
            0x07, 0x09, 0x07, 0x0A, 0x07, 0x0B, 0x07, 0x0C,
            0x07, 0x0D, 0x07, 0x0E, 0x07, 0x0F
    };

    // psk_key_exchange_modes: режим PSK_DHE_KE фиксирован — BAOS ни к чему.
    private static final byte[] PSK_DHE_KE_EXT = new byte[]{
            0x00, 0x2D, 0x00, 0x02, 0x01, 0x01
    };

    // status_request: OCSP-степплинг с пустыми списками.
    // Статический литерал, потому что тело из 5 байт не меняется между handshake.
    private static final byte[] STATUS_REQUEST_EXT = new byte[]{
            0x00, 0x05, 0x00, 0x05,
            0x01, 0x00, 0x00, 0x00, 0x00
    };

    /**
     * @param ciphersuite           cipher suite (определяет AEAD, KDF, TLSTREE-константы)
     * @param offeredCipherSuiteIds список cipher suite ID для отправки в ClientHello
     * @param selectedNamedGroup    выбранная именованная группа (по умолчанию GC256A)
     * @param selectedSigScheme     схема подписи для CertificateVerify
     * @param ourPrivateKey        закрытый ключ для подписи (null для клиента без аутентификации)
     * @param ourCertificateChain  цепочка сертификатов (leaf первый, root последний; null для клиента без аутентификации)
     * @param hashLen              32 для Streebog-256, 64 для Streebog-512
     */
    public TlsMessageBuilder(TlsCiphersuite ciphersuite,
                             List<Integer> offeredCipherSuiteIds,
                             int selectedNamedGroup,
                             int selectedSigScheme,
                             PrivateKeyParameters ourPrivateKey,
                             List<TlsCertificate> ourCertificateChain,
                             int hashLen) {
        this.ciphersuite = ciphersuite;
        this.offeredCipherSuiteIds = offeredCipherSuiteIds;
        this.selectedNamedGroup = selectedNamedGroup;
        this.selectedSigScheme = selectedSigScheme;
        this.ourPrivateKey = ourPrivateKey;
        this.ourCertificateChain = ourCertificateChain;
        this.hashLen = hashLen;
    }

    /**
     * @return список cipher suite ID, отправленных в ClientHello
     */
    public List<Integer> getOfferedCipherSuiteIds() {
        return offeredCipherSuiteIds;
    }

    /**
     * Обновляет схему подписи для CertificateVerify после согласования
     * с клиентом (выбирается из его signature_algorithms).
     */
    public void updateSigScheme(int scheme) {
        this.selectedSigScheme = scheme;
    }

    /**
     * Устанавливает протоколы ALPN для включения в ClientHello (RFC 7301).
     * Вызывать до buildClientHello / buildClientHelloWithPsk — протоколы будут
     * добавлены как отдельное расширение после общих расширений, но до PSK
     * (pre_shared_key MUST быть последним, RFC 8446 §4.2.11).
     *
     * @param protocols список протоколов ALPN в порядке убывания предпочтения
     */
    public void setClientAlpnProtocols(List<String> protocols) {
        this.clientAlpnProtocols = protocols;
    }

    /**
     * @return цепочка сертификатов сервера (leaf первый, root последний)
     */
    public List<TlsCertificate> getCertificateChain() {
        return ourCertificateChain;
    }

    /**
     * Собирает ClientHello (RFC 8446 §4.1.2, RFC 9367 §3.1).
     * <p>
     * Формат: legacy_version(2) || random(32) || legacy_session_id(1+0) ||
     * cipher_suites(2+2) || compression(1+1) || extensions.
     * <p>
     * Extensions:
     * <ul>
     *   <li>{@code server_name} — если задан serverName (RFC 6066 §3, RFC 8446 §4.2.1)</li>
     *   <li>{@code supported_versions} — TLS 1.3 (0x0304)</li>
     *   <li>{@code supported_groups} — все 7 ГОСТ-кривых (GC256A–D, GC512A–C)</li>
     *   <li>{@code signature_algorithms} — все 7 схем подписи (256b + 512a–c)</li>
     *   <li>{@code key_share} — точка ECDHE публичного ключа для выбранной группы</li>
     *   <li>{@code status_request} — OCSP-степплинг (RFC 8446 §4.4.2.1)</li>
     * </ul>
     * <p>
     * Random заполняется {@link CryptoRandom}.
     *
     * @param ecdhePoint эфемерный публичный ключ в формате X || Y (little-endian)
     * @return тело ClientHello (без handshake-заголовка)
     */
    public byte[] buildClientHello(byte[] ecdhePoint) {
        return buildClientHello(ecdhePoint, null);
    }

    /**
     * Собирает ClientHello с опциональным расширением server_name.
     *
     * @param ecdhePoint эфемерный публичный ключ в формате X || Y (little-endian)
     * @param serverName DNS-имя сервера для SNI (null = без расширения)
     * @return тело ClientHello (без handshake-заголовка)
     */
    public byte[] buildClientHello(byte[] ecdhePoint, String serverName) {
        byte[] preamble = buildClientHelloPreamble();
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        buildCommonExtensions(ext, ecdhePoint, serverName);
        addAlpnExtension(ext);
        byte[] extBytes = ext.toByteArray();
        byte[] out = new byte[preamble.length + 2 + extBytes.length];
        System.arraycopy(preamble, 0, out, 0, preamble.length);
        out[preamble.length] = (byte) (extBytes.length >>> 8);
        out[preamble.length + 1] = (byte) extBytes.length;
        System.arraycopy(extBytes, 0, out, preamble.length + 2, extBytes.length);
        return out;
    }

    /**
     * Собирает ClientHello с PSK-расширениями (RFC 8446 §4.1.2, §4.2.9, §4.2.11).
     * <p>
     * Включает {@code psk_key_exchange_modes} (psk_dhe_ke) и
     * {@code pre_shared_key} (identity + placeholder binder).
     * Binder всегда в конце тела: {@code binderOffset = body.length - hashLen}.
     * <p>
     * pre_shared_key MUST быть последним расширением (RFC 8446 §4.2.11).
     *
     * @param ecdhePoint            ECDHE-публичный ключ X || Y
     * @param pskIdentity           тикет (opaque ticket из NewSessionTicket)
     * @param obfuscatedTicketAge   obfuscated_ticket_age (uint32)
     * @return тело ClientHello с placeholder binder
     */
    public byte[] buildClientHelloWithPsk(byte[] ecdhePoint,
                                           byte[] pskIdentity,
                                           long obfuscatedTicketAge) {
        return buildClientHelloWithPsk(ecdhePoint, pskIdentity, obfuscatedTicketAge, null);
    }

    /**
     * Собирает ClientHello с PSK-расширениями и опциональным server_name.
     *
     * @param ecdhePoint            ECDHE-публичный ключ X || Y
     * @param pskIdentity           тикет (opaque ticket из NewSessionTicket)
     * @param obfuscatedTicketAge   obfuscated_ticket_age (uint32)
     * @param serverName            DNS-имя сервера для SNI (null = без расширения)
     * @return тело ClientHello с placeholder binder
     */
    public byte[] buildClientHelloWithPsk(byte[] ecdhePoint,
                                           byte[] pskIdentity,
                                           long obfuscatedTicketAge,
                                           String serverName) {
        byte[] preamble = buildClientHelloPreamble();
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        buildCommonExtensions(ext, ecdhePoint, serverName);
        addAlpnExtension(ext);

        // psk_key_exchange_modes (RFC 8446 §4.2.9) — только psk_dhe_ke
        ext.write(PSK_DHE_KE_EXT, 0, PSK_DHE_KE_EXT.length);

        // pre_shared_key (RFC 8446 §4.2.11) — MUST be last!
        int identityLen = (pskIdentity != null) ? pskIdentity.length : 0;
        int binderLen = hashLen;
        int pskExtSize = 2 + identityLen + 4 + 2 + 1 + binderLen;
        byte[] pskExt = new byte[pskExtSize];
        int pos = 0;
        pskExt[pos++] = (byte) ((identityLen + 6) >>> 8);
        pskExt[pos++] = (byte) (identityLen + 6);
        pskExt[pos++] = (byte) (identityLen >>> 8);
        pskExt[pos++] = (byte) identityLen;
        if (pskIdentity != null) {
            System.arraycopy(pskIdentity, 0, pskExt, pos, identityLen);
            pos += identityLen;
        }
        pskExt[pos++] = (byte) (obfuscatedTicketAge >>> 24);
        pskExt[pos++] = (byte) (obfuscatedTicketAge >>> 16);
        pskExt[pos++] = (byte) (obfuscatedTicketAge >>> 8);
        pskExt[pos++] = (byte) obfuscatedTicketAge;
        pskExt[pos++] = (byte) ((1 + binderLen) >>> 8);
        pskExt[pos++] = (byte) (1 + binderLen);
        pskExt[pos  ] = (byte) binderLen;
        // pskExt заполнен нулями при аллокации — placeholder binder будет
        // вставлен после вычисления через TlsPskHelper.computeBinder

        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_PRE_SHARED_KEY, pskExt);

        byte[] extBytes = ext.toByteArray();
        byte[] out = new byte[preamble.length + 2 + extBytes.length];
        System.arraycopy(preamble, 0, out, 0, preamble.length);
        out[preamble.length] = (byte) (extBytes.length >>> 8);
        out[preamble.length + 1] = (byte) extBytes.length;
        System.arraycopy(extBytes, 0, out, preamble.length + 2, extBytes.length);
        return out;
    }

    /**
     * Собирает ServerHello (RFC 8446 §4.1.3, RFC 9367 §3.1).
     * <p>
     * Формат: legacy_version(2) || random(32) || legacy_session_id(1+0) ||
     * cipher_suite(2) || compression(1) || extensions.
     * <p>
     * Расширения: supported_versions + key_share с серверной ECDHE-точкой.
     *
     * @param ecdhePoint эфемерный публичный ключ сервера X || Y (little-endian)
     * @return тело ServerHello (без handshake-заголовка)
     */
    public byte[] buildServerHello(byte[] ecdhePoint) {
        return buildServerHello(ecdhePoint, false);
    }

    /**
     * Собирает ServerHello с опциональным PSK-расширением.
     * <p>
     * При {@code pskAccepted = true} добавляет pre_shared_key extension
     * с selected_identity = 0 (RFC 8446 §4.2.11).
     *
     * @param ecdhePoint эфемерный публичный ключ сервера X || Y (little-endian)
     * @param pskAccepted true → включить pre_shared_key extension
     * @return тело ServerHello (без handshake-заголовка)
     */
    public byte[] buildServerHello(byte[] ecdhePoint, boolean pskAccepted) {
        return buildServerHello(ecdhePoint, pskAccepted, selectedNamedGroup);
    }

    /**
     * Собирает ServerHello с указанием именованной группы для key_share.
     * <p>
     * При {@code pskAccepted = true} добавляет pre_shared_key extension
     * с selected_identity = 0 (RFC 8446 §4.2.11).
     *
     * @param ecdhePoint эфемерный публичный ключ сервера X || Y (little-endian)
     * @param pskAccepted true → включить pre_shared_key extension
     * @param namedGroup  идентификатор именованной группы для key_share
     * @return тело ServerHello (без handshake-заголовка)
     */
    public byte[] buildServerHello(byte[] ecdhePoint, boolean pskAccepted, int namedGroup) {
        byte[] random = new byte[TlsConstants.RANDOM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(random);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(TlsConstants.LEGACY_VERSION_MAJOR);
        out.write(TlsConstants.LEGACY_VERSION_MINOR);

        out.write(random, 0, random.length);

        out.write(0x00);

        TlsEncoding.encodeUint16(out, ciphersuite.getId());

        out.write(0x00);

        ByteArrayOutputStream ext = new ByteArrayOutputStream();

        ext.write(SV_SERVER, 0, SV_SERVER.length);

        byte[] ksEntry = new byte[4 + ecdhePoint.length];
        ksEntry[0] = (byte) (namedGroup >>> 8);
        ksEntry[1] = (byte) namedGroup;
        ksEntry[2] = (byte) (ecdhePoint.length >>> 8);
        ksEntry[3] = (byte) ecdhePoint.length;
        System.arraycopy(ecdhePoint, 0, ksEntry, 4, ecdhePoint.length);
        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_KEY_SHARE, ksEntry);

        if (pskAccepted) {
            TlsEncoding.encodeExtension(ext, TlsConstants.EXT_PRE_SHARED_KEY,
                    new byte[]{0x00, 0x00}); // selected_identity = 0
        }

        TlsEncoding.encodeUint16(out, ext.size());
        out.write(ext.toByteArray(), 0, ext.size());

        return out.toByteArray();
    }

    /**
     * Собирает Certificate (RFC 8446 §4.4.2).
     * <p>
     * Формат: certificate_request_context(0) || CertificateEntry.
 * CertificateEntry: cert_len(3) || cert_der || extensions_len(2) || [].
 * Итерация по цепочке сертификатов; OCSP-степплинг включается
 * в extensions первого CertificateEntry при наличии.
 *
 * @return тело Certificate (без handshake-заголовка)
     * @throws IllegalStateException если сертификат не установлен
     */
    public byte[] buildCertificateBody() {
        return buildCertificateBody(null);
    }

    /**
     * Собирает Certificate (RFC 8446 §4.4.2) с опциональным OCSP-ответом.
     * <p>
     * Если {@code ocspResponse != null}, в extensions первого CertificateEntry
     * включается status_request (RFC 8446 §4.4.2.1).
     *
     * @param ocspResponse raw OCSPResponse DER (null = без OCSP)
     * @return тело Certificate (без handshake-заголовка)
     */
    public byte[] buildCertificateBody(byte[] ocspResponse) {
        if (ourCertificateChain == null || ourCertificateChain.isEmpty()) {
            throw new IllegalStateException("No certificate available");
        }
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (int i = 0; i < ourCertificateChain.size(); i++) {
            byte[] certData = ourCertificateChain.get(i).getCertData();
            TlsEncoding.encodeUint24(list, certData.length);
            list.write(certData, 0, certData.length);
            if (i == 0 && ocspResponse != null && ocspResponse.length > 0) {
                int extTotalLen = 2 + 2 + 1 + ocspResponse.length;
                TlsEncoding.encodeUint16(list, extTotalLen);
                TlsEncoding.encodeUint16(list, TlsConstants.EXT_STATUS_REQUEST);
                TlsEncoding.encodeUint16(list, 1 + ocspResponse.length);
                list.write(0x01);
                list.write(ocspResponse, 0, ocspResponse.length);
            } else {
                TlsEncoding.encodeUint16(list, 0);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x00);
        TlsEncoding.encodeUint24(out, list.size());
        out.write(list.toByteArray(), 0, list.size());
        return out.toByteArray();
    }

    /**
     * Строит тело пустого Certificate (RFC 8446 §4.4.2).
     * Используется клиентом, когда сервер отправил CertificateRequest,
     * но у клиента нет подходящего сертификата.
     * <p>
     * Формат: request_context (1 байт, 0x00) + certificate_list (3 байта, 0x000000).
     *
     * @return тело Certificate (без handshake-заголовка)
     */
    public byte[] buildEmptyCertificateBody() {
        // request_context = 0x00, certificate_list_length = 0x000000
        return new byte[]{0x00, 0x00, 0x00, 0x00};
    }

    /**
     * Собирает CertificateVerify (RFC 8446 §4.4.3, RFC 9367 §3.2).
     * <p>
     * Подписываемое содержимое (sigContent):
     * {@code 0x20 * 64 || context_string || 0x00 || Transcript-Hash}.
     * 64 байта 0x20 — фиксированный префикс для отделения контекста подписи
     * от других сообщений (RFC 8446 §4.4.3).
     * <p>
     * Сама подпись — ГОСТ Р 34.10-2012 с little-endian кодированием r ∥ s
     * (RFC 9367 §3.2). Перед подписью передаётся идентификатор схемы подписи (2 байта).
     *
     * @param transcriptHash Transcript-Hash от handshake-сообщений до CertificateVerify
     * @return тело CertificateVerify: scheme(2) || sig_len(2) || sig(N)
     */
    public byte[] buildCertificateVerify(byte[] transcriptHash) {
        return buildCertificateVerify(transcriptHash, TlsConstants.SERVER_CERTIFICATE_VERIFY_CTX);
    }

    /**
     * Строит тело CertificateVerify с указанием контекстной строки.
     * Позволяет выбрать серверный или клиентский контекст (mTLS).
     *
     * @param transcriptHash Transcript-Hash до CertificateVerify
     * @param contextString контекстная строка (SERVER_CERTIFICATE_VERIFY_CTX
     *                      или CLIENT_CERTIFICATE_VERIFY_CTX)
     * @return тело CertificateVerify: scheme(2) || sig_len(2) || sig(N)
     */
    public byte[] buildCertificateVerify(byte[] transcriptHash, String contextString) {
        byte[] sigContent = TlsEncoding.buildSigContent(transcriptHash, contextString);

        int sigHashLen = ourPrivateKey.getParams().hlen;
        Digest d = sigHashLen == 64 ? new Streebog512() : new Streebog256();
        d.update(sigContent, 0, sigContent.length);
        byte[] hash = new byte[sigHashLen];
        d.doFinal(hash, 0);
        int rolen = sigHashLen;
        byte[] sig = TlsSignatureCodec.sign(hash, ourPrivateKey, rolen);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(out, selectedSigScheme);
        TlsEncoding.encodeUint16(out, sig.length);
        out.write(sig, 0, sig.length);
        return out.toByteArray();
    }

    /**
     * EncryptedExtensions — пустой список расширений (RFC 9367 §6.1.2).
     * В ГОСТ-профиле TLS 1.3 не требуется никаких дополнительных расширений
     * на этом этапе, поэтому тело — всегда {@code 0x00 0x00}.
     */
    public static byte[] buildEncryptedExtensions() {
        return new byte[]{0x00, 0x00};
    }

    /**
     * Собирает preamble ClientHello: legacy_version, random, legacy_session_id,
     * cipher_suites (из {@link #offeredCipherSuiteIds}), compression_methods.
     * <p>
     * Размер: 39 + 2 × количество cipher suites.
     *
     * @return preamble ClientHello (размер зависит от числа cipher suites)
     */
    private byte[] buildClientHelloPreamble() {
        byte[] random = new byte[TlsConstants.RANDOM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(random);

        int suitesBytes = offeredCipherSuiteIds.size() * 2;
        byte[] out = new byte[39 + suitesBytes];
        int pos = 0;
        out[pos++] = TlsConstants.LEGACY_VERSION_MAJOR;
        out[pos++] = TlsConstants.LEGACY_VERSION_MINOR;
        System.arraycopy(random, 0, out, pos, TlsConstants.RANDOM_LENGTH);
        pos += TlsConstants.RANDOM_LENGTH;
        out[pos++] = 0;  // legacy_session_id length — всегда пусто в TLS 1.3

        // cipher suites: длина(2) + N наборов × 2 байта
        out[pos++] = (byte) (suitesBytes >>> 8);
        out[pos++] = (byte) suitesBytes;
        for (int id : offeredCipherSuiteIds) {
            out[pos++] = (byte) (id >>> 8);
            out[pos++] = (byte) id;
        }

        out[pos++] = 0x01;  // длина списка методов сжатия (только null)
        out[pos  ] = 0x00;  // null compression — RFC 8446 §4.1.2: MUST be present, single 0x00
        return out;
    }

    /**
     * Перегрузка без server_name — делегирует основному методу с null.
     */
    private void buildCommonExtensions(ByteArrayOutputStream ext, byte[] ecdhePoint) {
        buildCommonExtensions(ext, ecdhePoint, null);
    }

    /**
     * Собирает общий набор расширений ClientHello: server_name (если задан),
     * supported_versions, supported_groups, signature_algorithms, key_share, status_request.
     * <p>
     * Порядок не влияет на протокол, но pre_shared_key (если есть) MUST быть последним
     * и добавляется отдельно в buildClientHelloWithPsk().
     *
     * @param ext         поток для записи расширений
     * @param ecdhePoint  эфемерный публичный ключ X || Y
     * @param serverName  DNS-имя сервера для SNI (null = без расширения)
     */
    private void buildCommonExtensions(ByteArrayOutputStream ext, byte[] ecdhePoint, String serverName) {
        // SNI: server_name extension (RFC 6066 §3, RFC 8446 §4.2.1)
        String normalized = normalizeHostname(serverName);
        if (normalized != null) {
            ByteArrayOutputStream sniData = new ByteArrayOutputStream();
            byte[] nameBytes = normalized.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            // ServerNameList: length(2) || name_type(1)=host_name || name_length(2) || name(N)
            TlsEncoding.encodeUint16(sniData, 3 + nameBytes.length);
            sniData.write(0x00);
            TlsEncoding.encodeUint16(sniData, nameBytes.length);
            sniData.write(nameBytes, 0, nameBytes.length);
            TlsEncoding.encodeExtension(ext, TlsConstants.EXT_SERVER_NAME, sniData.toByteArray());
        }

        // Статические расширения: предварительно собранные байтовые массивы,
        // чтобы не аллоцировать BAOS на каждый handshake
        ext.write(SV_CLIENT, 0, SV_CLIENT.length);
        ext.write(SUPPORTED_GROUPS_EXT, 0, SUPPORTED_GROUPS_EXT.length);
        ext.write(SIG_ALG_EXT, 0, SIG_ALG_EXT.length);

        // key_share entry: группа(2) + длина_ключа(2) + точка(N)
        byte[] ksEntry = new byte[4 + ecdhePoint.length];
        ksEntry[0] = (byte) (selectedNamedGroup >>> 8);
        ksEntry[1] = (byte) selectedNamedGroup;
        ksEntry[2] = (byte) (ecdhePoint.length >>> 8);
        ksEntry[3] = (byte) ecdhePoint.length;
        System.arraycopy(ecdhePoint, 0, ksEntry, 4, ecdhePoint.length);

        // Оборачиваем entry в список key_share: длина_списка(2) + entry
        byte[] ks = new byte[2 + ksEntry.length];
        ks[0] = (byte) (ksEntry.length >>> 8);
        ks[1] = (byte) ksEntry.length;
        System.arraycopy(ksEntry, 0, ks, 2, ksEntry.length);

        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_KEY_SHARE, ks);
        ext.write(STATUS_REQUEST_EXT, 0, STATUS_REQUEST_EXT.length);
    }

    /**
     * Добавляет ALPN extension (RFC 7301 §3.1) в поток расширений ClientHello,
     * если список протоколов установлен через {@link #setClientAlpnProtocols}.
     * <p>
     * Расширение добавляется после {@link #buildCommonExtensions} — порядок не влияет
     * на протокол, но важно что pre_shared_key остаётся последним (RFC 8446 §4.2.11).
     */
    private void addAlpnExtension(ByteArrayOutputStream ext) {
        if (clientAlpnProtocols == null || clientAlpnProtocols.isEmpty()) return;
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (String p : clientAlpnProtocols) {
            byte[] name = p.getBytes(StandardCharsets.US_ASCII);
            list.write(name.length & 0xFF);
            list.write(name, 0, name.length);
        }
        byte[] listBytes = list.toByteArray();
        ByteArrayOutputStream extData = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(extData, listBytes.length);
        extData.write(listBytes, 0, listBytes.length);
        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, extData.toByteArray());
    }

    /**
     * Собирает EncryptedExtensions с опциональным ALPN (RFC 7301, RFC 8446 §4.3.1).
     * <p>
     * Если selectedAlpnProtocol == null, возвращает пустые расширения {0x00, 0x00}
     * для обратной совместимости (сервер без ALPN).
     * Формат ответа: ProtocolName = len(1) || name(N) — только один протокол, выбранный сервером.
     *
     * @param selectedAlpnProtocol выбранный сервером протокол, или null
     * @return тело EncryptedExtensions
     */
    public static byte[] buildEncryptedExtensions(String selectedAlpnProtocol) {
        if (selectedAlpnProtocol == null || selectedAlpnProtocol.isEmpty()) {
            return new byte[]{0x00, 0x00};
        }
        byte[] nameBytes = selectedAlpnProtocol.getBytes(StandardCharsets.US_ASCII);
        byte[] alpnBody = new byte[1 + nameBytes.length];
        alpnBody[0] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, alpnBody, 1, nameBytes.length);

        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        TlsEncoding.encodeExtension(extBody, TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpnBody);
        byte[] extBodyBytes = extBody.toByteArray();
        byte[] out = new byte[2 + extBodyBytes.length];
        out[0] = (byte) (extBodyBytes.length >>> 8);
        out[1] = (byte) extBodyBytes.length;
        System.arraycopy(extBodyBytes, 0, out, 2, extBodyBytes.length);
        return out;
    }

    /**
     * Нормализует DNS-имя для SNI (RFC 6066 §3, RFC 8446 §4.2.1).
     * <p>
     * Приводит к lowercase, удаляет завершающие точки (FQDN → relative),
     * проверяет что имя — чистый ASCII. Возвращает null при пустом/невалидном имени.
     * <p>
     * Используется и при сборке (TlsMessageBuilder) и при парсинге (TlsMessageParser).
     */
    static String normalizeHostname(String hostname) {
        if (hostname == null || hostname.isEmpty()) return null;
        String n = hostname.toLowerCase(Locale.ENGLISH);
        // RFC 8499 §5: удаляем trailing dot для унификации
        while (n.endsWith(".")) {
            n = n.substring(0, n.length() - 1);
        }
        if (n.isEmpty()) return null;
        // RFC 6066: host_name MUST be ASCII, не IDN
        for (int i = 0; i < n.length(); i++) {
            if (n.charAt(i) > 127) return null;
        }
        return n;
    }

    /**
     * Собирает CertificateRequest (RFC 8446 §4.3.2).
     * <p>
     * Формат: certificate_request_context(0) || extensions.
     * Расширения: signature_algorithms со всеми 7 ГОСТ-схемами подписи.
     *
     * @return тело CertificateRequest
     */
    public static byte[] buildCertificateRequest() {
        byte[] out = new byte[23];
        out[0] = 0;  // certificate_request_context
        out[1] = 0; out[2] = 20;  // extensions length (SIG_ALG_EXT size)
        System.arraycopy(SIG_ALG_EXT, 0, out, 3, SIG_ALG_EXT.length);
        return out;
    }

    /**
     * Собирает Finished (RFC 8446 §4.4.4).
     * verify_data = HMAC-Streebog(finished_key, Transcript-Hash).
     *
     * @param keySchedule   key schedule для выработки finished_key
     * @param trafficSecret handshake traffic secret
     * @param transcript    Transcript-Hash от handshake-сообщений
     * @return verify_data (32 или 64 байта)
     */
    public static byte[] buildFinished(TlsKeySchedule keySchedule,
                                        byte[] trafficSecret,
                                        byte[] transcript) {
        return keySchedule.computeVerifyData(trafficSecret, transcript);
    }

    /**
     * Собирает NewSessionTicket (RFC 8446 §4.6.1).
     * <p>
     * Формат: ticket_lifetime(4) || ticket_age_add(4) ||
     * ticket_nonce_len(1) || ticket_nonce ||
     * ticket_len(2) || ticket || extensions_len(2) || extensions.
     * <p>
     * Расширения пока пустые (early_data не поддерживается).
     *
     * @param ticketLifetime время жизни тикета в секундах (uint32)
     * @param ticketAgeAdd   obfuscated ticket age (uint32)
     * @param ticketNonce    nonce для диверсификации PSK (0..255 байт)
     * @param ticket         opaque ticket (1..65535 байт)
     * @return тело NewSessionTicket
     */
    public static byte[] buildNewSessionTicket(long ticketLifetime, long ticketAgeAdd,
                                                byte[] ticketNonce, byte[] ticket) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeUint32(out, ticketLifetime);
        TlsEncoding.encodeUint32(out, ticketAgeAdd);
        out.write(ticketNonce.length & 0xFF);
        out.write(ticketNonce, 0, ticketNonce.length);
        TlsEncoding.encodeUint16(out, ticket.length);
        out.write(ticket, 0, ticket.length);
        TlsEncoding.encodeUint16(out, 0); // empty extensions
        return out.toByteArray();
    }

    /**
     * Собирает TLS-запись в открытом виде (без шифрования).
     * <p>
     * Используется для передачи ClientHello / ServerHello / alert / close_notify
     * до установки защищённого соединения (RFC 8446 §5.1).
     *
     * @param contentType тип содержимого записи (CT_*)
     * @param body тело записи
     * @return собранная TLS-запись с заголовком
     */
    public static byte[] buildPlaintextRecord(byte contentType, byte[] body) {
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + body.length];
        record[0] = contentType;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (body.length >>> 8);
        record[4] = (byte) body.length;
        System.arraycopy(body, 0, record, TlsConstants.RECORD_HEADER_SIZE, body.length);
        return record;
    }
}
