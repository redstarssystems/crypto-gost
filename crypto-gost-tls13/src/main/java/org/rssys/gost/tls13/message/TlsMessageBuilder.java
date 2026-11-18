package org.rssys.gost.tls13.message;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostDnsName;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;
import org.rssys.gost.tls13.crypto.TlsSignatureCodec;
import org.rssys.gost.util.CryptoRandom;

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

    /**
     * Блок расширений ClientHello с PSK не помещается в uint16.
     *
     * <p>Размер тикета известен заранее, а размер остальных расширений - только при сборке,
     * поэтому раннее ограничение длины тикета лишь грубый фильтр. Вызывающий код решает, что
     * делать: отказаться от PSK (первый ClientHello) или прервать рукопожатие (второй).
     */
    public static final class ExtensionsOverflowException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        ExtensionsOverflowException(String message) {
            super(message);
        }
    }

    private TlsCiphersuite ciphersuite;
    private final List<Integer> offeredCipherSuiteIds;
    private final int selectedNamedGroup;

    /** Тестовое переопределение supported_groups (null - штатный список из 7 ГОСТ-групп). */
    private int[] supportedGroupsOverride;

    /** Тестовый режим: не писать расширение key_share вовсе (штатно оно обязательно). */
    private boolean omitKeyShare;

    /** Тестовый режим: не писать расширение supported_groups вовсе (штатно оно обязательно). */
    private boolean omitSupportedGroups;

    private int selectedSigScheme;
    private PrivateKeyParameters ourPrivateKey;
    private List<GostCertificate> ourCertificateChain;
    private int hashLen;

    // ALPN (RFC 7301): список протоколов клиента для включения в ClientHello
    private List<String> clientAlpnProtocols;

    // max_fragment_length (RFC 6066 §4): 0 = не отправлять, 1..4 = код лимита
    private int clientMaxFragLen;

    /** legacy_session_id из ClientHello для эхо-отражения (RFC 8446 §4.1.3). Null если пусто. */
    private byte[] clientSessionId;

    /**
     * {@code legacy_session_id}, который клиент пишет в ClientHello. Пустой: режим совместимости
     * с промежуточными узлами (RFC 8446 §D.4) у клиента не реализован. Один источник для
     * преамбулы и для проверки эха в ServerHello.
     */
    private final byte[] sentLegacySessionId = new byte[0];

    // Расширение supported_versions для ClientHello:
    // — вместо new byte[] + BAOS в buildCommonExtensions
    private static final byte[] SV_CLIENT = new byte[] {0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04};

    // Расширение supported_versions для ServerHello (без 0x02):
    // — отдельная константа, чтобы не аллоцировать byte[2] и не писать encodeExtension
    private static final byte[] SV_SERVER = new byte[] {0x00, 0x2B, 0x00, 0x02, 0x03, 0x04};

    // Весь extension supported_groups в сборе (тип+длина+тело).
    // Список из 7 групп ГОСТ фиксирован — незачем собирать его через BAOS каждый раз.
    private static final byte[] SUPPORTED_GROUPS_EXT =
            new byte[] {
                0x00, 0x0A, 0x00, 0x10, 0x00, 0x0E, 0x00, 0x22, 0x00, 0x23, 0x00, 0x24, 0x00, 0x25,
                0x00, 0x26, 0x00, 0x27, 0x00, 0x28
            };

    // Тело signature_algorithms (длина+список схем) без заголовка расширения.
    // Нужен отдельно для buildCertificateRequest, где используется encodeExtension.
    private static final byte[] SIG_ALG_BODY =
            new byte[] {
                0x00, 0x0E, 0x07, 0x09, 0x07, 0x0A, 0x07, 0x0B, 0x07, 0x0C, 0x07, 0x0D, 0x07, 0x0E,
                0x07, 0x0F
            };

    // Весь extension signature_algorithms в сборе — чтобы не аллоцировать
    // BAOS + toByteArray() для семи uint16 на каждый handshake (вызывается 2 раза).
    private static final byte[] SIG_ALG_EXT =
            new byte[] {
                0x00, 0x0D, 0x00, 0x10, 0x00, 0x0E, 0x07, 0x09, 0x07, 0x0A, 0x07, 0x0B, 0x07, 0x0C,
                0x07, 0x0D, 0x07, 0x0E, 0x07, 0x0F
            };

    // psk_key_exchange_modes: режим PSK_DHE_KE фиксирован — BAOS ни к чему.
    private static final byte[] PSK_DHE_KE_EXT = new byte[] {0x00, 0x2D, 0x00, 0x02, 0x01, 0x01};

    // status_request: OCSP-степплинг с пустыми списками.
    // Статический литерал, потому что тело из 5 байт не меняется между handshake.
    private static final byte[] STATUS_REQUEST_EXT =
            new byte[] {0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00};

    /**
     * @param ciphersuite           cipher suite (определяет AEAD, KDF, TLSTREE-константы)
     * @param offeredCipherSuiteIds список cipher suite ID для отправки в ClientHello
     * @param selectedNamedGroup    выбранная именованная группа (по умолчанию GC256A)
     * @param selectedSigScheme     схема подписи для CertificateVerify
     * @param ourPrivateKey        закрытый ключ для подписи (null для клиента без аутентификации)
     * @param ourCertificateChain  цепочка сертификатов (leaf первый, root последний; null для клиента без аутентификации)
     * @param hashLen              32 для Streebog-256, 64 для Streebog-512
     */
    public TlsMessageBuilder(
            TlsCiphersuite ciphersuite,
            List<Integer> offeredCipherSuiteIds,
            int selectedNamedGroup,
            int selectedSigScheme,
            PrivateKeyParameters ourPrivateKey,
            List<GostCertificate> ourCertificateChain,
            int hashLen) {
        this.ciphersuite = ciphersuite;
        this.offeredCipherSuiteIds = offeredCipherSuiteIds;
        this.selectedNamedGroup = selectedNamedGroup;
        this.selectedSigScheme = selectedSigScheme;
        this.ourPrivateKey = ourPrivateKey;
        this.ourCertificateChain = ourCertificateChain;
        this.hashLen = hashLen;
    }

    private void updateCiphersuite(TlsCiphersuite negotiated) {
        this.ciphersuite = negotiated;
        this.hashLen = negotiated.getHashLen();
    }

    /**
     * Согласует cipher suite по ClientHello клиента (RFC 8446 §4.1.1).
     * Сервер выбирает по своему приоритету: сначала preferred (если он есть в
     * offeredCipherSuiteIds, то есть разрешён), затем offeredCipherSuiteIds.
     * <p>
     * Наборы с другой длиной хеша, чем {@code requiredHashLen}, не выбираются: хеш транскрипта
     * и секреты рукопожатия движка уже построены под эту длину, и набор с иной длиной дал бы
     * неверные ключи. Такой набор пропускается, а не обрывает рукопожатие: клиент, предложивший
     * допустимый набор, получает его, а при отсутствии пересечения прежний {@code null}.
     *
     * @param chBody          тело ClientHello
     * @param preferred       предпочтительный suite сервера (может быть null)
     * @param requiredHashLen длина хеша, под которую построен движок (32 или 64)
     * @return согласованный suite, или null если подходящего пересечения нет
     * @throws TlsException при malformed ClientHello
     */
    public TlsCiphersuite negotiateCiphersuite(
            byte[] chBody, TlsCiphersuite preferred, int requiredHashLen) throws TlsException {
        TlsCiphersuite matched =
                matchClientCiphersuite(chBody, offeredCipherSuiteIds, preferred, requiredHashLen);
        if (matched != null && matched != this.ciphersuite) {
            updateCiphersuite(matched);
        }
        return matched;
    }

    /**
     * Находит согласованный ciphersuite: сначала предпочтительный suite сервера,
     * затем первое пересечение по приоритету сервера (RFC 8446 §4.1.1).
     */
    private static TlsCiphersuite matchClientCiphersuite(
            byte[] chBody,
            List<Integer> offeredSuites,
            TlsCiphersuite preferredSuite,
            int requiredHashLen)
            throws TlsException {
        try {
            int pos = 2 + TlsConstants.RANDOM_LENGTH;
            int sidLen = chBody[pos] & 0xFF;
            pos += 1 + sidLen;
            int csLen = ((chBody[pos] & 0xFF) << 8) | (chBody[pos + 1] & 0xFF);
            pos += 2;
            int clientCsEnd = pos + csLen;
            // Сначала предпочтительный suite сервера, но только если он разрешён: иначе
            // отключённый приложением набор принимался бы, раз клиент его предложил
            if (preferredSuite != null
                    && preferredSuite.getHashLen() == requiredHashLen
                    && offeredSuites.contains(preferredSuite.getId())) {
                int preferredId = preferredSuite.getId();
                for (int i = pos; i < clientCsEnd; i += 2) {
                    int clientId = ((chBody[i] & 0xFF) << 8) | (chBody[i + 1] & 0xFF);
                    if (clientId == preferredId) {
                        return preferredSuite;
                    }
                }
            }
            // Fallback: первое пересечение по приоритету сервера (RFC 8446 §4.1.1)
            for (int offeredId : offeredSuites) {
                TlsCiphersuite offered = TlsCiphersuite.byId(offeredId);
                // Неизвестный идентификатор в списке сервера - не повод падать с NPE:
                // такой набор просто не может быть выбран
                if (offered == null || offered.getHashLen() != requiredHashLen) {
                    continue;
                }
                for (int i = pos; i < clientCsEnd; i += 2) {
                    int clientId = ((chBody[i] & 0xFF) << 8) | (chBody[i + 1] & 0xFF);
                    if (clientId == offeredId) {
                        return offered;
                    }
                }
            }
            return null;
        } catch (IndexOutOfBoundsException e) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Malformed ClientHello (cipher suites)");
        }
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
     * Заменяет цепочку сертификатов для Certificate.
     * Используется при выборе клиентского сертификата по oid_filters.
     */
    public void setCertificateChain(List<GostCertificate> chain) {
        this.ourCertificateChain = chain;
    }

    /**
     * Заменяет закрытый ключ для CertificateVerify.
     * Используется при выборе клиентского сертификата по oid_filters.
     */
    public void setPrivateKey(PrivateKeyParameters key) {
        this.ourPrivateKey = key;
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
     * Возвращает {@code legacy_session_id}, записываемый в ClientHello этого клиента.
     * Эхо в ServerHello/HRR обязано совпасть с ним (RFC 8446 §4.1.3).
     * <p>
     * Сейчас значение всегда пустое: режим совместимости с промежуточными узлами (RFC 8446 §D.4),
     * в котором клиент шлёт непустой идентификатор, не реализован.
     *
     * @return копия значения; пустой массив, если идентификатор не отправляется
     */
    public byte[] getSentLegacySessionId() {
        return sentLegacySessionId.clone();
    }

    /**
     * Устанавливает legacy_session_id из ClientHello для эхо-отражения.
     * Вызывать до buildServerHello.
     *
     * @param sessionId legacy_session_id клиента или null/пустой если отсутствует
     */
    public void setClientSessionId(byte[] sessionId) {
        this.clientSessionId = (sessionId != null && sessionId.length > 0) ? sessionId : null;
    }

    /**
     * Устанавливает код max_fragment_length для включения в ClientHello (RFC 6066 §4).
     * 0 = не отправлять расширение, 1=512, 2=1024, 3=2048, 4=4096 байт.
     */
    public void setClientMaxFragLen(int maxFragLen) {
        this.clientMaxFragLen = maxFragLen;
    }

    /**
     * @return цепочка сертификатов сервера (leaf первый, root последний)
     */
    public List<GostCertificate> getCertificateChain() {
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
    /**
     * Собирает ClientHello с несколькими key_share entry (multi key_share, RFC 8446 §4.2.8).
     * Позволяет клиенту предложить несколько групп в первом сообщении, избегая HRR.
     *
     * @param ecdhePoints карта: NamedGroup -> закодированная точка X||Y
     * @param serverName  DNS-имя сервера для SNI (null = без расширения)
     * @return тело ClientHello (без handshake-заголовка)
     */
    public byte[] buildClientHello(Map<Integer, byte[]> ecdhePoints, String serverName) {
        return buildClientHello(ecdhePoints, serverName, null);
    }

    public byte[] buildClientHello(
            Map<Integer, byte[]> ecdhePoints, String serverName, byte[] cookie) {
        byte[] preamble = buildClientHelloPreamble();
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        buildCommonExtensions(ext, ecdhePoints, serverName);
        addAlpnExtension(ext);
        addCookieExtension(ext, cookie);
        byte[] extBytes = ext.toByteArray();
        byte[] out = new byte[preamble.length + 2 + extBytes.length];
        System.arraycopy(preamble, 0, out, 0, preamble.length);
        out[preamble.length] = (byte) (extBytes.length >>> 8);
        out[preamble.length + 1] = (byte) extBytes.length;
        System.arraycopy(extBytes, 0, out, preamble.length + 2, extBytes.length);
        return out;
    }

    public byte[] buildClientHello(byte[] ecdhePoint, String serverName) {
        return buildClientHello(Map.of(selectedNamedGroup, ecdhePoint), serverName, null);
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
    public byte[] buildClientHelloWithPsk(
            byte[] ecdhePoint, byte[] pskIdentity, long obfuscatedTicketAge) {
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
    /**
     * Собирает ClientHello с PSK и несколькими key_share entry (multi key_share).
     *
     * @param ecdhePoints         карта: NamedGroup -> закодированная точка X||Y
     * @param pskIdentity         тикет (opaque ticket из NewSessionTicket)
     * @param obfuscatedTicketAge obfuscated_ticket_age (uint32)
     * @param serverName          DNS-имя сервера для SNI (null = без расширения)
     * @return тело ClientHello с placeholder binder
     */
    public byte[] buildClientHelloWithPsk(
            Map<Integer, byte[]> ecdhePoints,
            byte[] pskIdentity,
            long obfuscatedTicketAge,
            String serverName) {
        return buildClientHelloWithPsk(
                ecdhePoints, pskIdentity, obfuscatedTicketAge, serverName, null);
    }

    public byte[] buildClientHelloWithPsk(
            Map<Integer, byte[]> ecdhePoints,
            byte[] pskIdentity,
            long obfuscatedTicketAge,
            String serverName,
            byte[] cookie) {
        byte[] preamble = buildClientHelloPreamble();
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        buildCommonExtensions(ext, ecdhePoints, serverName);
        addAlpnExtension(ext);
        addCookieExtension(ext, cookie);

        // psk_key_exchange_modes (RFC 8446 §4.2.9) — только psk_dhe_ke
        ext.write(PSK_DHE_KE_EXT, 0, PSK_DHE_KE_EXT.length);

        // pre_shared_key (RFC 8446 §4.2.11) — MUST be last!
        int identityLen = (pskIdentity != null) ? pskIdentity.length : 0;
        int binderLen = hashLen;
        // Структура (RFC 8446 §4.2.11): длина списка identities (2), длина identity (2), identity,
        // obfuscated_ticket_age (4), длина списка binders (2), длина binder (1), binder.
        // Binder подставляется в последние binderLen байт: размер обязан учитывать оба префикса
        // длины, иначе подстановка затирает длины списка binders и binder
        int pskExtSize = 2 + 2 + identityLen + 4 + 2 + 1 + binderLen;
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
        pskExt[pos] = (byte) binderLen;
        // pskExt заполнен нулями при аллокации — placeholder binder будет
        // вставлен после вычисления через TlsPskHelper.computeBinder

        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_PRE_SHARED_KEY, pskExt);

        byte[] extBytes = ext.toByteArray();
        // Длина блока расширений - uint16: при переполнении ClientHello вышел бы с обрезанной
        // длиной
        if (extBytes.length > TlsConstants.MAX_EXTENSIONS_BLOCK_SIZE) {
            throw new ExtensionsOverflowException(
                    "ClientHello extensions exceed "
                            + TlsConstants.MAX_EXTENSIONS_BLOCK_SIZE
                            + " bytes: PSK identity is too long");
        }
        byte[] out = new byte[preamble.length + 2 + extBytes.length];
        System.arraycopy(preamble, 0, out, 0, preamble.length);
        out[preamble.length] = (byte) (extBytes.length >>> 8);
        out[preamble.length + 1] = (byte) extBytes.length;
        System.arraycopy(extBytes, 0, out, preamble.length + 2, extBytes.length);
        return out;
    }

    public byte[] buildClientHelloWithPsk(
            byte[] ecdhePoint, byte[] pskIdentity, long obfuscatedTicketAge, String serverName) {
        return buildClientHelloWithPsk(
                Map.of(selectedNamedGroup, ecdhePoint),
                pskIdentity,
                obfuscatedTicketAge,
                serverName);
    }

    /**
     * Собирает ServerHello (RFC 8446 §4.1.3, RFC 9367 §3.1).
     * <p>
     * Формат: legacy_version(2) || random(32) || legacy_session_id(1+len) ||
     * cipher_suite(2) || compression(1) || extensions.
     * <p>
     * Extensions: supported_versions + key_share с серверной ECDHE-точкой.
     * legacy_session_id заполняется из {@link #setClientSessionId(byte[])}.
     *
     * @param ecdhePoint эфемерный публичный ключ сервера X || Y (little-endian)
     * @return тело ServerHello (без handshake-заголовка)
     */
    public byte[] buildServerHello(byte[] ecdhePoint) {
        return buildServerHello(ecdhePoint, NO_SELECTED_PSK, selectedNamedGroup);
    }

    /** Значение {@code selectedPskIdentity}: PSK не принят, расширение pre_shared_key не добавляется. */
    public static final int NO_SELECTED_PSK = -1;

    /**
     * Собирает ServerHello с указанием именованной группы для key_share и выбранной PSK identity.
     * <p>
     * При {@code selectedPskIdentity >= 0} добавляет pre_shared_key extension с этим номером
     * в качестве selected_identity (RFC 8446 §4.2.11): номер identity в списке клиента.
     *
     * @param ecdhePoint          эфемерный публичный ключ сервера X || Y (little-endian)
     * @param selectedPskIdentity номер выбранной identity (uint16) или {@link #NO_SELECTED_PSK}
     * @param namedGroup          идентификатор именованной группы для key_share
     * @return тело ServerHello (без handshake-заголовка)
     */
    public byte[] buildServerHello(byte[] ecdhePoint, int selectedPskIdentity, int namedGroup) {
        byte[] random = new byte[TlsConstants.RANDOM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(random);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(TlsConstants.LEGACY_VERSION_MAJOR);
        out.write(TlsConstants.LEGACY_VERSION_MINOR);

        out.write(random, 0, random.length);

        if (clientSessionId != null) {
            out.write(clientSessionId.length);
            out.write(clientSessionId, 0, clientSessionId.length);
        } else {
            out.write(0x00);
        }

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

        if (selectedPskIdentity != NO_SELECTED_PSK) {
            if (selectedPskIdentity < 0 || selectedPskIdentity > 0xFFFF) {
                throw new IllegalArgumentException("selected PSK identity out of uint16 range");
            }
            TlsEncoding.encodeExtension(
                    ext,
                    TlsConstants.EXT_PRE_SHARED_KEY,
                    new byte[] {(byte) (selectedPskIdentity >>> 8), (byte) selectedPskIdentity});
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
     * включается status_request (RFC 8446 §4.4.2.1). Вызывающий передаёт ответ только
     * если клиент запросил OCSP в ClientHello (RFC 8446 §4.2).
     * <p>
     * Метод принимает сырой OCSPResponse DER; на проводе он кодируется как
     * {@code status_type(1) || uint24(len) || DER} (CertificateStatus, RFC 6066 §8).
     * Отключается staple только значением {@code null}: пустой массив считается ошибкой,
     * чтобы не отправить пиру структуру с недопустимой нулевой длиной.
     *
     * @param ocspResponse raw OCSPResponse DER (null = без OCSP; иначе 1..65527 байт)
     * @return тело Certificate (без handshake-заголовка)
     * @throws IllegalArgumentException если {@code ocspResponse} пуст или длиннее 65527 байт
     */
    public byte[] buildCertificateBody(byte[] ocspResponse) {
        if (ourCertificateChain == null || ourCertificateChain.isEmpty()) {
            throw new IllegalStateException("No certificate available");
        }
        TlsUtils.validateOcspResponse(ocspResponse);
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (int i = 0; i < ourCertificateChain.size(); i++) {
            byte[] certData = ourCertificateChain.get(i).getEncoded();
            TlsEncoding.encodeUint24(list, certData.length);
            list.write(certData, 0, certData.length);
            if (i == 0 && ocspResponse != null) {
                // CertificateStatus: status_type || uint24(len) || OCSPResponse.
                // Длины считаем по уровням: тело расширения -> блок extensions записи.
                int extDataLen = TlsConstants.CERTIFICATE_STATUS_HEADER_SIZE + ocspResponse.length;
                int extensionsLen = 2 + 2 + extDataLen; // type(2) + length(2) + данные
                TlsEncoding.encodeUint16(list, extensionsLen);
                TlsEncoding.encodeUint16(list, TlsConstants.EXT_STATUS_REQUEST);
                TlsEncoding.encodeUint16(list, extDataLen);
                list.write(TlsConstants.STATUS_TYPE_OCSP);
                TlsEncoding.encodeUint24(list, ocspResponse.length);
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
        return new byte[] {0x00, 0x00, 0x00, 0x00};
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
        Digest d = HkdfStreebog.newDigest(sigHashLen);
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
     */
    public static byte[] buildEncryptedExtensions() {
        return buildEncryptedExtensions(null, 0);
    }

    /**
     * Собирает preamble ClientHello: legacy_version, random, legacy_session_id,
     * cipher_suites (из {@link #offeredCipherSuiteIds}), compression_methods.
     * <p>
     * Размер: {@link TlsConstants#CLIENT_HELLO_FIXED_PREAMBLE_LENGTH} + длина session id
     * + 2 × количество cipher suites.
     *
     * @return preamble ClientHello (размер зависит от числа cipher suites)
     */
    private byte[] buildClientHelloPreamble() {
        byte[] random = new byte[TlsConstants.RANDOM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(random);

        int suitesBytes = offeredCipherSuiteIds.size() * 2;
        byte[] out =
                new byte
                        [TlsConstants.CLIENT_HELLO_FIXED_PREAMBLE_LENGTH
                                + sentLegacySessionId.length
                                + suitesBytes];
        int pos = 0;
        out[pos++] = TlsConstants.LEGACY_VERSION_MAJOR;
        out[pos++] = TlsConstants.LEGACY_VERSION_MINOR;
        System.arraycopy(random, 0, out, pos, TlsConstants.RANDOM_LENGTH);
        pos += TlsConstants.RANDOM_LENGTH;
        out[pos++] = (byte) sentLegacySessionId.length;
        System.arraycopy(sentLegacySessionId, 0, out, pos, sentLegacySessionId.length);
        pos += sentLegacySessionId.length;

        // cipher suites: длина(2) + N наборов × 2 байта
        out[pos++] = (byte) (suitesBytes >>> 8);
        out[pos++] = (byte) suitesBytes;
        for (int id : offeredCipherSuiteIds) {
            out[pos++] = (byte) (id >>> 8);
            out[pos++] = (byte) id;
        }

        out[pos++] = 0x01; // длина списка методов сжатия (только null)
        out[pos] = 0x00; // null compression — RFC 8446 §4.1.2: MUST be present, single 0x00
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
    /**
     * Собирает общий набор расширений ClientHello с несколькими key_share entry.
     *
     * @param ext         поток для записи расширений
     * @param keyShares   карта: NamedGroup -> закодированная точка X||Y
     * @param serverName  DNS-имя сервера для SNI (null = без расширения)
     */
    private void buildCommonExtensions(
            ByteArrayOutputStream ext, Map<Integer, byte[]> keyShares, String serverName) {
        // SNI: server_name extension (RFC 6066 §3, RFC 8446 §4.2.1)
        // Последняя линия проверки: публичные TlsMessageBuilder и setServerHostname принимают
        // строку мимо GostDnsName, а недопустимое имя нельзя молча не отправлять (подмена
        // имени через NUL) и нельзя отправлять то, что отвергнет наш же сервер
        ServerNameCheck.requireValidForSni(serverName);
        String normalized = normalizeHostname(serverName);
        // RFC 6066 §3: host_name — DNS-имя, не IP-литерал.
        if (normalized != null && !GostDnsName.isIpAddress(normalized)) {
            ByteArrayOutputStream sniData = new ByteArrayOutputStream();
            byte[] nameBytes = normalized.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            TlsEncoding.encodeUint16(sniData, 3 + nameBytes.length);
            sniData.write(0x00);
            TlsEncoding.encodeUint16(sniData, nameBytes.length);
            sniData.write(nameBytes, 0, nameBytes.length);
            TlsEncoding.encodeExtension(ext, TlsConstants.EXT_SERVER_NAME, sniData.toByteArray());
        }

        ext.write(SV_CLIENT, 0, SV_CLIENT.length);
        if (omitSupportedGroups) {
            // Только тесты: ClientHello без supported_groups
        } else if (supportedGroupsOverride == null) {
            ext.write(SUPPORTED_GROUPS_EXT, 0, SUPPORTED_GROUPS_EXT.length);
        } else {
            writeSupportedGroups(ext, supportedGroupsOverride);
        }
        ext.write(SIG_ALG_EXT, 0, SIG_ALG_EXT.length);

        // Multi key_share: все entry из карты (RFC 8446 §4.2.8: clients MAY send multiple)
        byte[][] entries = new byte[keyShares.size()][];
        int totalEntryLen = 0;
        int idx = 0;
        for (Map.Entry<Integer, byte[]> ksEntry : keyShares.entrySet()) {
            byte[] point = ksEntry.getValue();
            byte[] entry = new byte[4 + point.length];
            int group = ksEntry.getKey();
            entry[0] = (byte) (group >>> 8);
            entry[1] = (byte) group;
            entry[2] = (byte) (point.length >>> 8);
            entry[3] = (byte) point.length;
            System.arraycopy(point, 0, entry, 4, point.length);
            entries[idx++] = entry;
            totalEntryLen += entry.length;
        }
        byte[] ks = new byte[2 + totalEntryLen];
        ks[0] = (byte) (totalEntryLen >>> 8);
        ks[1] = (byte) totalEntryLen;
        int ksPos = 2;
        for (byte[] entry : entries) {
            System.arraycopy(entry, 0, ks, ksPos, entry.length);
            ksPos += entry.length;
        }
        if (!omitKeyShare) {
            TlsEncoding.encodeExtension(ext, TlsConstants.EXT_KEY_SHARE, ks);
        }
        addMaxFragmentLengthExtension(ext);
        ext.write(STATUS_REQUEST_EXT, 0, STATUS_REQUEST_EXT.length);
    }

    private static void writeSupportedGroups(ByteArrayOutputStream ext, int[] groups) {
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (int g : groups) {
            TlsEncoding.encodeUint16(list, g);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(body, list.size());
        body.write(list.toByteArray(), 0, list.size());
        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_SUPPORTED_GROUPS, body.toByteArray());
    }

    /**
     * Подменяет список supported_groups. Только для тестов (шов в пакете; тестовый доступ -
     * {@code TlsMessageBuilderTestAccess}): штатный ClientHello всегда рекламирует все ГОСТ-группы.
     */
    void setSupportedGroups(int[] groups) {
        this.supportedGroupsOverride = groups == null ? null : groups.clone();
    }

    /** Только для тестов: ClientHello без расширения key_share. */
    void setOmitKeyShare(boolean omit) {
        this.omitKeyShare = omit;
    }

    /** Только для тестов: ClientHello без расширения supported_groups. */
    void setOmitSupportedGroups(boolean omit) {
        this.omitSupportedGroups = omit;
    }

    private void addMaxFragmentLengthExtension(ByteArrayOutputStream ext) {
        if (!TlsUtils.isMaxFragmentLengthCode(clientMaxFragLen)) return;
        byte[] body = new byte[] {(byte) clientMaxFragLen};
        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_MAX_FRAGMENT_LENGTH, body);
    }

    private void buildCommonExtensions(
            ByteArrayOutputStream ext, byte[] ecdhePoint, String serverName) {
        buildCommonExtensions(ext, Map.of(selectedNamedGroup, ecdhePoint), serverName);
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
            byte[] name = p.getBytes(StandardCharsets.ISO_8859_1);
            list.write(name.length & 0xFF);
            list.write(name, 0, name.length);
        }
        byte[] listBytes = list.toByteArray();
        ByteArrayOutputStream extData = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(extData, listBytes.length);
        extData.write(listBytes, 0, listBytes.length);
        TlsEncoding.encodeExtension(
                ext,
                TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                extData.toByteArray());
    }

    private static void addCookieExtension(ByteArrayOutputStream ext, byte[] cookie) {
        if (cookie == null) return;
        byte[] payload = new byte[2 + cookie.length];
        payload[0] = (byte) (cookie.length >>> 8);
        payload[1] = (byte) cookie.length;
        System.arraycopy(cookie, 0, payload, 2, cookie.length);
        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_COOKIE, payload);
    }

    /**
     * Собирает HelloRetryRequest (RFC 8446 §4.1.3, §4.2.8).
     * <p>
     * Структура тела идентична ServerHello, но:
     * <ul>
     *   <li>random = HRR_RANDOM: SHA-256("HelloRetryRequest"), RFC 8446 §4.1.3</li>
     *   <li>key_share содержит только NamedGroup (2 байта), без key_exchange</li>
     *   <li>legacy_session_id копируется из ClientHello (RFC 8446 §4.1.3)</li>
     * </ul>
     *
     * @param requestedGroup желаемая именованная группа сервера
     * @param cipherSuiteId  выбранный cipher suite
     * @return тело HelloRetryRequest (без handshake-заголовка)
     */
    public byte[] buildHelloRetryRequest(int requestedGroup, int cipherSuiteId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(TlsConstants.LEGACY_VERSION_MAJOR);
        out.write(TlsConstants.LEGACY_VERSION_MINOR);

        out.write(TlsMessageParser.HRR_RANDOM, 0, TlsMessageParser.HRR_RANDOM.length);

        if (clientSessionId != null) {
            out.write(clientSessionId.length);
            out.write(clientSessionId, 0, clientSessionId.length);
        } else {
            out.write(0x00);
        }

        TlsEncoding.encodeUint16(out, cipherSuiteId);

        out.write(0x00);

        ByteArrayOutputStream ext = new ByteArrayOutputStream();

        ext.write(SV_SERVER, 0, SV_SERVER.length);

        // key_share: только NamedGroup (RFC 8446 §4.2.8).
        // HelloRetryRequest использует сокращённую форму KeyShareEntry
        // без key_exchange вектора — только поле NamedGroup (2 байта).
        // OpenSSL ожидает именно такой формат, без key_len=0.
        byte[] ks = new byte[2];
        ks[0] = (byte) (requestedGroup >>> 8);
        ks[1] = (byte) requestedGroup;
        TlsEncoding.encodeExtension(ext, TlsConstants.EXT_KEY_SHARE, ks);

        TlsEncoding.encodeUint16(out, ext.size());
        out.write(ext.toByteArray(), 0, ext.size());

        return out.toByteArray();
    }

    /**
     * Собирает HelloRetryRequest без key_share extension, с опциональным cookie
     * (RFC 8446 §4.2.8: key_share MAY be omitted in HelloRetryRequest).
     * <p>
     * ПОЧЕМУ без key_share: сервер может не запрашивать смену группы —
     * достаточно прислать cookie для stateless HRR (некоторые реализации ГОСТ TLS 1.3 так и делают).
     *
     * <p>
     * Только для тестов: рабочий код сервера собирает HRR перегрузкой с запрошенной группой, а эта
     * всегда пишет {@code legacy_session_id} нулевой длины и не отражает значение клиента
     * (RFC 8446 §4.1.3), поэтому публичной быть не должна.
     *
     * @param cipherSuiteId выбранный cipher suite
     * @param cookie        cookie для второго ClientHello, или null
     * @return тело HelloRetryRequest (без handshake-заголовка)
     */
    byte[] buildHelloRetryRequest(int cipherSuiteId, byte[] cookie) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TlsConstants.LEGACY_VERSION_MAJOR);
        out.write(TlsConstants.LEGACY_VERSION_MINOR);
        out.write(TlsMessageParser.HRR_RANDOM, 0, TlsMessageParser.HRR_RANDOM.length);
        out.write(0x00); // session_id_len=0
        TlsEncoding.encodeUint16(out, cipherSuiteId);
        out.write(0x00); // compression=null

        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        ext.write(SV_SERVER, 0, SV_SERVER.length);
        addCookieExtension(ext, cookie);

        TlsEncoding.encodeUint16(out, ext.size());
        out.write(ext.toByteArray(), 0, ext.size());
        return out.toByteArray();
    }

    /**
     * Собирает EncryptedExtensions с опциональным ALPN (RFC 7301, RFC 8446 §4.3.1).
     * Делегирует полной перегрузке для избежания дублирования.
     */
    public static byte[] buildEncryptedExtensions(String selectedAlpnProtocol) {
        return buildEncryptedExtensions(selectedAlpnProtocol, 0);
    }

    /**
     * Собирает EncryptedExtensions с опциональным ALPN и max_fragment_length (RFC 6066 §4).
     *
     * @param selectedAlpnProtocol выбранный сервером протокол, или null
     * @param maxFragLen           код max_fragment_length (1..4), или 0
     * @return тело EncryptedExtensions
     */
    public static byte[] buildEncryptedExtensions(String selectedAlpnProtocol, int maxFragLen) {
        boolean hasAlpn = selectedAlpnProtocol != null && !selectedAlpnProtocol.isEmpty();
        boolean hasMaxFrag = TlsUtils.isMaxFragmentLengthCode(maxFragLen);
        if (!hasAlpn && !hasMaxFrag) {
            return new byte[] {0x00, 0x00};
        }
        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        if (hasAlpn) {
            byte[] nameBytes = selectedAlpnProtocol.getBytes(StandardCharsets.ISO_8859_1);
            // RFC 7301 §3.1 требует ProtocolNameList с 2-байтовой длиной
            // (listLength || nameLen || name). Используем encodeUint16, а не
            // ручное кодирование — (byte)(1+255) даёт переполнение.
            ByteArrayOutputStream alpnBody = new ByteArrayOutputStream();
            TlsEncoding.encodeUint16(alpnBody, 1 + nameBytes.length);
            alpnBody.write(nameBytes.length);
            alpnBody.write(nameBytes, 0, nameBytes.length);
            TlsEncoding.encodeExtension(
                    extBody,
                    TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    alpnBody.toByteArray());
        }
        if (hasMaxFrag) {
            byte[] body = new byte[] {(byte) maxFragLen};
            TlsEncoding.encodeExtension(extBody, TlsConstants.EXT_MAX_FRAGMENT_LENGTH, body);
        }
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
     * Приводит к lowercase, удаляет завершающие точки (FQDN -> relative),
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
        return buildCertificateRequest(null, false);
    }

    /**
     * Собирает CertificateRequest с OID-фильтрами (RFC 8446 §4.2.5).
     * <p>
     * Формат: certificate_request_context(0) || extensions.
     * Расширения: signature_algorithms + oid_filters.
     *
     * @param oidFilters список OID-фильтров для выбора сертификата клиента
     * @return тело CertificateRequest
     */
    public static byte[] buildCertificateRequest(List<OIDFilter> oidFilters) {
        return buildCertificateRequest(oidFilters, false);
    }

    /**
     * Собирает CertificateRequest (RFC 8446 §4.3.2) с необязательными oid_filters и запросом
     * OCSP-staple клиентского сертификата.
     * <p>
     * Формат: certificate_request_context(0) || extensions. Расширения:
     * signature_algorithms (всегда), oid_filters (если фильтры заданы),
     * status_request с пустым телом (если {@code requestOcsp}, RFC 8446 §4.4.2.1:
     * сервер просит клиента приложить OCSP-ответ к своему сертификату).
     * <p>
     * OIDFilter wire: { oid_len(1) || oid_bytes || values_len(2) || values_bytes }.
     * OIDFilterExtension: opaque filters<0..2^16-1>.
     *
     * @param oidFilters  список OID-фильтров для выбора сертификата клиента (null/пусто = нет)
     * @param requestOcsp true - добавить пустое расширение status_request
     * @return тело CertificateRequest
     */
    public static byte[] buildCertificateRequest(List<OIDFilter> oidFilters, boolean requestOcsp) {
        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        // signature_algorithms (всегда)
        TlsEncoding.encodeExtension(extBody, TlsConstants.EXT_SIGNATURE_ALGORITHMS, SIG_ALG_BODY);
        if (oidFilters != null && !oidFilters.isEmpty()) {
            ByteArrayOutputStream filterData = new ByteArrayOutputStream();
            for (OIDFilter filter : oidFilters) {
                byte[] oid = filter.extensionOid();
                byte[] values = filter.extensionValues();
                // RFC 8446 §4.2.5: opaque certificate_extension_oid<1..2^8-1>
                filterData.write(oid.length);
                filterData.write(oid, 0, oid.length);
                // opaque certificate_extension_values<0..2^16-1>
                filterData.write((values.length >>> 8) & 0xFF);
                filterData.write(values.length & 0xFF);
                filterData.write(values, 0, values.length);
            }
            byte[] filterBytes = filterData.toByteArray();
            ByteArrayOutputStream oidFilterExtData = new ByteArrayOutputStream();
            // RFC 8446 §4.2.5: OIDFilter filters<0..2^16-1> - двухбайтовая длина списка
            TlsEncoding.encodeUint16(oidFilterExtData, filterBytes.length);
            oidFilterExtData.write(filterBytes, 0, filterBytes.length);
            TlsEncoding.encodeExtension(
                    extBody, TlsConstants.EXT_OID_FILTERS, oidFilterExtData.toByteArray());
        }
        if (requestOcsp) {
            // Тело пустое: RFC 8446 §4.4.2.1 определяет запрос staple как пустое расширение.
            TlsEncoding.encodeExtension(extBody, TlsConstants.EXT_STATUS_REQUEST, new byte[0]);
        }
        // context_byte(1) || extensions_len(2) || extensions
        byte[] extBytes = extBody.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0); // certificate_request_context
        TlsEncoding.encodeUint16(out, extBytes.length);
        out.write(extBytes, 0, extBytes.length);
        return out.toByteArray();
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
    public static byte[] buildFinished(
            TlsKeySchedule keySchedule, byte[] trafficSecret, byte[] transcript) {
        return keySchedule.computeVerifyData(trafficSecret, transcript);
    }

    /**
     * Собирает NewSessionTicket (RFC 8446 §4.6.1).
     * <p>
     * Формат: ticket_lifetime(4) || ticket_age_add(4) ||
     * ticket_nonce_len(1) || ticket_nonce ||
     * ticket_len(2) || ticket || extensions_len(2) || extensions.
     * <p>
     * Расширения не заполняются: early_data не поддерживается.
     *
     * @param ticketLifetime время жизни тикета в секундах (uint32)
     * @param ticketAgeAdd   obfuscated ticket age (uint32)
     * @param ticketNonce    nonce для диверсификации PSK (0..255 байт)
     * @param ticket         opaque ticket (1..65535 байт)
     * @return тело NewSessionTicket
     */
    public static byte[] buildNewSessionTicket(
            long ticketLifetime, long ticketAgeAdd, byte[] ticketNonce, byte[] ticket) {
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
