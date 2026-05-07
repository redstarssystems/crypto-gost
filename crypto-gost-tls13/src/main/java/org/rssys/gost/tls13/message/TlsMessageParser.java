package org.rssys.gost.tls13.message;

import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.nio.charset.StandardCharsets;

/**
 * Парсинг TLS 1.3 handshake-сообщений (RFC 8446, RFC 9367).
 */
public final class TlsMessageParser {

    private TlsMessageParser() {
    }

    @FunctionalInterface
    private interface ExtensionHandler {
        void handle(int extType, byte[] body, int dataOffset, int dataLen) throws TlsException;
    }

    /**
     * Итерирует TLS-расширения в заданном диапазоне: type(2) + dataLen(2) + data.
     * <p>
     * Каждый entry передаётся в handler с телом расширения (без заголовка type+length).
     * На каждом шаге проверяются границы массива — при выходе TlsException.
     *
     * @param body    массив с данными расширений
     * @param start   начальная позиция
     * @param end     конечная позиция (эксклюзивная)
     * @param ctx     контекст ошибки (название сообщения)
     * @param handler обработчик каждого расширения
     * @throws TlsException при выходе за границы массива
     */
    private static void forEachExtension(byte[] body, int start, int end, String ctx,
                                            ExtensionHandler handler) throws TlsException {
        int pos = start;
        while (pos < end) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;
            handler.handle(extType, body, pos, extDataLen);
            pos += extDataLen;
        }
    }

    // ========================================================================
    // Внутренние типы
    // ========================================================================

    /**
     * Результат парсинга ClientHello: ECDHE public key, опциональный server_name
     * и фактическая NamedGroup из key_share entry.
     */
    public static class ParsedKeyShare {
        public final byte[] ecdhePublicKeyRaw;
        public final String serverName;
        public final int actualGroup;
        public final int matchedSigScheme;

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw) {
            this(ecdhePublicKeyRaw, null, TlsConstants.GRP_GC256A, 0);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         * @param serverName        запрошенное DNS-имя (SNI) или null
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw, String serverName) {
            this(ecdhePublicKeyRaw, serverName, TlsConstants.GRP_GC256A, 0);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         * @param serverName        запрошенное DNS-имя (SNI) или null
         * @param actualGroup       NamedGroup из key_share entry клиента
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw, String serverName, int actualGroup) {
            this(ecdhePublicKeyRaw, serverName, actualGroup, 0);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         * @param serverName        запрошенное DNS-имя (SNI) или null
         * @param actualGroup       NamedGroup из key_share entry клиента
         * @param matchedSigScheme  схема подписи, согласованная из signature_algorithms
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw, String serverName, int actualGroup, int matchedSigScheme) {
            this.ecdhePublicKeyRaw = ecdhePublicKeyRaw;
            this.serverName = serverName;
            this.actualGroup = actualGroup;
            this.matchedSigScheme = matchedSigScheme;
        }
    }

    /**
     * Результат парсинга ServerHello: ECDHE key, cipher suite ID
     * и фактическая NamedGroup из key_share entry.
     */
    public static class ParsedServerHello {
        public final byte[] ecdhePublicKeyRaw;
        public final int cipherSuiteId;
        public final int actualGroup;

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key
         * @param cipherSuiteId     ID выбранного cipher suite
         */
        ParsedServerHello(byte[] ecdhePublicKeyRaw, int cipherSuiteId) {
            this(ecdhePublicKeyRaw, cipherSuiteId, TlsConstants.GRP_GC256A);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key
         * @param cipherSuiteId     ID выбранного cipher suite
         * @param actualGroup       NamedGroup из key_share entry сервера
         */
        ParsedServerHello(byte[] ecdhePublicKeyRaw, int cipherSuiteId, int actualGroup) {
            this.ecdhePublicKeyRaw = ecdhePublicKeyRaw;
            this.cipherSuiteId = cipherSuiteId;
            this.actualGroup = actualGroup;
        }
    }

    // ========================================================================
    // Парсинг сообщений
    // ========================================================================

    /**
     * Проверяет границы массива: pos + needed не должен превышать data.length.
     *
     * @param data    массив байт
     * @param pos     текущая позиция
     * @param needed  сколько байт требуется
     * @param context контекст ошибки (название сообщения)
     * @throws TlsException если выход за границы
     */
    static void checkBounds(byte[] data, int pos, int needed, String context) throws TlsException {
        if (needed < 0 || pos < 0 || pos + needed > data.length) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, context + ": truncated message");
        }
    }

    // ========================================================================
    // ALPN (RFC 7301)
    // ========================================================================

    /**
     * Выбирает протокол ALPN: первый протокол из serverPrefs, который также есть в clientOfferings.
     * Возвращает null если пересечения нет — сервер обязан слать ALERT_NO_APPLICATION_PROTOCOL
     * (RFC 7301 §3.2 MUST).
     *
     * @param serverPrefs    предпочтения сервера (порядок убывания приоритета)
     * @param clientOfferings список протоколов от клиента
     * @return выбранный протокол или null при отсутствии пересечения
     */
    public static String selectAlpn(List<String> serverPrefs, List<String> clientOfferings) {
        if (serverPrefs == null || clientOfferings == null) return null;
        for (String s : serverPrefs) {
            for (String c : clientOfferings) {
                if (s.equals(c)) return s;
            }
        }
        return null;
    }

    /**
     * Извлекает список протоколов ALPN из ClientHello (RFC 7301 §3.1).
     * <p>
     * Формат расширения: ProtocolNameList = length(2) || { len(1) || name(N) }*.
     * Возвращает null если расширение отсутствует; пустой список если список протоколов пуст.
     *
     * @param body тело ClientHello
     * @return список протоколов ALPN клиента, или null
     * @throws TlsException при выходе за границы массива
     */
    public static List<String> parseClientHelloAlpn(byte[] body) throws TlsException {
        String ctx = "ClientHello";
        int extEnd = findExtensionsStart(body, false);
        if (extEnd < 0) return null;
        int pos = extEnd;
        while (pos < body.length) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;
            if (extType == TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
                if (extDataLen < 2) return Collections.emptyList();
                int listLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
                if (listLen + 2 != extDataLen) return Collections.emptyList();
                List<String> protocols = new ArrayList<>();
                int ppos = pos + 2;
                int pend = ppos + listLen;
                while (ppos < pend) {
                    checkBounds(body, ppos, 1, ctx);
                    int nameLen = body[ppos] & 0xFF;
                    ppos++;
                    checkBounds(body, ppos, nameLen, ctx);
                    if (nameLen > 0) {
                        protocols.add(new String(body, ppos, nameLen, StandardCharsets.US_ASCII));
                    }
                    ppos += nameLen;
                }
                return protocols.isEmpty() ? Collections.emptyList() : protocols;
            }
            pos += extDataLen;
        }
        return null;
    }

    /**
     * Извлекает выбранный сервером протокол ALPN из EncryptedExtensions (RFC 7301 §3.2).
     * <p>
     * В TLS 1.3 сервер передаёт выбранный протокол в EncryptedExtensions (RFC 8446 §4.2.1),
     * не в ServerHello. Формат: ProtocolName = len(1) || name(N).
     * Возвращает null если ALPN-расширение отсутствует.
     *
     * @param eeBody тело EncryptedExtensions
     * @return выбранный сервером протокол, или null
     * @throws TlsException при нарушении wire-формата (некорректная длина)
     */
    public static String parseEncryptedExtensionsAlpn(byte[] eeBody) throws TlsException {
        if (eeBody.length < 2) return null;
        int extLen = ((eeBody[0] & 0xFF) << 8) | (eeBody[1] & 0xFF);
        if (extLen + 2 != eeBody.length) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "EncryptedExtensions: length mismatch");
        }
        if (extLen == 0) return null;
        String[] resultRef = new String[1];
        forEachExtension(eeBody, 2, 2 + extLen, "EncryptedExtensions", (extType, data, off, len) -> {
            if (extType == TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
                if (len < 1) {
                    throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "ALPN: empty protocol name");
                }
                int nameLen = data[off] & 0xFF;
                if (nameLen < 1 || nameLen > len - 1) {
                    throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "ALPN: invalid name length");
                }
                resultRef[0] = new String(data, off + 1, nameLen, StandardCharsets.US_ASCII);
            }
        });
        return resultRef[0];
    }

    /**
     * Парсит ClientHello и извлекает key_share для указанной группы.
     * Без проверки cipher suite и схемы подписи (упрощённая перегрузка).
     *
     * @param body          тело ClientHello
     * @param expectedGroup ожидаемая NamedGroup для key_share
     * @return ParsedKeyShare с ECDHE-ключом
     * @throws TlsException при нарушении протокола
     */
    public static ParsedKeyShare parseClientHello(byte[] body, int expectedGroup) throws TlsException {
        return parseClientHello(body, expectedGroup, (int[]) null, 0);
    }

    /**
     * Парсит ClientHello с проверкой схемы подписи. Cipher suite не проверяется.
     *
     * @param body            тело ClientHello
     * @param expectedGroup   ожидаемая NamedGroup для key_share
     * @param serverSigScheme ожидаемая схема подписи (0 — не проверять)
     * @return ParsedKeyShare с ECDHE-ключом
     * @throws TlsException при нарушении протокола
     */
    public static ParsedKeyShare parseClientHello(byte[] body, int expectedGroup, int serverSigScheme) throws TlsException {
        return parseClientHello(body, expectedGroup, new int[]{serverSigScheme}, 0);
    }

    /**
     * Парсит ClientHello (RFC 8446 §4.1.2): извлекает key_share, проверяет
     * supported_versions, cipher suite и signature_algorithms при наличии.
     *
     * @param body тело ClientHello
     * @param expectedGroup ожидаемая NamedGroup для key_share
     * @param acceptableSchemes допустимые схемы подписи сервера (null или пустой — не проверять)
     * @param serverCipherSuite ожидаемый cipher suite (0 — не проверять)
     * @return ParsedKeyShare с ECDHE-ключом
     */
    public static ParsedKeyShare parseClientHello(byte[] body, int expectedGroup, int[] acceptableSchemes, int serverCipherSuite) throws TlsException {
        String ctx = "ClientHello";
        checkBounds(body, 0, 2, ctx);
        if ((body[0] & 0xFF) != 0x03 || (body[1] & 0xFF) != 0x03) {
            throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "ClientHello: legacy_version must be 0x0303");
        }

        int pos = 2 + TlsConstants.RANDOM_LENGTH;

        checkBounds(body, pos, 1, ctx);
        int sessionIdLen = body[pos] & 0xFF;
        checkBounds(body, pos, 1 + sessionIdLen, ctx);
        pos += 1 + sessionIdLen;

        checkBounds(body, pos, 2, ctx);
        int csLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, csLen, ctx);
        // Проверяем, что хотя бы одна из предложенных клиентом cipher suite совпадает с серверной
        if (serverCipherSuite != 0) {
            boolean found = false;
            for (int i = 0; i < csLen; i += 2) {
                int s = ((body[pos + 2 + i] & 0xFF) << 8) | (body[pos + 2 + i + 1] & 0xFF);
                if (s == serverCipherSuite) { found = true; break; }
            }
            if (!found) {
                throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                        "ClientHello: cipher suite not offered");
            }
        }
        pos += 2 + csLen;

        checkBounds(body, pos, 1, ctx);
        int compLen = body[pos] & 0xFF;
        checkBounds(body, pos + 1, compLen, ctx);
        if (compLen != 1 || (body[pos + 1] & 0xFF) != 0x00) {
            throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "ClientHello: compression must be single null byte (0x00)");
        }
        pos += 1 + compLen;

        checkBounds(body, pos, 2, ctx);
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, ctx);
        pos += 2;
        int extEnd = pos + extLen;

        byte[] ecdheKey = null;
        int parsedGroup = 0;
        boolean hasSupportedVersions = false;
        boolean hasSignatureAlgorithms = false;
        boolean hasSupportedGroups = false;
        int matchedSigScheme = 0;
        boolean needSigScheme = acceptableSchemes != null && acceptableSchemes.length > 0 && acceptableSchemes[0] != 0;
        String parsedServerName = null;

        while (pos < extEnd) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;

            if (extType == TlsConstants.EXT_KEY_SHARE && ecdheKey == null) {
                if (extDataLen < 2) {
                    throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                            "ClientHello: empty key_share list");
                }
                int listLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
                if (listLen + 2 != extDataLen) {
                    throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                            "ClientHello: key_share list length mismatch");
                }
                int listOff = pos + 2;
                int ksEnd = listOff + listLen;
                int[] actualGroupRef = new int[1];
                byte[] firstEntryKey = null;
                int firstEntryGroup = 0;
                while (listOff < ksEnd) {
                    byte[] entryKey = parseKeyShareEntry(body, listOff, ksEnd - listOff, actualGroupRef);
                    int entryGroup = actualGroupRef[0];
                    int keyLen = ((body[listOff + 2] & 0xFF) << 8) | (body[listOff + 3] & 0xFF);
                    if (firstEntryKey == null) {
                        firstEntryKey = entryKey;
                        firstEntryGroup = entryGroup;
                    }
                    if (entryGroup == expectedGroup) {
                        ecdheKey = entryKey;
                        parsedGroup = entryGroup;
                        break;
                    }
                    listOff += 4 + keyLen;
                }
                if (ecdheKey == null) {
                    ecdheKey = firstEntryKey;
                    parsedGroup = firstEntryGroup;
                }
            } else if (extType == TlsConstants.EXT_SUPPORTED_VERSIONS) {
                hasSupportedVersions = checkSupportedVersions(body, pos, extDataLen);
            } else if (extType == TlsConstants.EXT_SIGNATURE_ALGORITHMS && !hasSignatureAlgorithms) {
                hasSignatureAlgorithms = true;
                if (needSigScheme && matchedSigScheme == 0) {
                    matchedSigScheme = matchSigAlgorithm(body, pos, extDataLen, acceptableSchemes);
                }
            } else if (extType == TlsConstants.EXT_SUPPORTED_GROUPS && !hasSupportedGroups) {
                hasSupportedGroups = true;
            } else if (extType == TlsConstants.EXT_SERVER_NAME && parsedServerName == null) {
                parsedServerName = parseServerNameExtension(body, pos, extDataLen);
            }
            pos += extDataLen;
        }

        if (!hasSupportedVersions) {
            throw new TlsException(TlsConstants.ALERT_MISSING_EXTENSION,
                    "ClientHello: supported_versions extension required");
        }
        if (!hasSignatureAlgorithms) {
            throw new TlsException(TlsConstants.ALERT_MISSING_EXTENSION,
                    "ClientHello: signature_algorithms extension required");
        }
        if (ecdheKey == null) {
            throw new TlsException(TlsConstants.ALERT_MISSING_EXTENSION,
                    "ClientHello: key_share extension required");
        }
        return new ParsedKeyShare(ecdheKey, parsedServerName, parsedGroup, matchedSigScheme);
    }

    /**
     * Ищет первую схему подписи из списка acceptable, которая присутствует
     * в расширении signature_algorithms клиента.
     * <p>
     * Формат: alg_len(2) || algorithms(2*N). Каждая схема — uint16.
     * Если len или alg_len нечётные — wire-формат нарушен, возвращаем 0.
     *
     * @param body       массив с данными расширений
     * @param offset     смещение к телу расширения
     * @param len        длина тела расширения
     * @param acceptable список допустимых схем подписи сервера
     * @return первая общая схема или 0, если не найдена
     */
    private static int matchSigAlgorithm(byte[] body, int offset, int len, int[] acceptable) {
        if (len < 2 || acceptable == null) return 0;
        int algLen = ((body[offset] & 0xFF) << 8) | (body[offset + 1] & 0xFF);
        if (algLen + 2 != len || (algLen & 1) != 0) return 0;
        for (int i = 0; i < algLen; i += 2) {
            int s = ((body[offset + 2 + i] & 0xFF) << 8) | (body[offset + 2 + i + 1] & 0xFF);
            for (int a : acceptable) {
                if (s == a) return s;
            }
        }
        return 0;
    }

    /**
     * Проверяет, что расширение supported_versions содержит TLS 1.3 (0x0304).
     * <p>
     * Формат: version_len(1) || versions(2*N).
     * Пробегаем по списку uint16 — если хотя бы один равен PROTOCOL_TLS_1_3, OK.
     *
     * @param data   массив с данными расширений
     * @param offset смещение к телу расширения
     * @param len    длина тела расширения
     * @return true если TLS 1.3 присутствует
     * @throws TlsException при выходе за границы
     */
    private static boolean checkSupportedVersions(byte[] data, int offset, int len) throws TlsException {
        if (len < 1) return false;
        int versionsLen = data[offset] & 0xFF;
        if (versionsLen + 1 != len || (versionsLen & 1) != 0) return false;
        for (int i = 0; i < versionsLen; i += 2) {
            int v = ((data[offset + 1 + i] & 0xFF) << 8)
                    | (data[offset + 1 + i + 1] & 0xFF);
            if (v == TlsConstants.PROTOCOL_TLS_1_3) return true;
        }
        return false;
    }

    /**
     * Парсит ServerHello (RFC 8446 §4.1.3): извлекает ECDHE-ключ из key_share,
     * идентификатор cipher suite и фактическую NamedGroup.
     *
     * @param body тело ServerHello
     * @param expectedGroup (не используется — сохранён для совместимости)
     * @return ParsedServerHello с ECDHE-ключом, cipher suite и actualGroup
     */
    public static ParsedServerHello parseServerHello(byte[] body, int expectedGroup) throws TlsException {
        String ctx = "ServerHello";
        checkBounds(body, 0, 2 + TlsConstants.RANDOM_LENGTH + 1, ctx);
        int pos = 2 + TlsConstants.RANDOM_LENGTH; // legacy_version + random
        int sessionIdLen = body[pos] & 0xFF;
        checkBounds(body, pos, 1 + sessionIdLen, ctx);
        pos += 1 + sessionIdLen;
        int cipherSuiteId = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2; // cipher suite
        pos += 1; // compression

        checkBounds(body, pos, 2, ctx);
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, ctx);
        pos += 2;
        int extEnd = pos + extLen;

        byte[][] ecdheKeyRef = new byte[1][];
        int[] actualGroupRef = new int[1];

        forEachExtension(body, pos, extEnd, ctx, (extType, data, off, len) -> {
            if (extType == TlsConstants.EXT_KEY_SHARE) {
                ecdheKeyRef[0] = parseKeyShareEntry(data, off, len, actualGroupRef);
            }
        });

        if (ecdheKeyRef[0] == null) {
            throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "No key_share extension in ServerHello");
        }
        return new ParsedServerHello(ecdheKeyRef[0], cipherSuiteId, actualGroupRef[0]);
    }

    /**
     * Извлекает ECDHE-публичный ключ из key_share entry (RFC 8446 §4.2.8).
     * <p>
     * Формат entry: NamedGroup(2) || key_exchange_length(2) || key_exchange(N).
     * Валидации группы нет — caller определяет, подходит ли она.
     *
     * @param data            массив с данными расширений
     * @param offset          смещение к началу entry
     * @param extDataLen      длина данных расширения (для проверки границ)
     * @param actualGroupOut  [1] для получения NamedGroup из entry; null если не нужна
     * @return ECDHE-ключ (raw bytes X || Y, little-endian)
     */
    static byte[] parseKeyShareEntry(byte[] data, int offset, int extDataLen, int[] actualGroupOut)
            throws TlsException {
        if (extDataLen < 4) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "key_share: entry too short (" + extDataLen + " bytes)");
        }
        int group = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (actualGroupOut != null && actualGroupOut.length > 0) {
            actualGroupOut[0] = group;
        }
        int keyLen = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        if (keyLen < 1 || keyLen > extDataLen - 4) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "key_share: invalid key length " + keyLen + " (extDataLen=" + extDataLen + ")");
        }
        byte[] key = new byte[keyLen];
        System.arraycopy(data, offset + 4, key, 0, keyLen);
        return key;
    }

    /**
     * Парсит расширение server_name (RFC 6066 §3, RFC 8446 §4.2.1).
     * Извлекает первый (и единственный) host_name entry из ServerNameList.
     * <p>
     * Формат: ServerNameList::length(2) || ServerName(host_name(1) || name_len(2) || name(N)).
     * Допускается только host_name(0); другие name_type игнорируются.
     * После извлечения имя нормализуется через {@link TlsMessageBuilder#normalizeHostname}.
     *
     * @param data   массив с данными расширений
     * @param offset смещение к телу расширения (без type+length)
     * @param len    длина тела расширения
     * @return нормализованное DNS-имя или null при ошибке парсинга
     */
    static String parseServerNameExtension(byte[] data, int offset, int len) {
        if (len < 3) return null;
        // ServerNameList: длина списка как uint16 (RFC 6066 §3)
        int listLen = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (listLen + 2 != len || listLen < 3) return null;
        // name_type: 0x00 = host_name (RFC 6066 §3: другие типы не обязательны к поддержке)
        if (data[offset + 2] != 0x00) return null;
        int nameLen = ((data[offset + 3] & 0xFF) << 8) | (data[offset + 4] & 0xFF);
        if (3 + nameLen > listLen || nameLen == 0) return null;
        String raw = new String(data, offset + 5, nameLen, java.nio.charset.StandardCharsets.US_ASCII);
        return TlsMessageBuilder.normalizeHostname(raw);
    }

    /**
     * Парсит Certificate message (RFC 8446 §4.4.2).
     * Извлекает цепочку сертификатов с OCSP-стэпплингом.
     *
     * @param certBody тело Certificate handshake-сообщения
     * @return список сертификатов (первый — leaf)
     * @throws TlsException при нарушении протокола
     */
    public static List<TlsCertificate> parseCertificate(byte[] certBody) throws TlsException {
        // Certificate: request_context(0) + certificate_list<0..2^24-1>
        // CertificateEntry: cert_len(3) + cert_der + extensions_len(2) + extensions
        checkBounds(certBody, 0, 4, "Certificate");
        int pos = 1; // пропускаем request context
        int listLen = ((certBody[pos] & 0xFF) << 16)
                | ((certBody[pos + 1] & 0xFF) << 8)
                | (certBody[pos + 2] & 0xFF);
        checkBounds(certBody, pos + 3, listLen, "Certificate");
        pos += 3;
        int listEnd = pos + listLen;
        List<TlsCertificate> chain = new ArrayList<>();
        while (pos < listEnd) {
            checkBounds(certBody, pos, 3, "Certificate");
            int certLen = ((certBody[pos] & 0xFF) << 16)
                    | ((certBody[pos + 1] & 0xFF) << 8)
                    | (certBody[pos + 2] & 0xFF);
            checkBounds(certBody, pos + 3, certLen, "Certificate");
            if (certLen > TlsConstants.MAX_CERT_SIZE) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate too large: " + certLen + " bytes");
            }
            pos += 3;
            byte[] certDer = new byte[certLen];
            System.arraycopy(certBody, pos, certDer, 0, certLen);
            pos += certLen;

            // Парсим extensions CertificateEntry, ищем status_request (OCSP stapling)
            byte[][] ocspRef = new byte[1][];
            checkBounds(certBody, pos, 2, "Certificate");
            int extLen = ((certBody[pos] & 0xFF) << 8) | (certBody[pos + 1] & 0xFF);
            checkBounds(certBody, pos + 2, extLen, "Certificate");
            forEachExtension(certBody, pos + 2, pos + 2 + extLen, "Certificate", (extType, data, off, len) -> {
                if (extType == TlsConstants.EXT_STATUS_REQUEST && ocspRef[0] == null) {
                    // CertificateStatus: status_type(1) || OCSPResponse — strip status_type
                    if (len > 1 && (data[off] & 0xFF) == 0x01) {
                        ocspRef[0] = Arrays.copyOfRange(data, off + 1, off + len);
                    }
                }
            });
            pos = pos + 2 + extLen;

            TlsCertificate cert;
            try {
                cert = new TlsCertificate(certDer);
            } catch (RuntimeException e) {
                throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                        "Failed to parse certificate DER", e);
            }
            if (ocspRef[0] != null) {
                cert.setOcspResponse(ocspRef[0]);
            }
            chain.add(cert);
        }
        if (chain.isEmpty()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "No certificates in Certificate message");
        }
        if (chain.size() > TlsConstants.MAX_CERT_CHAIN_LENGTH) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain exceeds maximum length: " + chain.size());
        }
        return chain;
    }

    /**
     * Парсит CertificateRequest (RFC 8446 §4.3.2).
     * Валидирует, что signature_algorithms extension присутствует
     * и содержит хотя бы одну из поддерживаемых GOST-схем.
     * Извлекает certificate_authorities extension (RFC 8446 §4.2.4),
     * если присутствует.
     *
     * @param body тело CertificateRequest
     * @return список DistinguishedName в DER-кодировке,
     *         пустой список если extension отсутствует
     * @throws TlsException при нарушении протокола
     */
    public static List<byte[]> parseCertificateRequest(byte[] body) throws TlsException {
        String ctx = "CertificateRequest";
        checkBounds(body, 0, 4, ctx);
        int contextLen = body[0] & 0xFF;
        checkBounds(body, 1, contextLen + 2, ctx);
        int pos = 1 + contextLen;
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, ctx);
        pos += 2;
        int extEnd = pos + extLen;
        boolean hasSigAlgs = false;
        List<byte[]> acceptedCaDns = Collections.emptyList();
        while (pos < extEnd) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;
            if (extType == TlsConstants.EXT_SIGNATURE_ALGORITHMS) {
                hasSigAlgs = true;
                if (extDataLen < 2) {
                    throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                            "CertificateRequest: empty signature_algorithms");
                }
                int algLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
                if (algLen + 2 != extDataLen || (algLen & 1) != 0) {
                    throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                            "CertificateRequest: malformed signature_algorithms");
                }
                boolean found = false;
                int[] supported = {
                        TlsConstants.SIG_GOST_TC26_A_256, TlsConstants.SIG_GOST_CRYPTOPRO_A,
                        TlsConstants.SIG_GOST_CRYPTOPRO_B, TlsConstants.SIG_GOST_CRYPTOPRO_C,
                        TlsConstants.SIG_GOST_TC26_512_A, TlsConstants.SIG_GOST_TC26_512_B,
                        TlsConstants.SIG_GOST_TC26_512_C
                };
                for (int i = 0; i < algLen; i += 2) {
                    int scheme = ((body[pos + 2 + i] & 0xFF) << 8) | (body[pos + 2 + i + 1] & 0xFF);
                    for (int s : supported) {
                        if (scheme == s) { found = true; break; }
                    }
                    if (found) break;
                }
                if (!found) {
                    throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                            "CertificateRequest: no supported signature scheme");
                }
            } else if (extType == TlsConstants.EXT_CERTIFICATE_AUTHORITIES) {
                acceptedCaDns = parseCertificateAuthorities(body, pos, extDataLen, ctx);
            }
            pos += extDataLen;
        }
        if (!hasSigAlgs) {
            throw new TlsException(TlsConstants.ALERT_MISSING_EXTENSION,
                    "CertificateRequest: signature_algorithms extension is mandatory");
        }
        return acceptedCaDns;
    }

    /**
     * Парсит certificate_authorities extension (RFC 8446 §4.2.4).
     * Извлекает список DistinguishedName в DER-кодировке.
     * Каждый DN: 2 байта длина + opaque DN bytes.
     */
    private static List<byte[]> parseCertificateAuthorities(
            byte[] body, int pos, int extDataLen, String ctx) throws TlsException {
        checkBounds(body, pos, 2, ctx);
        int vecLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        if (vecLen + 2 != extDataLen) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    ctx + ": malformed certificate_authorities extension length");
        }
        if (vecLen == 0) {
            return Collections.emptyList();
        }
        pos += 2;
        int end = pos + vecLen;
        List<byte[]> dns = new ArrayList<>();
        while (pos < end) {
            checkBounds(body, pos, 2, ctx);
            int dnLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            checkBounds(body, pos + 2, dnLen, ctx);
            if (dnLen < 1) {
                throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                        ctx + ": empty DistinguishedName in certificate_authorities");
            }
            pos += 2;
            byte[] dn = new byte[dnLen];
            System.arraycopy(body, pos, dn, 0, dnLen);
            dns.add(dn);
            pos += dnLen;
        }
        return dns;
    }

    /**
     * Извлекает PSK-идентификатор (ticket) из ClientHello (RFC 8446 §4.2.11).
     * Возвращает null если pre_shared_key расширение отсутствует.
     *
     * @param body тело ClientHello
     * @return PSK-идентификатор или null
     * @throws TlsException при выходе за границы массива
     */
    public static byte[] parseClientHelloPskIdentity(byte[] body) throws TlsException {
        String ctx = "ClientHello";
        int extEnd = findExtensionsStart(body, false);
        if (extEnd < 0) return null;
        int pos = extEnd;
        while (pos < body.length) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;
            if (extType == TlsConstants.EXT_PRE_SHARED_KEY) {
                // identities: identities_len(2) || identity_len(2) || identity(N) || …
                if (extDataLen < 4) return null;
                int identitiesLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
                if (identitiesLen < 4) return null;
                int identityLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
                if (2 + identitiesLen > extDataLen || identityLen < 1) return null;
                return Arrays.copyOfRange(body, pos + 4, pos + 4 + identityLen);
            }
            pos += extDataLen;
        }
        return null;
    }

    /**
     * Проверяет, есть ли в ServerHello pre_shared_key extension (PSK принят).
     *
     * @param body тело ServerHello
     * @return true если PSK принят
     * @throws TlsException при выходе за границы массива
     */
    public static boolean parseServerHelloHasPsk(byte[] body) throws TlsException {
        String ctx = "ServerHello";
        int extEnd = findExtensionsStart(body, true);
        if (extEnd < 0) return false;
        int pos = extEnd;
        while (pos < body.length) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;
            if (extType == TlsConstants.EXT_PRE_SHARED_KEY) {
                return true;
            }
            pos += extDataLen;
        }
        return false;
    }

    /**
     * Пропускает заголовки ClientHello/ServerHello и возвращает позицию
     * начала списка расширений (extensions).
     * <p>
     * ServerHello короче — в нём нет cipher_suites длины и compression_methods длины,
     * только cipher_suite(2 байта) + compression(1 байт).
     *
     * @param body         тело handshake-сообщения
     * @param isServerHello true для ServerHello (нет cipher_suites)
     * @return позиция начала extensions или -1 при ошибке
     */
    private static int findExtensionsStart(byte[] body, boolean isServerHello) throws TlsException {
        String context = isServerHello ? "ServerHello" : "ClientHello";
        checkBounds(body, 0, 2, context);
        // legacy_version: MUST be 0x0303 for TLS 1.3 (или 0x0301/0x0302 для backwards)
        if ((body[0] & 0xFF) != 0x03 || (body[1] & 0xFF) != 0x03) return -1;
        int pos = 2 + TlsConstants.RANDOM_LENGTH;
        // legacy_session_id (RFC 8446 §4.1.2: может быть непустым для совместимости)
        checkBounds(body, pos, 1, context);
        int sessionIdLen = body[pos] & 0xFF;
        checkBounds(body, pos, 1 + sessionIdLen, context);
        pos += 1 + sessionIdLen;
        if (!isServerHello) {
            // ClientHello: cipher_suites имеют 2-байтовую длину + compression_methods с 1-байтовой
            checkBounds(body, pos, 2, context);
            int csLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            checkBounds(body, pos + 2, csLen, context);
            pos += 2 + csLen;
            checkBounds(body, pos, 1, context);
            int compLen = body[pos] & 0xFF;
            checkBounds(body, pos + 1, compLen, context);
            pos += 1 + compLen;
        } else {
            // ServerHello: cipher_suite(2) фиксированный + compression(1) всегда 0x00
            pos += 3;
        }
        checkBounds(body, pos, 2, context);
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, context);
        return pos + 2;
    }

    /**
     * Результат парсинга NewSessionTicket (RFC 8446 §4.6.1).
     */
    public static class ParsedNewSessionTicket {
        public final long ticketLifetime;
        public final long ticketAgeAdd;
        public final byte[] ticketNonce;
        public final byte[] ticket;

        /**
         * @param ticketLifetime время жизни тикета в секундах (uint32)
         * @param ticketAgeAdd   obfuscated ticket age (uint32)
         * @param ticketNonce    nonce для диверсификации PSK
         * @param ticket         opaque ticket
         */
        ParsedNewSessionTicket(long ticketLifetime, long ticketAgeAdd,
                               byte[] ticketNonce, byte[] ticket) {
            this.ticketLifetime = ticketLifetime;
            this.ticketAgeAdd = ticketAgeAdd;
            this.ticketNonce = ticketNonce;
            this.ticket = ticket;
        }
    }

    /**
     * Парсит NewSessionTicket (RFC 8446 §4.6.1).
     * <p>
     * Формат: ticket_lifetime(4) || ticket_age_add(4) ||
     * ticket_nonce_len(1) || ticket_nonce ||
     * ticket_len(2) || ticket || extensions_len(2) || extensions.
     *
     * @param body тело NewSessionTicket
     * @return распарсенный тикет
     * @throws TlsException при выходе за границы массива
     */
    public static ParsedNewSessionTicket parseNewSessionTicket(byte[] body) throws TlsException {
        String ctx = "NewSessionTicket";
        checkBounds(body, 0, 8, ctx);
        long ticketLifetime = ((long) (body[0] & 0xFF) << 24)
                | ((long) (body[1] & 0xFF) << 16)
                | ((long) (body[2] & 0xFF) << 8)
                | (long) (body[3] & 0xFF);
        long ticketAgeAdd = ((long) (body[4] & 0xFF) << 24)
                | ((long) (body[5] & 0xFF) << 16)
                | ((long) (body[6] & 0xFF) << 8)
                | (long) (body[7] & 0xFF);
        int pos = 8;
        checkBounds(body, pos, 1, ctx);
        int nonceLen = body[pos] & 0xFF;
        pos += 1;
        checkBounds(body, pos, nonceLen, ctx);
        byte[] ticketNonce = Arrays.copyOfRange(body, pos, pos + nonceLen);
        pos += nonceLen;
        checkBounds(body, pos, 2, ctx);
        int ticketLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2;
        checkBounds(body, pos, ticketLen, ctx);
        byte[] ticket = Arrays.copyOfRange(body, pos, pos + ticketLen);
        return new ParsedNewSessionTicket(ticketLifetime, ticketAgeAdd, ticketNonce, ticket);
    }

    /**
     * Извлекает payload из TLS-записи в открытом виде (без шифрования).
     * Используется для ClientHello / ServerHello / alert (RFC 8446 §5.1).
     *
     * @param record сырая TLS-запись (заголовок + данные)
     * @return тело записи (без заголовка)
     * @throws TlsException если запись слишком короткая или длина не совпадает
     */
    public static byte[] extractRecordData(byte[] record) throws TlsException {
        if (record == null || record.length < TlsConstants.RECORD_HEADER_SIZE) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "Record too short");
        }
        int len = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);
        if (record.length < TlsConstants.RECORD_HEADER_SIZE + len) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "Record truncated");
        }
        byte[] data = new byte[len];
        System.arraycopy(record, TlsConstants.RECORD_HEADER_SIZE, data, 0, len);
        return data;
    }
}
