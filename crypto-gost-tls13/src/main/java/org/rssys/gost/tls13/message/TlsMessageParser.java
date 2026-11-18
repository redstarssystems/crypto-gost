package org.rssys.gost.tls13.message;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.config.ClientCertificateRequest;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Парсинг TLS 1.3 handshake-сообщений (RFC 8446, RFC 9367).
 */
public final class TlsMessageParser {

    /**
     * Значение random у HelloRetryRequest: SHA-256("HelloRetryRequest") (RFC 8446 §4.1.3).
     * Это публичная константа протокола, не секрет. Массив изменяем, поэтому виден только
     * пакету: его читают разбор ServerHello и сборка HRR, наружу отдаётся лишь предикат
     * {@link #isHelloRetryRequest(ParsedServerHello)}.
     */
    static final byte[] HRR_RANDOM =
            new byte[] {
                (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A,
                        (byte) 0x61, (byte) 0x11,
                (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02, (byte) 0x1E, (byte) 0x65,
                        (byte) 0xB8, (byte) 0x91,
                (byte) 0xC2, (byte) 0xA2, (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB,
                        (byte) 0x8C, (byte) 0x5E,
                (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8,
                        (byte) 0x33, (byte) 0x9C
            };

    private TlsMessageParser() {}

    @FunctionalInterface
    private interface ExtensionHandler {
        void handle(int extType, byte[] body, int dataOffset, int dataLen) throws TlsException;
    }

    /**
     * Итерирует TLS-расширения в заданном диапазоне: type(2) + dataLen(2) + data.
     * <p>
     * Каждый entry передаётся в handler с телом расширения (без заголовка type+length).
     * На каждом шаге проверяются границы диапазона [start, end), а не всего массива:
     * расширение не может «зайти» в соседние поля — при выходе TlsException.
     * <p>
     * RFC 8446 §4.2: в блоке не более одного расширения каждого типа. Иначе разные реализации выберут
     * разное значение (первое или последнее), поэтому повтор любого типа - {@code illegal_parameter}.
     *
     * @param body    массив с данными расширений
     * @param start   начальная позиция
     * @param end     конечная позиция (эксклюзивная)
     * @param ctx     контекст ошибки (название сообщения)
     * @param handler обработчик каждого расширения
     * @throws TlsException при выходе за границы диапазона и при повторе типа расширения
     */
    private static void forEachExtension(
            byte[] body, int start, int end, String ctx, ExtensionHandler handler)
            throws TlsException {
        Set<Integer> seenTypes = new HashSet<>();
        int pos = start;
        while (pos < end) {
            checkBounds(body, pos, 4, end, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, end, ctx);
            if (!seenTypes.add(extType)) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        ctx + ": duplicate extension " + extType);
            }
            pos += 4;
            handler.handle(extType, body, pos, extDataLen);
            pos += extDataLen;
        }
    }

    // ========================================================================
    // Внутренние типы
    // ========================================================================

    /**
     * Запись key_share клиента.
     *
     * @param group NamedGroup записи (может быть неизвестной серверу, например GREASE)
     * @param key   публичный ключ записи (X||Y, little-endian), копия из ClientHello
     */
    public record KeyShareEntry(int group, byte[] key) {}

    /**
     * Результат парсинга ClientHello: ECDHE public key, опциональный server_name
     * и фактическая NamedGroup из key_share entry.
     */
    public static class ParsedKeyShare {
        public final byte[] ecdhePublicKeyRaw;
        public final String serverName;
        public final int actualGroup;
        public final int matchedSigScheme;
        public final int[] supportedGroups;
        public final int clientMaxFragLen;

        /** Присутствует ли расширение key_share в ClientHello (список может быть пустым). */
        public final boolean keySharePresent;

        /**
         * Все записи key_share в порядке следования, включая группы, неизвестные серверу
         * (GREASE). Выбор группы делает движок (RFC 8446 §4.2.8).
         */
        public final List<KeyShareEntry> keyShareEntries;

        /**
         * Присутствовало ли расширение supported_groups. Если нет, {@link #supportedGroups}
         * - лишь группы из key_share, и HRR по ним строить нельзя: поддержка клиента неизвестна.
         */
        public final boolean supportedGroupsDeclared;

        /**
         * Присутствовало ли расширение signature_algorithms. Парсер допускает его отсутствие, если
         * есть pre_shared_key (RFC 8446 §9.2); решение «PSK принят» принимает движок, и при
         * отвергнутом PSK отсутствие расширения для него missing_extension.
         */
        public final boolean signatureAlgorithmsPresent;

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw) {
            this(
                    ecdhePublicKeyRaw,
                    null,
                    TlsConstants.GRP_GC256A,
                    0,
                    new int[] {TlsConstants.GRP_GC256A},
                    0);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         * @param serverName        запрошенное DNS-имя (SNI) или null
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw, String serverName) {
            this(
                    ecdhePublicKeyRaw,
                    serverName,
                    TlsConstants.GRP_GC256A,
                    0,
                    new int[] {TlsConstants.GRP_GC256A},
                    0);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         * @param serverName        запрошенное DNS-имя (SNI) или null
         * @param actualGroup       NamedGroup из key_share entry клиента
         */
        ParsedKeyShare(byte[] ecdhePublicKeyRaw, String serverName, int actualGroup) {
            this(ecdhePublicKeyRaw, serverName, actualGroup, 0, new int[] {actualGroup}, 0);
        }

        /**
         * @param ecdhePublicKeyRaw raw ECDHE public key (X||Y, little-endian)
         * @param serverName        запрошенное DNS-имя (SNI) или null
         * @param actualGroup       NamedGroup из key_share entry клиента
         * @param matchedSigScheme  схема подписи, согласованная из signature_algorithms
         * @param supportedGroups   список NamedGroup из supported_groups клиента
         */
        ParsedKeyShare(
                byte[] ecdhePublicKeyRaw,
                String serverName,
                int actualGroup,
                int matchedSigScheme,
                int[] supportedGroups) {
            this(ecdhePublicKeyRaw, serverName, actualGroup, matchedSigScheme, supportedGroups, 0);
        }

        ParsedKeyShare(
                byte[] ecdhePublicKeyRaw,
                String serverName,
                int actualGroup,
                int matchedSigScheme,
                int[] supportedGroups,
                int clientMaxFragLen) {
            this(
                    ecdhePublicKeyRaw,
                    serverName,
                    actualGroup,
                    matchedSigScheme,
                    supportedGroups,
                    clientMaxFragLen,
                    ecdhePublicKeyRaw != null,
                    ecdhePublicKeyRaw != null
                            ? List.of(new KeyShareEntry(actualGroup, ecdhePublicKeyRaw))
                            : List.of(),
                    true,
                    true);
        }

        ParsedKeyShare(
                byte[] ecdhePublicKeyRaw,
                String serverName,
                int actualGroup,
                int matchedSigScheme,
                int[] supportedGroups,
                int clientMaxFragLen,
                boolean keySharePresent,
                List<KeyShareEntry> keyShareEntries,
                boolean supportedGroupsDeclared,
                boolean signatureAlgorithmsPresent) {
            this.signatureAlgorithmsPresent = signatureAlgorithmsPresent;
            this.ecdhePublicKeyRaw = ecdhePublicKeyRaw;
            this.serverName = serverName;
            this.actualGroup = actualGroup;
            this.matchedSigScheme = matchedSigScheme;
            this.supportedGroups = supportedGroups;
            this.clientMaxFragLen = clientMaxFragLen;
            this.keySharePresent = keySharePresent;
            this.keyShareEntries = keyShareEntries;
            this.supportedGroupsDeclared = supportedGroupsDeclared;
        }
    }

    /**
     * Результат парсинга ServerHello: ECDHE key, cipher suite ID,
     * фактическая NamedGroup, random и группа HRR (requestedGroup).
     * <p>
     * Для HRR key_share содержит только группу без ключа — requestedGroup
     * заполняется, ecdhePublicKeyRaw = пустой массив.
     */
    public static class ParsedServerHello {
        /** Значение {@link #selectedPskIdentity}, когда {@code pre_shared_key} в сообщении нет. */
        public static final int NO_PSK_IDENTITY = -1;

        public final byte[] ecdhePublicKeyRaw;
        public final int cipherSuiteId;
        public final int actualGroup;
        public final byte[] random;

        /** Для HRR: группа, запрошенная сервером (== actualGroup).
         *  Для обычного SH: совпадает с actualGroup. */
        public final int requestedGroup;

        /** Cookie из HRR (RFC 8446 §4.2.2), null если не было. */
        public final byte[] cookie;

        /** {@code legacy_session_id_echo} (RFC 8446 §4.1.3): копия, пустая если эхо нет. */
        public final byte[] legacySessionIdEcho;

        /**
         * {@code selected_identity} из {@code pre_shared_key} (RFC 8446 §4.2.11);
         * {@link #NO_PSK_IDENTITY}, если расширения нет.
         */
        public final int selectedPskIdentity;

        ParsedServerHello(
                byte[] ecdhePublicKeyRaw,
                int cipherSuiteId,
                int actualGroup,
                byte[] random,
                int requestedGroup,
                byte[] cookie,
                byte[] legacySessionIdEcho,
                int selectedPskIdentity) {
            this.ecdhePublicKeyRaw = ecdhePublicKeyRaw;
            this.cipherSuiteId = cipherSuiteId;
            this.actualGroup = actualGroup;
            this.random = random;
            this.requestedGroup = requestedGroup;
            this.cookie = cookie;
            this.legacySessionIdEcho = legacySessionIdEcho;
            this.selectedPskIdentity = selectedPskIdentity;
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
        checkBounds(data, pos, needed, data.length, context);
    }

    /**
     * Проверяет границы внутри контейнера: pos + needed не должен превышать limit.
     * <p>
     * Проверки по всему буферу недостаточно: вложенная запись, вылезшая за границу
     * объявленного контейнера, но оставшаяся внутри сообщения, разбирается как чужие
     * байты соседнего поля (расхождение парсеров, «контрабанда» данных).
     *
     * @param data    массив байт
     * @param pos     текущая позиция
     * @param needed  сколько байт требуется
     * @param limit   конец контейнера (эксклюзивный), не больше data.length
     * @param context контекст ошибки (название сообщения)
     * @throws TlsException если выход за границы контейнера
     */
    static void checkBounds(byte[] data, int pos, int needed, int limit, String context)
            throws TlsException {
        if (needed < 0 || pos < 0 || limit > data.length || (long) pos + needed > limit) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, context + ": truncated message");
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
        int extEnd = findExtensionsStart(body);
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
                        protocols.add(new String(body, ppos, nameLen, StandardCharsets.ISO_8859_1));
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
     * Проверяет, запросил ли клиент OCSP-степплинг через status_request (RFC 6066 §8).
     * <p>
     * Формат: status_type(1) || OCSPStatusRequest { responder_id_list<0..2^16-1>,
     * request_extensions<0..2^16-1> }. Сервер вправе прислать staple только на запрос
     * клиента (RFC 8446 §4.2: ответ на незапрошенное расширение запрещён).
     * Тип, отличный от ocsp, считается «не запрошено»: неизвестные варианты игнорируются
     * по RFC 8446 §4.2. Структура известного типа должна заполнять расширение точно.
     *
     * @param chBody тело ClientHello (без handshake-заголовка)
     * @return true если клиент запросил OCSP-ответ сервера
     * @throws TlsException decode_error при нарушении структуры ClientHello или расширения
     */
    public static boolean clientHelloRequestsOcsp(byte[] chBody) throws TlsException {
        String ctx = "ClientHello";
        int extStart = findExtensionsStart(chBody);
        if (extStart < 0) return false;
        int extEnd =
                extStart + (((chBody[extStart - 2] & 0xFF) << 8) | (chBody[extStart - 1] & 0xFF));
        boolean[] requested = new boolean[1];
        forEachExtension(
                chBody,
                extStart,
                extEnd,
                ctx,
                (extType, data, off, len) -> {
                    if (extType != TlsConstants.EXT_STATUS_REQUEST) return;
                    if (len < 1) {
                        throw new TlsException(
                                TlsConstants.ALERT_DECODE_ERROR, ctx + ": empty status_request");
                    }
                    if ((data[off] & 0xFF) != TlsConstants.STATUS_TYPE_OCSP) return;
                    int end = off + len;
                    int p = off + 1;
                    checkBounds(data, p, 2, end, ctx);
                    int responderIdsLen = ((data[p] & 0xFF) << 8) | (data[p + 1] & 0xFF);
                    p += 2;
                    checkBounds(data, p, responderIdsLen, end, ctx);
                    p += responderIdsLen;
                    checkBounds(data, p, 2, end, ctx);
                    int requestExtLen = ((data[p] & 0xFF) << 8) | (data[p + 1] & 0xFF);
                    p += 2;
                    checkBounds(data, p, requestExtLen, end, ctx);
                    p += requestExtLen;
                    if (p != end) {
                        throw new TlsException(
                                TlsConstants.ALERT_DECODE_ERROR,
                                ctx + ": trailing bytes in status_request");
                    }
                    requested[0] = true;
                });
        return requested[0];
    }

    /**
     * Результат парсинга EncryptedExtensions: ALPN-протокол и max_fragment_length.
     */
    public static class ParsedEncryptedExtensions {
        public final String alpn;
        public final int maxFragLen;

        ParsedEncryptedExtensions(String alpn, int maxFragLen) {
            this.alpn = alpn;
            this.maxFragLen = maxFragLen;
        }
    }

    /**
     * Извлекает типы расширений из собственного ClientHello.
     * <p>
     * Нужен клиенту, чтобы сверять ответные расширения сервера с тем, что реально ушло в сеть
     * (RFC 8446 §4.2: ответ на неотправленное расширение запрещён). Источник правды - итоговые
     * байты, а не конфигурация: пустой список ALPN, например, расширение не порождает.
     *
     * @param clientHelloBody тело собственного ClientHello (после подстановки binder)
     * @return неизменяемое множество типов расширений
     * @throws IllegalStateException если байты не разбираются: это дефект сборщика, а не ошибка
     *                               пира, поэтому alert-кода нет
     */
    public static Set<Integer> extensionTypesOfClientHello(byte[] clientHelloBody) {
        try {
            int pos = findExtensionsStart(clientHelloBody);
            if (pos < 0) {
                throw new IllegalStateException("Own ClientHello has unexpected legacy_version");
            }
            int extensionsLength =
                    ((clientHelloBody[pos - 2] & 0xFF) << 8) | (clientHelloBody[pos - 1] & 0xFF);
            int end = pos + extensionsLength;
            Set<Integer> types = new HashSet<>();
            forEachExtension(
                    clientHelloBody,
                    pos,
                    end,
                    "ClientHello",
                    (extType, data, off, len) -> types.add(extType));
            return Collections.unmodifiableSet(types);
        } catch (TlsException e) {
            throw new IllegalStateException("Own ClientHello is malformed: " + e.getMessage(), e);
        }
    }

    /**
     * Парсит EncryptedExtensions: извлекает ALPN (RFC 7301 §3.2) и
     * max_fragment_length (RFC 6066 §4).
     * <p>
     * Разбор двухфазный, чтобы код alert не зависел ни от порядка расширений, ни от кривизны
     * тела. Сначала проверяется структура (рамки, дубли) и таблица допустимости
     * ({@link TlsExtensionRegistry}): известное расширение не из EncryptedExtensions -
     * {@code illegal_parameter}, расширение без запроса, в том числе неизвестное, -
     * {@code unsupported_extension} (RFC 8446 §4.2). Только после этого читаются значения.
     *
     * @param eeBody              тело EncryptedExtensions
     * @param sentExtensionTypes  типы расширений, отправленных в последнем ClientHello
     * @return распарсенные расширения (поля null/0 если отсутствуют)
     * @throws TlsException при нарушении wire-формата или ответе на неотправленное расширение
     */
    public static ParsedEncryptedExtensions parseEncryptedExtensions(
            byte[] eeBody, Set<Integer> sentExtensionTypes) throws TlsException {
        // RFC 8446 §4.3.1: тело - это Extension extensions<0..2^16-1>, то есть минимум два байта
        if (eeBody.length < 2) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "EncryptedExtensions: truncated length field");
        }
        int extLen = ((eeBody[0] & 0xFF) << 8) | (eeBody[1] & 0xFF);
        if (extLen + 2 != eeBody.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "EncryptedExtensions: length mismatch");
        }
        if (extLen == 0) return new ParsedEncryptedExtensions(null, 0);

        // Фаза 1: структура и факт отправки. Значения тел ещё не читаются
        Set<Integer> present = new HashSet<>();
        forEachExtension(
                eeBody,
                2,
                2 + extLen,
                "EncryptedExtensions",
                (extType, data, off, len) -> present.add(extType));
        TlsExtensionRegistry.checkResponse(
                TlsExtensionRegistry.Message.ENCRYPTED_EXTENSIONS, present, sentExtensionTypes);

        // Фаза 2: значения. Дубли отсечены в фазе 1, поэтому каждый тип встретится не более раза
        String[] alpnRef = new String[1];
        int[] maxFragRef = new int[1];
        forEachExtension(
                eeBody,
                2,
                2 + extLen,
                "EncryptedExtensions",
                (extType, data, off, len) -> {
                    if (extType == TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
                        // RFC 7301 §3.1 - ответ сервера содержит ровно одно имя; ProtocolNameList
                        // предварён 2-байтовой длиной списка. Без её пропуска парсинг обламывается
                        // на серверах, формирующих ALPN корректно по RFC (например, некоторые
                        // реализации ГОСТ TLS 1.3).
                        if (len < 3) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR, "ALPN: extension too short");
                        }
                        int listLen = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
                        if (listLen < 1 || listLen + 2 != len) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR, "ALPN: invalid list length");
                        }
                        int nameLen = data[off + 2] & 0xFF;
                        if (nameLen < 1) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR, "ALPN: invalid name length");
                        }
                        // Хвост после первого имени означал бы несколько протоколов в ответе
                        if (nameLen + 1 != listLen) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR,
                                    "ALPN: server response must contain exactly one protocol name");
                        }
                        alpnRef[0] =
                                new String(data, off + 3, nameLen, StandardCharsets.ISO_8859_1);
                    } else if (extType == TlsConstants.EXT_MAX_FRAGMENT_LENGTH) {
                        if (len != 1) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR,
                                    "EncryptedExtensions: invalid max_fragment_length length");
                        }
                        // RFC 6066 §4: ответ не из допустимых кодов не может совпадать с запросом
                        if (!TlsUtils.isMaxFragmentLengthCode(data[off] & 0xFF)) {
                            throw new TlsException(
                                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                                    "EncryptedExtensions: invalid max_fragment_length value");
                        }
                        maxFragRef[0] = data[off] & 0xFF;
                    } else if (extType == TlsConstants.EXT_SERVER_NAME && len != 0) {
                        // RFC 6066 §3: подтверждение SNI сервером - расширение с пустым телом
                        throw new TlsException(
                                TlsConstants.ALERT_DECODE_ERROR,
                                "EncryptedExtensions: server_name acknowledgement must be empty");
                    }
                });
        return new ParsedEncryptedExtensions(alpnRef[0], maxFragRef[0]);
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
    public static ParsedKeyShare parseClientHello(byte[] body, int expectedGroup)
            throws TlsException {
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
    public static ParsedKeyShare parseClientHello(
            byte[] body, int expectedGroup, int serverSigScheme) throws TlsException {
        return parseClientHello(body, expectedGroup, new int[] {serverSigScheme}, 0);
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
    public static ParsedKeyShare parseClientHello(
            byte[] body, int expectedGroup, int[] acceptableSchemes, int serverCipherSuite)
            throws TlsException {
        String ctx = "ClientHello";
        checkBounds(body, 0, 2, ctx);
        if ((body[0] & 0xFF) != TlsConstants.LEGACY_VERSION_MAJOR
                || (body[1] & 0xFF) != TlsConstants.LEGACY_VERSION_MINOR) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
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
                if (s == serverCipherSuite) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new TlsException(
                        TlsConstants.ALERT_HANDSHAKE_FAILURE,
                        "ClientHello: cipher suite not offered");
            }
        }
        pos += 2 + csLen;

        checkBounds(body, pos, 1, ctx);
        int compLen = body[pos] & 0xFF;
        checkBounds(body, pos + 1, compLen, ctx);
        if (compLen != 1 || (body[pos + 1] & 0xFF) != 0x00) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "ClientHello: compression must be single null byte (0x00)");
        }
        pos += 1 + compLen;

        checkBounds(body, pos, 2, ctx);
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, ctx);
        pos += 2;
        int extEnd = pos + extLen;
        // Расширения замыкают ClientHello: хвост после них принимался бы молча
        if (extEnd != body.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "ClientHello: trailing bytes after extensions");
        }

        byte[] ecdheKey = null;
        int parsedGroup = 0;
        boolean keySharePresent = false;
        List<KeyShareEntry> keyShareEntries = new ArrayList<>();
        boolean hasSupportedVersions = false;
        boolean hasSignatureAlgorithms = false;
        boolean hasPreSharedKey = false;
        boolean hasSupportedGroups = false;
        int matchedSigScheme = 0;
        boolean needSigScheme =
                acceptableSchemes != null
                        && acceptableSchemes.length > 0
                        && acceptableSchemes[0] != 0;
        String parsedServerName = null;
        int[] supportedGroupsList = null;
        int clientMaxFragLen = 0;

        // RFC 8446 §4.2: повтор типа расширения до разбора значений - illegal_parameter
        forEachExtension(body, pos, extEnd, ctx, (extType, data, off, len) -> {});

        while (pos < extEnd) {
            checkBounds(body, pos, 4, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, ctx);
            pos += 4;

            if (extType == TlsConstants.EXT_KEY_SHARE && !keySharePresent) {
                keySharePresent = true;
                if (extDataLen < 2) {
                    throw new TlsException(
                            TlsConstants.ALERT_DECODE_ERROR, "ClientHello: empty key_share list");
                }
                int listLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
                if (listLen + 2 != extDataLen) {
                    throw new TlsException(
                            TlsConstants.ALERT_DECODE_ERROR,
                            "ClientHello: key_share list length mismatch");
                }
                int listOff = pos + 2;
                int ksEnd = listOff + listLen;
                int[] actualGroupRef = new int[1];
                byte[] firstEntryKey = null;
                int firstEntryGroup = 0;
                byte[] expectedEntryKey = null;
                int expectedEntryGroup = 0;
                // Проходим ВСЕ записи без раннего выхода: каждая проверяется (битая запись -
                // decode_error), а число записей нужно движку (после HRR ровно одна, RFC 8446
                // §4.2.8).
                while (listOff < ksEnd) {
                    byte[] entryKey =
                            parseKeyShareEntry(body, listOff, ksEnd - listOff, actualGroupRef);
                    int entryGroup = actualGroupRef[0];
                    int keyLen = ((body[listOff + 2] & 0xFF) << 8) | (body[listOff + 3] & 0xFF);
                    keyShareEntries.add(new KeyShareEntry(entryGroup, entryKey));
                    if (firstEntryKey == null) {
                        firstEntryKey = entryKey;
                        firstEntryGroup = entryGroup;
                    }
                    if (expectedEntryKey == null && entryGroup == expectedGroup) {
                        expectedEntryKey = entryKey;
                        expectedEntryGroup = entryGroup;
                    }
                    listOff += 4 + keyLen;
                }
                // Прежняя семантика полей: запись ожидаемой группы, иначе первая запись
                if (expectedEntryKey != null) {
                    ecdheKey = expectedEntryKey;
                    parsedGroup = expectedEntryGroup;
                } else {
                    ecdheKey = firstEntryKey;
                    parsedGroup = firstEntryGroup;
                }
            } else if (extType == TlsConstants.EXT_SUPPORTED_VERSIONS) {
                requireTls13InClientVersions(body, pos, extDataLen);
                hasSupportedVersions = true;
            } else if (extType == TlsConstants.EXT_SIGNATURE_ALGORITHMS
                    && !hasSignatureAlgorithms) {
                hasSignatureAlgorithms = true;
                // Структура проверяется всегда, а не только когда серверу нужна схема: битое
                // расширение при PSK или без цепочки иначе принималось бы молча
                requireWellFormedSignatureAlgorithms("ClientHello", extDataLen, body, pos);
                if (needSigScheme && matchedSigScheme == 0) {
                    matchedSigScheme = matchSigAlgorithm(body, pos, extDataLen, acceptableSchemes);
                }
            } else if (extType == TlsConstants.EXT_PRE_SHARED_KEY) {
                // Разбор самого PSK идёт отдельно (parseClientPsk); здесь важен только факт
                hasPreSharedKey = true;
            } else if (extType == TlsConstants.EXT_SUPPORTED_GROUPS && !hasSupportedGroups) {
                hasSupportedGroups = true;
                supportedGroupsList = parseSupportedGroupsList(body, pos, extDataLen);
            } else if (extType == TlsConstants.EXT_SERVER_NAME && parsedServerName == null) {
                parsedServerName = parseServerNameExtension(body, pos, extDataLen);
            } else if (extType == TlsConstants.EXT_MAX_FRAGMENT_LENGTH && clientMaxFragLen == 0) {
                if (extDataLen != 1) {
                    throw new TlsException(
                            TlsConstants.ALERT_DECODE_ERROR,
                            "ClientHello: invalid max_fragment_length length");
                }
                // RFC 6066 §4: сервер обязан ответить illegal_parameter на код не из 1..4
                if (!TlsUtils.isMaxFragmentLengthCode(body[pos] & 0xFF)) {
                    throw new TlsException(
                            TlsConstants.ALERT_ILLEGAL_PARAMETER,
                            "ClientHello: invalid max_fragment_length value");
                }
                clientMaxFragLen = body[pos] & 0xFF;
            }
            pos += extDataLen;
        }

        // Клиент без supported_versions предлагает TLS 1.2 или ниже (RFC 8446 §4.2.1), а сервер,
        // умеющий только TLS 1.3, отвечает protocol_version (§6.2). missing_extension здесь не
        // подходит: он относится к расширению, обязательному для предложенной версии (§4.2)
        if (!hasSupportedVersions) {
            throw new TlsException(
                    TlsConstants.ALERT_PROTOCOL_VERSION,
                    "ClientHello: supported_versions absent, TLS 1.3 was not offered");
        }
        // RFC 8446 §9.2: signature_algorithms обязателен в ClientHello без pre_shared_key. С PSK
        // его отсутствие допустимо, если сервер примет PSK: это решает движок, парсер лишь
        // сообщает, было ли расширение (signatureAlgorithmsPresent)
        if (!hasSignatureAlgorithms && !hasPreSharedKey) {
            throw new TlsException(
                    TlsConstants.ALERT_MISSING_EXTENSION,
                    "ClientHello: signature_algorithms extension required");
        }
        // Отсутствие key_share или пустой список парсер не отвергает: для CH1 это
        // missing_extension, для CH2 после HRR - illegal_parameter, решает движок.
        boolean supportedGroupsDeclared = supportedGroupsList != null;
        if (supportedGroupsList == null) {
            // supported_groups нет: берём группы из key_share, HRR по ним не строить
            supportedGroupsList = new int[keyShareEntries.size()];
            for (int i = 0; i < supportedGroupsList.length; i++) {
                supportedGroupsList[i] = keyShareEntries.get(i).group();
            }
        }
        return new ParsedKeyShare(
                ecdheKey,
                parsedServerName,
                parsedGroup,
                matchedSigScheme,
                supportedGroupsList,
                clientMaxFragLen,
                keySharePresent,
                List.copyOf(keyShareEntries),
                supportedGroupsDeclared,
                hasSignatureAlgorithms);
    }

    /** Читает список схем из уже проверенного тела signature_algorithms(_cert). */
    private static int[] readSchemeList(byte[] body, int offset) {
        int listLength = ((body[offset] & 0xFF) << 8) | (body[offset + 1] & 0xFF);
        int[] schemes = new int[listLength / 2];
        for (int i = 0; i < schemes.length; i++) {
            schemes[i] =
                    ((body[offset + 2 + 2 * i] & 0xFF) << 8) | (body[offset + 3 + 2 * i] & 0xFF);
        }
        return schemes;
    }

    /**
     * Проверяет структуру расширения signature_algorithms (RFC 8446 §4.2.3): {@code
     * supported_signature_algorithms<2..2^16-2>}, то есть длина списка чётная, не меньше 2 и ровно
     * заполняет расширение. Нарушение это {@code decode_error}. Расширение одной структуры живёт в
     * ClientHello и CertificateRequest, поэтому имя сообщения передаётся для текста ошибки.
     *
     * @param messageName имя сообщения для текста ошибки
     * @param extDataLen  длина тела расширения
     * @param body        массив с данными расширений
     * @param offset      смещение к телу расширения
     * @throws TlsException при нарушении структуры
     */
    private static void requireWellFormedSignatureAlgorithms(
            String messageName, int extDataLen, byte[] body, int offset) throws TlsException {
        if (extDataLen < 2) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    messageName + ": truncated signature_algorithms");
        }
        int algLen = ((body[offset] & 0xFF) << 8) | (body[offset + 1] & 0xFF);
        if (algLen + 2 != extDataLen || algLen < 2 || (algLen & 1) != 0) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    messageName + ": malformed signature_algorithms list");
        }
    }

    /**
     * Ищет первую схему подписи из списка acceptable, которая присутствует
     * в расширении signature_algorithms клиента.
     * <p>
     * Формат: alg_len(2) || algorithms(2*N). Каждая схема — uint16. Структуру списка уже проверил
     * {@link #requireWellFormedSignatureAlgorithms}; защита от нарушения оставлена на случай
     * вызова в обход.
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
     * Проверяет расширение supported_versions из ClientHello (RFC 8446 §4.2.1).
     * <p>
     * Формат: version_len(1) || versions(2*N), N не меньше одного. Исходы:
     * битый формат — {@code decode_error}; корректный список без TLS 1.3 (0x0304) —
     * {@code protocol_version}: клиент предлагает только прежние версии, а сервер умеет лишь
     * TLS 1.3 (§6.2).
     *
     * @param data   массив с данными расширений
     * @param offset смещение к телу расширения
     * @param len    длина тела расширения
     * @throws TlsException если формат битый или TLS 1.3 в списке нет
     */
    private static void requireTls13InClientVersions(byte[] data, int offset, int len)
            throws TlsException {
        if (len < 1) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "ClientHello: empty supported_versions");
        }
        int versionsLen = data[offset] & 0xFF;
        if (versionsLen + 1 != len || versionsLen == 0 || (versionsLen & 1) != 0) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "ClientHello: malformed supported_versions");
        }
        for (int i = 0; i < versionsLen; i += 2) {
            int v = ((data[offset + 1 + i] & 0xFF) << 8) | (data[offset + 1 + i + 1] & 0xFF);
            if (v == TlsConstants.PROTOCOL_TLS_1_3) return;
        }
        throw new TlsException(
                TlsConstants.ALERT_PROTOCOL_VERSION,
                "ClientHello: supported_versions does not offer TLS 1.3");
    }

    /**
     * Проверяет расширение supported_versions из ServerHello или HelloRetryRequest
     * (RFC 8446 §4.2.1): ровно {@code selected_version} в два байта и значение TLS 1.3.
     * <p>
     * Клиент предлагает только 0x0304, поэтому любое другое значение — версия, которую он не
     * предлагал, и это {@code illegal_parameter}. Та же проверка для HRR и ServerHello делает
     * отдельную проверку неизменности версии между ними лишней.
     *
     * @param ctx    имя сообщения для текста ошибки
     * @param data   массив с данными расширений
     * @param offset смещение к телу расширения
     * @param len    длина тела расширения
     * @throws TlsException при длине не два байта ({@code decode_error}) или иной версии
     *                      ({@code illegal_parameter})
     */
    private static void requireSelectedTls13(String ctx, byte[] data, int offset, int len)
            throws TlsException {
        if (len != 2) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": malformed supported_versions");
        }
        int selected = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (selected != TlsConstants.PROTOCOL_TLS_1_3) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    ctx + ": selected version is not TLS 1.3");
        }
    }

    /**
     * Парсит ServerHello и HelloRetryRequest (RFC 8446 §4.1.3): ECDHE-ключ из key_share,
     * cipher suite, группу, random, cookie, эхо {@code legacy_session_id} и
     * {@code selected_identity} из pre_shared_key.
     * <p>
     * Для HRR key_share entry содержит только группу (key_len=0) —
     * ecdhePublicKeyRaw будет пустым массивом, requestedGroup == actualGroup.
     * <p>
     * Проверки выполняются здесь, в таком порядке:
     * <ol>
     *   <li>структура расширений (рамки, дубли - {@code illegal_parameter});</li>
     *   <li>supported_versions обязан быть: нет расширения - {@code protocol_version}, тело не из
     *       двух байт - {@code decode_error}, версия не TLS 1.3 - {@code illegal_parameter}
     *       (RFC 8446 §4.2.1; {@code legacy_version} при этом игнорируется). Версия идёт раньше
     *       таблицы, иначе сервер TLS 1.2 получил бы не тот alert;</li>
     *   <li>таблица допустимости ({@link TlsExtensionRegistry}): известное расширение не из этого
     *       сообщения - {@code illegal_parameter}, расширение без запроса, в том числе неизвестное,
     *       - {@code unsupported_extension}; исключение - {@code cookie} в HRR;</li>
     *   <li>эхо {@code legacy_session_id} не длиннее 32 байт - иначе {@code illegal_parameter};</li>
     *   <li>{@code legacy_compression_method} равен 0 - иначе {@code illegal_parameter};</li>
     *   <li>значения расширений; форма key_share зависит от сообщения: в HRR ровно два байта
     *       (selected_group), в ServerHello полная запись, иначе {@code decode_error}.</li>
     * </ol>
     * Совпадение эха с идентификатором, отправленным клиентом, парсер не проверяет: у него нет
     * контекста клиента, это делает движок по {@link ParsedServerHello#legacySessionIdEcho}.
     *
     * @param body               тело ServerHello
     * @param sentExtensionTypes типы расширений последнего отправленного ClientHello
     * @return разобранное сообщение: ECDHE-ключ, cipher suite, фактическая группа, random,
     *         requestedGroup, cookie (или null), эхо идентификатора сессии (пустое, если нет) и
     *         {@code selectedPskIdentity} ({@link ParsedServerHello#NO_PSK_IDENTITY}, если
     *         pre_shared_key нет)
     * @throws TlsException при нарушении структуры или значений полей (коды выше)
     */
    public static ParsedServerHello parseServerHello(byte[] body, Set<Integer> sentExtensionTypes)
            throws TlsException {
        String ctx = "ServerHello";
        checkBounds(body, 0, 2 + TlsConstants.RANDOM_LENGTH + 1, ctx);
        byte[] random = new byte[TlsConstants.RANDOM_LENGTH];
        System.arraycopy(body, 2, random, 0, TlsConstants.RANDOM_LENGTH);
        int pos = 2 + TlsConstants.RANDOM_LENGTH; // legacy_version + random
        int sessionIdLen = body[pos] & 0xFF;
        checkBounds(body, pos, 1 + sessionIdLen, ctx);
        byte[] legacySessionIdEcho = Arrays.copyOfRange(body, pos + 1, pos + 1 + sessionIdLen);
        pos += 1 + sessionIdLen;
        checkBounds(body, pos, 3, ctx);
        int cipherSuiteId = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2; // cipher suite
        // Значение проверяется после расширений: версия раньше остального (RFC 8446 §4.2.1)
        int legacyCompression = body[pos] & 0xFF;
        pos += 1;

        checkBounds(body, pos, 2, ctx);
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, ctx);
        pos += 2;
        int extEnd = pos + extLen;
        boolean retryRequest = isHelloRetryRequest(random);

        // Проход 1: структура (рамки, дубли) и supported_versions. Тела остальных расширений
        // пока не читаются, поэтому код alert не зависит от их порядка и кривизны
        Set<Integer> presentTypes = new HashSet<>();
        int[] versionBody = {-1, 0};
        forEachExtension(
                body,
                pos,
                extEnd,
                ctx,
                (extType, data, off, len) -> {
                    presentTypes.add(extType);
                    if (extType == TlsConstants.EXT_SUPPORTED_VERSIONS) {
                        versionBody[0] = off;
                        versionBody[1] = len;
                    }
                });

        // Версия раньше остального: нет supported_versions - ответил сервер TLS 1.2 или ниже, а
        // клиент предлагал только TLS 1.3 (RFC 8446 §4.2.1). Иначе такой сервер с расширениями,
        // которых клиент не отправлял, получил бы unsupported_extension вместо protocol_version
        if (versionBody[0] < 0) {
            throw new TlsException(
                    TlsConstants.ALERT_PROTOCOL_VERSION,
                    ctx + ": supported_versions absent, server did not select TLS 1.3");
        }
        requireSelectedTls13(ctx, body, versionBody[0], versionBody[1]);

        // Таблица допустимости (RFC 8446 §4.2): cookie допустим только в HRR, pre_shared_key только
        // в ServerHello, а расширение, которого клиент не отправлял, - unsupported_extension
        TlsExtensionRegistry.checkResponse(
                retryRequest
                        ? TlsExtensionRegistry.Message.HELLO_RETRY_REQUEST
                        : TlsExtensionRegistry.Message.SERVER_HELLO,
                presentTypes,
                sentExtensionTypes);

        // Значения legacy-полей не зависят от того, что отправил клиент: сжатие обязано быть
        // нулевым (RFC 8446 §4.1.3), эхо идентификатора не длиннее 32 байт. Совпадение эха с
        // отправленным значением проверяет движок: у парсера нет контекста клиента
        if (sessionIdLen > TlsConstants.SESSION_ID_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    ctx + ": legacy_session_id_echo too long (" + sessionIdLen + ")");
        }
        if (legacyCompression != 0) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    ctx + ": legacy_compression_method must be 0");
        }

        // Проход 2: значения
        byte[][] ecdheKeyRef = new byte[1][];
        int[] actualGroupRef = new int[1];
        byte[][] cookieRef = new byte[1][];
        int[] selectedPskRef = {ParsedServerHello.NO_PSK_IDENTITY};
        forEachExtension(
                body,
                pos,
                extEnd,
                ctx,
                (extType, data, off, len) -> {
                    if (extType == TlsConstants.EXT_PRE_SHARED_KEY) {
                        if (len != 2) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR,
                                    ctx + ": malformed pre_shared_key selected_identity");
                        }
                        selectedPskRef[0] = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
                    }
                    if (extType == TlsConstants.EXT_KEY_SHARE) {
                        if (retryRequest) {
                            // HRR (RFC 8446 §4.2.8): key_share - только selected_group (2 байта),
                            // без key_exchange. Полная запись KeyShareEntry - другая структура
                            if (len != 2) {
                                throw new TlsException(
                                        TlsConstants.ALERT_DECODE_ERROR,
                                        "HRR: key_share must contain only selected_group");
                            }
                            actualGroupRef[0] = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
                            ecdheKeyRef[0] = new byte[0];
                        } else {
                            // ServerHello: полная запись; двухбайтовая форма HRR даёт decode_error
                            // в parseKeyShareEntry (запись короче 4 байт)
                            ecdheKeyRef[0] = parseKeyShareEntry(data, off, len, actualGroupRef);
                        }
                    }
                    if (extType == TlsConstants.EXT_COOKIE) {
                        // opaque cookie<1..2^16-1> (RFC 8446 §4.2.2)
                        if (len < 3) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR,
                                    "HRR: cookie extension too short (" + len + ")");
                        }
                        int cookieLen = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
                        // Тело расширения - ровно cookie<1..2^16-1>: лишние байты после cookie
                        // нарушают структуру (RFC 8446 §4.2.2)
                        if (cookieLen < 1 || cookieLen != len - 2) {
                            throw new TlsException(
                                    TlsConstants.ALERT_DECODE_ERROR,
                                    "HRR: cookie invalid length " + cookieLen);
                        }
                        cookieRef[0] = Arrays.copyOfRange(data, off + 2, off + 2 + cookieLen);
                    }
                });
        if (ecdheKeyRef[0] == null) {
            // RFC 8446 §4.2.8 разрешает опускать key_share в HRR.
            //      Клиент продолжает с той же группой, что и в CH1.
            //      actualGroupRef[0] остаётся 0 — handleHelloRetryRequest
            //      подставит selectedNamedGroup.
            ecdheKeyRef[0] = new byte[0];
        }
        int requestedGroup = actualGroupRef[0];
        return new ParsedServerHello(
                ecdheKeyRef[0],
                cipherSuiteId,
                actualGroupRef[0],
                random,
                requestedGroup,
                cookieRef[0],
                legacySessionIdEcho,
                selectedPskRef[0]);
    }

    /**
     * Проверяет, является ли ServerHello сообщением HelloRetryRequest (RFC 8446 §4.1.3).
     * <p>
     * HRR отличается от обычного ServerHello только значением random —
     * {@code HRR_RANDOM} (SHA-256 от строки «HelloRetryRequest»).
     *
     * @param sh распарсенный ServerHello
     * @return true если это HRR
     */
    public static boolean isHelloRetryRequest(ParsedServerHello sh) {
        return isHelloRetryRequest(sh.random);
    }

    /** Сравнение по значению random: единственное место сравнения с {@link #HRR_RANDOM}. */
    private static boolean isHelloRetryRequest(byte[] random) {
        return Arrays.equals(random, HRR_RANDOM);
    }

    /**
     * Извлекает ECDHE-публичный ключ из key_share entry (RFC 8446 §4.2.8).
     * <p>
     * Формат entry: NamedGroup(2) || key_exchange_length(2) || key_exchange(N).
     * Для HRR key_exchange_length = 0 — возвращает пустой массив.
     * Валидации группы нет — caller определяет, подходит ли она.
     *
     * @param data            массив с данными расширений
     * @param offset          смещение к началу entry
     * @param extDataLen      длина данных расширения (для проверки границ)
     * @param actualGroupOut  [1] для получения NamedGroup из entry; null если не нужна
     * @return ECDHE-ключ (raw bytes X || Y, little-endian), пустой массив для HRR
     */
    static byte[] parseKeyShareEntry(byte[] data, int offset, int extDataLen, int[] actualGroupOut)
            throws TlsException {
        if (extDataLen < 4) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "key_share: entry too short (" + extDataLen + " bytes)");
        }
        int group = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (actualGroupOut != null && actualGroupOut.length > 0) {
            actualGroupOut[0] = group;
        }
        int keyLen = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        if (keyLen < 0 || keyLen > extDataLen - 4) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "key_share: invalid key length " + keyLen + " (extDataLen=" + extDataLen + ")");
        }
        byte[] key = new byte[keyLen];
        if (keyLen > 0) {
            System.arraycopy(data, offset + 4, key, 0, keyLen);
        }
        return key;
    }

    /**
     * Извлекает server_name из ClientHello (RFC 6066 §3, RFC 8446 §4.2.1).
     * Легковесный метод — итерирует только расширения, не делает полный
     * парсинг ClientHello. Используется для SNI certificate selection.
     *
     * Тело ещё не проверено полностью, поэтому любая ошибка границ и формата расширения даёт
     * исключение с alert (а не {@code null} и не исключение Java): имя нельзя отдавать в
     * PSK-привязку и в выбор сертификата, пока его разбор не завершился успешно. Неверный
     * {@code legacy_version} по-прежнему даёт {@code null}: ответ на него даёт полный разбор.
     *
     * @param chBody тело ClientHello (без handshake-заголовка)
     * @return нормализованное DNS-имя или null, если расширения нет
     * @throws TlsException {@code decode_error} при битой структуре, {@code unrecognized_name}
     *                      при недопустимом имени
     */
    public static String parseClientHelloSni(byte[] chBody) throws TlsException {
        String ctx = "ClientHello";
        checkBounds(chBody, 0, 2, ctx);
        if ((chBody[0] & 0xFF) != TlsConstants.LEGACY_VERSION_MAJOR
                || (chBody[1] & 0xFF) != TlsConstants.LEGACY_VERSION_MINOR) return null;
        int pos = 2 + TlsConstants.RANDOM_LENGTH;
        checkBounds(chBody, pos, 1, ctx);
        int sessionIdLen = chBody[pos] & 0xFF;
        checkBounds(chBody, pos, 1 + sessionIdLen, ctx);
        pos += 1 + sessionIdLen;
        checkBounds(chBody, pos, 2, ctx);
        int csLen = ((chBody[pos] & 0xFF) << 8) | (chBody[pos + 1] & 0xFF);
        checkBounds(chBody, pos + 2, csLen, ctx);
        pos += 2 + csLen;
        checkBounds(chBody, pos, 1, ctx);
        int compLen = chBody[pos] & 0xFF;
        checkBounds(chBody, pos + 1, compLen, ctx);
        pos += 1 + compLen;
        checkBounds(chBody, pos, 2, ctx);
        int extLen = ((chBody[pos] & 0xFF) << 8) | (chBody[pos + 1] & 0xFF);
        checkBounds(chBody, pos + 2, extLen, ctx);
        int extStart = pos + 2;
        int extEnd = extStart + extLen;
        int p = extStart;
        while (p < extEnd) {
            checkBounds(chBody, p, 4, ctx);
            int extType = ((chBody[p] & 0xFF) << 8) | (chBody[p + 1] & 0xFF);
            int extDataLen = ((chBody[p + 2] & 0xFF) << 8) | (chBody[p + 3] & 0xFF);
            checkBounds(chBody, p + 4, extDataLen, ctx);
            p += 4;
            if (extType == TlsConstants.EXT_SERVER_NAME) {
                return parseServerNameExtension(chBody, p, extDataLen);
            }
            p += extDataLen;
        }
        return null;
    }

    /**
     * Парсит расширение server_name (RFC 6066 §3, RFC 8446 §4.2.1).
     * <p>
     * Формат: ServerNameList::length(2) || ServerName(host_name(1) || name_len(2) || name(N)).
     * Допускается ровно одна запись host_name и ничего после неё: RFC 6066 §3 требует от будущих
     * типов лишь 16-битного поля длины, и разборщик не может достоверно знать, следует ли
     * неизвестное значение этому правилу, а ошибка в длине разведёт нас с другими реализациями.
     * Поэтому запись неизвестного типа, как и хвост, отвергается целиком (строже OpenSSL:
     * неразобранная структура не принимается). Структурные нарушения дают {@code decode_error}, недопустимое имя
     * ({@link ServerNameCheck}) — {@code unrecognized_name}. После проверки имя нормализуется
     * через {@link TlsMessageBuilder#normalizeHostname}.
     *
     * @param data   массив с данными расширений
     * @param offset смещение к телу расширения (без type+length)
     * @param len    длина тела расширения
     * @return нормализованное DNS-имя
     * @throws TlsException при битой структуре или недопустимом имени
     */
    static String parseServerNameExtension(byte[] data, int offset, int len) throws TlsException {
        String ctx = "ClientHello";
        if (len < 2) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": truncated server_name extension");
        }
        // ServerNameList: длина списка как uint16 (RFC 6066 §3)
        int listLen = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (listLen + 2 != len) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": server_name list length mismatch");
        }
        // Запись host_name короче name_type(1) + name_len(2) + одного байта имени невозможна
        if (listLen < TlsConstants.SERVER_NAME_ENTRY_MIN_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": empty or truncated server_name list");
        }
        // name_type: 0x00 = host_name; структура других типов не определена (см. javadoc)
        if (data[offset + 2] != 0x00) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": unsupported server_name name_type");
        }
        int nameLen = ((data[offset + 3] & 0xFF) << 8) | (data[offset + 4] & 0xFF);
        if (nameLen == 0) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": empty server_name host_name");
        }
        // Ровно одна запись: и хвост после имени, и имя длиннее списка нарушают структуру
        if (TlsConstants.SERVER_NAME_ENTRY_HEADER_LENGTH + nameLen != listLen) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    ctx + ": server_name entry length mismatch or trailing data");
        }
        ServerNameCheck.Violation violation = ServerNameCheck.check(data, offset + 5, nameLen);
        if (violation != null) {
            throw new TlsException(
                    TlsConstants.ALERT_UNRECOGNIZED_NAME,
                    ctx + ": invalid server_name: " + violation.description());
        }
        String raw =
                new String(data, offset + 5, nameLen, java.nio.charset.StandardCharsets.US_ASCII);
        String normalized = TlsMessageBuilder.normalizeHostname(raw);
        if (normalized == null) {
            // Недостижимо после check(): имя непустое, ASCII и без пустых меток
            throw new TlsException(
                    TlsConstants.ALERT_UNRECOGNIZED_NAME, ctx + ": invalid server_name");
        }
        return normalized;
    }

    /**
     * Извлекает список NamedGroup из supported_groups (RFC 8446 §4.2.7).
     * <p>
     * Формат: NamedGroupList groups<2..2^16-1> — каждая группа как uint16.
     */
    private static int[] parseSupportedGroupsList(byte[] data, int offset, int len) {
        if (len < 2) return new int[0];
        int listLen = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (listLen + 2 != len || listLen < 2 || (listLen & 1) != 0) {
            return new int[0];
        }
        int count = listLen / 2;
        int[] groups = new int[count];
        for (int i = 0; i < count; i++) {
            groups[i] =
                    ((data[offset + 2 + i * 2] & 0xFF) << 8)
                            | (data[offset + 2 + i * 2 + 1] & 0xFF);
        }
        return groups;
    }

    /**
     * Парсит Certificate (RFC 8446 §4.4.2): извлекает цепочку сертификатов с OCSP-стэплингом и
     * проверяет расширения CertificateEntry.
     * <p>
     * Расширения CertificateEntry - ответ на запрос принимающей стороны, поэтому проверяются по
     * таблице {@link TlsExtensionRegistry}: известное расширение не из Certificate -
     * {@code illegal_parameter}; допустимое, но не запрошенное, и неизвестное -
     * {@code unsupported_extension}. Так пир не может навязать обработку ответа, который
     * не запрашивали.
     *
     * @param certBody                 тело Certificate handshake-сообщения
     * @param requestedEntryExtensions типы расширений, запрошенных у отправителя Certificate: для
     *                                 сертификата сервера - из нашего ClientHello, для
     *                                 сертификата клиента - из нашего CertificateRequest
     * @return список сертификатов (первый — leaf)
     * @throws TlsException при нарушении протокола
     */
    public static List<GostCertificate> parseCertificate(
            byte[] certBody, Set<Integer> requestedEntryExtensions) throws TlsException {
        // Certificate: certificate_request_context<0..2^8-1> + certificate_list<0..2^24-1>
        // CertificateEntry: cert_len(3) + cert_der + extensions_len(2) + extensions
        checkBounds(certBody, 0, 4, "Certificate");
        // RFC 8446 §4.4.2: в handshake контекст всегда пуст (серверная аутентификация —
        // SHALL be zero length; наш CertificateRequest шлёт пустой). Непустой контекст
        // сдвинул бы разбор длины списка на данные контекста.
        if (certBody[0] != 0) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "Certificate: non-empty certificate_request_context");
        }
        int pos = 1;
        int listLen =
                ((certBody[pos] & 0xFF) << 16)
                        | ((certBody[pos + 1] & 0xFF) << 8)
                        | (certBody[pos + 2] & 0xFF);
        checkBounds(certBody, pos + 3, listLen, "Certificate");
        pos += 3;
        int listEnd = pos + listLen;
        // Хвост за certificate_list не принадлежит ни одному полю сообщения.
        if (listEnd != certBody.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Certificate: trailing bytes after list");
        }
        List<GostCertificate> chain = new ArrayList<>();
        while (pos < listEnd) {
            // Ранний выход: не парсим больше MAX_CERT_CHAIN_LENGTH сертификатов —
            // защита от CPU DoS (каждый GostCertificate выполняет полный DER-парсинг).
            if (chain.size() >= TlsConstants.MAX_CERT_CHAIN_LENGTH) {
                throw new TlsException(
                        TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain exceeds maximum length");
            }
            // Границы записи — по listEnd: запись не должна пересекать конец списка.
            checkBounds(certBody, pos, 3, listEnd, "Certificate");
            int certLen =
                    ((certBody[pos] & 0xFF) << 16)
                            | ((certBody[pos + 1] & 0xFF) << 8)
                            | (certBody[pos + 2] & 0xFF);
            checkBounds(certBody, pos + 3, certLen, listEnd, "Certificate");
            if (certLen > TlsConstants.MAX_CERT_SIZE) {
                throw new TlsException(
                        TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate too large: " + certLen + " bytes");
            }
            pos += 3;
            byte[] certDer = new byte[certLen];
            System.arraycopy(certBody, pos, certDer, 0, certLen);
            pos += certLen;

            // Парсим extensions CertificateEntry, ищем status_request (OCSP stapling)
            byte[][] ocspRef = new byte[1][];
            checkBounds(certBody, pos, 2, listEnd, "Certificate");
            int extLen = ((certBody[pos] & 0xFF) << 8) | (certBody[pos + 1] & 0xFF);
            checkBounds(certBody, pos + 2, extLen, listEnd, "Certificate");
            // У большинства записей цепочки extLen == 0: набор для контроля дублей и разбор
            // расширений нужны только при непустом блоке, поэтому не выделяем их на каждую запись.
            if (extLen > 0) {
                // Сначала структура и таблица, потом значения: код alert не зависит от того,
                // насколько кривое тело у расширения
                Set<Integer> presentTypes = new HashSet<>();
                forEachExtension(
                        certBody,
                        pos + 2,
                        pos + 2 + extLen,
                        "Certificate",
                        (extType, data, off, len) -> presentTypes.add(extType));
                TlsExtensionRegistry.checkResponse(
                        TlsExtensionRegistry.Message.CERTIFICATE,
                        presentTypes,
                        requestedEntryExtensions);
                forEachExtension(
                        certBody,
                        pos + 2,
                        pos + 2 + extLen,
                        "Certificate",
                        (extType, data, off, len) -> {
                            if (extType == TlsConstants.EXT_STATUS_REQUEST) {
                                ocspRef[0] = parseCertificateStatus(data, off, len);
                            }
                        });
            }
            pos = pos + 2 + extLen;

            GostCertificate cert;
            try {
                cert = new GostCertificate(certDer);
            } catch (RuntimeException e) {
                throw new TlsException(
                        TlsConstants.ALERT_DECODE_ERROR,
                        "Failed to parse certificate DER: " + e.getMessage(),
                        e);
            }
            if (ocspRef[0] != null) {
                cert.setOcspResponse(ocspRef[0]);
            }
            chain.add(cert);
        }
        // Почему нет проверки chain.isEmpty(): RFC 8446 §4.4.2 разрешает клиенту
        // прислать пустой certificate_list. Решение об обязательности сертификата
        // принимает engine (receiveClientCertificate), не общий парсер.
        if (chain.size() > TlsConstants.MAX_CERT_CHAIN_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain exceeds maximum length: " + chain.size());
        }
        return chain;
    }

    /**
     * Разбирает тело {@code status_request} в CertificateEntry (CertificateStatus, RFC 6066 §8):
     * {@code status_type(1) || uint24(len) || OCSPResponse}.
     * <p>
     * Структура строго замкнута: длина ответа обязана точно заполнять остаток расширения,
     * ответ непуст. Формат старых версий без uint24-длины отвергается намеренно: угадывание
     * «с длиной / без» дало бы расхождение разборщиков у разных пиров.
     *
     * @return сырой OCSPResponse DER или {@code null}, если {@code status_type} неизвестен
     *         (RFC 8446 §4.2: неизвестное игнорируется)
     * @throws TlsException decode_error при нарушении структуры известного типа
     */
    private static byte[] parseCertificateStatus(byte[] data, int off, int len)
            throws TlsException {
        if (len < 1) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "CertificateStatus: empty status_request");
        }
        if ((data[off] & 0xFF) != TlsConstants.STATUS_TYPE_OCSP) {
            return null;
        }
        if (len < TlsConstants.CERTIFICATE_STATUS_HEADER_SIZE) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "CertificateStatus: truncated length field");
        }
        int ocspLen =
                ((data[off + 1] & 0xFF) << 16)
                        | ((data[off + 2] & 0xFF) << 8)
                        | (data[off + 3] & 0xFF);
        if (ocspLen == 0 || ocspLen != len - TlsConstants.CERTIFICATE_STATUS_HEADER_SIZE) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "CertificateStatus: OCSP response length does not match extension");
        }
        int ocspStart = off + TlsConstants.CERTIFICATE_STATUS_HEADER_SIZE;
        return Arrays.copyOfRange(data, ocspStart, ocspStart + ocspLen);
    }

    /**
     * Парсит CertificateRequest (RFC 8446 §4.3.2).
     * Валидирует, что signature_algorithms extension присутствует и корректен по структуре
     * (RFC 8446 §4.2.3, нарушение это decode_error). Отсутствие в списке наших схем не ошибка
     * разбора: клиент отправит пустой Certificate (RFC 8446 §4.4.2.3), решает движок.
     * Извлекает certificate_authorities (RFC 8446 §4.2.4) и
     * oid_filters (RFC 8446 §4.2.5) расширения, если присутствуют.
     *
     * @param body тело CertificateRequest
     * @return результат парсинга (CA DNs, OID-фильтры, запрос staple, схемы подписи)
     * @throws TlsException при нарушении протокола
     */
    public static ClientCertificateRequest parseCertificateRequest(byte[] body)
            throws TlsException {
        String ctx = "CertificateRequest";
        checkBounds(body, 0, 4, ctx);
        // RFC 8446 §4.3.2: в основном handshake контекст пуст; непустой допустим только
        // для post-handshake аутентификации, которую библиотека не поддерживает.
        if (body[0] != 0) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "CertificateRequest: non-empty certificate_request_context");
        }
        int pos = 1;
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, extLen, ctx);
        pos += 2;
        int extEnd = pos + extLen;
        if (extEnd != body.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "CertificateRequest: trailing bytes after extensions");
        }
        // RFC 8446 §4.2: повтор типа расширения - illegal_parameter. Без проверки второй список
        // схем
        // молча заменил бы первый, и решение «пустой или непустой Certificate» зависело бы от
        // порядка
        Set<Integer> presentTypes = new HashSet<>();
        forEachExtension(
                body, pos, extEnd, ctx, (extType, data, off, len) -> presentTypes.add(extType));
        // Известное расширение не из CertificateRequest - illegal_parameter, неизвестное
        // игнорируется: сервер вправе расширять собственные запросы (RFC 8446 §4.2)
        TlsExtensionRegistry.checkRequest(
                TlsExtensionRegistry.Message.CERTIFICATE_REQUEST, presentTypes);
        boolean hasSigAlgs = false;
        int[] signatureSchemes = new int[0];
        int[] certificateSchemes = null;
        List<byte[]> acceptedCaDns = Collections.emptyList();
        List<OIDFilter> oidFilters = Collections.emptyList();
        boolean ocspRequested = false;
        while (pos < extEnd) {
            checkBounds(body, pos, 4, extEnd, ctx);
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            checkBounds(body, pos + 4, extDataLen, extEnd, ctx);
            pos += 4;
            if (extType == TlsConstants.EXT_SIGNATURE_ALGORITHMS) {
                hasSigAlgs = true;
                requireWellFormedSignatureAlgorithms(ctx, extDataLen, body, pos);
                signatureSchemes = readSchemeList(body, pos);
            } else if (extType == TlsConstants.EXT_SIGNATURE_ALGORITHMS_CERT) {
                requireWellFormedSignatureAlgorithms(ctx, extDataLen, body, pos);
                certificateSchemes = readSchemeList(body, pos);
            } else if (extType == TlsConstants.EXT_CERTIFICATE_AUTHORITIES) {
                acceptedCaDns = parseCertificateAuthorities(body, pos, extDataLen, ctx);
            } else if (extType == TlsConstants.EXT_OID_FILTERS) {
                oidFilters = parseOidFilters(body, pos, extDataLen);
            } else if (extType == TlsConstants.EXT_STATUS_REQUEST) {
                // RFC 8446 §4.4.2.1: запрос staple в CertificateRequest - пустое расширение.
                // Непустое тело (например, форма CertificateStatusRequest из ClientHello)
                // не определено для этого сообщения; принимать его значит гадать о структуре.
                if (extDataLen != 0) {
                    throw new TlsException(
                            TlsConstants.ALERT_DECODE_ERROR,
                            "CertificateRequest: status_request must be empty");
                }
                ocspRequested = true;
            }
            pos += extDataLen;
        }
        if (!hasSigAlgs) {
            throw new TlsException(
                    TlsConstants.ALERT_MISSING_EXTENSION,
                    "CertificateRequest: signature_algorithms extension is mandatory");
        }
        // RFC 8446 §4.2.3: без signature_algorithms_cert список signature_algorithms относится и к
        // подписям в сертификатах
        return new ClientCertificateRequest(
                acceptedCaDns,
                oidFilters,
                ocspRequested,
                signatureSchemes,
                certificateSchemes != null ? certificateSchemes : signatureSchemes);
    }

    /**
     * Парсит oid_filters extension (RFC 8446 §4.2.5).
     * <p>
     * Формат: opaque filters<0..2^16-1>, где каждый filter:
     *   certificate_extension_oid<1..2^8-1> || certificate_extension_values<0..2^16-1>
     */
    private static List<OIDFilter> parseOidFilters(byte[] body, int pos, int extDataLen) {
        if (extDataLen < 2) return Collections.emptyList();
        int filtersLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        if (filtersLen + 2 != extDataLen) return Collections.emptyList();
        pos += 2;
        if (filtersLen == 0) return Collections.emptyList();
        List<OIDFilter> filters = new ArrayList<>();
        int end = pos + filtersLen;
        while (pos < end) {
            // certificate_extension_oid<1..2^8-1>: 1 байт длины
            int oidLen = body[pos] & 0xFF;
            if (oidLen < 1 || pos + 1 + oidLen > end) break;
            byte[] oid = Arrays.copyOfRange(body, pos + 1, pos + 1 + oidLen);
            pos += 1 + oidLen;
            // certificate_extension_values<0..2^16-1>: 2 байта длины
            if (pos + 2 > end) break;
            int valLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            if (pos + 2 + valLen > end) break;
            byte[] values =
                    valLen > 0 ? Arrays.copyOfRange(body, pos + 2, pos + 2 + valLen) : new byte[0];
            pos += 2 + valLen;
            filters.add(new OIDFilter(oid, values));
        }
        return filters;
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
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
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
                throw new TlsException(
                        TlsConstants.ALERT_DECODE_ERROR,
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
     * Результат строгого разбора расширений {@code psk_key_exchange_modes} и {@code pre_shared_key}
     * в ClientHello (RFC 8446 §4.2.9, §4.2.11).
     * <p>
     * Хранит ссылки на тело ClientHello и смещения записей, а не копии: identity копируется только
     * по запросу. Смещения отсчитываются от начала тела (без 4-байтового заголовка handshake).
     */
    public static final class ParsedClientPsk {
        private final byte[] body;
        private final int[] identityOffsets;
        private final int[] identityLengths;
        private final long[] obfuscatedAges;
        private final int[] binderOffsets;
        private final int bindersVectorOffset;
        private final boolean dheKeOffered;
        private final int count;

        ParsedClientPsk(
                byte[] body,
                int[] identityOffsets,
                int[] identityLengths,
                long[] obfuscatedAges,
                int[] binderOffsets,
                int bindersVectorOffset,
                boolean dheKeOffered,
                int count) {
            this.body = body;
            this.identityOffsets = identityOffsets;
            this.identityLengths = identityLengths;
            this.obfuscatedAges = obfuscatedAges;
            this.binderOffsets = binderOffsets;
            this.bindersVectorOffset = bindersVectorOffset;
            this.dheKeOffered = dheKeOffered;
            this.count = count;
        }

        /** @return число предложенных identity (равно числу binder) */
        public int count() {
            return count;
        }

        /** @return true, если клиент предложил режим psk_dhe_ke; иначе PSK выбирать нельзя (§4.2.9) */
        public boolean dheKeOffered() {
            return dheKeOffered;
        }

        /** @return копия identity с номером {@code index} */
        public byte[] identity(int index) {
            return Arrays.copyOfRange(
                    body, identityOffsets[index], identityOffsets[index] + identityLengths[index]);
        }

        /** @return совпадает ли identity с номером {@code index} с {@code other} (без копирования) */
        public boolean identityEquals(int index, byte[] other) {
            return Arrays.equals(
                    body,
                    identityOffsets[index],
                    identityOffsets[index] + identityLengths[index],
                    other,
                    0,
                    other.length);
        }

        /**
         * Снимок списка identity одним массивом: для каждой identity 2 байта длины и её байты.
         * <p>
         * Нужен, чтобы сверить identity второго ClientHello с первым, не держа ссылку на тело
         * ClientHello и не выделяя по массиву на каждую из тысяч identity недоверенного клиента.
         * Содержит тикеты, поэтому владелец обязан затереть его после использования.
         *
         * @return снимок списка identity
         */
        public byte[] identitiesSnapshot() {
            int total = 0;
            for (int i = 0; i < count; i++) {
                total += 2 + identityLengths[i];
            }
            byte[] snapshot = new byte[total];
            int pos = 0;
            for (int i = 0; i < count; i++) {
                snapshot[pos++] = (byte) (identityLengths[i] >>> 8);
                snapshot[pos++] = (byte) identityLengths[i];
                System.arraycopy(body, identityOffsets[i], snapshot, pos, identityLengths[i]);
                pos += identityLengths[i];
            }
            return snapshot;
        }

        /**
         * Проверяет, что identity этого ClientHello - упорядоченное подмножество снимка: то есть
         * клиент только удалял записи, не добавлял, не заменял и не переставлял (RFC 8446 §4.1.2).
         *
         * @param snapshot снимок списка identity первого ClientHello ({@link #identitiesSnapshot()});
         *                 повреждённый (усечённый) снимок даёт false, а не исключение
         * @return true, если identity образуют подпоследовательность снимка с сохранением порядка
         */
        public boolean isOrderedSubsetOf(byte[] snapshot) {
            int pos = 0;
            for (int i = 0; i < count; i++) {
                boolean found = false;
                while (!found && pos + 2 <= snapshot.length) {
                    int length = ((snapshot[pos] & 0xFF) << 8) | (snapshot[pos + 1] & 0xFF);
                    pos += 2;
                    if (pos + length > snapshot.length) {
                        // Усечённый снимок не результат identitiesSnapshot: совпадения быть не
                        // может
                        return false;
                    }
                    found =
                            length == identityLengths[i]
                                    && Arrays.equals(
                                            snapshot,
                                            pos,
                                            pos + length,
                                            body,
                                            identityOffsets[i],
                                            identityOffsets[i] + length);
                    pos += length;
                }
                if (!found) {
                    return false;
                }
            }
            return true;
        }

        /** @return obfuscated_ticket_age (uint32) identity с номером {@code index} */
        public long obfuscatedTicketAge(int index) {
            return obfuscatedAges[index];
        }

        /** @return смещение вектора binders (его 2-байтовой длины) от начала тела ClientHello */
        public int bindersVectorOffset() {
            return bindersVectorOffset;
        }

        /** @return смещение значения binder с номером {@code index} от начала тела ClientHello */
        public int binderOffset(int index) {
            return binderOffsets[index];
        }
    }

    /**
     * Строго разбирает {@code psk_key_exchange_modes} и {@code pre_shared_key} в ClientHello
     * (RFC 8446 §4.2.9, §4.2.11). Структурная проверка не зависит от хранилища тикетов.
     * <p>
     * Алерты: повтор расширения, {@code pre_shared_key} не последним, число binder не равно числу
     * identity, binder длиной от 32 до 255 байт, но не {@code hashLen} - {@code illegal_parameter};
     * {@code pre_shared_key} без {@code psk_key_exchange_modes} - {@code missing_extension};
     * обрезанные и лишние байты, binder короче 32 байт ({@code opaque PskBinderEntry<32..255>}),
     * хвост после блока расширений - {@code decode_error}. Разбирается весь вектор, включая
     * identity, которые сервер потом не станет искать в хранилище.
     *
     * @param body    тело ClientHello (без заголовка handshake)
     * @param hashLen длина хэша PSK, обязательная длина каждого binder
     * @return разобранное расширение или null, если {@code pre_shared_key} нет
     * @throws TlsException при нарушении структуры
     */
    public static ParsedClientPsk parseClientHelloPsk(byte[] body, int hashLen)
            throws TlsException {
        String ctx = "ClientHello";
        int extStart = findExtensionsStart(body);
        if (extStart < 0) return null;
        int extEnd = extStart + (((body[extStart - 2] & 0xFF) << 8) | (body[extStart - 1] & 0xFF));
        if (extEnd != body.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": data after extensions block");
        }

        int[] pskRange = {-1, 0};
        int[] modesRange = {-1, 0};
        boolean[] extensionAfterPsk = new boolean[1];
        forEachExtension(
                body,
                extStart,
                extEnd,
                ctx,
                (extType, data, off, len) -> {
                    if (pskRange[0] >= 0) {
                        extensionAfterPsk[0] = true;
                    }
                    if (extType == TlsConstants.EXT_PRE_SHARED_KEY) {
                        pskRange[0] = off;
                        pskRange[1] = len;
                    } else if (extType == TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES) {
                        modesRange[0] = off;
                        modesRange[1] = len;
                    }
                });
        if (pskRange[0] < 0) return null;

        if (extensionAfterPsk[0]) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    ctx + ": pre_shared_key must be the last extension");
        }
        if (modesRange[0] < 0) {
            throw new TlsException(
                    TlsConstants.ALERT_MISSING_EXTENSION,
                    ctx + ": pre_shared_key without psk_key_exchange_modes");
        }
        boolean dheKeOffered = parsePskKeyExchangeModes(body, modesRange[0], modesRange[1]);

        int off = pskRange[0];
        int end = off + pskRange[1];
        // identities<7..2^16-1>: минимум одна запись (2 + 1 + 4)
        checkBounds(body, off, 2, end, ctx);
        int identitiesLen = ((body[off] & 0xFF) << 8) | (body[off + 1] & 0xFF);
        if (identitiesLen < TlsConstants.MIN_PSK_IDENTITY_ENTRY) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": pre_shared_key identities too short");
        }
        int pos = off + 2;
        int identitiesEnd = pos + identitiesLen;
        checkBounds(body, pos, identitiesLen, end, ctx);

        int maxEntries = identitiesLen / TlsConstants.MIN_PSK_IDENTITY_ENTRY;
        int[] identityOffsets = new int[maxEntries];
        int[] identityLengths = new int[maxEntries];
        long[] ages = new long[maxEntries];
        int count = 0;
        while (pos < identitiesEnd) {
            checkBounds(body, pos, 2, identitiesEnd, ctx);
            int identityLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            if (identityLen < 1) {
                throw new TlsException(
                        TlsConstants.ALERT_DECODE_ERROR, ctx + ": empty PSK identity");
            }
            checkBounds(body, pos + 2, identityLen + 4, identitiesEnd, ctx);
            identityOffsets[count] = pos + 2;
            identityLengths[count] = identityLen;
            int ageOffset = pos + 2 + identityLen;
            ages[count] =
                    ((long) (body[ageOffset] & 0xFF) << 24)
                            | ((long) (body[ageOffset + 1] & 0xFF) << 16)
                            | ((long) (body[ageOffset + 2] & 0xFF) << 8)
                            | (long) (body[ageOffset + 3] & 0xFF);
            count++;
            pos = ageOffset + 4;
        }

        // binders<33..2^16-1>: минимум один binder (1 + 32); вектор обязан закрывать расширение
        checkBounds(body, pos, 2, end, ctx);
        int bindersVectorOffset = pos;
        int bindersLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        if (bindersLen < 1 + TlsConstants.MIN_PSK_BINDER_LENGTH || pos + 2 + bindersLen != end) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    ctx + ": pre_shared_key binders length mismatch");
        }
        pos += 2;
        int[] binderOffsets = new int[count];
        int binders = 0;
        while (pos < end) {
            int binderLen = body[pos] & 0xFF;
            if (binderLen < TlsConstants.MIN_PSK_BINDER_LENGTH) {
                throw new TlsException(
                        TlsConstants.ALERT_DECODE_ERROR,
                        ctx + ": PSK binder shorter than " + TlsConstants.MIN_PSK_BINDER_LENGTH);
            }
            checkBounds(body, pos + 1, binderLen, end, ctx);
            if (binderLen != hashLen) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        ctx + ": PSK binder length does not match the hash length");
            }
            if (binders == count) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        ctx + ": more PSK binders than identities");
            }
            binderOffsets[binders++] = pos + 1;
            pos += 1 + binderLen;
        }
        if (binders != count) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    ctx + ": fewer PSK binders than identities");
        }
        return new ParsedClientPsk(
                body,
                identityOffsets,
                identityLengths,
                ages,
                binderOffsets,
                bindersVectorOffset,
                dheKeOffered,
                count);
    }

    /**
     * Разбирает {@code psk_key_exchange_modes}: {@code ke_modes<1..255>} (RFC 8446 §4.2.9).
     *
     * @return true, если среди режимов есть psk_dhe_ke
     */
    private static boolean parsePskKeyExchangeModes(byte[] body, int off, int len)
            throws TlsException {
        String ctx = "ClientHello";
        if (len < 2 || (body[off] & 0xFF) != len - 1) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": malformed psk_key_exchange_modes");
        }
        for (int i = off + 1; i < off + len; i++) {
            if (body[i] == TlsConstants.PSK_DHE_KE) {
                return true;
            }
        }
        return false;
    }

    /**
     * Пропускает заголовки ClientHello и возвращает позицию начала списка расширений.
     *
     * @param body тело ClientHello
     * @return позиция начала extensions или -1, если {@code legacy_version} не 0x0303
     */
    private static int findExtensionsStart(byte[] body) throws TlsException {
        String context = "ClientHello";
        checkBounds(body, 0, 2, context);
        // legacy_version: MUST be 0x0303 for TLS 1.3 (или 0x0301/0x0302 для backwards)
        if ((body[0] & 0xFF) != TlsConstants.LEGACY_VERSION_MAJOR
                || (body[1] & 0xFF) != TlsConstants.LEGACY_VERSION_MINOR) return -1;
        int pos = 2 + TlsConstants.RANDOM_LENGTH;
        // legacy_session_id (RFC 8446 §4.1.2: может быть непустым для совместимости)
        checkBounds(body, pos, 1, context);
        int sessionIdLen = body[pos] & 0xFF;
        checkBounds(body, pos, 1 + sessionIdLen, context);
        pos += 1 + sessionIdLen;
        // cipher_suites имеют 2-байтовую длину, compression_methods - 1-байтовую
        checkBounds(body, pos, 2, context);
        int csLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        checkBounds(body, pos + 2, csLen, context);
        pos += 2 + csLen;
        checkBounds(body, pos, 1, context);
        int compLen = body[pos] & 0xFF;
        checkBounds(body, pos + 1, compLen, context);
        pos += 1 + compLen;
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
        ParsedNewSessionTicket(
                long ticketLifetime, long ticketAgeAdd, byte[] ticketNonce, byte[] ticket) {
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
     * @throws TlsException при выходе за границы массива или пустом ticket
     */
    public static ParsedNewSessionTicket parseNewSessionTicket(byte[] body) throws TlsException {
        String ctx = "NewSessionTicket";
        checkBounds(body, 0, 8, ctx);
        long ticketLifetime =
                ((long) (body[0] & 0xFF) << 24)
                        | ((long) (body[1] & 0xFF) << 16)
                        | ((long) (body[2] & 0xFF) << 8)
                        | (long) (body[3] & 0xFF);
        long ticketAgeAdd =
                ((long) (body[4] & 0xFF) << 24)
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
        // RFC 8446 §4.6.1: opaque ticket<1..2^16-1>. Пустой тикет предъявить нечем, а хранилища
        // отвергают его исключением, которое не должно рвать чтение данных приложения
        if (ticketLen < 1) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "NewSessionTicket: empty ticket");
        }
        checkBounds(body, pos, ticketLen, ctx);
        byte[] ticket = Arrays.copyOfRange(body, pos, pos + ticketLen);
        pos += ticketLen;
        // RFC 8446 §4.6.1: поле extensions обязательно (хотя бы два байта длины), хвост за ним
        // не принадлежит ни одному полю сообщения
        checkBounds(body, pos, 2, ctx);
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2;
        checkBounds(body, pos, extLen, ctx);
        if (pos + extLen != body.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, ctx + ": trailing bytes after extensions");
        }
        // По RFC 8446 §4.2 сервер вправе слать расширения в NewSessionTicket и без запроса,
        // поэтому здесь нет сверки с ClientHello: только известное расширение не из этого
        // сообщения недопустимо. Значения расширений не читаются: early_data не поддерживается
        Set<Integer> present = new HashSet<>();
        forEachExtension(
                body, pos, pos + extLen, ctx, (extType, data, off, len) -> present.add(extType));
        TlsExtensionRegistry.checkRequest(TlsExtensionRegistry.Message.NEW_SESSION_TICKET, present);
        return new ParsedNewSessionTicket(ticketLifetime, ticketAgeAdd, ticketNonce, ticket);
    }

    /** Разобранная запись в открытом виде: тип содержимого и тело без заголовка. */
    public static final class PlaintextRecord {
        public final byte contentType;
        public final byte[] body;

        PlaintextRecord(byte contentType, byte[] body) {
            this.contentType = contentType;
            this.body = body;
        }
    }

    /**
     * Разбирает TLS-запись в открытом виде (до установки ключей): ClientHello, ServerHello, alert
     * (RFC 8446 §5.1). Проверяет только рамку записи, смысл типа и содержимого проверяет вызывающий.
     * Версию в заголовке не проверяет: RFC 8446 §5.1 велит игнорировать {@code legacy_record_version}.
     *
     * @param record сырая TLS-запись (заголовок + данные), ровно одна
     * @return тип содержимого и тело записи
     * @throws TlsException {@code decode_error} при короткой, усечённой записи или хвосте после неё,
     *         {@code record_overflow} при длине больше 2¹⁴
     */
    public static PlaintextRecord parsePlaintextRecord(byte[] record) throws TlsException {
        if (record == null || record.length < TlsConstants.RECORD_HEADER_SIZE) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "Record too short");
        }
        int len = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);
        if (len > TlsConstants.MAX_PLAINTEXT_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Record too long: " + len + " > " + TlsConstants.MAX_PLAINTEXT_LENGTH);
        }
        if (record.length < TlsConstants.RECORD_HEADER_SIZE + len) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "Record truncated");
        }
        // Транспорт отдаёт ровно одну запись, поэтому хвост это нарушение, а не штатный случай
        if (record.length > TlsConstants.RECORD_HEADER_SIZE + len) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR, "Trailing bytes after record");
        }
        byte[] body = new byte[len];
        System.arraycopy(record, TlsConstants.RECORD_HEADER_SIZE, body, 0, len);
        return new PlaintextRecord(record[0], body);
    }
}
