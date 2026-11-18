package org.rssys.gost.pkix.cert;

import java.net.IDN;
import java.text.Normalizer;
import java.util.Locale;

/**
 * Единая нормализация DNS-имён и разбор IP-литералов.
 *
 * <p>В TLS SNI и SAN dNSName передаются только в ASCII. Кириллический адрес
 * нужно один раз преобразовать в punycode (A-label), чтобы SNI, выбор сертификата по SNI
 * и проверка hostname использовали одно и то же значение. Все правила нормализации и
 * распознавания IP живут здесь: расхождение между несколькими детекторами означало бы, что
 * одно и то же имя в разных местах трактуется по-разному (как IP и как DNS-имя).</p>
 *
 * <p>{@link IDN} реализует IDNA2003. Для кириллицы он совпадает с IDNA2008, но
 * для {@code ß}, {@code ς}, ZWNJ и ZWJ IDNA2003 меняет смысл домена
 * ({@code faß.de -> fass.de}). Кроме них nameprep молча отбрасывает или преобразует
 * управляющие и форматирующие символы (soft hyphen, ZWSP, word joiner, BOM) и приводит
 * совместимые формы (fullwidth) к ASCII. Принимается только курируемое подмножество:
 * такие имена отклоняются, иначе проверка могла бы принять сертификат другого домена.</p>
 *
 * <p>IP-литералы не преобразуются: SNI для них запрещён RFC 6066 §3, а
 * hostname проверяется по iPAddress SAN. Числовые формы IPv4 ({@code 2130706433},
 * {@code 0x7f000001}, {@code 127.1}, {@code 0177.0.0.1}) не являются ни IP-литералом, ни
 * допустимым именем: отдельные парсеры (в том числе операционной системы) трактуют их как
 * IPv4, поэтому они отвергаются. Подчёркивание в ASCII-именах допускается: оно встречается
 * во внутренних именах (docker-compose).</p>
 */
public final class GostDnsName {

    private static final int IPV4_OCTETS = 4;
    private static final int IPV4_MAX_OCTET = 255;
    private static final int IPV4_OCTET_MAX_DIGITS = 3;
    private static final int IPV6_GROUPS = 8;
    private static final int IPV6_MAX_GROUP_DIGITS = 4;
    private static final int IPV6_BYTES = 16;
    private static final int IPV4_MAPPED_PREFIX_ZERO_BYTES = 10;
    private static final int BITS_PER_BYTE = 8;
    private static final int HEX_RADIX = 16;
    private static final int MAX_NUMERIC_LABELS = 4;

    private GostDnsName() {}

    /**
     * Преобразует DNS-имя в lowercase A-label.
     *
     * <p>Пробельные символы по краям отбрасываются, затем снимается ровно одна завершающая
     * точка (FQDN -> относительное имя): несколько точек подряд - это пустая метка и ошибка.
     * Управляющие символы, включая NUL, отвергаются, а не отбрасываются молча.</p>
     *
     * @param hostname имя в Unicode или уже в A-label; {@code null} допустим
     * @return A-label, IP-литерал без изменений или {@code null}, если вход был
     *         {@code null}
     * @throws IllegalArgumentException если имя пустое, содержит `*`, пробелы, управляющие или
     *                                  форматирующие символы, символы с неоднозначным
     *                                  отображением IDNA2003, числовую форму IPv4 или не может
     *                                  быть преобразовано
     */
    public static String toAsciiHostname(String hostname) {
        if (hostname == null) {
            return null;
        }
        // strip(), а не trim(): trim() срезает и NUL с прочими символами <= U+0020, из-за чего
        // "example.com\0" проходило бы как "example.com".
        String normalized = stripSingleTrailingDot(hostname.strip());
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("hostname must not be empty");
        }
        if (isIpAddress(normalized)) {
            return normalized;
        }

        String lower = normalized.toLowerCase(Locale.ROOT);
        validateHostCharacters(lower);

        String ascii;
        if (isAscii(lower)) {
            ascii = lower;
        } else {
            ascii = toAsciiLabels(lower);
        }
        validateLabels(ascii);
        if (isAmbiguousNumericHost(ascii)) {
            throw new IllegalArgumentException(
                    "hostname is a numeric form of an IPv4 address, not a DNS name");
        }
        return ascii;
    }

    /**
     * Проверяет, является ли строка IP-литералом.
     *
     * <p>Поддерживаются строгий IPv4 (четыре десятичных октета без знака и ведущих нулей),
     * IPv6 (в том числе сжатый {@code ::} и со встроенным IPv4), IPv6 в квадратных скобках и
     * IPv6 с зоной ({@code fe80::1%eth0}). Разбор синтаксический: имя не резолвится и в сеть
     * запросов нет.</p>
     *
     * @param hostname адрес для проверки
     * @return true если это IP-литерал
     */
    public static boolean isIpAddress(String hostname) {
        return parseIpAddress(hostname) != null;
    }

    /**
     * Проверяет, что хост - IP-литерал либо числовая форма IPv4, которую нельзя считать именем.
     *
     * <p>Нужен там, где IP-адрес в качестве хоста запрещён (URI в NameConstraints): строгий
     * {@link #isIpAddress} пропустил бы {@code 2130706433}, {@code 127.1} или
     * {@code 0x7f000001}, и они прошли бы как DNS-имена, хотя ОС и многие парсеры читают их как
     * IPv4. Завершающие точки не скрывают адрес.</p>
     *
     * @param host хост из URI или имя
     * @return true если это IP-литерал или числовая форма IPv4
     */
    public static boolean isIpAddressOrNumericForm(String host) {
        if (host == null) {
            return false;
        }
        String trimmed = stripAllTrailingDots(host);
        if (trimmed.isEmpty()) {
            return false;
        }
        return isIpAddress(trimmed) || isAmbiguousNumericHost(trimmed.toLowerCase(Locale.ROOT));
    }

    /**
     * Разбирает IP-литерал в сырые байты, не обращаясь к DNS.
     *
     * <p>Результат: 4 байта для IPv4 и для IPv4-mapped IPv6 ({@code ::ffff:a.b.c.d},
     * любая форма записи), иначе 16 байт. Разворачивание mapped-адреса повторяет поведение
     * {@code InetAddress.getByName}: сертификат с IPv4 SAN должен совпадать с обеими формами.
     * IPv4-compatible ({@code ::a.b.c.d}) - не mapped, остаётся 16 байтами.</p>
     *
     * @param literal IPv4, IPv6, IPv6 в квадратных скобках или с зоной
     * @return сырой адрес или {@code null}, если строка не является IP-литералом
     */
    public static byte[] parseIpAddress(String literal) {
        if (literal == null || literal.isEmpty()) {
            return null;
        }
        String value = literal;
        boolean bracketed = false;
        if (value.length() >= 2
                && value.charAt(0) == '['
                && value.charAt(value.length() - 1) == ']') {
            value = value.substring(1, value.length() - 1);
            bracketed = true;
        }
        // Скобки - синтаксис URI только для IPv6; "[127.0.0.1]" не адрес и не имя.
        if (bracketed && value.indexOf(':') < 0) {
            return null;
        }
        int zoneStart = value.indexOf('%');
        if (zoneStart >= 0) {
            // Зона допустима только у IPv6: у IPv4 её нет.
            if (value.indexOf(':') < 0 || !isValidZone(value.substring(zoneStart + 1))) {
                return null;
            }
            value = value.substring(0, zoneStart);
        }
        if (value.indexOf(':') >= 0) {
            return unwrapIpv4Mapped(parseIpv6(value));
        }
        return parseIpv4(value);
    }

    private static boolean isValidZone(String zone) {
        if (zone.isEmpty()) {
            return false;
        }
        for (int i = 0; i < zone.length(); i++) {
            char c = zone.charAt(i);
            boolean allowed =
                    (c >= 'a' && c <= 'z')
                            || (c >= 'A' && c <= 'Z')
                            || (c >= '0' && c <= '9')
                            || c == '_'
                            || c == '-'
                            || c == '.';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    /** Строгий IPv4: четыре десятичных октета 0-255, без знака, пустых частей и ведущих нулей. */
    private static byte[] parseIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != IPV4_OCTETS) {
            return null;
        }
        byte[] result = new byte[IPV4_OCTETS];
        for (int i = 0; i < IPV4_OCTETS; i++) {
            int octet = parseStrictOctet(parts[i]);
            if (octet < 0) {
                return null;
            }
            result[i] = (byte) octet;
        }
        return result;
    }

    private static int parseStrictOctet(String part) {
        if (part.isEmpty() || part.length() > IPV4_OCTET_MAX_DIGITS) {
            return -1;
        }
        // Ведущий ноль отвергается: "0177" часть парсеров читает как восьмеричное число.
        if (part.length() > 1 && part.charAt(0) == '0') {
            return -1;
        }
        int octet = 0;
        for (int i = 0; i < part.length(); i++) {
            char c = part.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
            octet = octet * 10 + (c - '0');
        }
        return octet <= IPV4_MAX_OCTET ? octet : -1;
    }

    private static byte[] parseIpv6(String value) {
        int compression = value.indexOf("::");
        if (compression >= 0 && value.indexOf("::", compression + 1) >= 0) {
            return null;
        }
        int[] groups = new int[IPV6_GROUPS];
        int headCount;
        int tailCount = 0;
        int[] tailGroups = new int[IPV6_GROUPS];
        if (compression < 0) {
            headCount = parseGroups(value, true, groups);
            if (headCount != IPV6_GROUPS) {
                return null;
            }
        } else {
            String head = value.substring(0, compression);
            String tail = value.substring(compression + 2);
            headCount = parseGroups(head, false, groups);
            tailCount = parseGroups(tail, true, tailGroups);
            // "::" заменяет как минимум одну группу нулей
            if (headCount < 0 || tailCount < 0 || headCount + tailCount > IPV6_GROUPS - 1) {
                return null;
            }
            System.arraycopy(tailGroups, 0, groups, IPV6_GROUPS - tailCount, tailCount);
        }
        byte[] result = new byte[IPV6_BYTES];
        for (int i = 0; i < IPV6_GROUPS; i++) {
            result[2 * i] = (byte) (groups[i] >>> BITS_PER_BYTE);
            result[2 * i + 1] = (byte) groups[i];
        }
        return result;
    }

    /**
     * Разбирает группы IPv6 из {@code part} в {@code out}; встроенный IPv4 допустим только
     * последним элементом и только в конце адреса.
     *
     * @return число групп или -1 при ошибке
     */
    private static int parseGroups(String part, boolean allowIpv4Tail, int[] out) {
        if (part.isEmpty()) {
            return 0;
        }
        String[] pieces = part.split(":", -1);
        int count = 0;
        for (int i = 0; i < pieces.length; i++) {
            String piece = pieces[i];
            if (piece.isEmpty()) {
                return -1;
            }
            if (piece.indexOf('.') >= 0) {
                byte[] ipv4 = parseIpv4(piece);
                if (!allowIpv4Tail || i != pieces.length - 1 || ipv4 == null) {
                    return -1;
                }
                if (count + 2 > out.length) {
                    return -1;
                }
                out[count++] = ((ipv4[0] & 0xFF) << BITS_PER_BYTE) | (ipv4[1] & 0xFF);
                out[count++] = ((ipv4[2] & 0xFF) << BITS_PER_BYTE) | (ipv4[3] & 0xFF);
                continue;
            }
            int group = parseHexGroup(piece);
            if (group < 0 || count >= out.length) {
                return -1;
            }
            out[count++] = group;
        }
        return count;
    }

    private static int parseHexGroup(String piece) {
        if (piece.length() > IPV6_MAX_GROUP_DIGITS) {
            return -1;
        }
        int result = 0;
        for (int i = 0; i < piece.length(); i++) {
            int digit = asciiHexDigit(piece.charAt(i));
            if (digit < 0) {
                return -1;
            }
            result = result * HEX_RADIX + digit;
        }
        return result;
    }

    private static int asciiHexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    private static byte[] unwrapIpv4Mapped(byte[] ipv6) {
        if (ipv6 == null) {
            return null;
        }
        for (int i = 0; i < IPV4_MAPPED_PREFIX_ZERO_BYTES; i++) {
            if (ipv6[i] != 0) {
                return ipv6;
            }
        }
        if (ipv6[IPV4_MAPPED_PREFIX_ZERO_BYTES] != (byte) 0xFF
                || ipv6[IPV4_MAPPED_PREFIX_ZERO_BYTES + 1] != (byte) 0xFF) {
            return ipv6;
        }
        byte[] ipv4 = new byte[IPV4_OCTETS];
        System.arraycopy(ipv6, IPV6_BYTES - IPV4_OCTETS, ipv4, 0, IPV4_OCTETS);
        return ipv4;
    }

    /**
     * Хост целиком состоит из числовых меток (1-4 штуки), но не является строгим IPv4.
     * Так выглядят формы, которые часть парсеров читает как IPv4: {@code 2130706433},
     * {@code 0x7f000001}, {@code 127.1}, {@code 0177.0.0.1}, {@code 127.0.0.+1}. Хосты вида
     * {@code host.123} сюда не попадают: в них есть нечисловая метка.
     */
    private static boolean isAmbiguousNumericHost(String host) {
        String[] labels = host.split("\\.", -1);
        if (labels.length < 1 || labels.length > MAX_NUMERIC_LABELS) {
            return false;
        }
        for (String label : labels) {
            if (!isNumericLabel(label)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isNumericLabel(String label) {
        if (label.isEmpty()) {
            return false;
        }
        if (label.startsWith("0x")) {
            for (int i = 2; i < label.length(); i++) {
                if (asciiHexDigit(label.charAt(i)) < 0) {
                    return false;
                }
            }
            return true;
        }
        int start = label.charAt(0) == '+' || label.charAt(0) == '-' ? 1 : 0;
        if (start == label.length()) {
            return false;
        }
        for (int i = start; i < label.length(); i++) {
            char c = label.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /**
     * Преобразует имя с не-ASCII символами в A-label, предварительно отсекая то, что nameprep
     * молча отбросил бы или переписал.
     */
    private static String toAsciiLabels(String lower) {
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            if (c == 'ß' || c == 'ς' || c == '‌' || c == '‍') {
                throw new IllegalArgumentException(
                        "hostname contains an IDNA2003-ambiguous character: U+"
                                + String.format("%04X", (int) c));
            }
        }
        // Сначала NFC: разложенная кириллица (NFD) - валидное имя, и IDN.toASCII приведёт её к
        // NFC само. Если после NFC совместимая нормализация (NFKC) что-то меняет, имя содержит
        // fullwidth или иные совместимые формы, которые nameprep превратил бы в другие символы.
        String nfc = Normalizer.normalize(lower, Normalizer.Form.NFC);
        if (!Normalizer.normalize(nfc, Normalizer.Form.NFKC).equals(nfc)) {
            throw new IllegalArgumentException(
                    "hostname contains characters changed by compatibility normalization");
        }
        try {
            String ascii = IDN.toASCII(nfc);
            validateHostCharacters(ascii);
            return ascii.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("hostname is not a valid IDN", e);
        }
    }

    private static String stripSingleTrailingDot(String value) {
        if (value.endsWith(".")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }

    private static String stripAllTrailingDots(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '.') {
            end--;
        }
        return value.substring(0, end);
    }

    private static boolean isAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    private static void validateHostCharacters(String value) {
        for (int i = 0; i < value.length(); ) {
            int cp = value.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == '*') {
                throw new IllegalArgumentException("hostname must not contain a wildcard");
            }
            if (Character.isWhitespace(cp)) {
                throw new IllegalArgumentException("hostname must not contain whitespace");
            }
            // Явный отказ по категории, не полагаясь на IDN: управляющие и форматирующие
            // символы (soft hyphen, ZWSP, word joiner, BOM), непарные суррогаты, private use и
            // неназначенные кодовые точки не бывают частью имени хоста.
            if (isForbiddenCategory(Character.getType(cp))) {
                throw new IllegalArgumentException(
                        "hostname contains a forbidden character: U+" + String.format("%04X", cp));
            }
            if (cp < 0x80
                    && !(cp >= 'a' && cp <= 'z')
                    && !(cp >= 'A' && cp <= 'Z')
                    && !(cp >= '0' && cp <= '9')
                    && cp != '.'
                    && cp != '-'
                    && cp != '_') {
                throw new IllegalArgumentException(
                        "hostname contains an invalid character: U+" + String.format("%04X", cp));
            }
        }
    }

    private static boolean isForbiddenCategory(int type) {
        return type == Character.CONTROL
                || type == Character.FORMAT
                || type == Character.SURROGATE
                || type == Character.PRIVATE_USE
                || type == Character.UNASSIGNED;
    }

    private static void validateLabels(String value) {
        if (value.startsWith(".") || value.endsWith(".") || value.contains("..")) {
            throw new IllegalArgumentException("hostname must not contain empty labels");
        }
    }
}
