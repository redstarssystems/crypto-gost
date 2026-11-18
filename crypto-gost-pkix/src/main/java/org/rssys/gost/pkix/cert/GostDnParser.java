package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

/**
 * Парсер Distinguished Name (DN) из DER-кодировки в человеко-читаемый формат.
 *
 * <p>Разбирает DN SEQUENCE (RFC 5280 §4.1.2.4) в строку вида
 * {@code "CN=..., O=..., C=..."} и список полей с OID-значениями.
 * Поддерживает DN-атрибуты ГОСТ Р 5280 и RFC 4519, включая российские
 * сертификатные атрибуты (ИНН, ОГРН, СНИЛС, ОГРНИП).</p>
 *
 * <p>Вынесен из {@link GostCertificate} для разделения ответственности.</p>
 *
 * @see GostCertificate
 * @see GostDerParser
 */
public final class GostDnParser {

    private static final int TAG_UTF8_STRING = 0x0C;
    private static final int TAG_NUMERIC_STRING = 0x12;
    private static final int TAG_PRINTABLE_STRING = 0x13;
    private static final int TAG_IA5_STRING = 0x16;
    // Границы управляющих символов ASCII: C0 (< 0x20) и DEL (0x7F).
    private static final char ASCII_FIRST_PRINTABLE = 0x20;
    private static final char ASCII_DEL = 0x7F;

    private static final Charset UTF_32_BE = Charset.forName("UTF-32BE");

    private GostDnParser() {}

    /**
     * Одна запись DN: OID (точечная нотация) + строковое значение.
     */
    public static final class DnField {
        public final String oid;
        public final String value;

        public DnField(String oid, String value) {
            this.oid = oid;
            this.value = value;
        }
    }

    /**
     * Результат парсинга DN: готовая строка и список полей для lookup.
     */
    public static final class DnParseResult {
        public final String dnString;
        public final List<DnField> fields;

        public DnParseResult(String dnString, List<DnField> fields) {
            this.dnString = dnString;
            this.fields = fields;
        }
    }

    /**
     * Парсит DN SEQUENCE в человеко-читаемый DN-формат и список полей.
     * Формат строки: "CN=..., O=..., C=..."
     *
     * <p>try-catch: при ошибке парсинга возвращаем DnParseResult с null.
     * Безопасность: непечатные символы экранируются в escapeDnValue.</p>
     *
     * @param der   DER-поток сертификата
     * @param dnOff смещение на DN SEQUENCE
     * @param dnLen длина DN SEQUENCE
     * @return результат парсинга
     */
    static DnParseResult parseDnString(byte[] der, int dnOff, int dnLen) {
        try {
            // DN = SEQUENCE of SET, каждая SET содержит SEQUENCE { OID, value }
            if (dnOff >= der.length || (der[dnOff] & 0xFF) != TAG_SEQUENCE) {
                return new DnParseResult(null, new ArrayList<>(0));
            }
            int[] dnSeqTlv = readTlv(der, dnOff);
            int pos = dnSeqTlv[0];
            int end = dnSeqTlv[1];

            StringBuilder sb = new StringBuilder();
            List<DnField> fields = new ArrayList<>();
            boolean first = true;

            while (pos < end) {
                int tag = der[pos] & 0xFF;
                if (tag != 0x31) { // SET
                    pos = readTlv(der, pos)[1];
                    continue;
                }
                int[] setTlv = readTlv(der, pos);
                int setPos = setTlv[0];
                int setEnd = setTlv[1];

                while (setPos < setEnd) {
                    if ((der[setPos] & 0xFF) != TAG_SEQUENCE) {
                        setPos = readTlv(der, setPos)[1];
                        continue;
                    }
                    int[] attrTlv = readTlv(der, setPos);
                    int attrPos = attrTlv[0];
                    int attrEnd = attrTlv[1];
                    // OID — первый элемент SEQUENCE
                    if (attrPos >= attrEnd || (der[attrPos] & 0xFF) != TAG_OID) break;
                    int[] oidTlv = readTlv(der, attrPos);
                    String oidStr = oidBytesToDottedString(der, oidTlv[0], oidTlv[1] - oidTlv[0]);

                    // Value — второй элемент SEQUENCE (после OID)
                    int valPos = oidTlv[1];
                    if (valPos >= attrEnd) break;
                    int valTag = der[valPos] & 0xFF;
                    int[] valTlv = readTlv(der, valPos);
                    String value = decodeDnValue(der, valTlv[0], valTlv[1] - valTlv[0], valTag);

                    // В DN-строке используем короткое имя для известных OID
                    if (!first) sb.append(", ");
                    else first = false;
                    sb.append(lookupOidName(der, oidTlv[0], oidTlv[1] - oidTlv[0]));
                    sb.append('=').append(escapeDnValue(value));

                    fields.add(new DnField(oidStr, value));
                    setPos = attrTlv[1];
                }
                pos = setTlv[1];
            }
            return new DnParseResult(sb.toString(), fields);
        } catch (RuntimeException e) {
            // DER повреждён или неизвестный формат -> возвращаем null
            return new DnParseResult(null, new ArrayList<>(0));
        }
    }

    /**
     * Возвращает короткое имя OID для человеко-читаемого вывода.
     * Если OID неизвестен — возвращает точечную нотацию.
     */
    static String lookupOidName(byte[] der, int start, int len) {
        if (matchesOid(der, start, len, GostDerParser.CN_OID_BYTES)) return "CN";
        if (matchesOid(der, start, len, GostDerParser.C_OID_BYTES)) return "C";
        if (matchesOid(der, start, len, GostDerParser.L_OID_BYTES)) return "L";
        if (matchesOid(der, start, len, GostDerParser.ST_OID_BYTES)) return "ST";
        if (matchesOid(der, start, len, GostDerParser.STREET_OID_BYTES)) return "STREET";
        if (matchesOid(der, start, len, GostDerParser.O_OID_BYTES)) return "O";
        if (matchesOid(der, start, len, GostDerParser.OU_OID_BYTES)) return "OU";
        if (matchesOid(der, start, len, GostDerParser.T_OID_BYTES)) return "T";
        if (matchesOid(der, start, len, GostDerParser.SN_OID_BYTES)) return "SN";
        if (matchesOid(der, start, len, GostDerParser.GN_OID_BYTES)) return "GN";
        if (matchesOid(der, start, len, GostDerParser.SERIALNUM_OID_BYTES)) return "SERIALNUMBER";
        if (matchesOid(der, start, len, GostDerParser.POSTAL_CODE_OID_BYTES)) return "postalCode";
        if (matchesOid(der, start, len, GostDerParser.UNIQUE_ID_OID_BYTES))
            return "UNIQUE_IDENTIFIER";
        if (matchesOid(der, start, len, GostDerParser.PSEUDONYM_OID_BYTES)) return "pseudonym";
        if (matchesOid(der, start, len, GostDerParser.EMAIL_OID_BYTES)) return "emailAddress";
        if (matchesOid(der, start, len, GostDerParser.UID_OID_BYTES)) return "UID";
        if (matchesOid(der, start, len, GostDerParser.INN_OID_BYTES)) return "INN";
        if (matchesOid(der, start, len, GostDerParser.OGRNIP_OID_BYTES)) return "OGRNIP";
        if (matchesOid(der, start, len, GostDerParser.INNLE_OID_BYTES)) return "INNLE";
        if (matchesOid(der, start, len, GostDerParser.OGRN_OID_BYTES)) return "OGRN";
        if (matchesOid(der, start, len, GostDerParser.SNILS_OID_BYTES)) return "SNILS";
        if (matchesOid(der, start, len, GostDerParser.ORG_ID_OID_BYTES))
            return "organizationIdentifier";
        return oidBytesToDottedString(der, start, len);
    }

    /**
     * Декодирует значение DN-атрибута из DER в строку.
     * Поддерживает UTF8String, PrintableString, T61String, IA5String,
     * NumericString, BMPString.
     */
    static String decodeDnValue(byte[] der, int start, int len, int tag) {
        // Для показа DN терпимое декодирование: старые сертификаты могут
        // содержать кириллицу в PrintableString/IA5String, и отказ от такого
        // сертификата только из-за отображения недопустим. Строгость нужна
        // в NameConstraints (validateDnValue), где неоднозначность влияет
        // на решение о доверии.
        switch (tag) {
            case TAG_UTF8_STRING:
                return new String(der, start, len, StandardCharsets.UTF_8);
            case TAG_NUMERIC_STRING:
            case TAG_PRINTABLE_STRING:
            case TAG_IA5_STRING:
                return new String(der, start, len, StandardCharsets.US_ASCII);
            case TAG_T61_STRING:
                return new String(der, start, len, StandardCharsets.ISO_8859_1);
            case TAG_UNIVERSAL_STRING:
                return new String(der, start, len, UTF_32_BE);
            case TAG_BMP_STRING:
                return new String(der, start, len, StandardCharsets.UTF_16BE);
            default:
                // Неизвестный тип: hex dump (не теряем данные)
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < len && i < 128; i++) {
                    sb.append(String.format("%02X", der[start + i] & 0xFF));
                }
                if (len > 128) sb.append("...");
                return sb.toString();
        }
    }

    /**
     * Строго проверяет строковое значение DN-атрибута.
     *
     * <p>Замена символов при декодировании недопустима: два разных DER-значения
     * не должны сходиться в одну строку, иначе сравнение DN и NameConstraints
     * становится неоднозначным. Поэтому malformed input — ошибка, а не U+FFFD.</p>
     *
     * <p>{@code emailAddress} по RFC 5280 обязан быть IA5String; другие теги
     * для этого OID отклоняются.</p>
     *
     * @param der   DER-поток
     * @param start смещение значения
     * @param len   длина значения
     * @param tag   тег значения
     * @param oid   OID атрибута в точечной нотации
     * @throws IllegalArgumentException если значение недопустимо для своего тега
     */
    static void validateDnValue(byte[] der, int start, int len, int tag, String oid) {
        if (GostOids.ATTR_EMAIL.equals(oid) && tag != TAG_IA5_STRING) {
            throw new IllegalArgumentException("emailAddress must be encoded as IA5String");
        }
        switch (tag) {
            case TAG_UTF8_STRING:
                strictDecode(der, start, len, StandardCharsets.UTF_8);
                break;
            case TAG_NUMERIC_STRING:
                requireNumericString(strictDecode(der, start, len, StandardCharsets.US_ASCII));
                break;
            case TAG_PRINTABLE_STRING:
                requirePrintableString(strictDecode(der, start, len, StandardCharsets.US_ASCII));
                break;
            case TAG_IA5_STRING:
                String ia5Value = strictDecode(der, start, len, StandardCharsets.US_ASCII);
                if (GostOids.ATTR_EMAIL.equals(oid)) {
                    requireNoAsciiControl(ia5Value);
                }
                break;
            case TAG_T61_STRING:
                // ISO-8859-1 отображает любой байт, проверять нечего. Допускать T61 нужно: иначе
                // цепочки с T61 в DN не проходили бы при любых NameConstraints. Строгость
                // обеспечивает сравнение в DirectoryNameSubtree (там T61 не декодируется).
                break;
            case TAG_UNIVERSAL_STRING:
                if ((len & 3) != 0) {
                    throw new IllegalArgumentException(
                            "UniversalString length must be a multiple of 4");
                }
                strictDecode(der, start, len, UTF_32_BE);
                break;
            case TAG_BMP_STRING:
                if ((len & 1) != 0) {
                    throw new IllegalArgumentException("BMPString length must be even");
                }
                strictDecode(der, start, len, StandardCharsets.UTF_16BE);
                break;
            default:
                break;
        }
    }

    /**
     * Адрес электронной почты не содержит управляющих символов ASCII: NUL и переводы строк
     * обрезают значение в сторонних разборщиках и ломают сравнение с ограничениями.
     * C1 (0x80-0x9F) отвергает уже строгое декодирование US-ASCII.
     */
    private static void requireNoAsciiControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < ASCII_FIRST_PRINTABLE || c == ASCII_DEL) {
                throw new IllegalArgumentException("emailAddress contains a control character");
            }
        }
    }

    private static void requireNumericString(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != ' ' && (c < '0' || c > '9')) {
                throw new IllegalArgumentException(
                        "NumericString contains a character outside digits and space");
            }
        }
    }

    /**
     * RFC 5280 Appendix A: countryName — PrintableString (SIZE (2)), код
     * страны ISO 3166 — две заглавные латинские буквы.
     */
    private static void requireCountryCode(String value) {
        if (value.length() != 2
                || value.charAt(0) < 'A'
                || value.charAt(0) > 'Z'
                || value.charAt(1) < 'A'
                || value.charAt(1) > 'Z') {
            throw new IllegalArgumentException(
                    "countryName must be exactly two uppercase ASCII letters");
        }
    }

    /**
     * X.520 ub-serial-number: PrintableString (SIZE (1..64)). Это атрибут DN,
     * а не serialNumber сертификата.
     */
    private static void requireDnSerialNumber(String value) {
        if (value.isEmpty() || value.length() > 64) {
            throw new IllegalArgumentException(
                    "serialNumber DN value must contain 1..64 characters");
        }
        requirePrintableString(value);
    }

    private static String strictDecode(byte[] der, int start, int len, Charset charset) {
        CharsetDecoder decoder =
                charset.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(der, start, len)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("DN value is not valid " + charset.name(), e);
        }
    }

    /**
     * Экранирует символы в значении DN для безопасного вывода.
     *
     * <p>Зачем: запятые ломают формат CN=a,b (воспринимается как два RDN),
     * равно ломает key=value, управляющие символы опасны в логах.</p>
     */
    static String escapeDnValue(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ',' || c == '=' || c == '+' || c == '\\') {
                // RFC 4514: , = + \ экранируются обратным слешем.
                // \ критичен — без него не отличить escape от literal.
                sb.append('\\').append(c);
            } else if (c < 0x20 || (c >= 0x7F && c < 0xA0)) {
                // C0 (0x00-0x1F), DEL (0x7F) и C1 controls (0x80-0x9F) непечатны.
                // C1 возможны в T61String-декодированных значениях.
                sb.append('\\').append(String.format("u%04X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Обрезает строку для логирования, если она длиннее {@code maxLen}.
     * Добавляет {@code "...[truncated]"} при обрезке.
     *
     * <p>Открыт другим модулям библиотеки ({@code tls13}, {@code jsse}): DN и другие строки от
     * собеседника в журнал пишутся только усечёнными.
     *
     * @param s строка или {@code null}
     * @param maxLen предельная длина
     * @return строка не длиннее {@code maxLen} с суффиксом при обрезке; {@code null} для
     *     {@code null}
     */
    public static String truncateForLog(String s, int maxLen) {
        if (s == null) return null;
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...[truncated]";
    }

    /**
     * Возвращает массив значений указанного OID из DN-полей.
     *
     * @param fields массив DnField (может быть null)
     * @param oidDot OID в точечной нотации
     * @return массив значений (пустой если не найдено)
     */
    static String[] getDnField(DnField[] fields, String oidDot) {
        if (fields == null) return new String[0];
        List<String> result = new ArrayList<>();
        for (DnField f : fields) {
            if (f.oid.equals(oidDot)) result.add(f.value);
        }
        return result.toArray(new String[0]);
    }

    /**
     * Кодирует Distinguished Name в DER.
     * Строка формата {@code "CN=..., O=..., OU=..., L=..., ST=..., C=..."}.
     * Каждый элемент — отдельный RDN: SEQUENCE { SET { SEQUENCE { OID, UTF8String } } }.
     * Структура идентична ожидаемой {@link #parseDnString}.
     *
     * <p><b>Порядок RDN:</b> метод записывает RDN в том порядке, в котором они
     * перечислены в строке. RFC 4514 §2.1 задаёт обратный порядок строкового
     * представления (последний RDN последовательности идёт первым), поэтому
     * для многозначных DN этот метод не является RFC 4514-совместимым.
     * Для {@code directoryName} в Name Constraints порядок RDN семантически
     * важен: формируйте строку в порядке DER-последовательности (корень -> leaf),
     * например {@code "C=RU,O=Evil,CN=leaf"}.</p>
     *
     * <p>Типы значений выбираются по RFC 5280 Appendix A: countryName и
     * serialNumber кодируются PrintableString, emailAddress — IA5String,
     * остальные DirectoryString-атрибуты — UTF8String.</p>
     *
     * <p><b>Ограничения формата:</b> запятая всегда разделяет RDN, в значении её
     * передать нельзя; знак {@code =} в значении допустим (делится только по первому);
     * экранирование RFC 4514 не обрабатывается, обратная косая черта - обычный символ;
     * пробелы по краям ключа и значения отбрасываются. Управляющие символы
     * ({@link Character#isISOControl(int)}) отвергаются во всей строке, в том числе по
     * краям, где {@link String#trim()} иначе молча срезал бы их.</p>
     *
     * @param dn DN в строковом формате
     * @return DER-кодированный DN
     * @throws IllegalArgumentException если строка содержит управляющие символы, неизвестный
     *     атрибут или недопустимое значение
     */
    public static byte[] encodeDn(String dn) {
        // Проверка до split/trim: trim() срезает всё <= U+0020, включая NUL, и такой символ
        // прошёл бы в проверку значения уже «очищенным».
        for (int i = 0; i < dn.length(); i++) {
            if (Character.isISOControl(dn.charAt(i))) {
                throw new IllegalArgumentException("DN contains a control character");
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String part : dn.split(",")) {
            part = part.trim();
            String[] kv = part.split("=", 2);
            String key = kv[0].trim();
            String value = kv.length > 1 ? kv[1].trim() : "";
            String oid;
            String upperKey = key.toUpperCase(java.util.Locale.ROOT);
            switch (upperKey) {
                case "CN":
                    oid = GostOids.ATTR_CN;
                    break;
                case "O":
                    oid = GostOids.ATTR_O;
                    break;
                case "OU":
                    oid = GostOids.ATTR_OU;
                    break;
                case "L":
                    oid = GostOids.ATTR_L;
                    break;
                case "ST":
                    oid = GostOids.ATTR_ST;
                    break;
                case "C":
                    oid = GostOids.ATTR_C;
                    break;
                case "STREET":
                    oid = GostOids.ATTR_STREET;
                    break;
                case "T":
                    oid = GostOids.ATTR_T;
                    break;
                case "SN":
                    oid = GostOids.ATTR_SN;
                    break;
                case "GN":
                    oid = GostOids.ATTR_GN;
                    break;
                case "SERIALNUMBER":
                    oid = GostOids.ATTR_SERIALNUMBER;
                    break;
                case "POSTALCODE":
                    oid = GostOids.ATTR_POSTAL_CODE;
                    break;
                case "UNIQUE_IDENTIFIER":
                    oid = GostOids.ATTR_UNIQUE_ID;
                    break;
                case "PSEUDONYM":
                    oid = GostOids.ATTR_PSEUDONYM;
                    break;
                case "EMAILADDRESS":
                    oid = GostOids.ATTR_EMAIL;
                    break;
                case "UID":
                    oid = GostOids.ATTR_UID;
                    break;
                case "ORGANIZATIONIDENTIFIER":
                    oid = GostOids.ATTR_ORG_ID;
                    break;
                case "INN":
                    oid = GostOids.ATTR_INN;
                    break;
                case "OGRNIP":
                    oid = GostOids.ATTR_OGRNIP;
                    break;
                case "INNLE":
                    oid = GostOids.ATTR_INNLE;
                    break;
                case "OGRN":
                    oid = GostOids.ATTR_OGRN;
                    break;
                case "SNILS":
                    oid = GostOids.ATTR_SNILS;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown DN attribute: " + key);
            }
            // Типы значений по RFC 5280 Appendix A: countryName и serialNumber —
            // PrintableString, emailAddress — IA5String, остальное — UTF8String.
            int valueTag = DerCodec.TAG_UTF8_STRING;
            byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
            if (GostOids.ATTR_EMAIL.equals(oid)) {
                for (int i = 0; i < value.length(); i++) {
                    if (value.charAt(i) > 0x7F) {
                        throw new IllegalArgumentException(
                                "emailAddress value must contain only ASCII characters");
                    }
                }
                valueTag = TAG_IA5_STRING;
                valueBytes = value.getBytes(StandardCharsets.US_ASCII);
            } else if (GostOids.ATTR_C.equals(oid)) {
                requireCountryCode(value);
                valueTag = TAG_PRINTABLE_STRING;
                valueBytes = value.getBytes(StandardCharsets.US_ASCII);
            } else if (GostOids.ATTR_SERIALNUMBER.equals(oid)) {
                requireDnSerialNumber(value);
                valueTag = TAG_PRINTABLE_STRING;
                valueBytes = value.getBytes(StandardCharsets.US_ASCII);
            }
            byte[] attr =
                    DerCodec.encodeSequence(
                            DerCodec.encodeOid(oid), DerCodec.encodeTlv(valueTag, valueBytes));
            try {
                out.write(DerCodec.encodeTlv(DerCodec.TAG_SET, attr));
            } catch (java.io.IOException e) {
                throw new RuntimeException("DN encode failed", e);
            }
        }
        return DerCodec.encodeSequence(out.toByteArray());
    }
}
