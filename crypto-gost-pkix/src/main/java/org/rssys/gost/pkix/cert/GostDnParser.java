package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.io.ByteArrayOutputStream;
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
        switch (tag) {
            case 0x0C: // UTF8String
                return new String(der, start, len, StandardCharsets.UTF_8);
            case 0x12: // NumericString
            case 0x13: // PrintableString
            case 0x16: // IA5String
                return new String(der, start, len, StandardCharsets.US_ASCII);
            case 0x14: // T61String / TeletexString — фактически Latin-1
                return new String(der, start, len, StandardCharsets.ISO_8859_1);
            case 0x1E: // BMPString (UCS-2 big-endian)
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
     * Обрезает строку для логирования, если она длиннее maxLen.
     * Добавляет "...[truncated]" при обрезке.
     */
    static String truncateForLog(String s, int maxLen) {
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
     * @param dn DN в строковом формате
     * @return DER-кодированный DN
     */
    public static byte[] encodeDn(String dn) {
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
            byte[] attr =
                    DerCodec.encodeSequence(
                            DerCodec.encodeOid(oid),
                            DerCodec.encodeTlv(
                                    DerCodec.TAG_UTF8_STRING,
                                    value.getBytes(StandardCharsets.UTF_8)));
            try {
                out.write(DerCodec.encodeTlv(DerCodec.TAG_SET, attr));
            } catch (java.io.IOException e) {
                throw new RuntimeException("DN encode failed", e);
            }
        }
        return DerCodec.encodeSequence(out.toByteArray());
    }
}
