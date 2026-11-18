package org.rssys.gost.pkix.cert;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.rssys.gost.pkix.GostOids;

/**
 * Сопоставление directoryName с поддеревом DN по RFC 5280 §7.1.
 *
 * <p>Поддерево — префикс последовательности RDN в DER-порядке (root-first).
 * AVA внутри RDN сравниваются как multiset: порядок AVA в SET не значим.</p>
 *
 * <p>Для permitted сравнение консервативное: известные caseIgnore-атрибуты
 * сравниваются без учёта типа строки и регистра, неизвестные OID — побайтно.
 * Для excluded сравнение ещё консервативнее: если OID совпал, а значение не
 * удалось декодировать как строку, это считается совпадением; RDN имени с дополнительными
 * AVA тоже считается вхождением в запрещённое поддерево (строже RFC 5280 §7.1, где RDN
 * сравниваются как равные множества), иначе лишний AVA позволял бы обойти запрет.</p>
 *
 * <p>Полный RFC 4518 string-prep не выполняется. Для excluded используется
 * NFKC, удаление невидимых/управляющих символов, trim/collapse и регистровая
 * нормализация; для permitted — NFC, trim/collapse и нижний регистр.</p>
 */
final class DirectoryNameSubtree {

    static final int MAX_RDNS = 64;
    static final int MAX_AVAS_PER_RDN = 16;

    private static final int TAG_UTF8_STRING = 0x0C;
    private static final int TAG_NUMERIC_STRING = 0x12;
    private static final int TAG_PRINTABLE_STRING = 0x13;
    private static final int TAG_T61_STRING = 0x14;
    private static final int TAG_IA5_STRING = 0x16;
    private static final int TAG_UNIVERSAL_STRING = 0x1C;
    private static final int TAG_BMP_STRING = 0x1E;

    private static final Set<String> CASE_IGNORE_OIDS =
            Set.of(
                    GostOids.ATTR_CN,
                    GostOids.ATTR_O,
                    GostOids.ATTR_OU,
                    GostOids.ATTR_L,
                    GostOids.ATTR_ST,
                    GostOids.ATTR_C,
                    GostOids.ATTR_STREET,
                    GostOids.ATTR_T,
                    GostOids.ATTR_SN,
                    GostOids.ATTR_GN,
                    GostOids.ATTR_SERIALNUMBER,
                    GostOids.ATTR_POSTAL_CODE,
                    GostOids.ATTR_PSEUDONYM,
                    GostOids.ATTR_EMAIL,
                    GostOids.ATTR_UID,
                    GostOids.ATTR_ORG_ID,
                    GostOids.ATTR_INN,
                    GostOids.ATTR_OGRNIP,
                    GostOids.ATTR_OGRN,
                    GostOids.ATTR_SNILS,
                    GostOids.ATTR_INNLE);

    enum MatchMode {
        BINARY,
        PERMITTED,
        EXCLUDED
    }

    static final class Dn {
        final List<Rdn> rdns;

        Dn(List<Rdn> rdns) {
            this.rdns = List.copyOf(rdns);
        }

        boolean isEmpty() {
            return rdns.isEmpty();
        }
    }

    static final class Rdn {
        final List<Ava> avas;

        Rdn(List<Ava> avas) {
            this.avas = List.copyOf(avas);
        }
    }

    static final class Ava {
        final byte[] der;
        final int oidStart;
        final int oidLen;
        final int valueStart;
        final int valueLen;
        final int valueTag;
        final String oid;

        Ava(
                byte[] der,
                int oidStart,
                int oidLen,
                int valueStart,
                int valueLen,
                int valueTag,
                String oid) {
            this.der = der;
            this.oidStart = oidStart;
            this.oidLen = oidLen;
            this.valueStart = valueStart;
            this.valueLen = valueLen;
            this.valueTag = valueTag;
            this.oid = oid;
        }
    }

    private DirectoryNameSubtree() {}

    /**
     * Разбирает DER DN.
     *
     * @param dnDer DER SEQUENCE OF RDN; пустой DN ({@code 30 00}) допустим
     * @return разобранный DN
     * @throws PkixException если структура некорректна или превышены лимиты
     */
    static Dn parse(byte[] dnDer) throws PkixException {
        if (dnDer == null) {
            throw parseError(null);
        }
        try {
            if (dnDer.length == 0 || (dnDer[0] & 0xFF) != GostDerParser.TAG_SEQUENCE) {
                throw parseError(null);
            }
            int[] dnTlv = GostDerParser.readTlv(dnDer, 0);
            if (dnTlv[1] != dnDer.length) {
                throw parseError(null);
            }

            List<Rdn> rdns = new ArrayList<>();
            int pos = dnTlv[0];
            while (pos < dnTlv[1]) {
                if (rdns.size() >= MAX_RDNS) {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "directoryName has too many RDNs (max " + MAX_RDNS + ")");
                }
                if ((dnDer[pos] & 0xFF) != GostDerParser.TAG_SET) {
                    throw parseError(null);
                }
                // Границы вложенных элементов: RDN не выходит за DN, AVA за свой RDN, поля AVA за
                // AVA; иначе вложенный элемент «съедал» бы байты соседей
                int[] rdnTlv = GostDerParser.readTlv(dnDer, pos, dnTlv[1]);
                int rdnEnd = rdnTlv[1];
                List<Ava> avas = new ArrayList<>();
                int avaPos = rdnTlv[0];
                while (avaPos < rdnEnd) {
                    if (avas.size() >= MAX_AVAS_PER_RDN) {
                        throw new PkixException(
                                PkixException.Reason.PARSE_ERROR,
                                "directoryName RDN has too many AVAs (max "
                                        + MAX_AVAS_PER_RDN
                                        + ")");
                    }
                    if ((dnDer[avaPos] & 0xFF) != GostDerParser.TAG_SEQUENCE) {
                        throw parseError(null);
                    }
                    int[] avaTlv = GostDerParser.readTlv(dnDer, avaPos, rdnEnd);
                    int avaEnd = avaTlv[1];
                    int attrPos = avaTlv[0];
                    if (attrPos >= avaEnd || (dnDer[attrPos] & 0xFF) != GostDerParser.TAG_OID) {
                        throw parseError(null);
                    }
                    int[] oidTlv = GostDerParser.readTlv(dnDer, attrPos, avaEnd);
                    String oid =
                            GostDerParser.oidBytesToDottedString(
                                    dnDer, oidTlv[0], oidTlv[1] - oidTlv[0]);
                    int valuePos = oidTlv[1];
                    if (valuePos >= avaEnd) {
                        throw parseError(null);
                    }
                    int valueTag = dnDer[valuePos] & 0xFF;
                    int[] valueTlv = GostDerParser.readTlv(dnDer, valuePos, avaEnd);
                    if (valueTlv[1] != avaEnd) {
                        throw parseError(null);
                    }
                    // Валидация на этапе разбора, а не при сопоставлении: иначе
                    // некорректная строка всплыла бы RuntimeException внутри
                    // проверки цепочки. Для NC fail-closed важнее лояльности.
                    GostDnParser.validateDnValue(
                            dnDer, valueTlv[0], valueTlv[1] - valueTlv[0], valueTag, oid);
                    avas.add(
                            new Ava(
                                    dnDer,
                                    oidTlv[0],
                                    oidTlv[1] - oidTlv[0],
                                    valueTlv[0],
                                    valueTlv[1] - valueTlv[0],
                                    valueTag,
                                    oid));
                    avaPos = avaEnd;
                }
                if (avas.isEmpty()) {
                    throw parseError(null);
                }
                rdns.add(new Rdn(avas));
                pos = rdnEnd;
            }
            return new Dn(rdns);
        } catch (PkixException e) {
            throw e;
        } catch (RuntimeException e) {
            throw parseError(e);
        }
    }

    /**
     * Проверяет, входит ли имя в поддерево.
     *
     * @param name    разобранное имя
     * @param subtree разобранное поддерево
     * @param mode    режим сравнения AVA
     * @return true если поддерево является префиксом имени
     */
    static boolean isWithinSubtree(Dn name, Dn subtree, MatchMode mode) {
        if (name == null || subtree == null || subtree.rdns.size() > name.rdns.size()) {
            return false;
        }
        for (int i = 0; i < subtree.rdns.size(); i++) {
            if (!rdnMatches(subtree.rdns.get(i), name.rdns.get(i), mode)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Сопоставляет RDN запрета (поддерева) с RDN имени.
     *
     * <p>Для {@code PERMITTED} и {@code BINARY} RDN должны совпадать как мультимножества AVA
     * (равное число). Для {@code EXCLUDED} достаточно, чтобы AVA запрета были подмножеством
     * AVA имени: лишний AVA в RDN имени не должен выводить его из запрещённого поддерева.
     * Это намеренно строже RFC 5280 §7.1: для excluded ложное срабатывание допустимо, пропуск
     * запрета — нет.</p>
     */
    private static boolean rdnMatches(Rdn subtree, Rdn name, MatchMode mode) {
        int subtreeSize = subtree.avas.size();
        int nameSize = name.avas.size();
        boolean subsetAllowed = mode == MatchMode.EXCLUDED;
        if (subsetAllowed ? subtreeSize > nameSize : subtreeSize != nameSize) {
            return false;
        }
        // Частые случаи без выделения памяти: RDN из одного AVA.
        if (subtreeSize == 1) {
            Ava wanted = subtree.avas.get(0);
            for (int i = 0; i < nameSize; i++) {
                if (avaMatches(wanted, name.avas.get(i), mode)) {
                    return true;
                }
            }
            return false;
        }
        return hasPerfectSubtreeMatching(subtree, name, mode);
    }

    /**
     * Ищет паросочетание, в котором каждому AVA запрета достаётся отдельный AVA имени.
     *
     * <p>Жадного перебора недостаточно: для excluded недекодируемое значение совпадает с любым
     * значением того же OID (fail-closed), поэтому отношение не транзитивно, и жадный выбор
     * может занять AVA, нужный другому, и потерять существующее сопоставление, то есть
     * пропустить запрет. Алгоритм Куна (дополняющие пути) от порядка перебора не зависит;
     * число AVA в RDN ограничено {@link #MAX_AVAS_PER_RDN}.</p>
     */
    private static boolean hasPerfectSubtreeMatching(Rdn subtree, Rdn name, MatchMode mode) {
        int[] nameOwner = new int[name.avas.size()];
        Arrays.fill(nameOwner, -1);
        for (int subtreeIdx = 0; subtreeIdx < subtree.avas.size(); subtreeIdx++) {
            boolean[] visited = new boolean[name.avas.size()];
            if (!tryAssign(subtreeIdx, subtree, name, mode, nameOwner, visited)) {
                return false;
            }
        }
        return true;
    }

    private static boolean tryAssign(
            int subtreeIdx,
            Rdn subtree,
            Rdn name,
            MatchMode mode,
            int[] nameOwner,
            boolean[] visited) {
        Ava wanted = subtree.avas.get(subtreeIdx);
        for (int nameIdx = 0; nameIdx < name.avas.size(); nameIdx++) {
            if (visited[nameIdx] || !avaMatches(wanted, name.avas.get(nameIdx), mode)) {
                continue;
            }
            visited[nameIdx] = true;
            // Свободный AVA имени, либо прежнему владельцу находится другая пара.
            if (nameOwner[nameIdx] < 0
                    || tryAssign(nameOwner[nameIdx], subtree, name, mode, nameOwner, visited)) {
                nameOwner[nameIdx] = subtreeIdx;
                return true;
            }
        }
        return false;
    }

    private static boolean avaMatches(Ava a, Ava b, MatchMode mode) {
        if (!GostDerParser.arrayRangeEquals(
                a.der, a.oidStart, a.oidLen, b.der, b.oidStart, b.oidLen)) {
            return false;
        }
        return switch (mode) {
            case BINARY ->
                    a.valueTag == b.valueTag
                            && GostDerParser.arrayRangeEquals(
                                    a.der,
                                    a.valueStart,
                                    a.valueLen,
                                    b.der,
                                    b.valueStart,
                                    b.valueLen);
            case PERMITTED -> permittedAvaMatches(a, b);
            case EXCLUDED -> excludedAvaMatches(a, b);
        };
    }

    private static boolean permittedAvaMatches(Ava a, Ava b) {
        // Побайтовое равенство не зависит от трактовки кодировки: те же байты означают то же
        // имя у любого разборщика. Для T61 это единственное безопасное сравнение: декодирование
        // в Latin-1 с приведением регистра склеило бы байты, которые в настоящей T.61 разные.
        boolean bothT61 = a.valueTag == TAG_T61_STRING && b.valueTag == TAG_T61_STRING;
        if (bothT61 || !CASE_IGNORE_OIDS.contains(a.oid)) {
            return a.valueTag == b.valueTag
                    && GostDerParser.arrayRangeEquals(
                            a.der, a.valueStart, a.valueLen, b.der, b.valueStart, b.valueLen);
        }
        String av = decodeString(a);
        String bv = decodeString(b);
        if (av == null || bv == null) {
            return false;
        }
        return normalizePermitted(av).equals(normalizePermitted(bv));
    }

    private static boolean excludedAvaMatches(Ava a, Ava b) {
        String av = decodeString(a);
        String bv = decodeString(b);
        if (av == null || bv == null) {
            // Для excluded небезопасно пропускать неподдерживаемое представление:
            // OID совпал, значит потенциально это то же имя.
            return true;
        }
        return normalizeExcluded(av).equals(normalizeExcluded(bv));
    }

    /** Декодирует строковое значение AVA; null — тип не поддерживается. */
    static String stringValue(Ava ava) {
        return decodeString(ava);
    }

    private static String decodeString(Ava ava) {
        if (!isDecodableStringTag(ava.valueTag)) {
            return null;
        }
        if (ava.valueTag == TAG_UNIVERSAL_STRING && (ava.valueLen & 3) != 0) {
            return null;
        }
        try {
            return GostDnParser.decodeDnValue(ava.der, ava.valueStart, ava.valueLen, ava.valueTag);
        } catch (RuntimeException e) {
            return null;
        }
    }

    // T61String намеренно отсутствует: настоящая T.61 не совпадает с Latin-1, поэтому одно
    // и то же значение читалось бы по-разному у нас и у стороннего разборщика. Без
    // однозначного декодирования строка сравнивается fail-closed: excluded срабатывает,
    // permitted совпадает только для двух T61 с одинаковыми байтами.
    private static boolean isDecodableStringTag(int tag) {
        return tag == TAG_UTF8_STRING
                || tag == TAG_NUMERIC_STRING
                || tag == TAG_PRINTABLE_STRING
                || tag == TAG_IA5_STRING
                || tag == TAG_UNIVERSAL_STRING
                || tag == TAG_BMP_STRING;
    }

    private static String normalizePermitted(String value) {
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFC);
        return collapseWhitespace(normalized).toLowerCase(Locale.ROOT);
    }

    private static String normalizeExcluded(String value) {
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFKC);
        StringBuilder sb = new StringBuilder(normalized.length());
        boolean pendingSpace = false;
        for (int i = 0; i < normalized.length(); ) {
            int cp = normalized.codePointAt(i);
            int type = Character.getType(cp);
            if (Character.isWhitespace(cp)) {
                if (sb.length() > 0) {
                    pendingSpace = true;
                }
            } else if (type != Character.FORMAT && type != Character.CONTROL) {
                if (pendingSpace) {
                    sb.append(' ');
                    pendingSpace = false;
                }
                sb.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        return sb.toString().toUpperCase(Locale.ROOT).toLowerCase(Locale.ROOT);
    }

    private static String collapseWhitespace(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        boolean pendingSpace = false;
        for (int i = 0; i < value.length(); ) {
            int cp = value.codePointAt(i);
            if (Character.isWhitespace(cp)) {
                if (sb.length() > 0) {
                    pendingSpace = true;
                }
            } else {
                if (pendingSpace) {
                    sb.append(' ');
                    pendingSpace = false;
                }
                sb.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        return sb.toString();
    }

    private static PkixException parseError(RuntimeException cause) {
        return new PkixException(
                PkixException.Reason.PARSE_ERROR, "Invalid directoryName DER", cause);
    }
}
