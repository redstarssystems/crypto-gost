package org.rssys.gost.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Кодек DER-примитивов (TLV, OID, INTEGER, SEQUENCE, SET, BIT STRING, OCTET STRING).
 * <p>
 * Содержит encode и decode операции для основных ASN.1 DER-типов.
 * Выделен из {@code GostDerCodec} — тот теперь отвечает только за
 * публичный API кодирования ГОСТ-ключей, делегируя DER-инфраструктуру сюда.
 */
public final class DerCodec {

    // ========================================================================
    // ASN.1 теги
    // ========================================================================

    /** Размер тега в байтах: многобайтная форма тега не поддерживается. */
    private static final int TAG_LENGTH = 1;

    public static final int TAG_BOOLEAN = 0x01;
    public static final int TAG_INTEGER = 0x02;
    public static final int TAG_BIT_STRING = 0x03;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_NULL = 0x05;
    public static final int TAG_OID = 0x06;
    public static final int TAG_ENUMERATED = 0x0A;
    public static final int TAG_UTF8_STRING = 0x0C;
    public static final int TAG_PRINTABLE_STRING = 0x13;
    public static final int TAG_IA5_STRING = 0x16;
    public static final int TAG_UTC_TIME = 0x17;
    public static final int TAG_GENERALIZED_TIME = 0x18;
    public static final int TAG_SEQUENCE = 0x30;
    public static final int TAG_SET = 0x31;

    /** Базовый тег для контекстно-зависимых constructed-тегов: {@code 0xA0 | tagNum}. */
    public static final int TAG_CTX_BASE = 0xA0;

    /** BER constructed OCTET STRING: {@code 0x04 | 0x20}. */
    public static final int TAG_OCTET_STRING_CONSTRUCTED = 0x24;

    /** Контекстно-зависимый constructed-тег [0]. */
    public static final int TAG_CTX_CONSTRUCTED_0 = 0xA0;

    /** Контекстно-зависимый constructed-тег [1]. */
    public static final int TAG_CTX_CONSTRUCTED_1 = 0xA1;

    /** Контекстно-зависимый constructed-тег [2]. */
    public static final int TAG_CTX_CONSTRUCTED_2 = 0xA2;

    /** Контекстно-зависимый примитивный тег [0] (IMPLICIT). */
    public static final int TAG_CTX_PRIMITIVE_0 = 0x80;

    /** Специальное значение длины: BER indefinite-length (0x80). */
    public static final int INDEFINITE_LENGTH = -1;

    /** Максимальный размер DER-контента для BIT STRING (SPKI-ключи ~512 байт, запас ×128). */
    private static final int MAX_BIT_STRING_LENGTH = 65536;

    /** Максимальный размер DER-контента для INTEGER (серийные номера, BigInteger). */
    private static final int MAX_INTEGER_LENGTH = 65536;

    private DerCodec() {}

    // ========================================================================
    // Кодирование TLV
    // ========================================================================

    /** Кодирует TLV: тег (1 байт) + DER-длина + содержимое. */
    public static byte[] encodeTlv(int tag, byte[] content) {
        byte[] lenBytes = encodeLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    /** Кодирует DER-длину. Short form (≤ 127), long form (0x81—0x84). */
    public static byte[] encodeLength(int len) {
        if (len <= 0x7F) {
            return new byte[] {(byte) len};
        } else if (len <= 0xFF) {
            return new byte[] {(byte) 0x81, (byte) len};
        } else if (len <= 0xFFFF) {
            return new byte[] {(byte) 0x82, (byte) (len >> 8), (byte) len};
        } else if (len <= 0xFFFFFF) {
            return new byte[] {(byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len};
        } else {
            return new byte[] {
                (byte) 0x84, (byte) (len >> 24), (byte) (len >> 16), (byte) (len >> 8), (byte) len
            };
        }
    }

    /** Кодирует SEQUENCE (tag 0x30) из уже-кодированных элементов. */
    public static byte[] encodeSequence(byte[]... elements) {
        return encodeConstructed(TAG_SEQUENCE, elements);
    }

    /** Кодирует SET (tag 0x31) из уже-кодированных элементов. */
    public static byte[] encodeSet(byte[]... elements) {
        return encodeConstructed(TAG_SET, elements);
    }

    /** Кодирует INTEGER (tag 0x02). */
    public static byte[] encodeInteger(int value) {
        return encodeInteger(BigInteger.valueOf(value));
    }

    /** Кодирует INTEGER (tag 0x02). */
    public static byte[] encodeInteger(BigInteger value) {
        return encodeTlv(TAG_INTEGER, value.toByteArray());
    }

    /** Кодирует BOOLEAN (tag 0x01). DER: TRUE=0xFF, FALSE=0x00. */
    public static byte[] encodeBoolean(boolean value) {
        return encodeTlv(TAG_BOOLEAN, new byte[] {value ? (byte) 0xFF : 0x00});
    }

    /** Кодирует BIT STRING (tag 0x03) с нулём неиспользуемых бит. */
    public static byte[] encodeBitString(byte[] data) {
        byte[] content = new byte[1 + data.length];
        content[0] = 0x00;
        System.arraycopy(data, 0, content, 1, data.length);
        return encodeTlv(TAG_BIT_STRING, content);
    }

    /** Кодирует OCTET STRING (tag 0x04). */
    public static byte[] encodeOctetString(byte[] data) {
        return encodeTlv(TAG_OCTET_STRING, data);
    }

    /**
     * Кодирует OID (tag 0x06) из строки вида {@code "1.2.643.7.1.1.1.1"}.
     *
     * @throws IllegalArgumentException если дуг меньше двух, дуга отрицательна или не число,
     *                                  первая дуга больше 2, либо вторая не меньше 40 при первой 0 или 1
     *                                  (X.690 §8.19.4: иначе первый subidentifier неоднозначен)
     */
    public static byte[] encodeOid(String oidStr) {
        String[] parts = oidStr.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID must have at least two arcs: " + oidStr);
        }
        int[] arcs = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            arcs[i] = Integer.parseInt(parts[i]);
            if (arcs[i] < 0) {
                throw new IllegalArgumentException("OID arc must not be negative: " + oidStr);
            }
        }
        if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= OID_FIRST_ARC_SPAN)) {
            throw new IllegalArgumentException("Invalid first OID arcs: " + oidStr);
        }
        return encodeTlv(TAG_OID, encodeOidBody(arcs));
    }

    /**
     * Кодирует контекстно-зависимый constructed-тег [tagNum].
     * Например, tagNum=0 -> 0xA0, tagNum=1 -> 0xA1.
     */
    public static byte[] encodeContextConstructed(int tagNum, byte[] content) {
        return encodeTlv(TAG_CTX_BASE | tagNum, content);
    }

    /**
     * Кодирует контекстно-зависимый примитивный тег [tagNum].
     * Например, tagNum=0 -> 0x80 для [0] IMPLICIT INTEGER.
     */
    public static byte[] encodeContextPrimitive(int tagNum, byte[] content) {
        return encodeTlv(0x80 | tagNum, content);
    }

    /**
     * Кодирует NULL (tag 0x05, длина 0).
     */
    public static byte[] encodeNull() {
        return new byte[] {(byte) TAG_NULL, 0x00};
    }

    /**
     * Кодирует PrintableString (tag 0x13).
     * Используется для Distinguished Name (IssuerAndSerialNumber).
     */
    public static byte[] encodePrintableString(String str) {
        return encodeTlv(TAG_PRINTABLE_STRING, str.getBytes(StandardCharsets.US_ASCII));
    }

    /** Кодирует UTF8String (tag 0x0C). */
    public static byte[] encodeUTF8String(String str) {
        return encodeTlv(TAG_UTF8_STRING, str.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Кодирует GeneralizedTime (tag 0x18).
     * В отличие от {@link #encodeTime}, который выбирает тег по длине строки,
     * всегда использует тег 0x18. Обязательно для TSTInfo.genTime (RFC 3161 §2.4.2).
     */
    public static byte[] encodeGeneralizedTime(String timeStr) {
        return encodeTlv(TAG_GENERALIZED_TIME, timeStr.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Кодирует время в UTCTime (до 2049) или GeneralizedTime (после 2049).
     * Выбор тега — по длине строки: ≤13 символов (YYMMDDHHMMSSZ) -> UTCTime (0x17),
     * иначе (YYYYMMDDHHMMSSZ, 15 символов) -> GeneralizedTime (0x18).
     */
    public static byte[] encodeTime(String timeStr) {
        int tag = (timeStr.length() <= UTC_TIME_MAX_LENGTH) ? TAG_UTC_TIME : TAG_GENERALIZED_TIME;
        return encodeTlv(tag, timeStr.getBytes(StandardCharsets.US_ASCII));
    }

    /** Верхняя граница длины UTCTime (YYMMDDHHmmssZ = 13 символов). RFC 5280 §4.1.2.5. */
    private static final int UTC_TIME_MAX_LENGTH = 13;

    /**
     * DER-лексикографическая сортировка элементов SET OF in-place.
     * X.690 §11.6: элементы SET OF в DER обязаны быть отсортированы
     * лексикографически по их DER-кодированию.
     *
     * <p><b>Мутирует {@code elements} in-place.</b>
     * Для иммутабельной сортировки с кодированием используйте {@link #encodeSetOf}.
     */
    public static void sortDer(byte[][] elements) {
        Arrays.sort(elements, DerCodec::compareDer);
    }

    /**
     * Кодирует SET OF с DER-сортировкой элементов.
     * X.690 §11.6: элементы SET OF в DER обязаны быть отсортированы
     * лексикографически по их DER-кодированию.
     * Критично для signedAttrs: подписывается DER-кодирование SET OF,
     * при неверном порядке подпись не верифицируется.
     */
    public static byte[] encodeSetOf(byte[]... elements) {
        byte[][] sorted = elements.clone();
        sortDer(sorted);
        return encodeConstructed(TAG_SET, sorted);
    }

    /**
     * Склеивает несколько байтовых массивов в один (без добавления тегов).
     */
    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] result = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, result, off, p.length);
            off += p.length;
        }
        return result;
    }

    // ========================================================================
    // Декодирование DER-тега
    // ========================================================================

    /**
     * Декодирует ASN.1 тег.
     * Поддерживает только однобайтовые теги (номер тега ≤ 30).
     * Многобайтовая форма (high-tag-number, {@code 0x1F} в младших битах первого октета)
     * в протоколах проекта не встречается — при её обнаружении выбрасывается исключение.
     *
     * @param data   данные
     * @param offset смещение первого байта тега
     * @return значение тега (занимает ровно один байт)
     */
    public static int decodeTag(byte[] data, int offset) {
        if (offset >= data.length) {
            throw new IllegalArgumentException(
                    "Tag offset " + offset + " out of bounds (data length " + data.length + ")");
        }
        int tag = data[offset] & 0xFF;
        if ((tag & 0x1F) == 0x1F) {
            throw new IllegalArgumentException(
                    "Multi-byte tag (high-tag-number form) at offset "
                            + offset
                            + " is not supported. All tags in CMS/X.509 fit single-byte form (≤ 30).");
        }
        return tag;
    }

    // ========================================================================
    // Декодирование DER-длины
    // ========================================================================

    /**
     * Декодирует DER-длину начиная с позиции {@code offset}.
     *
     * @return {@code int[2]}: [длина_содержимого, байт_под_длину]
     */
    public static int[] decodeLength(byte[] data, int offset) {
        if (offset >= data.length) {
            throw new IllegalArgumentException(
                    "Offset " + offset + " out of bounds (data length " + data.length + ")");
        }
        int first = data[offset] & 0xFF;
        if (first <= 0x7F) {
            return new int[] {first, 1};
        } else if (first == 0x81) {
            if (offset + 1 >= data.length) {
                throw new IllegalArgumentException(
                        "Truncated DER length (0x81): need 1 byte, have "
                                + (data.length - offset - 1));
            }
            int len = data[offset + 1] & 0xFF;
            // Минимальность кодирования (X.690 §10.1): значение <= 0x7F обязано
            // кодироваться short-form, long-form здесь — неканоническая malleability.
            if (len < 0x80) {
                throw new IllegalArgumentException(
                        "Non-minimal DER length encoding (0x81) at offset " + offset);
            }
            return new int[] {len, 2};
        } else if (first == 0x82) {
            if (offset + 2 >= data.length) {
                throw new IllegalArgumentException(
                        "Truncated DER length (0x82): need 2 bytes, have "
                                + (data.length - offset - 1));
            }
            int len = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
            if (len < 0x100) {
                throw new IllegalArgumentException(
                        "Non-minimal DER length encoding (0x82) at offset " + offset);
            }
            return new int[] {len, 3};
        } else if (first == 0x83) {
            if (offset + 3 >= data.length) {
                throw new IllegalArgumentException(
                        "Truncated DER length (0x83): need 3 bytes, have "
                                + (data.length - offset - 1));
            }
            int len =
                    ((data[offset + 1] & 0xFF) << 16)
                            | ((data[offset + 2] & 0xFF) << 8)
                            | (data[offset + 3] & 0xFF);
            if (len < 0x10000) {
                throw new IllegalArgumentException(
                        "Non-minimal DER length encoding (0x83) at offset " + offset);
            }
            return new int[] {len, 4};
        } else if (first == 0x84) {
            if (offset + 4 >= data.length) {
                throw new IllegalArgumentException(
                        "Truncated DER length (0x84): need 4 bytes, have "
                                + (data.length - offset - 1));
            }
            int len =
                    ((data[offset + 1] & 0xFF) << 24)
                            | ((data[offset + 2] & 0xFF) << 16)
                            | ((data[offset + 3] & 0xFF) << 8)
                            | (data[offset + 4] & 0xFF);
            if (len < 0) {
                throw new IllegalArgumentException(
                        "DER length 0x"
                                + Integer.toHexString(len)
                                + " at offset "
                                + offset
                                + " exceeds Integer.MAX_VALUE");
            }
            if (len < 0x1000000) {
                throw new IllegalArgumentException(
                        "Non-minimal DER length encoding (0x84) at offset " + offset);
            }
            return new int[] {len, 5};
        } else if (first == 0x80) {
            // BER indefinite-length: длина определяется маркером 0x00 0x00 (EOC)
            return new int[] {INDEFINITE_LENGTH, 1};
        }
        throw new IllegalArgumentException(
                "Unsupported DER length encoding: 0x" + Integer.toHexString(first));
    }

    /**
     * Декодирует длину и требует определённую (definite) форму.
     * <p>
     * Отклоняет indefinite-length (0x80): по X.690 §8.1.3.6 она допустима только для
     * constructed-типов, а в DER (§10.1) запрещена вовсе. Используется примитивными
     * декодерами, чтобы malformed-BER не приводил к молчаливому мис-парсингу значения.
     *
     * @param data     исходный массив
     * @param offset   смещение байта длины
     * @param typeName имя типа для диагностики
     * @return {@code [длина, число байт кодировки длины]}
     * @throws IllegalArgumentException при indefinite-length
     */
    private static int[] decodeDefiniteLength(byte[] data, int offset, String typeName) {
        int[] lenInfo = decodeLength(data, offset);
        if (lenInfo[0] == INDEFINITE_LENGTH) {
            throw new IllegalArgumentException(
                    typeName + " at offset " + (offset - 1) + ": INDEFINITE_LENGTH not supported");
        }
        return lenInfo;
    }

    /**
     * Возвращает конец содержимого примитивного элемента, проверяя границы без переполнения.
     * <p>
     * Сумма {@code contentOff + len} при длине около {@code Integer.MAX_VALUE} переходит в
     * отрицательное число и проходит проверку «не больше data.length»; сравнение остатка
     * буфера с длиной такого переполнения лишено.
     *
     * @param data       исходный массив
     * @param contentOff смещение начала содержимого
     * @param len        заявленная длина содержимого (после {@link #decodeDefiniteLength})
     * @param limit      верхняя граница (не включая), не больше {@code data.length}
     * @param typeName   имя типа для диагностики
     * @param offset     смещение тега элемента для диагностики
     * @return смещение конца содержимого
     * @throws IllegalArgumentException если содержимое выходит за границу
     */
    private static int contentEndWithin(
            byte[] data, int contentOff, int len, int limit, String typeName, int offset) {
        if (contentOff > limit || len < 0 || len > limit - contentOff) {
            throw new IllegalArgumentException(
                    typeName
                            + " at offset "
                            + offset
                            + ": content length "
                            + len
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        return contentOff + len;
    }

    // ========================================================================
    // Парсинг (возвращают копии содержимого)
    // ========================================================================

    /**
     * Разбирает SEQUENCE и возвращает вложенные элементы как массив DER-байт каждого.
     *
     * @param data   исходный массив
     * @param offset смещение тега SEQUENCE (0x30)
     */
    public static byte[][] parseSequenceContents(byte[] data, int offset) {
        return parseConstructedContents(data, offset, TAG_SEQUENCE, "SEQUENCE");
    }

    /**
     * Общий разбор SEQUENCE и SET: различаются только тег и название в сообщениях об ошибках,
     * а правила длины, indefinite-length и границ дочерних элементов одни.
     */
    private static byte[][] parseConstructedContents(
            byte[] data, int offset, int expectedTag, String name) {
        checkTag(data, offset, expectedTag, name);
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        int contentEnd;
        boolean indefinite = (lenInfo[0] == INDEFINITE_LENGTH);
        if (indefinite) {
            contentEnd = findEoc(data, contentOff);
        } else {
            int remaining = data.length - contentOff;
            if (lenInfo[0] < 0 || lenInfo[0] > remaining) {
                throw new IllegalArgumentException(
                        name
                                + " at offset "
                                + offset
                                + ": content length "
                                + lenInfo[0]
                                + " exceeds remaining data ("
                                + remaining
                                + " bytes)");
            }
            contentEnd = contentOff + lenInfo[0];
        }

        if (contentEnd > data.length) {
            throw new IllegalArgumentException(
                    name
                            + " at offset "
                            + offset
                            + ": content end "
                            + contentEnd
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }

        ArrayList<byte[]> elements = new ArrayList<>();
        int pos = contentOff;
        while (pos < contentEnd) {
            int[] childLen = decodeLength(data, pos + 1);
            int childTotal;
            if (childLen[0] == INDEFINITE_LENGTH) {
                // BER: конец элемента по EOC (0x00 0x00)
                int eoc = findEoc(data, pos + 1 + childLen[1]);
                childTotal = eoc + 2 - pos; // включая тег, длину, содержимое и EOC
            } else {
                // Проверка до сложения — предотвращает int overflow от больших длин
                int childRemaining = contentEnd - pos - 1 - childLen[1];
                if (childLen[0] < 0 || childLen[0] > childRemaining) {
                    throw new IllegalArgumentException(
                            name
                                    + " at offset "
                                    + offset
                                    + ": child content length "
                                    + childLen[0]
                                    + " exceeds remaining data ("
                                    + childRemaining
                                    + " bytes)"
                                    + " at position "
                                    + pos);
                }
                childTotal = 1 + childLen[1] + childLen[0];
            }
            if (pos + childTotal > contentEnd) {
                throw new IllegalArgumentException(
                        name
                                + " at offset "
                                + offset
                                + ": child at position "
                                + pos
                                + " exceeds "
                                + name
                                + " bounds (contentEnd "
                                + contentEnd
                                + ")");
            }
            elements.add(Arrays.copyOfRange(data, pos, pos + childTotal));
            pos += childTotal;
        }
        return elements.toArray(new byte[0][]);
    }

    /**
     * Строго разбирает SEQUENCE по DER и возвращает копии вложенных элементов.
     * <p>
     * В отличие от {@link #parseSequenceContents}: принимает только определённую длину
     * (indefinite-length отвергается на всех уровнях, {@link #findEoc} не вызывается), требует,
     * чтобы SEQUENCE занимала весь вход ({@code data} — точный TLV, без хвоста), и не допускает
     * потомка с тегом {@code 0x00} (EOC) или многобайтным тегом. Метод самостоятельный, а не
     * обёртка над {@code parseSequenceContents}: иначе indefinite-length легко протащить во
     * вложенный элемент. Возвращает копии, поэтому вызов на элементе результата снова получает
     * точный TLV-срез.
     *
     * @param data DER-кодирование SEQUENCE целиком
     * @throws IllegalArgumentException при BER-форме, хвосте, выходе потомка за границу родителя
     */
    public static byte[][] parseStrictSequence(byte[] data) {
        checkTag(data, 0, TAG_SEQUENCE, "SEQUENCE");
        int[] lenInfo = decodeDefiniteLength(data, 1, "SEQUENCE");
        int contentOff = 1 + lenInfo[1];
        int contentEnd = contentEndWithin(data, contentOff, lenInfo[0], data.length, "SEQUENCE", 0);
        if (contentEnd != data.length) {
            throw new IllegalArgumentException(
                    "SEQUENCE: "
                            + (data.length - contentEnd)
                            + " trailing byte(s) after the element (data length "
                            + data.length
                            + ")");
        }

        ArrayList<byte[]> elements = new ArrayList<>();
        int pos = contentOff;
        while (pos < contentEnd) {
            if (data[pos] == 0x00) {
                // 0x00 в позиции тега — маркер EOC, а не элемент: так выглядит BER indefinite
                throw new IllegalArgumentException(
                        "SEQUENCE: unexpected end-of-contents marker at position " + pos);
            }
            decodeTag(data, pos); // отвергает многобайтные теги
            int[] childLen = decodeDefiniteLength(data, pos + 1, "SEQUENCE child");
            int childContentOff = pos + 1 + childLen[1];
            int childEnd =
                    contentEndWithin(
                            data, childContentOff, childLen[0], contentEnd, "SEQUENCE child", pos);
            elements.add(Arrays.copyOfRange(data, pos, childEnd));
            pos = childEnd;
        }
        return elements.toArray(new byte[0][]);
    }

    /**
     * Приводит BER-кодирование SEQUENCE, допускающее indefinite-length, к DER с определённой длиной.
     * <p>
     * Предназначено для AlgorithmIdentifier и подобных структур из SEQUENCE и примитивов,
     * которые КриптоПро в CMS иногда кодирует с indefinite-length. Определённая длина сама
     * по себе не делает элемент DER, поэтому метод намеренно узкий: вход — ровно один элемент
     * SEQUENCE без байт после него (после EOC тоже); вложенные SEQUENCE переписываются
     * рекурсивно (глубина ограничена); примитивные элементы копируются без изменений и обязаны
     * иметь определённую длину; любой иной constructed-тег (constructed OCTET STRING/BIT STRING,
     * SET и т.п.) отвергается — для них нужны склейка или сортировка. Результат идемпотентен.
     *
     * @param element BER- или DER-кодирование SEQUENCE
     * @return DER-кодирование того же значения
     * @throws IllegalArgumentException при любом нарушении перечисленного
     */
    public static byte[] normalizeBerSequenceToDer(byte[] element) {
        int[] elementEnd = new int[1];
        byte[] normalized = normalizeSequence(element, 0, element.length, 0, elementEnd);
        if (elementEnd[0] != element.length) {
            throw new IllegalArgumentException(
                    "SEQUENCE: "
                            + (element.length - elementEnd[0])
                            + " trailing byte(s) after the element (data length "
                            + element.length
                            + ")");
        }
        return normalized;
    }

    private static byte[] normalizeSequence(
            byte[] data, int offset, int limit, int depth, int[] elementEnd) {
        if (depth > MAX_BER_NORMALIZE_NESTING) {
            throw new IllegalArgumentException(
                    "SEQUENCE nesting exceeds "
                            + MAX_BER_NORMALIZE_NESTING
                            + " at offset "
                            + offset);
        }
        if (offset < 0 || offset >= limit) {
            throw new IllegalArgumentException(
                    "Offset " + offset + " out of bounds (data length " + limit + ")");
        }
        checkTag(data, offset, TAG_SEQUENCE, "SEQUENCE");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        int contentEnd;
        if (lenInfo[0] == INDEFINITE_LENGTH) {
            contentEnd = findEoc(data, contentOff, limit);
            elementEnd[0] = contentEnd + EOC_LENGTH;
        } else {
            contentEnd = contentEndWithin(data, contentOff, lenInfo[0], limit, "SEQUENCE", offset);
            elementEnd[0] = contentEnd;
        }

        ArrayList<byte[]> children = new ArrayList<>();
        int pos = contentOff;
        while (pos < contentEnd) {
            int tag = decodeTag(data, pos);
            if (tag == 0x00) {
                throw new IllegalArgumentException(
                        "SEQUENCE: unexpected end-of-contents marker at position " + pos);
            }
            if (tag == TAG_SEQUENCE) {
                int[] childEnd = new int[1];
                children.add(normalizeSequence(data, pos, contentEnd, depth + 1, childEnd));
                pos = childEnd[0];
            } else if ((tag & CONSTRUCTED_BIT) != 0) {
                throw new IllegalArgumentException(
                        "Unsupported constructed tag 0x"
                                + Integer.toHexString(tag)
                                + " at offset "
                                + pos
                                + ": only SEQUENCE and primitive elements can be normalized");
            } else {
                int[] childLen = decodeDefiniteLength(data, pos + 1, "primitive element");
                int childContentOff = pos + 1 + childLen[1];
                int childEnd =
                        contentEndWithin(
                                data,
                                childContentOff,
                                childLen[0],
                                contentEnd,
                                "primitive element",
                                pos);
                children.add(Arrays.copyOfRange(data, pos, childEnd));
                pos = childEnd;
            }
        }
        return encodeSequence(children.toArray(new byte[0][]));
    }

    /**
     * Значение BIT STRING: число неиспользуемых бит последнего байта и сами данные.
     *
     * @param unusedBits число неиспользуемых бит последнего байта (0..7)
     * @param data       содержимое без ведущего байта {@code unusedBits}
     */
    public record BitStringValue(int unusedBits, byte[] data) {}

    /**
     * Разбирает BIT STRING и возвращает содержимое без ведущего байта.
     * <p>
     * Число неиспользуемых бит проверяется так же, как в {@link #parseBitStringWithUnused}
     * (не больше 7, неиспользуемые биты нулевые), но не возвращается: подходит для полей,
     * где допустимы неиспользуемые биты (например, KeyUsage). Для ключей и подписей, где они
     * недопустимы, используйте {@link #parseBitStringWithUnused}.
     */
    public static byte[] parseBitString(byte[] data, int offset) {
        return parseBitStringWithUnused(data, offset).data();
    }

    /**
     * Разбирает BIT STRING по DER (X.690 §11.2) и возвращает число неиспользуемых бит вместе с данными.
     * <p>
     * Отвергает: пустое содержимое (без байта {@code unusedBits}); {@code unusedBits > 7};
     * ненулевые неиспользуемые биты последнего байта; {@code unusedBits != 0} при отсутствии данных.
     * Единственное место проверки, чтобы путь SPKI не получил невалидированный {@code unusedBits}.
     */
    public static BitStringValue parseBitStringWithUnused(byte[] data, int offset) {
        checkTag(data, offset, TAG_BIT_STRING, "BIT STRING");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "BIT STRING");
        int contentOff = offset + 1 + lenInfo[1];
        if (lenInfo[0] < 1 || lenInfo[0] > MAX_BIT_STRING_LENGTH) {
            throw new IllegalArgumentException(
                    "BIT STRING at offset "
                            + offset
                            + ": content length "
                            + lenInfo[0]
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        int contentEnd =
                contentEndWithin(data, contentOff, lenInfo[0], data.length, "BIT STRING", offset);
        int unusedBits = data[contentOff] & 0xFF;
        if (unusedBits > 7) {
            throw new IllegalArgumentException(
                    "BIT STRING at offset "
                            + offset
                            + ": unused bits count "
                            + unusedBits
                            + " > 7");
        }
        if (unusedBits != 0) {
            // Без данных неиспользуемых бит быть не может; иначе младшие биты последнего байта
            // обязаны быть нулевыми, иначе одно значение имеет разные кодировки (X.690 §11.2.1)
            if (lenInfo[0] == 1 || (data[contentEnd - 1] & ((1 << unusedBits) - 1)) != 0) {
                throw new IllegalArgumentException(
                        "BIT STRING at offset "
                                + offset
                                + ": non-zero unused bits (DER requires zero padding)");
            }
        }
        return new BitStringValue(unusedBits, Arrays.copyOfRange(data, contentOff + 1, contentEnd));
    }

    /** Разбирает OCTET STRING и возвращает содержимое. */
    public static byte[] parseOctetString(byte[] data, int offset) {
        checkTag(data, offset, TAG_OCTET_STRING, "OCTET STRING");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "OCTET STRING");
        int contentOff = offset + 1 + lenInfo[1];
        int contentEnd =
                contentEndWithin(data, contentOff, lenInfo[0], data.length, "OCTET STRING", offset);
        return Arrays.copyOfRange(data, contentOff, contentEnd);
    }

    /** Предел вложенности constructed OCTET STRING — защита от переполнения стека на злонамеренном BER. */
    private static final int MAX_OCTET_STRING_NESTING = 32;

    /** Предел вложенности SEQUENCE при нормализации BER в DER; AlgorithmIdentifier вкладывается на 2–3 уровня. */
    private static final int MAX_BER_NORMALIZE_NESTING = 16;

    /** Длина маркера конца BER indefinite-length (0x00 0x00). */
    private static final int EOC_LENGTH = 2;

    /** Бит constructed в октете тега (X.690 §8.1.2.5). */
    private static final int CONSTRUCTED_BIT = 0x20;

    /**
     * Собирает содержимое OCTET STRING, допуская BER-кодирования, которые
     * {@link #parseOctetString} отклоняет. Предназначен для полей вида
     * {@code [n] IMPLICIT OCTET STRING} (например {@code encryptedContent} в CMS),
     * где КриптоПРО применяет constructed context-тег с indefinite-length.
     *
     * <p>Принимает:
     * <ul>
     *   <li>{@code 0x04} — primitive OCTET STRING (только definite-length);</li>
     *   <li>{@code 0x24} — constructed OCTET STRING (definite или indefinite);</li>
     *   <li>{@code 0xA0} — constructed context [0] ({@code [0] IMPLICIT} для
     *       сегментированного OCTET STRING; сегменты внутри — {@code 0x04}/{@code 0x24}).</li>
     * </ul>
     * Содержимое всех вложенных сегментов конкатенируется в порядке следования.
     * Любой иной тег -> {@link IllegalArgumentException} (fail-closed).
     */
    public static byte[] collectImplicitOctets(byte[] data, int offset) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        collectImplicitOctets(data, offset, data.length, out, 0);
        return out.toByteArray();
    }

    /**
     * Рекурсивно собирает содержимое сегмента OCTET STRING.
     * <p>
     * Каждый элемент обязан целиком лежать внутри {@code limit} (конец содержимого родителя):
     * без этого потомок с заявленной длиной за границей родителя читал бы байты соседних полей,
     * а переполнение сумм давало пустой результат вместо ошибки. BER indefinite-length
     * допустим только у constructed-сегментов.
     *
     * @return смещение первого байта после разобранного элемента (с учётом EOC)
     */
    private static int collectImplicitOctets(
            byte[] data, int offset, int limit, ByteArrayOutputStream out, int depth) {
        if (depth > MAX_OCTET_STRING_NESTING) {
            throw new IllegalArgumentException(
                    "OCTET STRING nesting exceeds "
                            + MAX_OCTET_STRING_NESTING
                            + " at offset "
                            + offset);
        }
        if (offset < 0 || offset >= limit) {
            throw new IllegalArgumentException(
                    "Offset " + offset + " out of bounds (data length " + limit + ")");
        }
        int tag = data[offset] & 0xFF;

        if (tag == TAG_OCTET_STRING) {
            // primitive: indefinite-length по X.690 недопустима -> decodeDefiniteLength отвергнет
            int[] lenInfo = decodeDefiniteLength(data, offset + 1, "OCTET STRING");
            int contentOff = offset + 1 + lenInfo[1];
            int contentEnd =
                    contentEndWithin(data, contentOff, lenInfo[0], limit, "OCTET STRING", offset);
            out.write(data, contentOff, lenInfo[0]);
            return contentEnd;
        }

        if (tag == TAG_OCTET_STRING_CONSTRUCTED || tag == TAG_CTX_CONSTRUCTED_0) {
            int[] lenInfo = decodeLength(data, offset + 1);
            int contentOff = offset + 1 + lenInfo[1];
            int contentEnd;
            int elementEnd;
            if (lenInfo[0] == INDEFINITE_LENGTH) {
                contentEnd = findEoc(data, contentOff, limit);
                elementEnd = contentEnd + EOC_LENGTH;
            } else {
                contentEnd =
                        contentEndWithin(
                                data,
                                contentOff,
                                lenInfo[0],
                                limit,
                                "Constructed OCTET STRING",
                                offset);
                elementEnd = contentEnd;
            }
            int pos = contentOff;
            while (pos < contentEnd) {
                // Потомок ограничен contentEnd: рекурсия возвращает конец не дальше него
                pos = collectImplicitOctets(data, pos, contentEnd, out, depth + 1);
            }
            return elementEnd;
        }

        throw new IllegalArgumentException(
                "Unexpected tag 0x"
                        + Integer.toHexString(tag)
                        + " at offset "
                        + offset
                        + ": expected OCTET STRING (0x04/0x24) or constructed context [0] (0xA0)");
    }

    /**
     * Разбирает OID по DER (X.690 §8.19) и возвращает строку вида {@code "1.2.643.7.1.1.1.1"}.
     * <p>
     * Отвергает: пустое содержимое; обрезанную последнюю дугу (бит продолжения в последнем байте);
     * неминимальную дугу (ведущий {@code 0x80}); дугу, не помещающуюся в 63 бита. Первый subidentifier
     * (X.690 §8.19.4) может занимать несколько байт и раскладывается на первые две дуги:
     * значение &lt; 40 -> {@code 0.x}, &lt; 80 -> {@code 1.(x-40)}, иначе {@code 2.(x-80)}.
     */
    public static String parseOid(byte[] data, int offset) {
        checkTag(data, offset, TAG_OID, "OID");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "OID");
        int contentOff = offset + 1 + lenInfo[1];
        int contentEnd = contentEndWithin(data, contentOff, lenInfo[0], data.length, "OID", offset);
        if (lenInfo[0] == 0) {
            throw new IllegalArgumentException("OID at offset " + offset + ": empty content");
        }

        StringBuilder sb = new StringBuilder();
        boolean firstSubidentifier = true;
        boolean arcStarted = false;
        long value = 0;
        for (int i = contentOff; i < contentEnd; i++) {
            int b = data[i] & 0xFF;
            if (!arcStarted && b == 0x80) {
                // Ведущий 0x80 — нулевые старшие разряды: одно значение имело бы несколько
                // кодировок
                throw new IllegalArgumentException(
                        "Non-minimal OID arc encoding at position "
                                + i
                                + " in OID at offset "
                                + offset);
            }
            arcStarted = true;
            // Защита от переполнения: после сдвига value должно остаться < 2^63
            if ((value >>> OID_ARC_OVERFLOW_SHIFT) != 0) {
                throw new IllegalArgumentException(
                        "OID arc value overflow at position " + i + " in OID at offset " + offset);
            }
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                if (firstSubidentifier) {
                    appendFirstTwoArcs(sb, value);
                    firstSubidentifier = false;
                } else {
                    sb.append('.').append(value);
                }
                value = 0;
                arcStarted = false;
            }
        }
        if (arcStarted) {
            throw new IllegalArgumentException(
                    "Truncated OID arc (continuation bit set in last byte) in OID at offset "
                            + offset);
        }
        return sb.toString();
    }

    /** Сдвиг для проверки переполнения дуги: {@code value >>> 56 != 0} означает, что {@code value << 7} выйдет за 2^63. */
    private static final int OID_ARC_OVERFLOW_SHIFT = 56;

    /** Первая дуга 0 или 1 покрывает по 40 значений первого subidentifier. */
    private static final int OID_FIRST_ARC_SPAN = 40;

    /** Значения первого subidentifier от 80 принадлежат дуге 2 (joint-iso-itu-t). */
    private static final int OID_FIRST_ARC_JOINT = 80;

    private static void appendFirstTwoArcs(StringBuilder sb, long firstSubidentifier) {
        if (firstSubidentifier < OID_FIRST_ARC_SPAN) {
            sb.append("0.").append(firstSubidentifier);
        } else if (firstSubidentifier < OID_FIRST_ARC_JOINT) {
            sb.append("1.").append(firstSubidentifier - OID_FIRST_ARC_SPAN);
        } else {
            sb.append("2.").append(firstSubidentifier - OID_FIRST_ARC_JOINT);
        }
    }

    /** Разбирает INTEGER и возвращает BigInteger. */
    public static BigInteger parseInteger(byte[] data, int offset) {
        checkTag(data, offset, TAG_INTEGER, "INTEGER");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "INTEGER");
        int contentOff = offset + 1 + lenInfo[1];
        if (lenInfo[0] > MAX_INTEGER_LENGTH) {
            throw new IllegalArgumentException(
                    "INTEGER at offset "
                            + offset
                            + ": content length "
                            + lenInfo[0]
                            + " exceeds "
                            + MAX_INTEGER_LENGTH);
        }
        int contentEnd =
                contentEndWithin(data, contentOff, lenInfo[0], data.length, "INTEGER", offset);
        return new BigInteger(Arrays.copyOfRange(data, contentOff, contentEnd));
    }

    /**
     * Разбирает BOOLEAN (tag 0x01) строго по DER (X.690 §11.1): ровно один октет,
     * {@code 0x00} = FALSE, {@code 0xFF} = TRUE. Любое другое значение и длина отвергаются:
     * BER-вариант «любой ненулевой октет = TRUE» не принимается.
     */
    public static boolean parseBoolean(byte[] data, int offset) {
        checkTag(data, offset, TAG_BOOLEAN, "BOOLEAN");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "BOOLEAN");
        int contentOff = offset + 1 + lenInfo[1];
        contentEndWithin(data, contentOff, lenInfo[0], data.length, "BOOLEAN", offset);
        if (lenInfo[0] != 1) {
            throw new IllegalArgumentException(
                    "BOOLEAN at offset " + offset + ": length must be 1, got " + lenInfo[0]);
        }
        int value = data[contentOff] & 0xFF;
        if (value == 0x00) {
            return false;
        }
        if (value == 0xFF) {
            return true;
        }
        throw new IllegalArgumentException(
                "BOOLEAN at offset "
                        + offset
                        + ": DER value must be 0x00 or 0xFF, got 0x"
                        + Integer.toHexString(value));
    }

    /** Разбирает GeneralizedTime (tag 0x18) и возвращает строку YYYYMMDDHHmmssZ. */
    public static String parseGeneralizedTime(byte[] data, int offset) {
        checkTag(data, offset, TAG_GENERALIZED_TIME, "GeneralizedTime");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "GeneralizedTime");
        int contentOff = offset + 1 + lenInfo[1];
        contentEndWithin(data, contentOff, lenInfo[0], data.length, "GeneralizedTime", offset);
        return new String(data, contentOff, lenInfo[0], StandardCharsets.US_ASCII);
    }

    /** Разбирает UTF8String (tag 0x0C) и возвращает строку. */
    public static String parseUTF8String(byte[] data, int offset) {
        checkTag(data, offset, TAG_UTF8_STRING, "UTF8String");
        int[] lenInfo = decodeDefiniteLength(data, offset + 1, "UTF8String");
        int contentOff = offset + 1 + lenInfo[1];
        contentEndWithin(data, contentOff, lenInfo[0], data.length, "UTF8String", offset);
        return new String(data, contentOff, lenInfo[0], StandardCharsets.UTF_8);
    }

    /**
     * Разбирает SET OF — возвращает элементы как DER-байты.
     * Поддерживает BER indefinite-length.
     */
    public static byte[][] parseSetContents(byte[] data, int offset) {
        return parseConstructedContents(data, offset, TAG_SET, "SET");
    }

    // ========================================================================
    // Приватные утилиты
    // ========================================================================

    /** Кодирует constructed-тип (SEQUENCE, SET) из уже-кодированных элементов. */
    private static byte[] encodeConstructed(int tag, byte[]... elements) {
        int total = 0;
        for (byte[] e : elements) total += e.length;
        byte[] content = new byte[total];
        int off = 0;
        for (byte[] e : elements) {
            System.arraycopy(e, 0, content, off, e.length);
            off += e.length;
        }
        return encodeTlv(tag, content);
    }

    /** Кодирует тело OID (без тега и длины) из массива компонентов. */
    private static byte[] encodeOidBody(int[] arcs) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // Первый subidentifier 40*a0 + a1 при a0 = 2 может не поместиться в байт (2.999 -> 1079)
        // и кодируется тем же base-128, что остальные дуги; считаем в long, чтобы не переполнить
        // int
        writeBase128(buf, (long) OID_FIRST_ARC_SPAN * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            writeBase128(buf, arcs[i]);
        }
        return buf.toByteArray();
    }

    /** Записывает неотрицательное значение в base-128: старшие группы с битом продолжения. */
    private static void writeBase128(ByteArrayOutputStream buf, long val) {
        int bits = 64 - Long.numberOfLeadingZeros(val);
        int groups = Math.max(1, (bits + 6) / 7);
        for (int g = groups - 1; g >= 0; g--) {
            int b = (int) ((val >>> (g * 7)) & 0x7F);
            if (g > 0) b |= 0x80;
            buf.write(b);
        }
    }

    /** Лексикографическое сравнение двух DER-кодированных элементов для сортировки SET OF. */
    private static int compareDer(byte[] a, byte[] b) {
        int minLen = Math.min(a.length, b.length);
        for (int i = 0; i < minLen; i++) {
            int cmp = (a[i] & 0xFF) - (b[i] & 0xFF);
            if (cmp != 0) return cmp;
        }
        return a.length - b.length;
    }

    /**
     * Находит позицию парного EOC-маркера (0x00 0x00) для BER indefinite-length TLV.
     * Отслеживает вложенность через структурный TLV-walk: definite-length элементы
     * пропускаются по заявленной длине, indefinite-length спускаются в контент.
     * Контентные байты не сканируются — исключены ложные срабатывания на
     * {@code 0x00 0x00} и {@code (constructed_tag, 0x80)} внутри данных.
     *
     * <p>Порядок проверок в цикле критичен: EOC-детекция выполняется строго до
     * {@link #decodeTag}, так как октеты EOC ({@code 0x00 0x00}) синтаксически
     * валидны как тег 0 с длиной 0 и были бы тихо «съедены» без проверки.
     *
     * @param data  данные
     * @param start начало содержимого (после тега и байта длины 0x80)
     */
    public static int findEoc(byte[] data, int start) {
        return findEoc(data, start, data.length);
    }

    /**
     * То же, что {@link #findEoc(byte[], int)}, но поиск ограничен {@code end} (не включая):
     * indefinite-потомок не может «убежать» за границу содержимого родителя и занять байты
     * соседних полей.
     *
     * @param data  данные
     * @param start начало содержимого (после тега и байта длины 0x80)
     * @param end   верхняя граница поиска (не больше {@code data.length})
     */
    public static int findEoc(byte[] data, int start, int end) {
        if (start < 0 || end > data.length || start > end) {
            throw new IllegalArgumentException(
                    "EOC search range [" + start + ", " + end + ") out of bounds");
        }
        int depth = 1; // текущий indefinite-элемент
        int i = start;
        while (i < end - 1) {
            // 1. EOC-проверка — строго до decodeTag, иначе 0x00 тихо распознался бы как тег 0
            if (data[i] == 0x00 && data[i + 1] == 0x00) {
                depth--;
                if (depth == 0) {
                    return i;
                }
                i += 2; // пропускаем оба байта EOC
                continue;
            }
            // 2. Декодируем тег (однобайтовый)
            int tag = decodeTag(data, i);

            // 3. Декодируем длину
            int[] lenInfo = decodeLength(data, i + TAG_LENGTH);
            int lenValue = lenInfo[0];
            int lenBytes = lenInfo[1];

            if (lenValue == INDEFINITE_LENGTH) {
                // 4. indefinite-length: constructed-элемент -> спускаемся в контент
                if ((tag & 0x20) != 0 || (tag >= 0xA0 && tag <= 0xBF)) {
                    depth++;
                }
                i += TAG_LENGTH + lenBytes;
            } else {
                // 5. definite-length: пропускаем элемент целиком (тег + длина + контент)
                int remaining = end - i - TAG_LENGTH - lenBytes;
                if (lenValue < 0 || lenValue > remaining) {
                    throw new IllegalArgumentException(
                            "Length "
                                    + lenValue
                                    + " exceeds remaining data ("
                                    + remaining
                                    + " bytes) at offset "
                                    + (i + TAG_LENGTH));
                }
                i += TAG_LENGTH + lenBytes + lenValue;
            }
        }
        throw new IllegalArgumentException("EOC marker (0x00 0x00) not found");
    }

    /** Проверяет тег DER-структуры по смещению. */
    public static void checkTag(byte[] data, int offset, int expectedTag, String name) {
        if (offset < 0 || offset >= data.length) {
            throw new IllegalArgumentException(
                    "Offset "
                            + offset
                            + " out of bounds for "
                            + name
                            + " (data length "
                            + data.length
                            + ")");
        }
        if ((data[offset] & 0xFF) != expectedTag) {
            throw new IllegalArgumentException(
                    "Expected "
                            + name
                            + " (0x"
                            + Integer.toHexString(expectedTag)
                            + ") at offset "
                            + offset
                            + ", got 0x"
                            + Integer.toHexString(data[offset] & 0xFF));
        }
    }

    /**
     * Проверяет, является ли первый байт DER-элемента контекстно-зависимым constructed-тегом
     * с указанным номером. Контекстные теги имеют диапазон {@code 0xA0 | tagNum}
     * для constructed и {@code 0x80 | tagNum} для примитивных — здесь проверяются только
     * constructed (бит 5 установлен).
     *
     * @param data   DER-элемент (хотя бы 1 байт)
     * @param tagNum номер тега (0–15)
     * @return {@code true} если первый байт совпадает с {@code 0xA0 | tagNum}
     */
    public static boolean isContextTag(byte[] data, int tagNum) {
        return data.length > 0 && (data[0] & 0xFF) == (TAG_CTX_BASE | tagNum);
    }
}
