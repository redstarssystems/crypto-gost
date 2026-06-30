package org.rssys.gost.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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

    /** Кодирует OID (tag 0x06) из строки вида {@code "1.2.643.7.1.1.1.1"}. */
    public static byte[] encodeOid(String oidStr) {
        String[] parts = oidStr.split("\\.");
        int[] arcs = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            arcs[i] = Integer.parseInt(parts[i]);
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
     * Аналог {@code concat} из OcspRequestBuilder.
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
     * @return {@code int[2]}: [значение_тега, количество_байт_под_тег]
     */
    public static int[] decodeTag(byte[] data, int offset) {
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
        return new int[] {tag, 1};
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
            return new int[] {data[offset + 1] & 0xFF, 2};
        } else if (first == 0x82) {
            if (offset + 2 >= data.length) {
                throw new IllegalArgumentException(
                        "Truncated DER length (0x82): need 2 bytes, have "
                                + (data.length - offset - 1));
            }
            int len = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
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
            return new int[] {len, 5};
        } else if (first == 0x80) {
            // BER indefinite-length: длина определяется маркером 0x00 0x00 (EOC)
            return new int[] {INDEFINITE_LENGTH, 1};
        }
        throw new IllegalArgumentException(
                "Unsupported DER length encoding: 0x" + Integer.toHexString(first));
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
        checkTag(data, offset, TAG_SEQUENCE, "SEQUENCE");
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
                        "SEQUENCE at offset "
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
                    "SEQUENCE at offset "
                            + offset
                            + ": content end "
                            + contentEnd
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }

        java.util.ArrayList<byte[]> elements = new java.util.ArrayList<>();
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
                            "SEQUENCE at offset "
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
                        "SEQUENCE at offset "
                                + offset
                                + ": child at position "
                                + pos
                                + " exceeds SEQUENCE bounds (contentEnd "
                                + contentEnd
                                + ")");
            }
            elements.add(Arrays.copyOfRange(data, pos, pos + childTotal));
            pos += childTotal;
        }
        return elements.toArray(new byte[0][]);
    }

    /** Разбирает BIT STRING и возвращает содержимое без ведущего байта. */
    public static byte[] parseBitString(byte[] data, int offset) {
        checkTag(data, offset, TAG_BIT_STRING, "BIT STRING");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        if (lenInfo[0] < 1
                || lenInfo[0] > MAX_BIT_STRING_LENGTH
                || contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                    "BIT STRING at offset "
                            + offset
                            + ": content length "
                            + lenInfo[0]
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        return Arrays.copyOfRange(data, contentOff + 1, contentOff + lenInfo[0]);
    }

    /** Разбирает OCTET STRING и возвращает содержимое. */
    public static byte[] parseOctetString(byte[] data, int offset) {
        checkTag(data, offset, TAG_OCTET_STRING, "OCTET STRING");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        if (contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                    "OCTET STRING at offset "
                            + offset
                            + ": content length "
                            + lenInfo[0]
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        return Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]);
    }

    /** Разбирает OID и возвращает строку вида {@code "1.2.643.7.1.1.1.1"}. */
    public static String parseOid(byte[] data, int offset) {
        checkTag(data, offset, TAG_OID, "OID");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        int contentEnd = contentOff + lenInfo[0];

        if (contentOff >= data.length) {
            throw new IllegalArgumentException(
                    "OID at offset "
                            + offset
                            + ": content offset "
                            + contentOff
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        StringBuilder sb = new StringBuilder();
        int first = data[contentOff] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = contentOff + 1; i < contentEnd; i++) {
            int b = data[i] & 0xFF;
            // Защита от переполнения: биты 57–63 long заняты — value << 7 переполнит
            if ((value & 0xFE00_0000_0000_0000L) != 0) {
                throw new IllegalArgumentException(
                        "OID arc value overflow at position " + i + " in OID at offset " + offset);
            }
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(value);
                value = 0;
            }
        }
        return sb.toString();
    }

    /** Разбирает INTEGER и возвращает BigInteger. */
    public static BigInteger parseInteger(byte[] data, int offset) {
        checkTag(data, offset, TAG_INTEGER, "INTEGER");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        if (lenInfo[0] > MAX_INTEGER_LENGTH || contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                    "INTEGER at offset "
                            + offset
                            + ": content length "
                            + lenInfo[0]
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        return new BigInteger(Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]));
    }

    /** Разбирает BOOLEAN (tag 0x01). DER: 0x00 = FALSE, иначе TRUE. */
    public static boolean parseBoolean(byte[] data, int offset) {
        checkTag(data, offset, TAG_BOOLEAN, "BOOLEAN");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        if (contentOff >= data.length) {
            throw new IllegalArgumentException(
                    "BOOLEAN at offset "
                            + offset
                            + ": content offset "
                            + contentOff
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }
        return data[contentOff] != 0x00;
    }

    /** Разбирает GeneralizedTime (tag 0x18) и возвращает строку YYYYMMDDHHmmssZ. */
    public static String parseGeneralizedTime(byte[] data, int offset) {
        checkTag(data, offset, TAG_GENERALIZED_TIME, "GeneralizedTime");
        int[] lenInfo = decodeLength(data, offset + 1);
        if (lenInfo[0] < 0) {
            throw new IllegalArgumentException(
                    "GeneralizedTime at offset " + offset + ": INDEFINITE_LENGTH not supported");
        }
        int contentOff = offset + 1 + lenInfo[1];
        if (contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                    "GeneralizedTime at offset "
                            + offset
                            + ": content range ["
                            + contentOff
                            + ", "
                            + (contentOff + lenInfo[0])
                            + ") out of bounds (data length "
                            + data.length
                            + ")");
        }
        return new String(data, contentOff, lenInfo[0], StandardCharsets.US_ASCII);
    }

    /** Разбирает UTF8String (tag 0x0C) и возвращает строку. */
    public static String parseUTF8String(byte[] data, int offset) {
        checkTag(data, offset, TAG_UTF8_STRING, "UTF8String");
        int[] lenInfo = decodeLength(data, offset + 1);
        if (lenInfo[0] < 0) {
            throw new IllegalArgumentException(
                    "UTF8String at offset " + offset + ": INDEFINITE_LENGTH not supported");
        }
        int contentOff = offset + 1 + lenInfo[1];
        if (contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                    "UTF8String at offset "
                            + offset
                            + ": content range ["
                            + contentOff
                            + ", "
                            + (contentOff + lenInfo[0])
                            + ") out of bounds (data length "
                            + data.length
                            + ")");
        }
        return new String(data, contentOff, lenInfo[0], StandardCharsets.UTF_8);
    }

    /**
     * Разбирает SET OF — возвращает элементы как DER-байты.
     * Поддерживает BER indefinite-length.
     */
    public static byte[][] parseSetContents(byte[] data, int offset) {
        checkTag(data, offset, TAG_SET, "SET");
        int[] lenInfo = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        int contentEnd;
        if (lenInfo[0] == INDEFINITE_LENGTH) {
            contentEnd = findEoc(data, contentOff);
        } else {
            int remaining = data.length - contentOff;
            if (lenInfo[0] < 0 || lenInfo[0] > remaining) {
                throw new IllegalArgumentException(
                        "SET at offset "
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
                    "SET at offset "
                            + offset
                            + ": content end "
                            + contentEnd
                            + " out of bounds (data length "
                            + data.length
                            + ")");
        }

        java.util.ArrayList<byte[]> elements = new java.util.ArrayList<>();
        int pos = contentOff;
        while (pos < contentEnd) {
            int[] childLen = decodeLength(data, pos + 1);
            int childTotal;
            if (childLen[0] == INDEFINITE_LENGTH) {
                int eoc = findEoc(data, pos + 1 + childLen[1]);
                childTotal = eoc + 2 - pos;
            } else {
                int childRemaining = contentEnd - pos - 1 - childLen[1];
                if (childLen[0] < 0 || childLen[0] > childRemaining) {
                    throw new IllegalArgumentException(
                            "SET at offset "
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
                        "SET at offset "
                                + offset
                                + ": child at position "
                                + pos
                                + " exceeds SET bounds (contentEnd "
                                + contentEnd
                                + ")");
            }
            elements.add(Arrays.copyOfRange(data, pos, pos + childTotal));
            pos += childTotal;
        }
        return elements.toArray(new byte[0][]);
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
        buf.write(40 * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            long val = Integer.toUnsignedLong(arcs[i]);
            int bits = 64 - Long.numberOfLeadingZeros(val);
            int groups = Math.max(1, (bits + 6) / 7);
            for (int g = groups - 1; g >= 0; g--) {
                int shift = g * 7;
                int b = (int) ((val >>> shift) & 0x7F);
                if (g > 0) b |= 0x80;
                buf.write(b);
            }
        }
        return buf.toByteArray();
    }

    /** Лексикографическое сравнение двух DER-кодированных элементов для сортировки SET OF. */
    public static int compareDer(byte[] a, byte[] b) {
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
        int depth = 1; // текущий indefinite-элемент
        int i = start;
        while (i < data.length - 1) {
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
            int[] tagInfo = decodeTag(data, i);
            int tag = tagInfo[0];
            int tagBytes = tagInfo[1];

            // 3. Декодируем длину
            int[] lenInfo = decodeLength(data, i + tagBytes);
            int lenValue = lenInfo[0];
            int lenBytes = lenInfo[1];

            if (lenValue == INDEFINITE_LENGTH) {
                // 4. indefinite-length: constructed-элемент -> спускаемся в контент
                if ((tag & 0x20) != 0 || (tag >= 0xA0 && tag <= 0xBF)) {
                    depth++;
                }
                i += tagBytes + lenBytes;
            } else {
                // 5. definite-length: пропускаем элемент целиком (тег + длина + контент)
                int remaining = data.length - i - tagBytes - lenBytes;
                if (lenValue < 0 || lenValue > remaining) {
                    throw new IllegalArgumentException(
                            "Length "
                                    + lenValue
                                    + " exceeds remaining data ("
                                    + remaining
                                    + " bytes) at offset "
                                    + (i + tagBytes));
                }
                i += tagBytes + lenBytes + lenValue;
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
