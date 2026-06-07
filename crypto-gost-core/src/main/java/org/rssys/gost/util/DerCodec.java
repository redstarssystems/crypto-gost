package org.rssys.gost.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
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

    public static final int TAG_BOOLEAN         = 0x01;
    public static final int TAG_INTEGER         = 0x02;
    public static final int TAG_BIT_STRING      = 0x03;
    public static final int TAG_OCTET_STRING    = 0x04;
    public static final int TAG_OID             = 0x06;
    public static final int TAG_UTF8_STRING     = 0x0C;
    public static final int TAG_UTC_TIME        = 0x17;
    public static final int TAG_GENERALIZED_TIME = 0x18;
    public static final int TAG_SEQUENCE        = 0x30;
    public static final int TAG_SET             = 0x31;
    /** Базовый тег для контекстно-зависимых constructed-тегов: {@code 0xA0 | tagNum}. */
    public static final int TAG_CTX_BASE        = 0xA0;

    private DerCodec() {}

    // ========================================================================
    // Кодирование TLV
    // ========================================================================

    /** Кодирует TLV: тег (1 байт) + DER-длина + содержимое. */
    public static byte[] encodeTlv(int tag, byte[] content) {
        byte[] lenBytes = encodeLength(content.length);
        byte[] result   = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1,                   lenBytes.length);
        System.arraycopy(content,  0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    /** Кодирует DER-длину. Short form (≤ 127), long form (81/82). */
    public static byte[] encodeLength(int len) {
        if (len <= 0x7F) {
            return new byte[]{ (byte) len };
        } else if (len <= 0xFF) {
            return new byte[]{ (byte) 0x81, (byte) len };
        } else if (len <= 0xFFFF) {
            return new byte[]{ (byte) 0x82, (byte) (len >> 8), (byte) len };
        }
        throw new IllegalArgumentException("DER length too large: " + len);
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
        int[]    arcs  = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            arcs[i] = Integer.parseInt(parts[i]);
        }
        return encodeTlv(TAG_OID, encodeOidBody(arcs));
    }

    /**
     * Кодирует контекстно-зависимый constructed-тег [tagNum].
     * Например, tagNum=0 → 0xA0, tagNum=1 → 0xA1.
     */
    public static byte[] encodeContextConstructed(int tagNum, byte[] content) {
        return encodeTlv(TAG_CTX_BASE | tagNum, content);
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
    // Декодирование DER-длины
    // ========================================================================

    /**
     * Декодирует DER-длину начиная с позиции {@code offset}.
     *
     * @return {@code int[2]}: [длина_содержимого, байт_под_длину]
     */
    public static int[] decodeLength(byte[] data, int offset) {
        if (offset >= data.length) {
            throw new IllegalArgumentException("Offset " + offset
                + " out of bounds (data length " + data.length + ")");
        }
        int first = data[offset] & 0xFF;
        if (first <= 0x7F) {
            return new int[]{ first, 1 };
        } else if (first == 0x81) {
            if (offset + 1 >= data.length) {
                throw new IllegalArgumentException(
                    "Truncated DER length (0x81): need 1 byte, have "
                    + (data.length - offset - 1));
            }
            return new int[]{ data[offset + 1] & 0xFF, 2 };
        } else if (first == 0x82) {
            if (offset + 2 >= data.length) {
                throw new IllegalArgumentException(
                    "Truncated DER length (0x82): need 2 bytes, have "
                    + (data.length - offset - 1));
            }
            int len = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
            return new int[]{ len, 3 };
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
        int[] lenInfo    = decodeLength(data, offset + 1);
        int contentOff   = offset + 1 + lenInfo[1];
        int contentEnd   = contentOff + lenInfo[0];

        if (contentEnd > data.length) {
            throw new IllegalArgumentException(
                "SEQUENCE at offset " + offset + ": content end "
                + contentEnd + " out of bounds (data length " + data.length + ")");
        }

        java.util.ArrayList<byte[]> elements = new java.util.ArrayList<>();
        int pos = contentOff;
        while (pos < contentEnd) {
            int[] childLen  = decodeLength(data, pos + 1);
            int childTotal  = 1 + childLen[1] + childLen[0];
            if (pos + childTotal > data.length) {
                throw new IllegalArgumentException(
                    "SEQUENCE at offset " + offset + ": child at position "
                    + pos + " exceeds data bounds (data length " + data.length + ")");
            }
            elements.add(Arrays.copyOfRange(data, pos, pos + childTotal));
            pos += childTotal;
        }
        return elements.toArray(new byte[0][]);
    }

    /** Разбирает BIT STRING и возвращает содержимое без ведущего байта. */
    public static byte[] parseBitString(byte[] data, int offset) {
        checkTag(data, offset, TAG_BIT_STRING, "BIT STRING");
        int[] lenInfo   = decodeLength(data, offset + 1);
        int contentOff  = offset + 1 + lenInfo[1];
        if (lenInfo[0] < 1 || contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                "BIT STRING at offset " + offset + ": content length "
                + lenInfo[0] + " out of bounds (data length " + data.length + ")");
        }
        return Arrays.copyOfRange(data, contentOff + 1, contentOff + lenInfo[0]);
    }

    /** Разбирает OCTET STRING и возвращает содержимое. */
    public static byte[] parseOctetString(byte[] data, int offset) {
        checkTag(data, offset, TAG_OCTET_STRING, "OCTET STRING");
        int[] lenInfo   = decodeLength(data, offset + 1);
        int contentOff  = offset + 1 + lenInfo[1];
        if (contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                "OCTET STRING at offset " + offset + ": content length "
                + lenInfo[0] + " out of bounds (data length " + data.length + ")");
        }
        return Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]);
    }

    /** Разбирает OID и возвращает строку вида {@code "1.2.643.7.1.1.1.1"}. */
    public static String parseOid(byte[] data, int offset) {
        checkTag(data, offset, TAG_OID, "OID");
        int[] lenInfo   = decodeLength(data, offset + 1);
        int contentOff  = offset + 1 + lenInfo[1];
        int contentEnd  = contentOff + lenInfo[0];

        if (contentOff >= data.length) {
            throw new IllegalArgumentException(
                "OID at offset " + offset + ": content offset "
                + contentOff + " out of bounds (data length " + data.length + ")");
        }
        StringBuilder sb = new StringBuilder();
        int first = data[contentOff] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = contentOff + 1; i < contentEnd; i++) {
            int b = data[i] & 0xFF;
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
        int[] lenInfo  = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        if (contentOff + lenInfo[0] > data.length) {
            throw new IllegalArgumentException(
                "INTEGER at offset " + offset + ": content length "
                + lenInfo[0] + " out of bounds (data length " + data.length + ")");
        }
        return new BigInteger(Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]));
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

    /** Проверяет тег DER-структуры по смещению. */
    private static void checkTag(byte[] data, int offset, int expectedTag, String name) {
        if (offset < 0 || offset >= data.length) {
            throw new IllegalArgumentException(
                "Offset " + offset + " out of bounds for " + name
                + " (data length " + data.length + ")");
        }
        if ((data[offset] & 0xFF) != expectedTag) {
            throw new IllegalArgumentException(
                "Expected " + name + " (0x" + Integer.toHexString(expectedTag)
                + ") at offset " + offset
                + ", got 0x" + Integer.toHexString(data[offset] & 0xFF));
        }
    }
}
