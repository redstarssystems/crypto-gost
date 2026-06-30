package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Тесты DerCodec — кодирование/декодирование DER-примитивов.
 * До рефакторинга эта функциональность была приватной в GostDerCodec,
 * теперь это публичный API, участвующий в парсинге внешних ключей.
 * <p>
 * Дублирует часть поведения существующих roundtrip-тестов,
 * но тестирует DerCodec напрямую, а не транзитивно через ключи.
 */
@DisplayName("DerCodec")
class DerCodecTest {

    // ========================================================================
    // encodeLength — граничные значения
    // ========================================================================

    @Test
    @DisplayName("encodeLength: short form на длинах 0..127")
    void encodeLengthShortForm() {
        assertArrayEquals(new byte[] {0x00}, DerCodec.encodeLength(0));
        assertArrayEquals(new byte[] {0x7F}, DerCodec.encodeLength(127));
    }

    @Test
    @DisplayName("encodeLength: long form 0x81 на длинах 128..255")
    void encodeLengthLongForm81() {
        assertArrayEquals(new byte[] {(byte) 0x81, (byte) 0x80}, DerCodec.encodeLength(128));
        assertArrayEquals(new byte[] {(byte) 0x81, (byte) 0xFF}, DerCodec.encodeLength(255));
    }

    @Test
    @DisplayName("encodeLength: long form 0x82 на длине 256..0xFFFF")
    void encodeLengthLongForm82() {
        assertArrayEquals(new byte[] {(byte) 0x82, 0x01, 0x00}, DerCodec.encodeLength(256));
        assertArrayEquals(
                new byte[] {(byte) 0x82, (byte) 0xFF, (byte) 0xFF}, DerCodec.encodeLength(0xFFFF));
    }

    @Test
    @DisplayName("encodeLength: поддержка длинных форм 0x83 и 0x84 для CMS")
    void encodeLengthLongForms() {
        // 0x83 — 3-байтовая длина (до 0xFFFFFF)
        assertArrayEquals(
                new byte[] {(byte) 0x83, 0x01, 0x00, 0x00}, DerCodec.encodeLength(0x10000));
        // 0x84 — 4-байтовая длина (до 0x7FFFFFFF)
        assertArrayEquals(
                new byte[] {(byte) 0x84, 0x01, 0x00, 0x00, 0x00},
                DerCodec.encodeLength(0x01000000));
    }

    // ========================================================================
    // encodeOid — граничные компоненты (arc)
    // ========================================================================

    @Test
    @DisplayName("encodeOid: arc=0 и arc>127")
    void encodeOidArcs() {
        // arc=0 и arc=127 — границы 7-bit кодирования
        assertArrayEquals(new byte[] {0x06, 0x02, 0x28, 0x00}, DerCodec.encodeOid("1.0.0"));
        assertArrayEquals(
                new byte[] {0x06, 0x03, 0x28, (byte) 0x81, 0x00}, DerCodec.encodeOid("1.0.128"));
        // arc=99999 — многобайтное base-128 кодирование
        DerCodec.encodeOid("1.2.99999");
    }

    // ========================================================================
    // Roundtrip OID
    // ========================================================================

    @Test
    @DisplayName("Roundtrip OID: encodeOid -> parseOid для реальных ГОСТ OID")
    void roundtripOid() {
        String[] oids = {
            "1.2.643.7.1.1.1.1", // id_tc26_signwithdigest_gost3410_2012_256
            "1.2.643.7.1.1.2.2", // id_tc26_hmac_gost3411_2012_256
            "1.2.643.7.1.2.1.1.1", // id_tc26_gost_3410_2012_256_paramSetA
            "1.2.643.2.2.35.1", // id_GostR3410_2001_CryptoPro_A_ParamSet
            "0.0.0", // минимальный OID
        };
        for (String oid : oids) {
            byte[] encoded = DerCodec.encodeOid(oid);
            String decoded = DerCodec.parseOid(encoded, 0);
            assertEquals(oid, decoded, "OID roundtrip failed for: " + oid);
        }
    }

    // ========================================================================
    // Roundtrip INTEGER
    // ========================================================================

    @Test
    @DisplayName("Roundtrip INTEGER: encodeInteger -> parseInteger")
    void roundtripInteger() {
        BigInteger[] values = {
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.TEN,
            BigInteger.valueOf(Long.MAX_VALUE),
            BigInteger.valueOf(-1),
            new BigInteger("123456789012345678901234567890"),
        };
        for (BigInteger val : values) {
            byte[] encoded = DerCodec.encodeInteger(val);
            BigInteger decoded = DerCodec.parseInteger(encoded, 0);
            assertEquals(val, decoded, "INTEGER roundtrip failed for: " + val);
        }
    }

    // ========================================================================
    // Roundtrip BIT STRING
    // ========================================================================

    @Test
    @DisplayName("Roundtrip BIT STRING: encodeBitString -> parseBitString")
    void roundtripBitString() {
        byte[][] inputs = {
            new byte[] {}, new byte[] {0x01}, new byte[] {0x00, 0x01, 0x02, 0x03},
        };
        for (byte[] input : inputs) {
            byte[] encoded = DerCodec.encodeBitString(input);
            byte[] decoded = DerCodec.parseBitString(encoded, 0);
            assertArrayEquals(
                    input, decoded, "BIT STRING roundtrip failed for length " + input.length);
        }
    }

    // ========================================================================
    // Roundtrip SEQUENCE
    // ========================================================================

    @Test
    @DisplayName("Roundtrip SEQUENCE: encodeSequence -> parseSequenceContents")
    void roundtripSequence() {
        byte[] elem1 = DerCodec.encodeInteger(42);
        byte[] elem2 = DerCodec.encodeOid("1.2.643.7.1.1.1.1");
        byte[] elem3 = DerCodec.encodeBitString(new byte[] {0x01, 0x02});

        byte[] encoded = DerCodec.encodeSequence(elem1, elem2, elem3);
        byte[][] decoded = DerCodec.parseSequenceContents(encoded, 0);

        assertEquals(3, decoded.length, "SEQUENCE должен содержать 3 элемента");
        assertArrayEquals(elem1, decoded[0]);
        assertArrayEquals(elem2, decoded[1]);
        assertArrayEquals(elem3, decoded[2]);
    }

    // ========================================================================
    // parse* защита от некорректного входа
    // ========================================================================

    @Test
    @DisplayName("parse*: бросают IllegalArgumentException на некорректных данных")
    void parseInvalidInput() {
        // data для parseSequenceContents: SEQUENCE-тег + усечённая длина
        byte[] seqTruncated81 = {0x30, (byte) 0x81}; // вложенный 0x81 без байта длины
        byte[] seqTruncated82 = {0x30, (byte) 0x82, 0x01}; // вложенный 0x82 без второго байта
        // data для decodeLength: 0x81/0x82 как первый байт (offset=0)
        byte[] lenTruncated81 = {(byte) 0x81}; // 0x81 без байта длины
        byte[] lenTruncated82 = {(byte) 0x82, 0x01}; // 0x82 без второго байта
        byte[] unknownTag = {(byte) 0x85, 0x01, 0x00, 0x00, 0x00}; // неподдерживаемый 0x85
        byte[] wrongTagOid = {0x02, 0x01, 0x00}; // INTEGER тег вместо OID

        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseSequenceContents(seqTruncated81, 0),
                "Усечённый 0x81 в SEQUENCE должен бросать IllegalArgumentException");
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseSequenceContents(seqTruncated82, 0),
                "Усечённый 0x82 в SEQUENCE должен бросать IllegalArgumentException");
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.decodeLength(lenTruncated81, 0),
                "decodeLength с усечённым 0x81 должен бросать IllegalArgumentException");
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.decodeLength(lenTruncated82, 0),
                "decodeLength с усечённым 0x82 должен бросать IllegalArgumentException");
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.decodeLength(unknownTag, 0),
                "decodeLength с 0x85 должен бросать IllegalArgumentException");
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseOid(wrongTagOid, 0),
                "parseOid с тегом INTEGER должен бросать IllegalArgumentException");
    }

    // ========================================================================
    // decodeTag
    // ========================================================================

    @Test
    @DisplayName("decodeTag: корректный разбор однобайтовых тегов")
    void decodeTagValidSingleByte() {
        int[][] cases = {
            {0x02, 1, 0x02}, // INTEGER
            {0x04, 1, 0x04}, // OCTET STRING
            {0x06, 1, 0x06}, // OID
            {0x30, 1, 0x30}, // SEQUENCE
            {0x31, 1, 0x31}, // SET
            {0xA0, 1, 0xA0}, // CTX CONSTRUCTED [0]
            {0x80, 1, 0x80}, // CTX PRIMITIVE [0]
            {0x1E, 1, 0x1E}, // UNIVERSAL 30 (максимальный однобайтовый тег)
        };
        for (int[] c : cases) {
            byte[] data = {(byte) c[0]};
            int[] result = DerCodec.decodeTag(data, 0);
            assertEquals(c[2], result[0], "tag value для 0x" + Integer.toHexString(c[0]));
            assertEquals(c[1], result[1], "tag byte count для 0x" + Integer.toHexString(c[0]));
        }
    }

    @Test
    @DisplayName("decodeTag: multi-byte тег (0x1F+) бросает исключение")
    void decodeTagHighTagThrows() {
        // multi-byte тег: первый байт = 0x1F (или с классом),
        // второй байт = 0x80+ (старший бит 1 = продолжение)
        byte[][] multiByteCases = {
            {0x1F, (byte) 0x81, 0x00}, // universal, tag 128
            {(byte) 0xBF, (byte) 0x81, 0x00}, // context-specific constructed, tag 128
            {0x1F, (byte) 0x80}, // truncated multi-byte
        };
        for (byte[] data : multiByteCases) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> DerCodec.decodeTag(data, 0),
                    "Multi-byte тег должен бросать исключение: 0x"
                            + Integer.toHexString(data[0] & 0xFF));
        }
    }

    // ========================================================================
    // findEoc — структурный TLV-walk
    // ========================================================================

    @Test
    @DisplayName("findEoc: двойная вложенность indefinite-length")
    void findEocDoubleNestedIndefinite() {
        // [0xA0,0x80] EXPLICIT [0] indefinite
        //   [0x24,0x80] constructed OCTET STRING indefinite
        //     [0x04,0x01,0xFF] primitive OCTET STRING
        //     0x00,0x00 (EOC constructed OCTET STRING)
        //   0x00,0x00 (EOC EXPLICIT [0])
        byte[] data = {
            (byte) 0xA0,
            (byte) 0x80, // EXPLICIT [0], indefinite
            0x24,
            (byte) 0x80, // constructed OCTET STRING, indefinite
            0x04,
            0x01,
            (byte) 0xFF, // primitive OCTET STRING, value=0xFF
            0x00,
            0x00, // EOC #1 (constructed OCTET STRING)
            0x00,
            0x00 // EOC #2 (EXPLICIT [0])
        };
        // start=2 — после тега и длины EXPLICIT [0]
        int eoc = DerCodec.findEoc(data, 2);
        assertEquals(9, eoc, "EOC внешнего EXPLICIT [0] должен быть на позиции 9");
    }

    @Test
    @DisplayName("findEoc: тройная вложенность indefinite-length")
    void findEocTripleNestedIndefinite() {
        // [0x30,0x80] SEQUENCE indefinite
        //   [0xA0,0x80] EXPLICIT [0] indefinite
        //     [0x24,0x80] constructed OCTET STRING indefinite
        //       [0x04,0x01,0xFF] primitive OCTET STRING
        //       0x00,0x00 (EOC #1, constructed OCTET STRING)
        //     0x00,0x00 (EOC #2, EXPLICIT [0])
        //   0x00,0x00 (EOC #3, SEQUENCE)
        byte[] data = {
            0x30,
            (byte) 0x80, // SEQUENCE, indefinite
            (byte) 0xA0,
            (byte) 0x80, // EXPLICIT [0], indefinite
            0x24,
            (byte) 0x80, // constructed OCTET STRING, indefinite
            0x04,
            0x01,
            (byte) 0xFF, // primitive OCTET STRING, value=0xFF
            0x00,
            0x00, // EOC #1 (constructed OCTET STRING)
            0x00,
            0x00, // EOC #2 (EXPLICIT [0])
            0x00,
            0x00 // EOC #3 (SEQUENCE)
        };
        // start=2 — после тега и длины SEQUENCE
        int eoc = DerCodec.findEoc(data, 2);
        assertEquals(13, eoc, "EOC внешнего SEQUENCE должен быть на позиции 13");
    }

    @Test
    @DisplayName("findEoc: пустой indefinite-контейнер")
    void findEocEmptyIndefinite() {
        byte[] data = {0x30, (byte) 0x80, 0x00, 0x00};
        int eoc = DerCodec.findEoc(data, 2);
        assertEquals(2, eoc, "EOC пустого indefinite-контейнера на позиции 2");
    }

    @Test
    @DisplayName("findEoc: 0x00 0x00 внутри definite OCTET STRING не сбивает depth")
    void findEocEocInsideDefiniteOctetString() {
        // [0x30,0x80] SEQUENCE indefinite
        //   [0x04,0x04, 0x00,0x00,0xFF,0xFF] OCTET STRING definite (с EOC-like байтами внутри)
        //   0x00,0x00 (EOC SEQUENCE)
        byte[] data = {
            0x30,
            (byte) 0x80, // SEQUENCE, indefinite
            0x04,
            0x04, // OCTET STRING, len=4
            0x00,
            0x00, // EOC-like байты внутри контента
            (byte) 0xFF,
            (byte) 0xFF,
            0x00,
            0x00 // реальный EOC SEQUENCE
        };
        int eoc = DerCodec.findEoc(data, 2);
        assertEquals(
                8,
                eoc,
                "EOC SEQUENCE должен быть на позиции 8 — внутренние 0x00 0x00 не должны влиять");
    }

    @Test
    @DisplayName("findEoc: constructed-like байты внутри definite элемента не дают ложный depth++")
    void findEocConstructedLikeInsideDefinite() {
        // [0x30,0x80] SEQUENCE indefinite
        //   [0x04,0x04, 0xA0,0x80,0x01,0x02] OCTET STRING definite (с constructed-like байтами
        // внутри)
        //   0x00,0x00 (EOC SEQUENCE)
        byte[] data = {
            0x30,
            (byte) 0x80, // SEQUENCE, indefinite
            0x04,
            0x04, // OCTET STRING, len=4
            (byte) 0xA0,
            (byte) 0x80, // constructed-like байты внутри контента
            0x01,
            0x02,
            0x00,
            0x00 // реальный EOC SEQUENCE
        };
        int eoc = DerCodec.findEoc(data, 2);
        assertEquals(
                8,
                eoc,
                "EOC SEQUENCE должен быть на позиции 8 — (0xA0,0x80) внутри контента не должны влиять на depth");
    }

    // ========================================================================
    // parseSequenceContents / parseSetContents с BER indefinite вложенностью
    // ========================================================================

    @Test
    @DisplayName("parseSequenceContents: SEQUENCE с вложенным indefinite EXPLICIT [0]")
    void parseSequenceContentsNestedBer() {
        // SEQUENCE (indefinite) {
        //   INTEGER 42
        //   [0] EXPLICIT (indefinite) {
        //     OCTET STRING 0xFF
        //   }
        // }
        byte[] data = {
            0x30,
            (byte) 0x80, // SEQUENCE, indefinite
            0x02,
            0x01,
            0x2A, // INTEGER 42
            (byte) 0xA0,
            (byte) 0x80, // EXPLICIT [0], indefinite
            0x04,
            0x01,
            (byte) 0xFF, // OCTET STRING 0xFF
            0x00,
            0x00, // EOC EXPLICIT [0]
            0x00,
            0x00 // EOC SEQUENCE
        };
        byte[][] parts = DerCodec.parseSequenceContents(data, 0);
        assertEquals(2, parts.length, "SEQUENCE должен содержать 2 элемента");
        assertArrayEquals(new byte[] {0x02, 0x01, 0x2A}, parts[0], "Часть 0: INTEGER 42");
        assertArrayEquals(
                new byte[] {(byte) 0xA0, (byte) 0x80, 0x04, 0x01, (byte) 0xFF, 0x00, 0x00},
                parts[1],
                "Часть 1: EXPLICIT [0] с EOC");
    }

    @Test
    @DisplayName("parseSetContents: SET OF с вложенным indefinite элементом")
    void parseSetContentsNestedBer() {
        // SET (indefinite) {
        //   [1] EXPLICIT (indefinite) {
        //     OCTET STRING 0x42
        //   }
        // }
        byte[] data = {
            0x31,
            (byte) 0x80, // SET, indefinite
            (byte) 0xA1,
            (byte) 0x80, // EXPLICIT [1], indefinite
            0x04,
            0x01,
            0x42, // OCTET STRING 0x42
            0x00,
            0x00, // EOC EXPLICIT [1]
            0x00,
            0x00 // EOC SET
        };
        byte[][] parts = DerCodec.parseSetContents(data, 0);
        assertEquals(1, parts.length, "SET должен содержать 1 элемент");
        assertArrayEquals(
                new byte[] {(byte) 0xA1, (byte) 0x80, 0x04, 0x01, 0x42, 0x00, 0x00},
                parts[0],
                "Часть 0: EXPLICIT [1] с EOC");
    }

    // ========================================================================
    // decodeLength: защита от отрицательной длины (0x84 с MSB=1)
    // ========================================================================

    @Test
    @DisplayName(
            "decodeLength: 0x84 80 80 80 00 -> signed int = -2139062272 (0x80808000 unsigned) -> исключение")
    void decodeLengthNegativeLength84() {
        // 4 байта длины: 0x80 0x80 0x80 0x00 -> big-endian unsigned = 2155905024,
        // signed int в Java = -2139062272 (overflow from unsigned)
        byte[] data = {(byte) 0x84, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x00};
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.decodeLength(data, 0),
                "0x80808000 (unsigned) -> -2139062272 (signed) — должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("decodeLength: 0x84 FF FF FF FF -> signed int = -1 -> исключение")
    void decodeLengthNegativeLength84Max() {
        // 4 байта длины: 0xFF FF FF FF -> signed int = -1
        byte[] data = {(byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.decodeLength(data, 0),
                "0xFFFFFFFF (unsigned) -> -1 (signed) — должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName(
            "decodeLength: 0x84 80 00 00 00 -> signed int = -2147483648 (Integer.MIN_VALUE, граничный) -> исключение")
    void decodeLengthNegativeLength84Min() {
        // 4 байта длины: 0x80 00 00 00 -> signed int = Integer.MIN_VALUE = -2147483648
        // Это минимальное отрицательное значение — граничный случай negative overflow
        byte[] data = {(byte) 0x84, (byte) 0x80, 0x00, 0x00, 0x00};
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.decodeLength(data, 0),
                "0x80000000 (unsigned) -> Integer.MIN_VALUE (-2147483648 signed) — должен бросать IllegalArgumentException");
    }

    // ========================================================================
    // findEoc: защита от crash-инпута фаззера (отрицательная длина 0x84)
    // ========================================================================

    @Test
    @DisplayName(
            "findEoc: crash-input фаззера 30 80 07 84 80 80 80 00 00 07 80 -> IllegalArgumentException, не AIOOBE")
    void findEocCrashInput() {
        // Инпут, найденный фаззером:
        //   SEQUENCE indefinite (30 80)
        //     тег 0x07 (произвольный мусорный байт от фаззера)
        //     длина 0x84 с 4 байтами: 80 80 80 00 -> signed int = -2139062272
        //     затем 00 07 80 (остаток)
        // Раньше: i += tagBytes + lenBytes + lenValue -> отрицательный индекс -> AIOOBE
        // После фикса: IllegalArgumentException (длина превышает оставшиеся данные)
        byte[] data = {
            0x30,
            (byte) 0x80, // SEQUENCE, indefinite
            0x07, // тег (мусорный)
            (byte) 0x84, // long-form длина, 4 байта
            (byte) 0x80,
            (byte) 0x80,
            (byte) 0x80,
            0x00, // длина = -2139062272 signed
            0x00,
            0x07,
            (byte) 0x80 // остаток
        };
        // findEoc(data, 2) — после тега и длины SEQUENCE
        // Должен бросить IllegalArgumentException, НЕ ArrayIndexOutOfBoundsException
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.findEoc(data, 2),
                "Crash-input фаззера должен бросать IllegalArgumentException, а не AIOOBE");
    }

    @Test
    @DisplayName(
            "findEoc: положительная длина (256), превышающая remaining (5 байт) — defence-in-depth проверка в findEoc, не decodeLength")
    void findEocPositiveLengthExceedsRemaining() {
        // decodeLength пропустит: 0x82 01 00 -> len=256, положительный.
        // Но remaining = 8 - 2 - 1 - 3 = 2, 256 > 2 -> IllegalArgumentException.
        // Проверяем именно ветку lenValue > remaining в findEoc,
        // а не len < 0 в decodeLength.
        byte[] data = {
            0x30,
            (byte) 0x80, // SEQUENCE, indefinite
            0x04, // OCTET STRING тег
            (byte) 0x82,
            0x01,
            0x00, // длина 256 (2-byte long form, положительная)
            0x00,
            0x00 // 2 байта «контента» (недостаточно для заявленных 256)
        };
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.findEoc(data, 2),
                "Положительная длина 256 при 2 доступных байтах — defence-in-depth в findEoc должен бросить IllegalArgumentException");
    }

    // ========================================================================
    // parseSequenceContents: защита от int overflow в childTotal
    // ========================================================================

    @Test
    @DisplayName(
            "parseSequenceContents: 0x84 7F FF FF F8 (len=2147483640, положительная, ≈2 ГБ) -> IllegalArgumentException, не OOM")
    void parseSequenceContentsOverflowCrashInput() {
        // Crash-инпут из фаззера:
        //   SEQUENCE 0x30 len=6
        //     OID [06 01 00] (первый элемент)
        //     тег 0x5A, длина 0x84 -> 4 байта: 7F FF FF F8 -> signed int = 2147483640
        // Раньше: childTotal = 1 + 5 + 2147483640 = 2147483646,
        //         5 + 2147483646 переполняло int -> проверка > data.length молча пропускала,
        //         Arrays.copyOfRange(5, ~2.1 млрд) -> OOM.
        // После фикса: childLen[0] > childRemaining (от contentEnd) -> IllegalArgumentException.
        byte[] data = {
            0x30,
            0x06, // SEQUENCE, len=6
            0x06,
            0x01,
            0x00, // первый элемент: OID (3 байта)
            0x5A, // тег (произвольный)
            (byte) 0x84, // long-form длина, 4 байта
            0x7F,
            (byte) 0xFF,
            (byte) 0xFF,
            (byte) 0xF8, // len = 2147483640 (signed int positive)
            0x00,
            0x5A // остаток
        };
        // Должен бросить IllegalArgumentException от проверки childLen[0] > childRemaining,
        // НЕ упасть с OutOfMemoryError
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseSequenceContents(data, 0),
                "Длина контента 2147483640 при 2 оставшихся байтах — должен бросать IllegalArgumentException, не OOM");
    }

    @Test
    @DisplayName(
            "parseSequenceContents: 2-й crash-инпут 30 05 06 01 01 01 84 7F FF FF F8 01 01 -> IllegalArgumentException, не OOM")
    void parseSequenceContentsOverflowCrashInput2() {
        // Второй crash-инпут из фаззера: SEQUENCE len=5, первый элемент [06 01 01],
        // второй — длина 0x84 7F FF FF F8 = 2147483640.
        // childRemaining (от contentEnd) = 7 - 5 - 1 - 5 = -4, отрицательно ->
        // childLen[0] > childRemaining -> IllegalArgumentException.
        byte[] data = {
            0x30,
            0x05, // SEQUENCE, len=5
            0x06,
            0x01,
            0x01, // первый элемент: OID (3 байта)
            0x01, // тег (произвольный)
            (byte) 0x84, // long-form длина, 4 байта
            0x7F,
            (byte) 0xFF,
            (byte) 0xFF,
            (byte) 0xF8, // len = 2147483640
            0x01,
            0x01 // остаток
        };
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseSequenceContents(data, 0),
                "Второй crash-инпут фаззера — должен бросать IllegalArgumentException от childRemaining ≤ 0");
    }

    @Test
    @DisplayName(
            "parseSequenceContents: 3-й crash-инпут 30 04 06 01 3F 00 84 7F FF FF F8 3F 00 -> IllegalArgumentException, не OOM")
    void parseSequenceContentsOverflowCrashInput3() {
        // Третий crash-инпут из фаззера: SEQUENCE len=4, первый элемент [06 01 3F],
        // второй — длина 0x84 7F FF FF F8 = 2147483640.
        // childRemaining = contentEnd - pos - 1 - childLen[1] = 6 - 5 - 1 - 5 = -5.
        // childLen[0] > childRemaining -> IllegalArgumentException.
        // DEDUP-токен совпадает с предыдущими — тот же класс бага, другой wrapper.
        byte[] data = {
            0x30,
            0x04, // SEQUENCE, len=4
            0x06,
            0x01,
            0x3F, // первый элемент: OID (3 байта)
            0x00, // тег (произвольный)
            (byte) 0x84, // long-form длина, 4 байта
            0x7F,
            (byte) 0xFF,
            (byte) 0xFF,
            (byte) 0xF8, // len = 2147483640
            0x3F,
            0x00 // остаток
        };
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseSequenceContents(data, 0),
                "Третий crash-инпут фаззера — должен бросать IllegalArgumentException, не OOM");
    }

    // ========================================================================
    // INDEFINITE_LENGTH
    // ========================================================================

    @Test
    @DisplayName("parseGeneralizedTime бросает IllegalArgumentException при INDEFINITE_LENGTH")
    void parseGeneralizedTimeThrowsOnIndefiniteLength() {
        byte[] data = {0x18, (byte) 0x80}; // GeneralizedTime + indefinite length
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseGeneralizedTime(data, 0),
                "INDEFINITE_LENGTH в parseGeneralizedTime должен бросать исключение");
    }

    @Test
    @DisplayName("parseOid: дуга с 9 continuation-байтами → переполнение long → IllegalArgumentException")
    void parseOidArcOverflow() {
        // 9 continuation-байт × 7 бит = 63 бита → 10-й байт вызывает переполнение.
        // Строим DER вручную: тег OID (0x06), длина, 1.0 + 9×0xFF + 1 байт.
        byte[] data = new byte[] {
            0x06, 0x0B, // OID tag, length 11
            0x28,       // 1.0 (first=40 → 1.0)
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 9 continuation-байт → value = 2^63-1 (63 бита)
            0x01        // 10-й байт — проверка переполнения ДО сдвига value << 7
        };
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseOid(data, 0),
                "OID с дугой > 9 continuation-байт должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("parseUTF8String бросает IllegalArgumentException при INDEFINITE_LENGTH")
    void parseUTF8StringThrowsOnIndefiniteLength() {
        byte[] data = {0x0C, (byte) 0x80}; // UTF8String + indefinite length
        assertThrows(
                IllegalArgumentException.class,
                () -> DerCodec.parseUTF8String(data, 0),
                "INDEFINITE_LENGTH в parseUTF8String должен бросать исключение");
    }
}
