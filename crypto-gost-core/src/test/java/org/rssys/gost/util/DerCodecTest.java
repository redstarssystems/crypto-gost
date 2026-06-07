package org.rssys.gost.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

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
        assertArrayEquals(new byte[]{0x00}, DerCodec.encodeLength(0));
        assertArrayEquals(new byte[]{0x7F}, DerCodec.encodeLength(127));
    }

    @Test
    @DisplayName("encodeLength: long form 0x81 на длинах 128..255")
    void encodeLengthLongForm81() {
        assertArrayEquals(new byte[]{(byte) 0x81, (byte) 0x80}, DerCodec.encodeLength(128));
        assertArrayEquals(new byte[]{(byte) 0x81, (byte) 0xFF}, DerCodec.encodeLength(255));
    }

    @Test
    @DisplayName("encodeLength: long form 0x82 на длине 256..0xFFFF")
    void encodeLengthLongForm82() {
        assertArrayEquals(new byte[]{(byte) 0x82, 0x01, 0x00}, DerCodec.encodeLength(256));
        assertArrayEquals(new byte[]{(byte) 0x82, (byte) 0xFF, (byte) 0xFF}, DerCodec.encodeLength(0xFFFF));
    }

    @Test
    @DisplayName("encodeLength: бросает IllegalArgumentException на длине > 0xFFFF")
    void encodeLengthTooLarge() {
        assertThrows(IllegalArgumentException.class, () -> DerCodec.encodeLength(0x10000));
    }

    // ========================================================================
    // encodeOid — граничные компоненты (arc)
    // ========================================================================

    @Test
    @DisplayName("encodeOid: arc=0 и arc>127")
    void encodeOidArcs() {
        // arc=0 и arc=127 — границы 7-bit кодирования
        assertArrayEquals(new byte[]{0x06, 0x02, 0x28, 0x00}, DerCodec.encodeOid("1.0.0"));
        assertArrayEquals(new byte[]{0x06, 0x03, 0x28, (byte) 0x81, 0x00}, DerCodec.encodeOid("1.0.128"));
        // arc=99999 — многобайтное base-128 кодирование
        DerCodec.encodeOid("1.2.99999");
    }

    // ========================================================================
    // Roundtrip OID
    // ========================================================================

    @Test
    @DisplayName("Roundtrip OID: encodeOid → parseOid для реальных ГОСТ OID")
    void roundtripOid() {
        String[] oids = {
            "1.2.643.7.1.1.1.1",    // id_tc26_signwithdigest_gost3410_2012_256
            "1.2.643.7.1.1.2.2",    // id_tc26_hmac_gost3411_2012_256
            "1.2.643.7.1.2.1.1.1",  // id_tc26_gost_3410_2012_256_paramSetA
            "1.2.643.2.2.35.1",     // id_GostR3410_2001_CryptoPro_A_ParamSet
            "0.0.0",                // минимальный OID
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
    @DisplayName("Roundtrip INTEGER: encodeInteger → parseInteger")
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
    @DisplayName("Roundtrip BIT STRING: encodeBitString → parseBitString")
    void roundtripBitString() {
        byte[][] inputs = {
            new byte[]{},
            new byte[]{0x01},
            new byte[]{0x00, 0x01, 0x02, 0x03},
        };
        for (byte[] input : inputs) {
            byte[] encoded = DerCodec.encodeBitString(input);
            byte[] decoded = DerCodec.parseBitString(encoded, 0);
            assertArrayEquals(input, decoded, "BIT STRING roundtrip failed for length " + input.length);
        }
    }

    // ========================================================================
    // Roundtrip SEQUENCE
    // ========================================================================

    @Test
    @DisplayName("Roundtrip SEQUENCE: encodeSequence → parseSequenceContents")
    void roundtripSequence() {
        byte[] elem1 = DerCodec.encodeInteger(42);
        byte[] elem2 = DerCodec.encodeOid("1.2.643.7.1.1.1.1");
        byte[] elem3 = DerCodec.encodeBitString(new byte[]{0x01, 0x02});

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
        byte[] seqTruncated81 = {0x30, (byte) 0x81};          // вложенный 0x81 без байта длины
        byte[] seqTruncated82 = {0x30, (byte) 0x82, 0x01};    // вложенный 0x82 без второго байта
        // data для decodeLength: 0x81/0x82 как первый байт (offset=0)
        byte[] lenTruncated81 = {(byte) 0x81};                 // 0x81 без байта длины
        byte[] lenTruncated82 = {(byte) 0x82, 0x01};           // 0x82 без второго байта
        byte[] unknownTag      = {(byte) 0x83, 0x01, 0x00};    // неподдерживаемый 0x83
        byte[] wrongTagOid     = {0x02, 0x01, 0x00};           // INTEGER тег вместо OID

        assertThrows(IllegalArgumentException.class,
            () -> DerCodec.parseSequenceContents(seqTruncated81, 0),
            "Усечённый 0x81 в SEQUENCE должен бросать IllegalArgumentException");
        assertThrows(IllegalArgumentException.class,
            () -> DerCodec.parseSequenceContents(seqTruncated82, 0),
            "Усечённый 0x82 в SEQUENCE должен бросать IllegalArgumentException");
        assertThrows(IllegalArgumentException.class,
            () -> DerCodec.decodeLength(lenTruncated81, 0),
            "decodeLength с усечённым 0x81 должен бросать IllegalArgumentException");
        assertThrows(IllegalArgumentException.class,
            () -> DerCodec.decodeLength(lenTruncated82, 0),
            "decodeLength с усечённым 0x82 должен бросать IllegalArgumentException");
        assertThrows(IllegalArgumentException.class,
            () -> DerCodec.decodeLength(unknownTag, 0),
            "decodeLength с 0x83 должен бросать IllegalArgumentException");
        assertThrows(IllegalArgumentException.class,
            () -> DerCodec.parseOid(wrongTagOid, 0),
            "parseOid с тегом INTEGER должен бросать IllegalArgumentException");
    }
}
