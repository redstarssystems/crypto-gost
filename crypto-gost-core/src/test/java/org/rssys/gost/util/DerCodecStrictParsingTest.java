package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Регрессионные байтовые векторы строгого разбора DER: границы длин без переполнения,
 * OID, BOOLEAN, BIT STRING, строгая SEQUENCE и нормализация BER-SEQUENCE.
 */
@DisplayName("DerCodec: строгий разбор")
class DerCodecStrictParsingTest {

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = (byte) values[i];
        }
        return result;
    }

    private static void assertRejected(byte[] data, java.util.function.Consumer<byte[]> parser) {
        assertThrows(
                IllegalArgumentException.class,
                () -> parser.accept(data),
                "Некорректный вход должен отвергаться IllegalArgumentException, а не другим исключением");
    }

    @Nested
    @DisplayName("parseOid")
    class ParseOid {

        @Test
        @DisplayName("Обрезанная дуга (бит продолжения в последнем байте) отвергается")
        void truncatedArc() {
            assertRejected(bytes(0x06, 0x01, 0x81), d -> DerCodec.parseOid(d, 0));
            assertRejected(bytes(0x06, 0x02, 0x2A, 0x81), d -> DerCodec.parseOid(d, 0));
            assertRejected(bytes(0x06, 0x03, 0x2A, 0x03, 0x83), d -> DerCodec.parseOid(d, 0));
        }

        @Test
        @DisplayName(
                "Неминимальная дуга (ведущий 0x80) отвергается, в том числе в первом subidentifier")
        void nonMinimalArc() {
            assertRejected(bytes(0x06, 0x03, 0x2A, 0x80, 0x01), d -> DerCodec.parseOid(d, 0));
            assertRejected(bytes(0x06, 0x02, 0x80, 0x00), d -> DerCodec.parseOid(d, 0));
        }

        @Test
        @DisplayName("Нулевая длина не читает байт за пределами значения")
        void zeroLength() {
            assertRejected(bytes(0x06, 0x00, 0x2A), d -> DerCodec.parseOid(d, 0));
            assertRejected(bytes(0x06, 0x00), d -> DerCodec.parseOid(d, 0));
        }

        @Test
        @DisplayName("Длина за границей данных: IllegalArgumentException, не ArrayIndexOutOfBounds")
        void lengthBeyondData() {
            assertRejected(bytes(0x06, 0x05, 0x2A, 0x03), d -> DerCodec.parseOid(d, 0));
        }

        @Test
        @DisplayName("Длина 0x7FFFFFFF не переполняет сумму и не даёт молчаливого результата")
        void maxIntLength() {
            assertRejected(bytes(0x06, 0x84, 0x7F, 0xFF, 0xFF, 0xFF), d -> DerCodec.parseOid(d, 0));
            assertRejected(
                    bytes(0x06, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x2A), d -> DerCodec.parseOid(d, 0));
        }

        @Test
        @DisplayName("Первый subidentifier: границы раскладки на первые две дуги")
        void firstSubidentifierBoundaries() {
            assertEquals("0.0", DerCodec.parseOid(bytes(0x06, 0x01, 0x00), 0));
            assertEquals("0.39", DerCodec.parseOid(bytes(0x06, 0x01, 0x27), 0));
            assertEquals("1.0", DerCodec.parseOid(bytes(0x06, 0x01, 0x28), 0));
            assertEquals("1.39", DerCodec.parseOid(bytes(0x06, 0x01, 0x4F), 0));
            assertEquals("2.0", DerCodec.parseOid(bytes(0x06, 0x01, 0x50), 0));
            // Раньше first / 40 для 120..127 давал дугу 3
            assertEquals("2.40", DerCodec.parseOid(bytes(0x06, 0x01, 0x78), 0));
            assertEquals("2.47", DerCodec.parseOid(bytes(0x06, 0x01, 0x7F), 0));
            // Многобайтный первый subidentifier
            assertEquals("2.48", DerCodec.parseOid(bytes(0x06, 0x02, 0x81, 0x00), 0));
            assertEquals("2.49", DerCodec.parseOid(bytes(0x06, 0x02, 0x81, 0x01), 0));
            assertEquals("2.999", DerCodec.parseOid(bytes(0x06, 0x02, 0x88, 0x37), 0));
            assertEquals("2.999.3", DerCodec.parseOid(bytes(0x06, 0x03, 0x88, 0x37, 0x03), 0));
        }

        @Test
        @DisplayName("Обычные OID разбираются как раньше")
        void regularOids() {
            assertEquals(
                    "1.2.643.7.1.1.1.1",
                    DerCodec.parseOid(DerCodec.encodeOid("1.2.643.7.1.1.1.1"), 0));
            assertEquals("1.2.3", DerCodec.parseOid(bytes(0x06, 0x02, 0x2A, 0x03), 0));
        }

        @Test
        @DisplayName("Дуга больше 63 бит отвергается, а не становится отрицательной")
        void arcOverflow() {
            byte[] tooBig =
                    bytes(
                            0x06, 0x0B, 0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0x7F);
            assertRejected(tooBig, d -> DerCodec.parseOid(d, 0));
        }
    }

    @Nested
    @DisplayName("encodeOid")
    class EncodeOid {

        @Test
        @DisplayName("Первая пара дуг 2.999 кодируется двумя байтами и разбирается обратно")
        void roundtripJointArc() {
            assertArrayEquals(bytes(0x06, 0x02, 0x88, 0x37), DerCodec.encodeOid("2.999"));
            assertEquals("2.999", DerCodec.parseOid(DerCodec.encodeOid("2.999"), 0));
            assertEquals("2.999.3", DerCodec.parseOid(DerCodec.encodeOid("2.999.3"), 0));
        }

        @Test
        @DisplayName("Границы раскладки кодируются обратно")
        void roundtripBoundaries() {
            for (String oid :
                    new String[] {
                        "0.0", "0.39", "1.0", "1.39", "2.0", "2.40", "2.47", "2.48", "2.49"
                    }) {
                assertEquals(
                        oid,
                        DerCodec.parseOid(DerCodec.encodeOid(oid), 0),
                        "Круговое преобразование OID " + oid + " должно сохранять значение");
            }
        }

        @Test
        @DisplayName("Недопустимые первые дуги и короткие OID отвергаются")
        void invalidArcs() {
            for (String oid :
                    new String[] {"1", "3.0", "1.40", "0.40", "-1.2", "1.-2", "1.2.-3", ""}) {
                assertThrows(
                        IllegalArgumentException.class,
                        () -> DerCodec.encodeOid(oid),
                        "OID '" + oid + "' должен отвергаться IllegalArgumentException");
            }
        }
    }

    @Nested
    @DisplayName("Длины без переполнения в примитивных парсерах")
    class PrimitiveLengths {

        // Длина 0x7FFFFFFF и один байт данных: contentOff + len переполняется в int
        private byte[] withTag(int tag) {
            return bytes(tag, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x41);
        }

        @Test
        @DisplayName(
                "parseOctetString с длиной 0x7FFFFFFF: IllegalArgumentException, не OutOfMemoryError")
        void octetString() {
            assertRejected(withTag(0x04), d -> DerCodec.parseOctetString(d, 0));
        }

        @Test
        @DisplayName("parseInteger с длиной 0x7FFFFFFF отвергается")
        void integer() {
            assertRejected(withTag(0x02), d -> DerCodec.parseInteger(d, 0));
        }

        @Test
        @DisplayName("parseGeneralizedTime с длиной 0x7FFFFFFF отвергается")
        void generalizedTime() {
            assertRejected(withTag(0x18), d -> DerCodec.parseGeneralizedTime(d, 0));
        }

        @Test
        @DisplayName("parseUTF8String с длиной 0x7FFFFFFF отвергается")
        void utf8String() {
            assertRejected(withTag(0x0C), d -> DerCodec.parseUTF8String(d, 0));
        }

        @Test
        @DisplayName("parseBitString с длиной 0x7FFFFFFF отвергается")
        void bitString() {
            assertRejected(withTag(0x03), d -> DerCodec.parseBitString(d, 0));
        }
    }

    @Nested
    @DisplayName("collectImplicitOctets")
    class CollectImplicitOctets {

        @Test
        @DisplayName("Длина 0x7FFFFFFF у constructed и примитивного сегмента отвергается")
        void maxIntLengths() {
            assertRejected(
                    bytes(0x24, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x04, 0x01, 0x41),
                    d -> DerCodec.collectImplicitOctets(d, 0));
            assertRejected(
                    bytes(0xA0, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x04, 0x01, 0x41),
                    d -> DerCodec.collectImplicitOctets(d, 0));
            assertRejected(
                    bytes(0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x41),
                    d -> DerCodec.collectImplicitOctets(d, 0));
        }

        @Test
        @DisplayName(
                "Вложенный потомок с длиной 0x7FFFFFFF: IllegalArgumentException, не ArrayIndexOutOfBounds")
        void nestedMaxIntLength() {
            assertRejected(
                    bytes(0xA0, 0x06, 0x24, 0x84, 0x7F, 0xFF, 0xFF, 0xFF),
                    d -> DerCodec.collectImplicitOctets(d, 0));
        }

        @Test
        @DisplayName("Потомок не может выйти за границу родителя")
        void childBeyondParent() {
            // Родитель заявил 4 байта содержимого, а сегмент 04 03 01 02 03 занимает 5
            assertRejected(
                    bytes(0xA0, 0x04, 0x04, 0x03, 0x01, 0x02, 0x03),
                    d -> DerCodec.collectImplicitOctets(d, 0));
        }

        @Test
        @DisplayName(
                "BER КриптоПро с indefinite-length у constructed-сегментов по-прежнему принимается")
        void indefiniteLengthAccepted() {
            assertArrayEquals(
                    bytes(0x41, 0x42),
                    DerCodec.collectImplicitOctets(
                            bytes(0x24, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00), 0));
            assertArrayEquals(
                    bytes(0x41),
                    DerCodec.collectImplicitOctets(
                            bytes(0xA0, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00), 0));
            // Вложенный indefinite внутри definite
            assertArrayEquals(
                    bytes(0x41, 0x42),
                    DerCodec.collectImplicitOctets(
                            bytes(
                                    0xA0, 0x0A, 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00, 0x04,
                                    0x01, 0x42),
                            0));
        }

        @Test
        @DisplayName("Indefinite-потомок не выходит за границу родителя")
        void indefiniteChildBeyondParent() {
            // EOC потомка лежит за пределами содержимого родителя (A0 len=3: 24 80 04)
            assertRejected(
                    bytes(0xA0, 0x03, 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00),
                    d -> DerCodec.collectImplicitOctets(d, 0));
        }

        @Test
        @DisplayName("Примитивный сегмент с indefinite-length отвергается")
        void primitiveIndefinite() {
            assertRejected(
                    bytes(0x04, 0x80, 0x41, 0x00, 0x00), d -> DerCodec.collectImplicitOctets(d, 0));
        }

        @Test
        @DisplayName("Обычные сегменты склеиваются в порядке следования")
        void regularSegments() {
            assertArrayEquals(
                    bytes(0x01, 0x02, 0x03),
                    DerCodec.collectImplicitOctets(
                            bytes(0x24, 0x07, 0x04, 0x02, 0x01, 0x02, 0x04, 0x01, 0x03), 0));
        }
    }

    @Nested
    @DisplayName("parseBoolean")
    class ParseBoolean {

        @Test
        @DisplayName("DER: 0x00 = FALSE, 0xFF = TRUE")
        void validValues() {
            assertFalse(DerCodec.parseBoolean(bytes(0x01, 0x01, 0x00), 0));
            assertTrue(DerCodec.parseBoolean(bytes(0x01, 0x01, 0xFF), 0));
        }

        @Test
        @DisplayName("Длина 0, длина 2 и значение 0x01 отвергаются")
        void invalidValues() {
            assertRejected(bytes(0x01, 0x00, 0xFF), d -> DerCodec.parseBoolean(d, 0));
            assertRejected(bytes(0x01, 0x02, 0x00, 0xFF), d -> DerCodec.parseBoolean(d, 0));
            assertRejected(bytes(0x01, 0x01, 0x01), d -> DerCodec.parseBoolean(d, 0));
            assertRejected(bytes(0x01, 0x01, 0x7F), d -> DerCodec.parseBoolean(d, 0));
        }
    }

    @Nested
    @DisplayName("parseBitString и parseBitStringWithUnused")
    class ParseBitString {

        @Test
        @DisplayName("Число неиспользуемых бит больше 7 отвергается")
        void unusedBitsTooLarge() {
            assertRejected(bytes(0x03, 0x02, 0xC8, 0xFF), d -> DerCodec.parseBitString(d, 0));
            assertRejected(bytes(0x03, 0x02, 0x08, 0x00), d -> DerCodec.parseBitString(d, 0));
        }

        @Test
        @DisplayName("Ненулевые неиспользуемые биты отвергаются, нулевые принимаются")
        void unusedBitsMustBeZero() {
            assertRejected(bytes(0x03, 0x02, 0x07, 0xFF), d -> DerCodec.parseBitString(d, 0));
            DerCodec.BitStringValue value =
                    DerCodec.parseBitStringWithUnused(bytes(0x03, 0x02, 0x07, 0x80), 0);
            assertEquals(7, value.unusedBits(), "Число неиспользуемых бит должно возвращаться");
            assertArrayEquals(bytes(0x80), value.data());
        }

        @Test
        @DisplayName("Пустое содержимое отвергается, пустое значение 03 01 00 принимается")
        void emptyContent() {
            assertRejected(bytes(0x03, 0x00), d -> DerCodec.parseBitString(d, 0));
            assertRejected(bytes(0x03, 0x01, 0x03), d -> DerCodec.parseBitString(d, 0));
            assertArrayEquals(new byte[0], DerCodec.parseBitString(bytes(0x03, 0x01, 0x00), 0));
        }

        @Test
        @DisplayName("parseBitString возвращает те же данные, что parseBitStringWithUnused")
        void wrapperConsistency() {
            byte[] encoded = DerCodec.encodeBitString(bytes(0x01, 0x02, 0x03));
            assertArrayEquals(
                    DerCodec.parseBitStringWithUnused(encoded, 0).data(),
                    DerCodec.parseBitString(encoded, 0));
        }
    }

    @Nested
    @DisplayName("parseStrictSequence")
    class ParseStrictSequence {

        @Test
        @DisplayName("Корректная SEQUENCE возвращает копии элементов")
        void validSequence() {
            byte[] first = DerCodec.encodeOid("1.2.3");
            byte[] second = DerCodec.encodeInteger(5);
            byte[] sequence = DerCodec.encodeSequence(first, second);
            byte[][] parts = DerCodec.parseStrictSequence(sequence);
            assertEquals(2, parts.length);
            assertArrayEquals(first, parts[0]);
            assertArrayEquals(second, parts[1]);
            parts[0][0] = 0x00;
            assertEquals(
                    0x30, sequence[0] & 0xFF, "Результат должен быть копией, а не срезом входа");
        }

        @Test
        @DisplayName("Пустая SEQUENCE даёт пустой массив")
        void emptySequence() {
            assertEquals(0, DerCodec.parseStrictSequence(bytes(0x30, 0x00)).length);
        }

        @Test
        @DisplayName("Indefinite-length отвергается")
        void indefiniteLength() {
            assertRejected(
                    bytes(0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00), DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Байты после SEQUENCE отвергаются, а не игнорируются")
        void trailingBytes() {
            assertRejected(
                    bytes(0x30, 0x03, 0x02, 0x01, 0x05, 0x00), DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Длина SEQUENCE больше входа отвергается")
        void lengthBeyondInput() {
            assertRejected(bytes(0x30, 0x05, 0x02, 0x01, 0x05), DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Потомок за границей родителя отвергается")
        void childBeyondParent() {
            assertRejected(bytes(0x30, 0x03, 0x04, 0x05, 0x01), DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Неминимальная длина и многобайтный тег отвергаются")
        void nonMinimalLengthAndHighTag() {
            assertRejected(
                    bytes(0x30, 0x81, 0x03, 0x02, 0x01, 0x05), DerCodec::parseStrictSequence);
            assertRejected(bytes(0x30, 0x03, 0x1F, 0x01, 0x00), DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Потомок с тегом 0x00 (маркер EOC) отвергается")
        void endOfContentsChild() {
            assertRejected(bytes(0x30, 0x02, 0x00, 0x00), DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Indefinite-length во вложенном элементе отвергается")
        void nestedIndefinite() {
            // Потомок с indefinite-length отвергается уже при разборе внешней SEQUENCE
            byte[] outer = DerCodec.encodeSequence(bytes(0x30, 0x80, 0x00, 0x00));
            assertRejected(outer, DerCodec::parseStrictSequence);
        }

        @Test
        @DisplayName("Тег не SEQUENCE отвергается")
        void wrongTag() {
            assertRejected(bytes(0x31, 0x00), DerCodec::parseStrictSequence);
        }
    }

    @Nested
    @DisplayName("normalizeBerSequenceToDer")
    class NormalizeBerSequence {

        private final byte[] oidA = DerCodec.encodeOid("1.2.643.7.1.1.1.1");
        private final byte[] oidB = DerCodec.encodeOid("1.2.643.7.1.2.1.1.1");
        private final byte[] oidC = DerCodec.encodeOid("1.2.643.7.1.1.2.2");

        private byte[] derAlgorithm() {
            return DerCodec.encodeSequence(oidA, DerCodec.encodeSequence(oidB, oidC));
        }

        private byte[] berAlgorithm() {
            return DerCodec.concat(
                    bytes(0x30, 0x80),
                    oidA,
                    bytes(0x30, 0x80),
                    oidB,
                    oidC,
                    bytes(0x00, 0x00, 0x00, 0x00));
        }

        @Test
        @DisplayName(
                "AlgorithmIdentifier с indefinite-length даёт тот же DER, что исходный definite")
        void indefiniteBecomesDefinite() {
            assertArrayEquals(derAlgorithm(), DerCodec.normalizeBerSequenceToDer(berAlgorithm()));
        }

        @Test
        @DisplayName(
                "Определённая длина у внешней и вложенной SEQUENCE при indefinite у одной из них")
        void mixedLengths() {
            byte[] outerDefiniteInnerIndefinite =
                    DerCodec.encodeSequence(
                            oidA,
                            DerCodec.concat(bytes(0x30, 0x80), oidB, oidC, bytes(0x00, 0x00)));
            assertArrayEquals(
                    derAlgorithm(),
                    DerCodec.normalizeBerSequenceToDer(outerDefiniteInnerIndefinite));
        }

        @Test
        @DisplayName("Нормализация идемпотентна: DER остаётся тем же DER")
        void idempotent() {
            byte[] once = DerCodec.normalizeBerSequenceToDer(berAlgorithm());
            assertArrayEquals(once, DerCodec.normalizeBerSequenceToDer(once));
            assertArrayEquals(derAlgorithm(), DerCodec.normalizeBerSequenceToDer(derAlgorithm()));
        }

        @Test
        @DisplayName("Байты после EOC и после definite SEQUENCE отвергаются")
        void trailingBytes() {
            assertRejected(
                    DerCodec.concat(berAlgorithm(), bytes(0x00)),
                    DerCodec::normalizeBerSequenceToDer);
            assertRejected(
                    DerCodec.concat(derAlgorithm(), bytes(0x05)),
                    DerCodec::normalizeBerSequenceToDer);
        }

        @Test
        @DisplayName("Примитив с indefinite-length отвергается")
        void primitiveIndefinite() {
            assertRejected(
                    bytes(0x30, 0x06, 0x04, 0x80, 0x41, 0x00, 0x00, 0x00),
                    DerCodec::normalizeBerSequenceToDer);
        }

        @Test
        @DisplayName("Constructed OCTET STRING, constructed BIT STRING и SET отвергаются")
        void unsupportedConstructed() {
            assertRejected(
                    DerCodec.encodeSequence(bytes(0x24, 0x03, 0x04, 0x01, 0x41)),
                    DerCodec::normalizeBerSequenceToDer);
            assertRejected(
                    DerCodec.encodeSequence(bytes(0x23, 0x03, 0x03, 0x01, 0x00)),
                    DerCodec::normalizeBerSequenceToDer);
            assertRejected(
                    DerCodec.encodeSequence(DerCodec.encodeSet(DerCodec.encodeInteger(1))),
                    DerCodec::normalizeBerSequenceToDer);
        }

        @Test
        @DisplayName("Не SEQUENCE и вложенность глубже предела отвергаются")
        void wrongTagAndDepth() {
            assertRejected(DerCodec.encodeInteger(1), DerCodec::normalizeBerSequenceToDer);
            byte[] nested = DerCodec.encodeSequence();
            for (int i = 0; i < 40; i++) {
                nested = DerCodec.encodeSequence(nested);
            }
            assertRejected(nested, DerCodec::normalizeBerSequenceToDer);
        }

        @Test
        @DisplayName("Indefinite-потомок не выходит за границу родителя")
        void indefiniteChildBeyondParent() {
            // Внешняя definite SEQUENCE заявляет 4 байта содержимого, EOC потомка лежит за ними
            assertRejected(
                    bytes(0x30, 0x04, 0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00),
                    DerCodec::normalizeBerSequenceToDer);
        }
    }
}
