package org.rssys.gost.util;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тесты для {@link DerCodec}.
 * <p>
 * DerCodec — фундамент всех DER-операций в проекте. Если его парсеры
 * пропускают битые данные, последующие проверки (ключи, сертификаты, OCSP)
 * бессмысленны. Все parse* методы принимают {@code byte[] data, int offset}
 * из внешнего входа.
 * <p>
 * ПОЧЕМУ ловим RuntimeException: DerCodec использует checkTag() и decodeLength(),
 * которые обращаются к data[offset] без предварительной проверки границ массива.
 * AIOOBE на битом входе — ожидаемо. IllegalArgumentException — тоже ожидаемо
 * (проверка тега). Если бы мы не ловили RuntimeException, fuzzer спотыкался бы
 * об AIOOBE на первом же вызове и не доходил до глубоких веток.
 */
class DerCodecFuzzTest {

    /**
     * decodeLength — декодирует DER-длину. Имеет проверку offset >= data.length
     * (строка 138), но ветки 0x81/0x82 (строки 146-158) могут дать AIOOBE,
     * если длины не хватает на 1-2 байта. offset выбирается consumeInt чтобы
     * покрыть граничные случаи (последние байты массива).
     */
    @FuzzTest
    void fuzzDecodeLength(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.decodeLength(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseSequenceContents — разбирает SEQUENCE и возвращает вложенные элементы.
     * decodeLength может вернуть len=0xFFFF при 0x82 encoding (строка 158).
     * В цикле while (строка 183) вызывается Arrays.copyOfRange с этим len —
     * потенциальный OOM-вектор.
     */
    @FuzzTest
    void fuzzParseSequenceContents(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseSequenceContents(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseBitString — разбирает BIT STRING. После decodeLength обращается
     * к data[contentOff + 1] (ведущий байт неиспользуемых бит) без проверки.
     * Если contentLen = 0, будет AIOOBE.
     */
    @FuzzTest
    void fuzzParseBitString(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseBitString(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseOctetString — разбирает OCTET STRING. После decodeLength вызывает
     * Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]) — OOM-вектор
     * при 0xFFFF длине.
     */
    @FuzzTest
    void fuzzParseOctetString(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseOctetString(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseOid — разбирает OID в строку вида "1.2.643.7.1.1.1.1".
     * Обращается к data[contentOff] на строке 216 без проверки.
     * Цикл for (строка 220) с value = (value << 7) | (b & 0x7F) —
     * потенциально медленный на длинных последовательностях, но не крашит JVM.
     */
    @FuzzTest
    void fuzzParseOid(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseOid(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseInteger — разбирает INTEGER. После decodeLength вызывает
     * Arrays.copyOfRange — OOM-вектор при 0xFFFF длине.
     */
    @FuzzTest
    void fuzzParseInteger(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseInteger(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * findEoc — ищет EOC-маркер в BER indefinite-length контейнере.
     * Новый структурный TLV-walk: decodeTag + decodeLength на каждом смещении,
     * проверка границ при skip'е definite-length элементов.
     * start передаётся consumeInt чтобы покрыть вылет за границы массива.
     */
    @FuzzTest
    void fuzzFindEoc(FuzzedDataProvider data) {
        int start = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.findEoc(input, start);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * fuzz-последовательность с внедрёнными indefinite-маркерами (0x80)
     * и EOC (0x00 0x00) для проверки устойчивости parseSequenceContents
     * к структурно некорректному BER-входу.
     */
    @FuzzTest
    void fuzzParseSequenceWithIndefinite(FuzzedDataProvider data) {
        // Формируем массив, начинающийся с SEQUENCE-префикса
        byte[] raw = data.consumeBytes(data.consumeInt(0, 65536));
        if (raw.length < 4) return;
        byte[] input = new byte[raw.length + 1];
        input[0] = 0x30; // принудительно SEQUENCE тег
        System.arraycopy(raw, 0, input, 1, raw.length);
        int offset = 0;
        try {
            DerCodec.parseSequenceContents(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseBoolean — разбирает BOOLEAN (tag 0x01). Обращается к data[contentOff]
     * без проверки, что contentOff < data.length при длине контента 0
     * после заголовка тэга и длины.
     */
    @FuzzTest
    void fuzzParseBoolean(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseBoolean(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseGeneralizedTime — разбирает GeneralizedTime (tag 0x18).
     * decodeLength может вернуть INDEFINITE_LENGTH (0x80) через
     * indefinite-маркер → new String с отрицательной длиной →
     * NegativeArraySizeException. Гигантский len → OOM.
     */
    @FuzzTest
    void fuzzParseGeneralizedTime(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseGeneralizedTime(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseUTF8String — разбирает UTF8String (tag 0x0C).
     * Аналогичный риск: decodeLength с INDEFINITE_LENGTH или
     * гигантской длиной → OOM / NegativeArraySizeException.
     */
    @FuzzTest
    void fuzzParseUTF8String(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeBytes(data.consumeInt(0, 65536));
        if (input.length == 0) return;
        try {
            DerCodec.parseUTF8String(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    // ======================================================================
    // Targeted-тесты — indefinite-length (0x80) для примитивных типов
    // (фикс 0.6.2: decodeDefiniteLength, X.690 §8.1.3.6)
    // ======================================================================

    /**
     * Подаёт INTEGER (0x02) с indefinite-length (0x80) на вход decodeDefiniteLength.
     * До 0.6.2 0x80 молча принимался (X.690 violation), сейчас должен выбрасывать
     * {@code IllegalArgumentException}.
     * <p>
     * Inject-паттерн: prefix = тег примитивного типа + 0x80, тело = fuzzed-байты.
     */
    @FuzzTest
    void fuzzPrimitiveIndefiniteLength(FuzzedDataProvider data) {
        byte[] body = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] input = new byte[body.length + 2];
        int tag = data.consumeInt(0, 1) == 0 ? 0x02 : 0x01;
        input[0] = (byte) tag;
        input[1] = (byte) 0x80;
        if (body.length > 0) {
            System.arraycopy(body, 0, input, 2, body.length);
        }
        try {
            if (tag == 0x02) {
                DerCodec.parseInteger(input, 0);
            } else {
                DerCodec.parseBoolean(input, 0);
            }
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * Non-canonical DER-длина: 0x81 0x05 (long-form для 5 байт) вместо канонического 0x05.
     * Фикс 0.6.2: проверка минимальности в decodeLength (X.690 §10.1).
     * <p>
     * Inject-паттерн: тег INTEGER + 0x81 0x05 + 5 байт тела.
     */
    @FuzzTest
    void fuzzNonCanonicalLength(FuzzedDataProvider data) {
        byte[] body = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] input = new byte[body.length + 3];
        input[0] = 0x02;
        input[1] = (byte) 0x81;
        input[2] = (byte) 0x05;
        if (body.length > 0) {
            System.arraycopy(body, 0, input, 3, body.length);
        }
        try {
            DerCodec.parseInteger(input, 0);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
