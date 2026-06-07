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
        byte[] input = data.consumeRemainingAsBytes();
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
        byte[] input = data.consumeRemainingAsBytes();
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
        byte[] input = data.consumeRemainingAsBytes();
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
        byte[] input = data.consumeRemainingAsBytes();
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
        byte[] input = data.consumeRemainingAsBytes();
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
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            DerCodec.parseInteger(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
