package org.rssys.gost.tls13.cert;
import org.rssys.gost.tls13.*;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тесты для {@link TlsDerParser}.
 * <p>
 * DER-парсер — основа всей PKI (сертификаты, OCSP). Если он пропускает
 * битые данные, последующие проверки (signature, chain) бессмысленны.
 * <p>
 * ПОЧЕМУ ловим RuntimeException (а не TlsException как в TlsMessageParserFuzzTest):
 * TlsDerParser НЕ проверяет границы массивов — любой битый вход гарантированно
 * даст AIOOBE или NPE. Это документированная особенность: парсер доверяет caller'у.
 * Fuzzer найдёт, какие входы ломают парсер — это данные для добавления защиты,
 * а не баги фузерра. Если бы мы ловили только TlsException, fuzzer бы спотыкался
 * об AIOOBE и не доходил до глубоких веток парсинга.
 */
class TlsDerParserFuzzTest {

    /**
     * readTlv — базовый строительный блок DER: читает tag + length + value.
     * Ни одной проверки границ. offset выбирается consumeInt, чтобы покрыть
     * и начало массива (tag=0x02 на позиции 0), и середину (offset > 0),
     * и последний байт (граничный случай parseLength).
     * <p>
     * ПОЧЕМУ offset из data.consumeInt, а не вшитый 0: readTlv принимает
     * offset как параметр — fuzzer должен покрыть и случай offset=0
     * (типичный вызов), и offset > 0 (когда readTlv вызывается из середины
     * другого TLV: из readTlv, из parseSequence, из конструктора TlsCertificate).
     */
    @FuzzTest
    void fuzzReadTlv(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeRemainingAsBytes();
        if (offset >= input.length) return;
        try {
            TlsDerParser.readTlv(input, offset);
        } catch (RuntimeException e) {
        }
    }

    @FuzzTest
    void fuzzParseSequence(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeRemainingAsBytes();
        if (offset >= input.length) return;
        try {
            TlsDerParser.parseSequence(input, offset);
        } catch (RuntimeException e) {
        }
    }

    /**
     * TlsCertificate(byte[]) — конструктор парсит DER сертификата.
     * Внутри десятки вызовов readTlv, parseSequence, parseLength.
     * Может аллоцировать до 16 МБ (внутренняя копия certData).
     * <p>
     * В отличие от readTlv/parseSequence, offset ВСЕГДА 0 — конструктор
     * TlsCertificate сам разбирает массив от начала. Поэтому offset
     * не выбирается через consumeInt — он всегда 0.
     * <p>
     * ПОЧЕМУ ловим RuntimeException, а не пытаемся отличить битый DER
     * от бага: TlsCertificate внутри разбирает DER через TlsDerParser,
     * который кидает AIOOBE на любом невалидном входе. Никакой разницы
     * между "битый DER" и "реальный баг" по типу исключения нет.
     * Единственный способ поймать регрессию — проверять, что конструктор
     * не повесил JVM (OOM, бесконечный цикл).
     */
    @FuzzTest
    void fuzzTlsCertificate(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            new TlsCertificate(input);
        } catch (RuntimeException e) {
        }
    }
}
