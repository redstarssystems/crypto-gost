package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.util.FuzzTestUtils;

/**
 * Fuzz-тесты для {@link GostDerParser}.
 * <p>
 * DER-парсер — основа всей PKI (сертификаты, OCSP). Если он пропускает
 * битые данные, последующие проверки (signature, chain) бессмысленны.
 * <p>
 * ПОЧЕМУ ловим RuntimeException (а не PkixException, как в фаззерах верификаторов):
 * GostDerParser НЕ проверяет границы массивов — любой битый вход гарантированно
 * даст AIOOBE или NPE. Это документированная особенность: парсер доверяет caller'у.
 * Fuzzer найдёт, какие входы ломают парсер — это данные для добавления защиты,
 * а не баги фузерра. Если бы мы ловили только PkixException, fuzzer бы спотыкался
 * об AIOOBE и не доходил до глубоких веток парсинга.
 */
class GostDerParserFuzzTest {

    /**
     * readTlv — базовый строительный блок DER: читает tag + length + value.
     * Ни одной проверки границ. offset выбирается consumeInt, чтобы покрыть
     * и начало массива (tag=0x02 на позиции 0), и середину (offset > 0),
     * и последний байт (граничный случай parseLength).
     * <p>
     * ПОЧЕМУ offset из data.consumeInt, а не вшитый 0: readTlv принимает
     * offset как параметр — fuzzer должен покрыть и случай offset=0
     * (типичный вызов), и offset > 0 (когда readTlv вызывается из середины
     * другого TLV: из readTlv, из parseSequence, из конструктора GostCertificate).
     */
    @FuzzTest
    void fuzzReadTlv(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0 || offset >= input.length) return;
        try {
            GostDerParser.readTlv(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzParseSequence(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0 || offset >= input.length) return;
        try {
            GostDerParser.parseSequence(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseLength — парсит DER-длину (Length).
     * В отличие от DerCodec.decodeLength (проверка offset >= data.length на входе),
     * GostDerParser.parseLength вызывает der[offset] без проверки границ.
     * <p>
     * Наиболее опасны ветки 0x81/0x82 (long form): доступ к der[offset + 1]
     * и der[offset + 2] без каких-либо граничных проверок.
     */
    @FuzzTest
    void fuzzParseLength(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0 || offset >= input.length) return;
        try {
            GostDerParser.parseLength(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseTime — парсит UTCTime / GeneralizedTime из DER.
     * <p>
     * Высокий риск: обращается к der[offset] без проверки границ до вызова
     * parseLength. Если offset = data.length - 1, падает с AIOOBE в строке
     * {@code int tag = der[offset] & 0xFF} до того, как parseLength успеет
     * проверить длину. Дополнительно: SimpleDateFormat.parse() на произвольной
     * строке — потенциально медленный, но безопасный.
     */
    @FuzzTest
    void fuzzParseTime(FuzzedDataProvider data) {
        int offset = data.consumeInt(0, Integer.MAX_VALUE);
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0 || offset >= input.length) return;
        try {
            GostDerParser.parseTime(input, offset);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * GostCertificate(byte[]) — конструктор парсит DER сертификата.
     * Внутри десятки вызовов readTlv, parseSequence, parseLength.
     * Может аллоцировать до 16 МБ (внутренняя копия certData).
     * <p>
     * В отличие от readTlv/parseSequence, offset ВСЕГДА 0 — конструктор
     * GostCertificate сам разбирает массив от начала. Поэтому offset
     * не выбирается через consumeInt — он всегда 0.
     * <p>
     * ПОЧЕМУ ловим RuntimeException, а не пытаемся отличить битый DER
     * от бага: GostCertificate внутри разбирает DER через GostDerParser,
     * который кидает AIOOBE на любом невалидном входе. Никакой разницы
     * между "битый DER" и "реальный баг" по типу исключения нет.
     * Единственный способ поймать регрессию — проверять, что конструктор
     * не повесил JVM (OOM, бесконечный цикл).
     */
    @FuzzTest
    void fuzzGostCertificate(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            new GostCertificate(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * Targeted: прямой вызов {@link GostDerParser#oidBytesToDottedString(byte[], int, int)}.
     * Фикс 0.6.2: integer overflow при >9 continuation-байт, пустой OID,
     * >128 арок (MAX_OID_ARCS, MAX_OID_SUBIDENTIFIER_BYTES).
     * <p>
     * Фаззер подаёт произвольные OID-байты напрямую в парсер. Покрывает:
     * <ul>
     *   <li>len == 0 или диапазон вне массива -> IllegalArgumentException ("OID range is invalid")</li>
     *   <li>subIdBytes > 9 -> IllegalArgumentException ("subidentifier exceeds MAX_OID_SUBIDENTIFIER_BYTES")</li>
     *   <li>арок > 128 -> IllegalArgumentException ("OID arc count exceeds 128")</li>
     * </ul>
     */
    @FuzzTest
    void fuzzOidBytesToDottedString(FuzzedDataProvider data) {
        // Пустой массив не отсекается: len == 0 должен давать IllegalArgumentException.
        byte[] oidBytes = data.consumeRemainingAsBytes();
        try {
            GostDerParser.oidBytesToDottedString(oidBytes, 0, oidBytes.length);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: оборванный OID, слишком много арок
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
