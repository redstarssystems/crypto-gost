package org.rssys.gost.tls13.message;
import org.rssys.gost.tls13.*;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тесты для {@link TlsMessageParser}.
 * <p>
 * Парсинг — первая линия обороны от атак: злоумышленник шлёт произвольные байты,
 * сервер их разбирает. Fuzzer находит краши, которые вручную пропустили.
 * <p>
 * Каждый {@code @FuzzTest} — один entry point парсера. В регрессе прогоняет
 * сохранённые seed-файлы (corpus). В fuzz-режиме (JAZZER_FUZZ=1) генерирует
 * новые входы, guided by coverage.
 * <p>
 * ПОЧЕМУ ловим только TlsException|IllegalArgumentException, а не RuntimeException:
 * TlsMessageParser НЕ ДОЛЖЕН кидать NPE/AIOOBE на битом входе — это баги парсера,
 * а не ожидаемое поведение. Если fuzzer найдёт NPE, тест упадёт, и мы узнаем о баге.
 * IllegalArgumentException ловим — checkBounds внутри парсера пока кидает IAE,
 * а не TlsException, но это деталь реализации, которую fuzzer не должен тригерить.
 */
class TlsMessageParserFuzzTest {

    @FuzzTest
    void fuzzExtractRecordData(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.extractRecordData(input);
        } catch (TlsException e) {
            // любой битый ввод — ожидаемое исключение
        }
    }

    @FuzzTest
    void fuzzParseClientHello(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseClientHello(input, TlsConstants.GRP_GC256A,
                    TlsConstants.SIG_GOST_TC26_A_256);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }

    @FuzzTest
    void fuzzParseServerHello(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseServerHello(input, TlsConstants.GRP_GC256A);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }

    /**
     * OOM-вектор закрыт: parseCertificate проверяет certLen через
     * TlsConstants.MAX_CERT_SIZE (256 КБ), аллокация не превысит лимит.
     */
    @FuzzTest
    void fuzzParseCertificate(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseCertificate(input);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }

    @FuzzTest
    void fuzzParseNewSessionTicket(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseNewSessionTicket(input);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }

    @FuzzTest
    void fuzzParseCertificateRequest(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseCertificateRequest(input);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }

    @FuzzTest
    void fuzzParseClientHelloPskIdentity(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseClientHelloPskIdentity(input);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }

    @FuzzTest
    void fuzzParseEncryptedExtensions(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            TlsMessageParser.parseEncryptedExtensions(input);
        } catch (TlsException | IllegalArgumentException e) {
        }
    }
}
