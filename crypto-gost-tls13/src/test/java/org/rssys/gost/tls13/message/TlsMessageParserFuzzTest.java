package org.rssys.gost.tls13.message;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Set;
import org.rssys.gost.tls13.*;

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
 * ПОЧЕМУ ловим только TlsException, а не RuntimeException:
 * TlsMessageParser НЕ ДОЛЖЕН кидать NPE/AIOOBE/IllegalArgumentException на битом входе —
 * это баги парсера, а не ожидаемое поведение (ошибки формата, в том числе checkBounds,
 * сообщаются как TlsException). Если fuzzer найдёт такое исключение, тест упадёт, и мы
 * узнаем о баге.
 */
class TlsMessageParserFuzzTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    /** Типы ответных расширений EE, на которые клиент якобы отправил запрос. */
    private static final Set<Integer> ALL_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    TlsConstants.EXT_MAX_FRAGMENT_LENGTH,
                    TlsConstants.EXT_SERVER_NAME);

    @FuzzTest
    void fuzzParsePlaintextRecord(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parsePlaintextRecord(input);
        } catch (TlsException e) {
            // любой битый ввод — ожидаемое исключение
        }
    }

    @FuzzTest
    void fuzzParseClientHello(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseClientHello(
                    input, TlsConstants.GRP_GC256A, TlsConstants.SIG_GOST_TC26_A_256);
        } catch (TlsException e) {
        }
    }

    @FuzzTest
    void fuzzParseServerHello(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseServerHello(input, SERVER_RESPONSE_TYPES_SENT);
        } catch (TlsException e) {
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
            TlsMessageParser.parseCertificate(input, Set.of(TlsConstants.EXT_STATUS_REQUEST));
        } catch (TlsException e) {
        }
    }

    @FuzzTest
    void fuzzParseNewSessionTicket(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseNewSessionTicket(input);
        } catch (TlsException e) {
        }
    }

    @FuzzTest
    void fuzzParseCertificateRequest(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseCertificateRequest(input);
        } catch (TlsException e) {
        }
    }

    /**
     * Строгий лёгкий разбор SNI кормит PSK-привязку и выбор сертификата до полного разбора, поэтому
     * на любом входе допустим только TlsException: исключение Java означало бы сбой сервера.
     */
    @FuzzTest
    void fuzzParseClientHelloSni(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseClientHelloSni(input);
        } catch (TlsException e) {
        }
    }

    @FuzzTest
    void fuzzParseServerNameExtension(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseServerNameExtension(input, 0, input.length);
        } catch (TlsException e) {
        }
    }

    @FuzzTest
    void fuzzParseClientHelloPsk(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        try {
            TlsMessageParser.parseClientHelloPsk(input, TlsConstants.STREEBOG_256_HASH_LEN);
        } catch (TlsException e) {
        }
    }

    @FuzzTest
    void fuzzParseEncryptedExtensions(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            TlsMessageParser.parseEncryptedExtensions(input, ALL_RESPONSE_TYPES_SENT);
        } catch (TlsException e) {
        }
    }
}
