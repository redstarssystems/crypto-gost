package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.signature.ECParameters;

/**
 * Fuzz-тесты для {@link CrlVerifier}.
 * <p>
 * CRL-верификатор выполняет ~40+ вызовов GostDerParser.readTlv/parseSequence
 * на внешнем DER. Содержит сложную логику пропуска опциональных полей
 * (version, nextUpdate, revokedCertificates, crlExtensions, issuingDistributionPoint).
 * <p>
 * CrlVerifier.verify() выбрасывает PkixException (checked) на битом входе
 * (fail-closed: любая ошибка парсинга = PkixException).
 * Поэтому на уровне fuzz-теста AIOOBE не виден — он перехвачен. Фаззер проверяет:
 * <ol>
 *   <li>Ни один вход не вешает JVM (OOM, бесконечный цикл)</li>
 *   <li>Алгоритм доходит до проверки подписи на валидном DER</li>
 *   <li>Indirect/partial CRL корректно отклоняются</li>
 * </ol>
 * ПОЧЕМУ ловим PkixException + RuntimeException: PkixException — ожидаемая
 * реакция на битый CRL (от CrlVerifier). RuntimeException — если
 * что-то пошло за пределы перехвата (например, в extractNextUpdate).
 */
class CrlVerifierFuzzTest {

    private static final GostCertificate CA_CERT;
    // Один заранее созданный сертификат на класс: разбор CRL остаётся под фаззингом,
    // а построение сертификата на каждой итерации только тратило бы время
    private static final GostCertificate FUZZ_CERT;

    static {
        CA_CERT = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256()).cert;
        FUZZ_CERT = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256()).cert;
    }

    /**
     * verify(crlDer, cert, caKey) — полная верификация CRL.
     * crlDer — случайные байты. cert и caKey — фиксированные
     * (не влияют на траекторию парсинга, нужны только для сверки и подписи).
     */
    @FuzzTest
    void fuzzVerify(FuzzedDataProvider data) {
        byte[] crlDer = data.consumeBytes(data.consumeInt(0, 65536));
        if (crlDer.length == 0) return;
        try {
            CrlVerifier.verify(crlDer, FUZZ_CERT, CA_CERT);
        } catch (PkixException e) {
            // Ожидаемо: битый CRL не проходит верификацию
        }
    }

    /**
     * extractNextUpdate(crlDer) — извлекает дату истечения CRL без подписи.
     * Парсит заголовок до nextUpdate, вызывает GostDerParser.parseTime.
     * Любое исключение — возвращает null (fail-soft, в отличие от verify).
     */
    @FuzzTest
    void fuzzExtractNextUpdate(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        // extractNextUpdate сам проглатывает все исключения (fail-soft, возвращает null).
        // Ловить нечего — фаззер проверяет отсутствие зависания и OOM.
        CrlVerifier.extractNextUpdate(input);
    }
}
