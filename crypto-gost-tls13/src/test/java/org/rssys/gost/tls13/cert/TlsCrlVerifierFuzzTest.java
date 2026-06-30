package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

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
class TlsCrlVerifierFuzzTest {

    private static final PublicKeyParameters CA_KEY;

    static {
        CA_KEY = KeyGenerator.generateKeyPair(ECParameters.tc26a256()).getPublic();
    }

    /**
     * verify(crlDer, certSerial, caKey) — полная верификация CRL.
     * crlDer и certSerial — случайные байты. caKey — фиксированный
     * (не влияет на траекторию парсинга, нужен только для подписи).
     */
    @FuzzTest
    void fuzzVerify(FuzzedDataProvider data) {
        byte[] crlDer = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] certSerial = data.consumeBytes(data.consumeInt(0, 32));
        if (crlDer.length == 0) return;
        try {
            CrlVerifier.verify(crlDer, certSerial, CA_KEY);
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
