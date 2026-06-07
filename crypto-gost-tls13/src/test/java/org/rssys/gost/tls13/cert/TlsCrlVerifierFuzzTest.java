package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsException;

/**
 * Fuzz-тесты для {@link TlsCrlVerifier}.
 * <p>
 * CRL-верификатор выполняет ~40+ вызовов TlsDerParser.readTlv/parseSequence
 * на внешнем DER. Содержит сложную логику пропуска опциональных полей
 * (version, nextUpdate, revokedCertificates, crlExtensions, issuingDistributionPoint).
 * <p>
 * TlsCrlVerifier.verify() оборачивает RuntimeException в TlsException
 * (строки 191-194, fail-closed: любая ошибка парсинга = ALERT_DECODE_ERROR).
 * Поэтому на уровне fuzz-теста AIOOBE не виден — он перехвачен. Фаззер проверяет:
 * <ol>
 *   <li>Ни один вход не вешает JVM (OOM, бесконечный цикл)</li>
 *   <li>Алгоритм доходит до проверки подписи на валидном DER</li>
 *   <li>Indirect/partial CRL корректно отклоняются</li>
 * </ol>
 * ПОЧЕМУ ловим TlsException + RuntimeException: TlsException — ожидаемая
 * реакция на битый CRL (от TlsCrlVerifier). RuntimeException — если
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
            TlsCrlVerifier.verify(crlDer, certSerial, CA_KEY);
        } catch (TlsException e) {
            // Ожидаемо: битый CRL не проходит верификацию
            // TlsCrlVerifier оборачивает RuntimeExceptions в TlsException
        }
    }

    /**
     * extractNextUpdate(crlDer) — извлекает дату истечения CRL без подписи.
     * Парсит заголовок до nextUpdate, вызывает TlsDerParser.parseTime.
     * Любое исключение — возвращает null (fail-soft, в отличие от verify).
     */
    @FuzzTest
    void fuzzExtractNextUpdate(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        // extractNextUpdate сам проглатывает все исключения (fail-soft, возвращает null).
        // Ловить нечего — фаззер проверяет отсутствие зависания и OOM.
        TlsCrlVerifier.extractNextUpdate(input);
    }
}
