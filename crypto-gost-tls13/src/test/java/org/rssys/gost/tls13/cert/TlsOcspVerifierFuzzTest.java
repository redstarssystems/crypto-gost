package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.*;

/**
 * Fuzz-тесты для {@link OcspVerifier}.
 * <p>
 * OCSP-верификатор — входная точка для аутентификации OCSP-степплинга.
 * Внутри вызывает GostDerParser (нет проверки границ — AIOOBE на битом входе)
 * и Signature.verifyHash (может упасть с RuntimeException).
 * <p>
 * ПОЧЕМУ ловим RuntimeException:
 * GostDerParser НЕ проверяет границы массивов — любой битый OCSP-ответ
 * гарантированно даст AIOOBE или NPE, как документировано в GostDerParser.
 * OcspVerifier.verify() при нормальной работе кидает только PkixException.
 * RuntimeException внутри означает баг GostDerParser, а не битый OCSP-ответ.
 * <p>
 * ПОЧЕМУ caKey — один на весь класс:
 * PublicKeyParameters — тяжелый объект (ECDSA + кривая). Генерируется один раз
 * @BeforeAll, а не на каждый fuzz-вызов. Ключ не влияет на траекторию парсинга
 * OCSP-ответа — он нужен только на финальном шаге (проверка подписи).
 */
class TlsOcspVerifierFuzzTest {

    private static PublicKeyParameters caKey;

    // @BeforeAll не поддерживается Jazzer; инициализация в статике
    static {
        caKey = KeyGenerator.generateKeyPair(ECParameters.tc26a256()).getPublic();
    }

    /**
     * Fuzz-тест для OcspVerifier.verify() с CertID-проверкой (5-param overload).
     * <p>
     * Отличается от fuzzVerify тем, что передаёт fuzzed issuerCertDer и
     * expectedIssuerDn — код CertID-секции (issuerNameHash/issuerKeyHash)
     * теперь тоже покрыт случайными данными.
     */
    @FuzzTest
    void fuzzVerifyWithCertId(FuzzedDataProvider data) {
        byte[] ocspResponse = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] serialNumber = data.consumeBytes(data.consumeInt(0, 32));
        byte[] issuerDn = data.consumeBytes(data.consumeInt(0, 256));
        byte[] issuerCert = data.consumeBytes(data.consumeInt(0, 4096));
        if (ocspResponse.length == 0) return;
        try {
            OcspVerifier.verify(ocspResponse, serialNumber, caKey, issuerDn, issuerCert);
        } catch (PkixException e) {
            // Ожидаемо: битый OCSP-ответ не проходит верификацию
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * Fuzz-тест для OcspVerifier.verify().
     * <p>
     * ocspResponse и serialNumber — случайные байты из FuzzedDataProvider.
     * caKey — заранее сгенерированный ключ CA (не из фузерра — валидный).
     * <p>
     * ПОЧЕМУ serialNumber из random bytes, а не константа:
     * serialNumber влияет на траекторию поиска certId внутри OCSP-ответа
     * (OcspVerifier ищет certId с совпадающим serialNumber). Разные
     * serialNumber заставят парсер обходить больше веток, а не останавливаться
     * на первом несовпадении.
     */
    @FuzzTest
    void fuzzVerify(FuzzedDataProvider data) {
        byte[] ocspResponse = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] serialNumber = data.consumeBytes(data.consumeInt(0, 32));
        if (ocspResponse.length == 0) return;
        try {
            OcspVerifier.verify(ocspResponse, serialNumber, caKey);
        } catch (PkixException e) {
            // Ожидаемо: битый OCSP-ответ не проходит верификацию
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
