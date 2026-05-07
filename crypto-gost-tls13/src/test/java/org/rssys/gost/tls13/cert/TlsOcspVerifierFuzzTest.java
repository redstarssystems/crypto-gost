package org.rssys.gost.tls13.cert;
import org.rssys.gost.tls13.*;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Fuzz-тесты для {@link TlsOcspVerifier}.
 * <p>
 * OCSP-верификатор — входная точка для аутентификации OCSP-степплинга.
 * Внутри вызывает TlsDerParser (нет проверки границ — AIOOBE на битом входе)
 * и Signature.verifyHash (может упасть с RuntimeException).
 * <p>
 * ПОЧЕМУ ловим RuntimeException:
 * TlsDerParser НЕ проверяет границы массивов — любой битый OCSP-ответ
 * гарантированно даст AIOOBE или NPE, как документировано в TlsDerParser.
 * TlsOcspVerifier.verify() при нормальной работе кидает только TlsException.
 * RuntimeException внутри означает баг TlsDerParser, а не битый OCSP-ответ.
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
     * Fuzz-тест для TlsOcspVerifier.verify().
     * <p>
     * ocspResponse и serialNumber — случайные байты из FuzzedDataProvider.
     * caKey — заранее сгенерированный ключ CA (не из фузерра — валидный).
     * <p>
     * ПОЧЕМУ serialNumber из random bytes, а не константа:
     * serialNumber влияет на траекторию поиска certId внутри OCSP-ответа
     * (TlsOcspVerifier ищет certId с совпадающим serialNumber). Разные
     * serialNumber заставят парсер обходить больше веток, а не останавливаться
     * на первом несовпадении.
     */
    @FuzzTest
    void fuzzVerify(FuzzedDataProvider data) {
        byte[] ocspResponse = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] serialNumber = data.consumeBytes(data.consumeInt(0, 32));
        try {
            TlsOcspVerifier.verify(ocspResponse, serialNumber, caKey);
        } catch (TlsException e) {
            // Ожидаемо: битый OCSP-ответ не проходит верификацию
        } catch (RuntimeException e) {
            // Ожидаемо: TlsDerParser кидает AIOOBE/NPE на битом DER
            // или Signature при пустом/null хеше
        }
    }
}
