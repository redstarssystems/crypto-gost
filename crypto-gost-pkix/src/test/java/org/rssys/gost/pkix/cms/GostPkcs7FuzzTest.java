package org.rssys.gost.pkix.cms;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.BeforeAll;

/**
 * Фаззинг-тесты извлечения сертификатов из PKCS#7/.p7b.
 * Проверяют отсутствие крашей (AIOOBE, NPE, NegativeArraySizeException) на случайных
 * и полу-структурированных байтах: ожидаемый исход на битом входе — только PkixException.
 */
class GostPkcs7FuzzTest {

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
    }

    @FuzzTest
    void fuzzExtractCertificates(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        try {
            GostPkcs7.extractCertificates(der);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        } catch (Exception ignored) {
            // ожидаемо: битый DER -> PkixException
        }
    }

    /**
     * Targeted: префикс SEQUENCE (0x30) направляет фаззер в разбор тела SignedData,
     * увеличивая шанс дойти до навигации и поля certificates.
     */
    @FuzzTest
    void fuzzExtractWithSequencePrefix(FuzzedDataProvider data) {
        byte[] body = data.consumeBytes(data.consumeInt(0, 65536));
        if (body.length < 4) return;
        byte[] input = new byte[body.length + 1];
        input[0] = 0x30;
        System.arraycopy(body, 0, input, 1, body.length);
        try {
            GostPkcs7.extractCertificates(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        } catch (Exception ignored) {
        }
    }

    /**
     * formatText — новая структурная точка входа (certs-only + crls[1] без signerInfos),
     * которую verify-фаззер не покрывает. Логика разбора сертификатов и CRL уже фаззится
     * (extractCertificates, CmsVerifierFuzzTest.parseEmbeddedCrls), но собственная навигация
     * formatText по полям SignedData и форматирование недоверенных значений — нет.
     * Ожидаемый исход на битом входе — только PkixException, без крашей.
     */
    @FuzzTest
    void fuzzFormatText(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        try {
            GostPkcs7.formatText(der);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        } catch (Exception ignored) {
            // ожидаемо: битый DER -> PkixException
        }
    }
}
