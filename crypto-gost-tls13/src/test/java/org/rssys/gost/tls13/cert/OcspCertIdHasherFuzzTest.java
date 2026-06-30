package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.cert.CertIdHasher;

/**
 * Fuzz-тесты для {@link CertIdHasher}.
 * <p>
 * Хешеры CertID вызывают GostDerParser.readTlv на внешнем DER-сертификате
 * (issuerNameHash, issuerKeyHash). GostDerParser не проверяет границы —
 * AIOOBE на битом сертификате гарантирован.
 * <p>
 * ПОЧЕМУ ловим RuntimeException: как и в TlsDerParserFuzzTest,
 * любой битой вход даёт AIOOBE или NPE.
 */
class OcspCertIdHasherFuzzTest {

    /**
     * hashIssuerName(certDer) — извлекает subject DN и хеширует его Streebog-256.
     * Внутри: GostDerParser.parseSequence, readTlv на внешнем сертификате.
     */
    @FuzzTest
    void fuzzHashIssuerName(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            CertIdHasher.hashIssuerName(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * hashIssuerPublicKey(certDer) — извлекает SubjectPublicKeyInfo BIT STRING value
     * и хеширует его Streebog-256. Вызывает GostDerParser.readTlv для навигации
     * по DER сертификата.
     */
    @FuzzTest
    void fuzzHashIssuerPublicKey(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            CertIdHasher.hashIssuerPublicKey(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
