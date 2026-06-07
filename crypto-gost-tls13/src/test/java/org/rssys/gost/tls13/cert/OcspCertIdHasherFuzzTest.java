package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тесты для {@link OcspCertIdHasher}.
 * <p>
 * Хешеры CertID вызывают TlsDerParser.readTlv на внешнем DER-сертификате
 * (issuerNameHash, issuerKeyHash). TlsDerParser не проверяет границы —
 * AIOOBE на битом сертификате гарантирован.
 * <p>
 * ПОЧЕМУ ловим RuntimeException: как и в TlsDerParserFuzzTest,
 * любой битой вход даёт AIOOBE или NPE.
 */
class OcspCertIdHasherFuzzTest {

    /**
     * hashIssuerName(certDer) — извлекает subject DN и хеширует его Streebog-256.
     * Внутри: TlsDerParser.parseSequence, readTlv на внешнем сертификате.
     */
    @FuzzTest
    void fuzzHashIssuerName(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            OcspCertIdHasher.hashIssuerName(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * hashIssuerPublicKey(certDer) — извлекает SubjectPublicKeyInfo BIT STRING value
     * и хеширует его Streebog-256. Вызывает TlsDerParser.readTlv для навигации
     * по DER сертификата.
     */
    @FuzzTest
    void fuzzHashIssuerPublicKey(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            OcspCertIdHasher.hashIssuerPublicKey(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
