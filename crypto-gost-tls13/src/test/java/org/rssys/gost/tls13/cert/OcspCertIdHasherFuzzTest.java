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

    /**
     * Targeted: Certificate с wrong-tag issuer в tbsCertificate.
     * Фикс 0.6.2: extractSubject проверяет тег issuer (TAG_SEQUENCE) позиционно,
     * чужой тег (OCTET STRING) — IllegalArgumentException.
     * <p>
     * Структура (параметризованные байты из фаззера):
     * <pre>
     * 30 ZZ                         -- Certificate SEQUENCE (внешний)
     *   30 XX                       -- tbsCertificate
     *     A0 03 02 01 02            -- version [0] v3
     *     02 01 7B                  -- serialNumber 123
     *     30 0A 06 08 OID_8байт     -- signature AlgId
     *     04 XX ...                 -- issuer: OCTET STRING (WRONG TAG)
     *     30 04 00 00 00 00         -- validity (dummy)
     *     30 04 00 00 00 00         -- subject (dummy)
     *     30 04 00 00 00 00         -- SPKI (dummy)
     *   30 0A 06 08 OID_8байт       -- sigAlg (dummy)
     *   03 04 00 00 00 00           -- signature (dummy)
     * </pre>
     * extractSubject проходит: findTbsOffset -> skip version -> check serial INTEGER ->
     * skip serial -> check sigAlg SEQUENCE -> skip sigAlg -> check issuer SEQUENCE —
     * здесь ждёт 0x30, получает 0x04 -> IllegalArgumentException.
     */
    @FuzzTest
    void fuzzHashIssuerNameWithWrongTag(FuzzedDataProvider data) {
        byte[] oidBytes = data.consumeBytes(8);
        if (oidBytes.length < 8) return;
        byte[] issuerContent = data.consumeBytes(data.consumeInt(1, 32));
        int issuerLen = issuerContent.length;
        // Пресеты для фиксированных полей
        byte[] version = {(byte) 0xA0, 0x03, 0x02, 0x01, 0x02};
        byte[] serial = {0x02, 0x01, 0x7B};
        byte[] sigAlgPrefix = {0x30, 0x0A, 0x06, 0x08};
        byte[] validity = {0x30, 0x04, 0x00, 0x00, 0x00, 0x00};
        byte[] subject = {0x30, 0x04, 0x00, 0x00, 0x00, 0x00};
        byte[] spki = {0x30, 0x04, 0x00, 0x00, 0x00, 0x00};
        // issuer OCTET STRING: 0x04 + len + content
        int issuerTlvLen = 1 + 1 + issuerLen;
        // tbsCertificate content
        int tbsContentLen =
                version.length
                        + serial.length
                        + sigAlgPrefix.length
                        + oidBytes.length
                        + issuerTlvLen
                        + validity.length
                        + subject.length
                        + spki.length;
        // sigAlg: 30 0A 06 08 + 8-byte OID = 12 bytes
        int sigAlgLen = 12;
        byte[] sigVal = {0x03, 0x04, 0x00, 0x00, 0x00, 0x00};
        // Certificate content = tbsCertTLV + sigAlg + sigVal
        int tbsTlvLen = 2 + tbsContentLen;
        int certContentLen = tbsTlvLen + sigAlgLen + sigVal.length;
        byte[] input = new byte[2 + certContentLen];
        int pos = 0;
        input[pos++] = 0x30;
        input[pos++] = (byte) certContentLen;
        input[pos++] = 0x30;
        input[pos++] = (byte) tbsContentLen;
        System.arraycopy(version, 0, input, pos, version.length);
        pos += version.length;
        System.arraycopy(serial, 0, input, pos, serial.length);
        pos += serial.length;
        System.arraycopy(sigAlgPrefix, 0, input, pos, sigAlgPrefix.length);
        pos += sigAlgPrefix.length;
        System.arraycopy(oidBytes, 0, input, pos, oidBytes.length);
        pos += oidBytes.length;
        input[pos++] = 0x04; // WRONG TAG — должен быть 0x30 (SEQUENCE)
        input[pos++] = (byte) issuerLen;
        System.arraycopy(issuerContent, 0, input, pos, issuerLen);
        pos += issuerLen;
        System.arraycopy(validity, 0, input, pos, validity.length);
        pos += validity.length;
        System.arraycopy(subject, 0, input, pos, subject.length);
        pos += subject.length;
        System.arraycopy(spki, 0, input, pos, spki.length);
        pos += spki.length;
        System.arraycopy(sigAlgPrefix, 0, input, pos, sigAlgPrefix.length);
        pos += sigAlgPrefix.length;
        System.arraycopy(oidBytes, 0, input, pos, oidBytes.length);
        pos += oidBytes.length;
        System.arraycopy(sigVal, 0, input, pos, sigVal.length);
        try {
            CertIdHasher.hashIssuerName(input);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: wrong tag на месте issuer
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
