package org.rssys.gost.jsse.ocsp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.cert.GostOcspRequestBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Smoke-тест проброса {@link GostSigner} через {@link OcspRequestBuilder}
 * в {@link GostOcspRequestBuilder}. План 231.
 */
@DisplayName("OcspRequestBuilder: проброс GostSigner в GostOcspRequestBuilder")
class OcspRequestBuilderSignerTest {

    @Test
    @DisplayName("Smoke: signKey(GostSigner) — OCSPRequest содержит валидную подпись")
    void gostSignerPropagatesToPkixBuilder() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        // Строим минимальный самоподписанный сертификат для теста
        byte[] issuerDn = org.rssys.gost.pkix.cert.GostDnParser.encodeDn("CN=Test CA");
        byte[] tbs =
                org.rssys.gost.pkix.cert.GostCertificateBuilder.create(params, issuerDn)
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBefore("20250101000000Z")
                        .notAfter("20351231235959Z")
                        .issuerDn(issuerDn)
                        .buildTbs();
        byte[] certDer =
                org.rssys.gost.pkix.cert.GostCertificateBuilder.sign(
                                tbs, GostSigner.of(kp.getPrivate()))
                        .getEncoded();

        // Строим запрос через jsse-билдер с GostSigner
        OcspRequest req =
                OcspRequestBuilder.create()
                        .targetCert(certDer)
                        .issuerCert(certDer)
                        .signKey(GostSigner.of(kp.getPrivate()))
                        .build();

        assertNotNull(req, "OCSPRequest не должен быть null");
        byte[] der = req.der();
        assertNotNull(der, "DER не должен быть null");

        // Извлекаем подпись из DER и проверяем её против открытого ключа
        boolean verified = verifyOcspRequestSignature(der, kp.getPublic());
        assertTrue(
                verified, "Подпись OCSPRequest должна верифицироваться открытым ключом подписанта");
    }

    /**
     * Извлекает signatureValue из DER OCSPRequest и проверяет подпись против pubKey.
     * Структура: OCSPRequest ::= SEQUENCE { tbsRequest, [0] EXPLICIT signature OPTIONAL }
     * signature ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
     */
    private static boolean verifyOcspRequestSignature(byte[] ocspDer, PublicKeyParameters pubKey) {
        int[] topSeq = org.rssys.gost.pkix.cert.GostDerParser.readTlv(ocspDer, 0);
        int pos = topSeq[0];
        int end = topSeq[1];

        while (pos < end) {
            if ((ocspDer[pos] & 0xFF) == 0xA0) {
                int[] sigTlv = org.rssys.gost.pkix.cert.GostDerParser.readTlv(ocspDer, pos);
                byte[] sigSeq = Arrays.copyOfRange(ocspDer, sigTlv[0], sigTlv[1]);

                int[] sigSeqBounds = org.rssys.gost.pkix.cert.GostDerParser.readTlv(sigSeq, 0);
                int sigOffset = sigSeqBounds[0];
                int sigEnd = sigSeqBounds[1];

                while (sigOffset < sigEnd) {
                    if ((sigSeq[sigOffset] & 0xFF) == org.rssys.gost.util.DerCodec.TAG_BIT_STRING) {
                        byte[] sigValue =
                                org.rssys.gost.util.DerCodec.parseBitString(sigSeq, sigOffset);

                        byte[] tbs = Arrays.copyOfRange(ocspDer, topSeq[0], pos);
                        int hlen = pubKey.getParams().hlen;
                        byte[] tbsHash =
                                hlen == 32
                                        ? org.rssys.gost.api.Digest.digest256(tbs)
                                        : org.rssys.gost.api.Digest.digest512(tbs);

                        return Signature.verifyHash(tbsHash, sigValue, pubKey);
                    }
                    int[] tlv = org.rssys.gost.pkix.cert.GostDerParser.readTlv(sigSeq, sigOffset);
                    sigOffset = tlv[1];
                }
                return false;
            }
            int[] tlv = org.rssys.gost.pkix.cert.GostDerParser.readTlv(ocspDer, pos);
            pos = tlv[1];
        }
        return false;
    }
}
