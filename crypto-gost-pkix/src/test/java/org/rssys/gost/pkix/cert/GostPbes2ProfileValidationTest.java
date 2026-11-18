package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.util.DerCodec.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.Pbes2Params;
import org.rssys.gost.util.CryptoRandom;

/**
 * Профильная валидация PBES2 (RFC 9337 §7.3): допустимы только два OID Кузнечика,
 * UKM обязателен и имеет длину ровно 16 байт.
 */
@DisplayName("PBES2 — проверка OID шифра и длины UKM")
class GostPbes2ProfileValidationTest {

    private static final int ITERATIONS = 2_000;

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    private static byte[] params(String encOid, byte[] ukm) {
        return GostPbes2.buildPbes2Params(
                random(16), ITERATIONS, ukm, GostOids.HMAC_STREEBOG_512, encOid);
    }

    @Test
    @DisplayName("Оба поддерживаемых OID с UKM 16 байт принимаются")
    void supportedOidsAccepted() {
        for (String oid : new String[] {GostOids.KUZ_CTR_ACPKM, GostOids.KUZ_CTR_ACPKM_OMAC}) {
            Pbes2Params p = GostPkcs12Parser.parsePbes2Params(params(oid, random(16)));
            assertEquals(oid, p.getEncryptionSchemeOid(), "OID шифра должен сохраниться");
        }
    }

    @Test
    @DisplayName("Неизвестный OID шифра отвергается, а не обрабатывается как Кузнечик")
    void unknownEncryptionOidRejected() {
        byte[] data = params("1.2.643.7.1.1.5.1.1", random(16));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Parser.parsePbes2Params(data),
                "OID Магмы/неизвестный OID должен отвергаться");
    }

    @Test
    @DisplayName("UKM неверной длины отвергается")
    void wrongUkmLengthRejected() {
        for (int len : new int[] {0, 8, 15, 17, 32}) {
            byte[] data = params(GostOids.KUZ_CTR_ACPKM, random(len));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostPkcs12Parser.parsePbes2Params(data),
                    "UKM длиной " + len + " должен отвергаться");
        }
    }

    @Test
    @DisplayName("Отсутствие параметров шифра (UKM) отвергается")
    void missingUkmRejected() {
        byte[] prfAlgId = encodeSequence(encodeOid(GostOids.HMAC_STREEBOG_512));
        byte[] kdfParams =
                encodeSequence(encodeOctetString(random(16)), encodeInteger(ITERATIONS), prfAlgId);
        byte[] kdfAlgId = encodeSequence(encodeOid(GostOids.PBKDF2), kdfParams);
        byte[] encAlgId = encodeSequence(encodeOid(GostOids.KUZ_CTR_ACPKM));
        byte[] data = encodeSequence(kdfAlgId, encAlgId);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Parser.parsePbes2Params(data),
                "PBES2 без ukm не должен расшифровываться с нулевым IV");
    }

    @Test
    @DisplayName("Параметры PRF кодируются с NULL (RFC 9337 §7.1)")
    void prfParametersEncodedAsNull() {
        byte[] data = params(GostOids.KUZ_CTR_ACPKM, random(16));

        // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
        byte[][] top = parseSequenceContents(data, 0);
        // keyDerivationFunc ::= SEQUENCE { PBKDF2 OID, PBKDF2-params }
        byte[][] kdfAlg = parseSequenceContents(top[0], 0);
        // PBKDF2-params ::= SEQUENCE { salt, iterationCount, prf }
        byte[][] kdfParams = parseSequenceContents(kdfAlg[1], 0);
        byte[][] prf = parseSequenceContents(kdfParams[2], 0);

        assertEquals(GostOids.HMAC_STREEBOG_512, parseOid(prf[0], 0), "OID PRF");
        assertEquals(2, prf.length, "AlgorithmIdentifier PRF: OID и параметры");
        assertEquals(0x05, prf[1][0] & 0xFF, "Параметры PRF должны быть NULL");
        assertEquals(2, prf[1].length, "NULL не содержит данных");
    }
}
