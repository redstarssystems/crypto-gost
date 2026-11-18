package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.security.PrivateKey;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Регрессия транзитивной защиты: маскированный закрытый ключ RFC 9548 (|I| > n) отвергается
 * на всех путях pkix, которые разбирают PKCS#8, хотя отдельной проверки там нет —
 * её выполняет {@link GostDerCodec#decodePrivateKey}.
 */
@DisplayName("Маскированный закрытый ключ: отказ в pkix")
class GostMaskedPrivateKeyRegressionTest {

    private static final int PBKDF2_ITERATIONS = 1000;

    /** PKCS#8, в котором I = d ‖ ненулевая «маска» длиной n (форма маскированного ключа RFC 9548). */
    private static byte[] maskedPkcs8(ECParameters params) {
        byte[] template =
                GostDerCodec.encodePrivateKey(
                        new PrivateKeyParameters(java.math.BigInteger.valueOf(0x1234567L), params));
        byte[][] outer = DerCodec.parseSequenceContents(template, 0);
        int n = (params.n.bitLength() + 7) / 8;
        byte[] content = new byte[2 * n];
        content[0] = 0x67;
        Arrays.fill(content, n, content.length, (byte) 0x11);
        return DerCodec.encodeSequence(outer[0], outer[1], DerCodec.encodeOctetString(content));
    }

    @Test
    @DisplayName(
            "GostPbes2.decryptKey: маскированный открытый текст отвергается после расшифрования")
    void pbes2RejectsMaskedPlaintext() {
        byte[] plaintext = maskedPkcs8(ECParameters.tc26a256());
        byte[] password = {'p', 'w'};
        byte[] salt = new byte[GostOids.PBKDF2_SALT_LEN];
        byte[] ukm = new byte[GostOids.PBES2_UKM_LEN];
        CryptoRandom.INSTANCE.nextBytes(salt);
        CryptoRandom.INSTANCE.nextBytes(ukm);
        byte[] dk =
                Pbkdf2Streebog.generate(
                        password, salt, PBKDF2_ITERATIONS, GostOids.KUZNYECHIK_KEY_LEN);
        SymmetricKey key = new SymmetricKey(dk);
        byte[] encrypted;
        try {
            encrypted = CtrAcpkmMode.encryptWithMac(key, ukm, plaintext);
        } finally {
            key.destroy();
            Arrays.fill(dk, (byte) 0);
        }
        byte[] params =
                GostPbes2.buildPbes2Params(
                        salt,
                        PBKDF2_ITERATIONS,
                        ukm,
                        GostOids.HMAC_STREEBOG_512,
                        GostOids.KUZ_CTR_ACPKM_OMAC);
        byte[] epkiDer = GostPbes2.buildEncryptedPrivateKeyInfo(params, encrypted);

        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        GostPbes2.decryptKey(
                                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(epkiDer),
                                password,
                                PBKDF2_ITERATIONS),
                "маскированный ключ внутри PBES2 должен быть отвергнут, а не усечён");
    }

    @Test
    @DisplayName("GostPkcs12Loader.adaptPrivateKey: PrivateKey с маскированным DER отвергается")
    void adaptPrivateKeyRejectsMaskedKey() {
        byte[] masked = maskedPkcs8(ECParameters.tc26a256());
        PrivateKey jdkKey =
                new PrivateKey() {
                    @Override
                    public String getAlgorithm() {
                        return "ECGOST3410";
                    }

                    @Override
                    public String getFormat() {
                        return "PKCS#8";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return masked.clone();
                    }
                };

        assertThrows(
                UnsupportedOperationException.class,
                () -> GostPkcs12Loader.adaptPrivateKey(jdkKey),
                "adaptPrivateKey не должен молча возвращать K_M вместо ключа");
    }
}
