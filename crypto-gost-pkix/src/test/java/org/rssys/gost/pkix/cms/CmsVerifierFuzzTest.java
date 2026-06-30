package org.rssys.gost.pkix.cms;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Фаззинг-тесты верификации CMS SignedData и расшифровки CMS EnvelopedData.
 * Проверяют отсутствие крашей (AIOOBE, NPE, NegativeArraySizeException) на случайных байтах.
 */
class CmsVerifierFuzzTest {

    private static PrivateKeyParameters privKey;
    private static GostCertificate cert;
    private static CmsKeyWrap keyWrap;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        privKey = kp.getPrivate();
        PublicKeyParameters pubKey = kp.getPublic();
        cert =
                CmsTestUtils.createSelfSignedCert(
                        privKey, pubKey, BigInteger.valueOf(System.currentTimeMillis()));
        keyWrap = new Kexp15CmsKeyWrap();
    }

    @FuzzTest
    void fuzzDecryptEnvelopedData(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        try {
            CmsEnvelopedDataDecryptor.decrypt(der, privKey, cert, keyWrap);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        } catch (Exception ignored) {
            // ожидаемо: битый DER -> ошибка парсинга, несоответствие ключей
        }
    }

    @FuzzTest
    void fuzzVerifySignedData(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        try {
            CmsSignedDataVerifier.verifyAny(der, cert);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        } catch (Exception ignored) {
            // ожидаемо: битый DER -> ошибка парсинга, неверная подпись
        }
    }
}
