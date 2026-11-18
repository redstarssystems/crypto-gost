package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.security.PrivateKey;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;

@DisplayName("GostPkcs12Loader — расшифровка приватного ключа")
class GostPkcs12LoaderTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final int TEST_ITER = 100;

    @Test
    @DisplayName(
            "Расшифровка EncryptedPrivateKeyInfo через decryptPrivateKey даёт тот же ключ, что и load PFX")
    void testDecryptPrivateKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] passwordBytes = PkixCertTestHelper.toUtf8Bytes(PASSWORD);

        // Избегаем зависимости от внутренней структуры PFX — EncryptedPrivateKeyInfo
        // создаётся независимо через GostPbes2.encryptKey, без обхода через PFX-парсер
        byte[] encryptedDer =
                GostPbes2.encryptKey(
                        bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        // Расшифровываем через новый метод
        PrivateKeyParameters decrypted =
                GostPkcs12Loader.decryptPrivateKey(encryptedDer, PASSWORD, 50);

        // Сравниваем с исходным ключом
        assertArrayEquals(
                bundle.priv.getDBytes(), decrypted.getDBytes(), "d-компонента ключа совпадает");
        assertEquals(
                bundle.priv.getParams().n, decrypted.getParams().n, "порядок кривой (n) совпадает");
    }

    @Test
    @DisplayName("encryptKey пишет соль PBKDF2 длиной 32 байта (рекомендация RFC 9337)")
    void testEncryptKeyWritesSalt32() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] encryptedDer =
                GostPbes2.encryptKey(
                        bundle.priv,
                        PkixCertTestHelper.toUtf8Bytes(PASSWORD),
                        GostOids.KUZ_CTR_ACPKM_OMAC,
                        TEST_ITER);

        GostPkcs12Parser.EncryptedPrivateKeyInfo epki =
                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(encryptedDer);
        GostPkcs12Parser.Pbes2Params pbes2 =
                GostPkcs12Parser.parsePbes2Params(epki.getEncryptionParams(), 50);

        assertEquals(
                GostOids.PBKDF2_SALT_LEN,
                pbes2.getSalt().length,
                "соль PBES2 должна иметь длину PBKDF2_SALT_LEN");
    }

    @Test
    @DisplayName("Неверный пароль бросает IllegalArgumentException")
    void testDecryptPrivateKeyWrongPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] passwordBytes = PkixCertTestHelper.toUtf8Bytes(PASSWORD);

        byte[] encryptedDer =
                GostPbes2.encryptKey(
                        bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.decryptPrivateKey(encryptedDer, "wrong".toCharArray()),
                "Неверный пароль должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Plain DER PrivateKeyInfo бросает IllegalArgumentException")
    void testDecryptPrivateKeyPlainKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] plainDer = org.rssys.gost.jca.spec.GostDerCodec.encodePrivateKey(bundle.priv);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.decryptPrivateKey(plainDer, PASSWORD),
                "Plain PrivateKeyInfo не является EncryptedPrivateKeyInfo");
    }

    // ========================================================================
    // P2-5: оригинальный char[] password не затирается (clone+wipe clone)
    // ========================================================================

    @Test
    @DisplayName("decryptPrivateKey: оригинальный char[] password сохраняется после вызова")
    void testDecryptPrivateKeyPreservesPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] passwordBytes = PkixCertTestHelper.toUtf8Bytes(PASSWORD);

        byte[] encryptedDer =
                GostPbes2.encryptKey(
                        bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        char[] pwd = PASSWORD.clone();
        GostPkcs12Loader.decryptPrivateKey(encryptedDer, pwd, 50);

        assertArrayEquals(
                PASSWORD,
                pwd,
                "Оригинальный char[] пароль не должен затираться после decryptPrivateKey");
        Arrays.fill(pwd, '\0');
    }

    @Test
    @DisplayName("adaptPrivateKey затирает jdkKey.getEncoded() после парсинга")
    void testAdaptPrivateKeyWipesEncoded() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] encoded = GostDerCodec.encodePrivateKey(bundle.priv);

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
                        return encoded;
                    }
                };

        PrivateKeyParameters result = GostPkcs12Loader.adaptPrivateKey(jdkKey);

        assertNotNull(result, "Ключ должен быть расшифрован");
        assertArrayEquals(
                bundle.priv.getDBytes(), result.getDBytes(), "d-компонента ключа совпадает");
        // Затирание должно обнулить массив, возвращённый getEncoded()
        for (byte b : encoded) {
            assertEquals(0, b, "Каждый байт исходного массива должен быть затерт");
        }
    }

    @Test
    @DisplayName("load: оригинальный char[] password сохраняется после вызова")
    void testLoadPreservesPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        char[] pwd = PASSWORD.clone();
        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(pwd)
                        .iterations(100)
                        .build();

        char[] loadPwd = PASSWORD.clone();
        GostPkcs12Loader.load(pfx, loadPwd, false, 50);

        assertArrayEquals(
                PASSWORD, loadPwd, "Оригинальный char[] пароль не должен затираться после load");
        Arrays.fill(loadPwd, '\0');
    }
}
