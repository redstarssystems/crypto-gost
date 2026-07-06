package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
