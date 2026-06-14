package org.rssys.gost.tls13.cert;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsTestHelper;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostPkcs12Loader.decryptPrivateKey")
class GostPkcs12LoaderTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final int TEST_ITER = 100;

    @Test
    @DisplayName("Расшифровка EncryptedPrivateKeyInfo через decryptPrivateKey даёт тот же ключ, что и load PFX")
    void testDecryptPrivateKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] passwordBytes = toUtf8Bytes(PASSWORD);

        // Избегаем зависимости от внутренней структуры PFX — EncryptedPrivateKeyInfo
        // создаётся независимо через GostPbes2.encryptKey, без обхода через PFX-парсер
        byte[] encryptedDer = GostPbes2.encryptKey(
                bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        // Расшифровываем через новый метод
        PrivateKeyParameters decrypted = GostPkcs12Loader.decryptPrivateKey(encryptedDer, PASSWORD);

        // Сравниваем с исходным ключом
        assertArrayEquals(bundle.priv.getDBytes(), decrypted.getDBytes(),
                "d-компонента ключа совпадает");
        assertEquals(bundle.priv.getParams().n, decrypted.getParams().n,
                "порядок кривой (n) совпадает");
    }

    @Test
    @DisplayName("Неверный пароль бросает IllegalArgumentException")
    void testDecryptPrivateKeyWrongPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] passwordBytes = toUtf8Bytes(PASSWORD);

        byte[] encryptedDer = GostPbes2.encryptKey(
                bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Loader.decryptPrivateKey(encryptedDer, "wrong".toCharArray()),
                "Неверный пароль должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Plain DER PrivateKeyInfo бросает IllegalArgumentException")
    void testDecryptPrivateKeyPlainKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] plainDer = org.rssys.gost.jca.spec.GostDerCodec.encodePrivateKey(bundle.priv);

        assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Loader.decryptPrivateKey(plainDer, PASSWORD),
                "Plain PrivateKeyInfo не является EncryptedPrivateKeyInfo");
    }

    private static byte[] toUtf8Bytes(char[] password) {
        if (password == null || password.length == 0) return new byte[0];
        return new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}
