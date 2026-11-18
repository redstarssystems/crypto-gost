package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPbes2;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;

@DisplayName("GostSsl.loadPrivateKey: загрузка закрытых ключей")
class GostSslTest {

    private static byte[] toUtf8Bytes(char[] password) {
        if (password == null || password.length == 0) return new byte[0];
        return new String(password).getBytes(StandardCharsets.UTF_8);
    }

    private static String pemEncode(byte[] der, String type) {
        String b64 = Base64.getEncoder().encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    @Test
    @DisplayName("loadPrivateKey: PEM и DER дают одинаковый ключ")
    void testLoadPrivateKeyPlain() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] der = GostDerCodec.encodePrivateKey(bundle.priv);
        byte[] pem = pemEncode(der, "PRIVATE KEY").getBytes(StandardCharsets.US_ASCII);

        PrivateKeyParameters fromDer = GostSsl.loadPrivateKey(der);
        PrivateKeyParameters fromPem = GostSsl.loadPrivateKey(pem);

        assertArrayEquals(fromDer.getDBytes(), fromPem.getDBytes(), "d-компонента совпадает");
        assertEquals(fromDer.getParams().n, fromPem.getParams().n, "порядок кривой (n) совпадает");
    }

    @Test
    @DisplayName("loadPrivateKey: маскированный ключ RFC 9548 отвергается, а не усекается")
    void testLoadPrivateKeyRejectsMasked() {
        ECParameters params = ECParameters.tc26a256();
        byte[] template =
                GostDerCodec.encodePrivateKey(
                        new PrivateKeyParameters(java.math.BigInteger.valueOf(0x1234567L), params));
        byte[][] outer = org.rssys.gost.util.DerCodec.parseSequenceContents(template, 0);
        int n = (params.n.bitLength() + 7) / 8;
        byte[] content = new byte[2 * n];
        content[0] = 0x67;
        java.util.Arrays.fill(content, n, content.length, (byte) 0x11);
        byte[] masked =
                org.rssys.gost.util.DerCodec.encodeSequence(
                        outer[0],
                        outer[1],
                        org.rssys.gost.util.DerCodec.encodeOctetString(content));

        assertThrows(
                UnsupportedOperationException.class,
                () -> GostSsl.loadPrivateKey(masked),
                "loadPrivateKey не должен молча возвращать K_M вместо ключа");
    }

    @Test
    @DisplayName("loadPrivateKey: зашифрованный ключ расшифровывается корректно")
    void testLoadPrivateKeyEncrypted() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] passwordBytes = toUtf8Bytes("secret".toCharArray());

        byte[] encryptedDer =
                GostPbes2.encryptKey(bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, 1000);
        byte[] encryptedPem =
                pemEncode(encryptedDer, "ENCRYPTED PRIVATE KEY")
                        .getBytes(StandardCharsets.US_ASCII);

        PrivateKeyParameters decrypted =
                GostSsl.loadPrivateKey(encryptedPem, "secret".toCharArray());

        assertArrayEquals(bundle.priv.getDBytes(), decrypted.getDBytes(), "d-компонента совпадает");
        assertEquals(
                bundle.priv.getParams().n, decrypted.getParams().n, "порядок кривой (n) совпадает");
    }

    @Test
    @DisplayName("loadPrivateKey: данные не ключ - исключение о формате, а не молчаливый сбой")
    void testLoadPrivateKeyRejectsGarbage() {
        byte[] garbage = {1, 2, 3, 4, 5};

        assertThrows(RuntimeException.class, () -> GostSsl.loadPrivateKey(garbage));
        assertThrows(
                RuntimeException.class,
                () -> GostSsl.loadPrivateKey(garbage, "пароль".toCharArray()),
                "с паролем разбор как EncryptedPrivateKeyInfo не должен скрывать причину отказа");
    }

    @Test
    @DisplayName("loadPrivateKey: plain ключ с не-null паролем — пароль игнорируется")
    void testLoadPrivateKeyPlainWithPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] der = GostDerCodec.encodePrivateKey(bundle.priv);
        byte[] pem = pemEncode(der, "PRIVATE KEY").getBytes(StandardCharsets.US_ASCII);

        PrivateKeyParameters result = GostSsl.loadPrivateKey(pem, "irrelevant".toCharArray());

        assertNotNull(result, "Ключ должен быть загружен, пароль игнорируется");
        assertArrayEquals(bundle.priv.getDBytes(), result.getDBytes(), "d-компонента совпадает");
    }
}
