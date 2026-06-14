package org.rssys.gost.jsse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.GostPbes2;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostSsl.loadPrivateKey")
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
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] der = GostDerCodec.encodePrivateKey(bundle.priv);
        byte[] pem = pemEncode(der, "PRIVATE KEY").getBytes(StandardCharsets.US_ASCII);

        PrivateKeyParameters fromDer = GostSsl.loadPrivateKey(der);
        PrivateKeyParameters fromPem = GostSsl.loadPrivateKey(pem);

        assertArrayEquals(fromDer.getDBytes(), fromPem.getDBytes(),
                "d-компонента совпадает");
        assertEquals(fromDer.getParams().n, fromPem.getParams().n,
                "порядок кривой (n) совпадает");
    }

    @Test
    @DisplayName("loadPrivateKey: зашифрованный ключ расшифровывается корректно")
    void testLoadPrivateKeyEncrypted() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] passwordBytes = toUtf8Bytes("secret".toCharArray());

        byte[] encryptedDer = GostPbes2.encryptKey(
                bundle.priv, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, 100);
        byte[] encryptedPem = pemEncode(encryptedDer, "ENCRYPTED PRIVATE KEY")
                .getBytes(StandardCharsets.US_ASCII);

        PrivateKeyParameters decrypted = GostSsl.loadPrivateKey(encryptedPem, "secret".toCharArray());

        assertArrayEquals(bundle.priv.getDBytes(), decrypted.getDBytes(),
                "d-компонента совпадает");
        assertEquals(bundle.priv.getParams().n, decrypted.getParams().n,
                "порядок кривой (n) совпадает");
    }

    @Test
    @DisplayName("loadPrivateKey: plain ключ с не-null паролем — пароль игнорируется")
    void testLoadPrivateKeyPlainWithPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] der = GostDerCodec.encodePrivateKey(bundle.priv);
        byte[] pem = pemEncode(der, "PRIVATE KEY").getBytes(StandardCharsets.US_ASCII);

        PrivateKeyParameters result = GostSsl.loadPrivateKey(pem, "irrelevant".toCharArray());

        assertNotNull(result, "Ключ должен быть загружен, пароль игнорируется");
        assertArrayEquals(bundle.priv.getDBytes(), result.getDBytes(),
                "d-компонента совпадает");
    }
}
