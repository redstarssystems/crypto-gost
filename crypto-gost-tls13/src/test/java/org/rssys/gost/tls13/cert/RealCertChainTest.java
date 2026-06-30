package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;

@DisplayName("RealCertChain — верификация реальных сертификатов Минцифры")
class RealCertChainTest {

    @Test
    @DisplayName("Минцифры: sub CA подписан root CA (512-бит ГОСТ-2012)")
    void testMincifryChainVerification() throws Exception {
        byte[] rootDer = loadResource("/org/rssys/gost/tls13/cert/real/mincifry-root-ca.der");
        byte[] subCaDer = loadResource("/org/rssys/gost/tls13/cert/real/mincifry-sub-ca.der");

        GostCertificate root = new GostCertificate(rootDer);
        GostCertificate subCa = new GostCertificate(subCaDer);

        assertNotNull(root.getPublicKey(), "Открытый ключ root CA должен читаться");
        assertNotNull(subCa.getPublicKey(), "Открытый ключ sub CA должен читаться");

        assertTrue(
                subCa.verifySignature(root.getPublicKey()),
                "Подпись sub CA должна верифицироваться ключом root CA Минцифры (ГОСТ-2012 512-бит)");
    }

    private static byte[] loadResource(String path) throws Exception {
        java.io.InputStream in = RealCertChainTest.class.getResourceAsStream(path);
        assertNotNull(in, "Ресурс не найден: " + path);
        return in.readAllBytes();
    }
}
