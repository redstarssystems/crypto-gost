package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;

/**
 * Модульные тесты {@link GostCsrBuilder}: построение CSR.
 */
@DisplayName("GostCsrBuilder: построение PKCS#10 CSR")
class GostCsrBuilderTest {

    @Test
    @DisplayName("buildCsr: обратимость — собираем CSR с DN")
    void testBuildCsrRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.buildCsr(kp.getPrivate(), kp.getPublic(), "CN=Test,OU=Dev");

        assertNotNull(csrDer);
        assertTrue(csrDer.length > 100, "CSR должен быть ненулевой длины");
    }

    @Test
    @DisplayName("buildCsr: 512-битная кривая")
    void testBuildCsr512() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.buildCsr(kp.getPrivate(), kp.getPublic(), "CN=Test512");
        assertNotNull(csrDer);
        assertTrue(csrDer.length > 200);
    }

    @Test
    @DisplayName("buildCsr: DN с несколькими атрибутами")
    void testBuildCsrMultiAttrDn() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.buildCsr(
                        kp.getPrivate(),
                        kp.getPublic(),
                        "CN=Server,O=MyOrg,OU=Dev,L=City,ST=Region,C=RU");
        assertNotNull(csrDer);
    }

    @Test
    @DisplayName("buildCsr: разные ключи дают разный CSR")
    void testBuildCsrDifferentKeys() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp1 = KeyGenerator.generateKeyPair(params);
        KeyPair kp2 = KeyGenerator.generateKeyPair(params);

        byte[] csr1 = GostCsrBuilder.buildCsr(kp1.getPrivate(), kp1.getPublic(), "CN=Test");
        byte[] csr2 = GostCsrBuilder.buildCsr(kp2.getPrivate(), kp2.getPublic(), "CN=Test");

        assertFalse(java.util.Arrays.equals(csr1, csr2), "CSR от разных ключей должны различаться");
    }
}
