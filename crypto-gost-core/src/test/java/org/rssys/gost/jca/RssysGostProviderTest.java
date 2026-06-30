package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Provider;
import java.security.Security;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("RssysGostProvider — регистрация провайдера")
class RssysGostProviderTest {

    @BeforeAll
    static void registerProvider() {
        // Регистрируем только если ещё не зарегистрирован
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    @Test
    @DisplayName("провайдер зарегистрирован и доступен через Security.getProvider")
    void testProviderRegistered() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p, "Провайдер должен быть зарегистрирован");
        assertEquals(RssysGostProvider.PROVIDER_NAME, p.getName());
    }

    @ParameterizedTest
    @DisplayName("провайдер поддерживает MessageDigest")
    @CsvSource({"GOST3411-2012-256", "GOST3411-2012-512"})
    void testHasMessageDigest(String algo) {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("MessageDigest", algo));
    }

    @ParameterizedTest
    @DisplayName("провайдер поддерживает Mac.HmacGOST3411-2012")
    @CsvSource({"HmacGOST3411-2012-256", "HmacGOST3411-2012-512"})
    void testHasHmac(String algo) {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("Mac", algo));
    }

    @Test
    @DisplayName("провайдер поддерживает Mac.CMAC-Kuznyechik")
    void testHasCmac() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("Mac", "CMAC-Kuznyechik"));
    }

    @Test
    @DisplayName("провайдер поддерживает Cipher.Kuznyechik")
    void testHasCipher() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("Cipher", "Kuznyechik"));
    }

    @Test
    @DisplayName("провайдер поддерживает KeyGenerator.Kuznyechik")
    void testHasKeyGenerator() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("KeyGenerator", "Kuznyechik"));
    }

    @Test
    @DisplayName("провайдер поддерживает KeyPairGenerator.ECGOST3410-2012")
    void testHasKeyPairGenerator() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("KeyPairGenerator", "ECGOST3410-2012"));
    }

    @Test
    @DisplayName("провайдер поддерживает KeyFactory.ECGOST3410-2012")
    void testHasKeyFactory() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("KeyFactory", "ECGOST3410-2012"));
    }

    @Test
    @DisplayName("провайдер поддерживает SecretKeyFactory.Kuznyechik")
    void testHasSecretKeyFactory() {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("SecretKeyFactory", "Kuznyechik"));
    }

    @ParameterizedTest
    @DisplayName("провайдер поддерживает Signature.ECGOST3410-2012")
    @CsvSource({"ECGOST3410-2012-256", "ECGOST3410-2012-512"})
    void testHasSignature(String algo) {
        Provider p = Security.getProvider(RssysGostProvider.PROVIDER_NAME);
        assertNotNull(p.getService("Signature", algo));
    }

    @Test
    @DisplayName("алиас Streebog-256 разрешается в GOST3411-2012-256")
    void testAlias256() throws Exception {
        // getInstance должен найти алгоритм через алиас
        java.security.MessageDigest md =
                java.security.MessageDigest.getInstance(
                        "Streebog-256", RssysGostProvider.PROVIDER_NAME);
        assertNotNull(md);
    }

    @Test
    @DisplayName("алиас OID 1.2.643.7.1.1.2.3 разрешается в GOST3411-2012-512")
    void testOidAlias512() throws Exception {
        java.security.MessageDigest md =
                java.security.MessageDigest.getInstance(
                        "1.2.643.7.1.1.2.3", RssysGostProvider.PROVIDER_NAME);
        assertNotNull(md);
    }
}
