package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;

@DisplayName("GostTrustManagerFactorySpi.init(ManagerFactoryParameters) (план 200, часть B)")
class GostTrustManagerParametersTest {

    private static PublicKeyParameters caKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        return rootCa.cert.getPublicKey();
    }

    @Test
    @DisplayName("init с GostTrustManagerParameters даёт сконфигурированный TrustManager")
    void testInitWithParameters() throws Exception {
        GostTrustManagerParameters p =
                GostTrustManagerParameters.builder()
                        .caPublicKeys(List.of(caKey()))
                        .ocspPolicy(OcspPolicy.IF_PRESENT)
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .maxCrlSize(1024 * 1024)
                        .maxRevokedEntries(1000)
                        .maxOcspAgeMs(3600_000L)
                        .build();

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(p);
        TrustManager[] tms = spi.engineGetTrustManagers();

        assertEquals(1, tms.length, "ожидается один TrustManager");
        assertInstanceOf(GostX509TrustManager.class, tms[0], "должен быть GostX509TrustManager");
    }

    @Test
    @DisplayName("init с чужим ManagerFactoryParameters бросает IllegalArgumentException")
    void testInitWithWrongParametersType() {
        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        ManagerFactoryParameters alien = new ManagerFactoryParameters() {};
        assertThrows(
                IllegalArgumentException.class,
                () -> spi.engineInit(alien),
                "чужой тип параметров должен отвергаться");
    }

    @Test
    @DisplayName("Дефолты билдера параметров безопасны (CRL DISABLED, OCSP-age по умолчанию)")
    void testBuilderDefaults() {
        GostTrustManagerParameters p = GostTrustManagerParameters.builder().build();
        assertEquals(CrlPolicy.DISABLED, p.getCrlPolicy(), "по умолчанию CRL выключен");
        assertEquals(OcspPolicy.IF_PRESENT, p.getOcspPolicy(), "по умолчанию OCSP IF_PRESENT");
        assertEquals(
                GostOids.MAX_OCSP_AGE_MS,
                p.getMaxOcspAgeMs(),
                "по умолчанию OCSP-age = GostOids.MAX_OCSP_AGE_MS");
    }
}
