package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Principal;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Тесты фильтрации алиасов по issuers в GostX509KeyManager.
 */
@DisplayName("GostX509KeyManager: фильтрация записей по издателю")
class GostX509KeyManagerIssuerTest {

    private static PkixCertTestHelper.CertBundle caA;
    private static PkixCertTestHelper.CertBundle caB;
    private static PkixCertTestHelper.CertBundle leafA;
    private static PkixCertTestHelper.CertBundle leafB;
    private static PkixCertTestHelper.CertBundle leafRoot;
    private static X509Certificate caAJca;
    private static X509Certificate caBJca;
    private static X509Certificate rootJca;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        caA = PkixCertTestHelper.createRootCA(params);
        caB = PkixCertTestHelper.createRootCA(params);
        caAJca = CertificateBridge.toJca(caA.cert);
        caBJca = CertificateBridge.toJca(caB.cert);

        leafA =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        caA.priv,
                        caA.cert.getPublicKey(),
                        caA.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
        leafB =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        caB.priv,
                        caB.cert.getPublicKey(),
                        caB.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
        // Для теста no-match используем leafA с issuer caA, а запрашиваем issuers от caB
    }

    @Test
    @DisplayName("issuers filter — совпадение по CA")
    void testIssuerFilterMatch() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        X509Certificate[] jcaChain = CertificateBridge.toJca(List.of(leafA.cert, caA.cert));
        km.addKeyEntry("leafA", jcaChain, leafA.priv);

        Principal[] issuers = new Principal[] {caAJca.getSubjectX500Principal()};
        String alias =
                km.chooseEngineClientAlias(new String[] {"ECGOST3410-2012-256"}, issuers, null);
        assertEquals("leafA", alias, "Должен выбрать leafA — его issuer совпадает с subject caA");
    }

    @Test
    @DisplayName("issuers filter — нет совпадения")
    void testIssuerFilterNoMatch() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        X509Certificate[] jcaChain = CertificateBridge.toJca(List.of(leafA.cert, caA.cert));
        km.addKeyEntry("leafA", jcaChain, leafA.priv);

        // Запрашиваем issuers от caB — leafA выпущен caA
        Principal[] issuers = new Principal[] {caBJca.getSubjectX500Principal()};
        String alias =
                km.chooseEngineClientAlias(new String[] {"ECGOST3410-2012-256"}, issuers, null);
        assertNull(alias, "Должен вернуть null — issuer leafA (caA) не совпадает с caB");
    }
}
