package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.logging.Level;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

@DisplayName("GostTrustManagerFactorySpi: fail-closed и все якоря")
class GostTrustManagerFactorySpiTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    @Test
    @DisplayName("init(null) бросает KeyStoreException")
    void testInitNullRejected() {
        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        assertThrows(
                KeyStoreException.class,
                () -> spi.engineInit((KeyStore) null),
                "null-хранилище не должно означать trust-all");
    }

    @Test
    @DisplayName("init(KeyStore) предупреждает о фиксированной политике отзыва, init(params) нет")
    void testKeyStoreInitWarnsAboutFixedRevocationPolicy() throws Exception {
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(PARAMS);
        KeyStore ks = emptyStore();
        ks.setCertificateEntry("root", CertificateBridge.toJca(rootCa.cert));

        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
            spi.engineInit(ks);
            List<String> warnings = log.messages(Level.WARNING, "GostTrustManagerFactorySpi");
            assertEquals(1, warnings.size(), "ровно одно предупреждение на init(KeyStore)");
            assertTrue(
                    log.loggerNames()
                            .contains("org.rssys.gost.jsse.manager.GostTrustManagerFactorySpi"),
                    "имя логгера равно имени класса: " + log.loggerNames());
            assertTrue(
                    warnings.get(0).contains("GostTrustManagerParameters"),
                    "предупреждение указывает путь строгой настройки отзыва");

            log.clear();
            spi.engineInit(
                    GostTrustManagerParameters.builder()
                            .trustAnchors(TrustAnchors.ofCertificate(rootCa.cert))
                            .build());
            assertTrue(
                    log.messages(Level.WARNING, "GostTrustManagerFactorySpi").isEmpty(),
                    "явная настройка через параметры без предупреждения");
        }
    }

    @Test
    @DisplayName("Пустое хранилище бросает KeyStoreException")
    void testEmptyStoreRejected() throws Exception {
        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        assertThrows(
                KeyStoreException.class,
                () -> spi.engineInit(emptyStore()),
                "хранилище без ГОСТ-якорей не должно означать trust-all");
    }

    @Test
    @DisplayName("Все ГОСТ-сертификаты становятся якорями, а не только последний")
    void testAllAnchorsTrusted() throws Exception {
        PkixCertTestHelper.CertBundle rootA = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle rootB = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle leafA = serverLeaf(rootA);
        PkixCertTestHelper.CertBundle leafB = serverLeaf(rootB);

        KeyStore ks = emptyStore();
        ks.setCertificateEntry("root-a", CertificateBridge.toJca(rootA.cert));
        ks.setCertificateEntry("root-b", CertificateBridge.toJca(rootB.cert));

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(ks);
        TrustManager[] tms = spi.engineGetTrustManagers();
        GostX509TrustManager tm = (GostX509TrustManager) tms[0];

        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(List.of(leafA.cert), "localhost", false),
                "якорь root-a должен приниматься");
        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(List.of(leafB.cert), "localhost", false),
                "якорь root-b должен приниматься");
        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(List.of(leafA.cert, rootA.cert), "localhost", false),
                "цепочка [leaf, root] должна приниматься");
    }

    @Test
    @DisplayName("Якорь-сертификат из KeyStore сохраняет NameConstraints корня")
    void testKeyStoreCertAnchorEnforcesRootNameConstraints() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCAWithNameConstraints(
                        PARAMS, new String[] {"example.com"}, null);
        PkixCertTestHelper.CertBundle good =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"host.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        PkixCertTestHelper.CertBundle untrustedLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"bank.ru"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        KeyStore ks = emptyStore();
        ks.setCertificateEntry("root", CertificateBridge.toJca(root.cert));

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(ks);
        GostX509TrustManager tm = (GostX509TrustManager) spi.engineGetTrustManagers()[0];

        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(List.of(good.cert), "host.example.com", false));
        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(List.of(untrustedLeaf.cert), "bank.ru", false),
                "SAN вне permitted корня должен быть отклонён");
    }

    @Test
    @DisplayName("KeyStore cert-якорь: excluded dNSName не обходится wildcard-SAN")
    void testKeyStoreCertAnchorRejectsWildcardCoveringExcludedDns() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCAWithNameConstraints(
                        PARAMS, null, new String[] {"pay.example.com"});
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"*.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        KeyStore ks = emptyStore();
        ks.setCertificateEntry("root", CertificateBridge.toJca(root.cert));
        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(ks);
        GostX509TrustManager tm = (GostX509TrustManager) spi.engineGetTrustManagers()[0];

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(List.of(leaf.cert), "pay.example.com", false));
    }

    @Test
    @DisplayName("Самоподписанный сертификат не проходит через TMF")
    void testSelfSignedRejected() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle selfSigned =
                PkixCertTestHelper.createCertWithKey(
                        PARAMS,
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH});

        KeyStore ks = emptyStore();
        ks.setCertificateEntry("root", CertificateBridge.toJca(root.cert));

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(ks);
        GostX509TrustManager tm = (GostX509TrustManager) spi.engineGetTrustManagers()[0];

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(List.of(selfSigned.cert), "localhost", false),
                "самоподписанный сертификат не должен приниматься без явного insecure-режима");
    }

    @Test
    @DisplayName("Повторный init без ГОСТ-якорей не оставляет старые якоря")
    void testReinitResetsAnchors() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        KeyStore withRoot = emptyStore();
        withRoot.setCertificateEntry("root", CertificateBridge.toJca(root.cert));

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(withRoot);

        assertThrows(
                KeyStoreException.class,
                () -> spi.engineInit(emptyStore()),
                "повторный init без якорей должен падать");
        assertThrows(
                IllegalStateException.class,
                spi::engineGetTrustManagers,
                "после неудачного init старые якоря недоступны");
    }

    @Test
    @DisplayName("init(params), затем init(KeyStore) не оставляет старые params")
    void testReinitParamsToKeyStoreResetsState() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        GostTrustManagerParameters params =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(root.cert))
                        .ocspPolicy(OcspPolicy.IF_PRESENT)
                        .build();

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(params);
        assertDoesNotThrow(spi::engineGetTrustManagers);

        assertThrows(KeyStoreException.class, () -> spi.engineInit(emptyStore()));
        assertThrows(
                IllegalStateException.class,
                spi::engineGetTrustManagers,
                "старые params не должны пережить неудачный init(KeyStore)");
    }

    private static KeyStore emptyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        return ks;
    }

    private static PkixCertTestHelper.CertBundle serverLeaf(PkixCertTestHelper.CertBundle issuer)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20250101000000Z",
                "21010101000000Z",
                new String[] {"localhost"},
                new byte[] {(byte) 0x80},
                new String[] {GostOids.EXT_SERVER_AUTH},
                false,
                null);
    }
}
