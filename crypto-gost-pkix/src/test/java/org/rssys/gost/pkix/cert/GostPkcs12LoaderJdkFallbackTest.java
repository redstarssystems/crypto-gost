package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("GostPkcs12Loader — JDK-fallback: связность цепочки без MAC")
class GostPkcs12LoaderJdkFallbackTest {

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final int MIN_ITERATIONS = 50;

    /** Самоподписанный RSA-сертификат: ГОСТ-загрузчик не умеет разбирать такой SPKI. */
    private static final String RSA_ROOT_DER_BASE64 =
            "MIIDEDCCAfigAwIBAgIUYsQqV27hEUhOdz6rAIE4nRdw6S0wDQYJKoZIhvcNAQELBQAwGDEWMBQG"
                    + "A1UEAwwNVGVzdCBSU0EgUm9vdDAgFw0yNjExMDEyMTIwMDZaGA8yMTI2MTAwODIxMjAwNlowGDEW"
                    + "MBQGA1UEAwwNVGVzdCBSU0EgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9k"
                    + "AeGA/7xXtyuo4k3DjVSHT02nwqiPYi6tTlzDZFJQ4KSS+MqX3vFoWw9boNOKXliWEUbcsb1ZuReF"
                    + "NhwSRP0abfi4+5q+UPClynSGcakngxXm1Gax72Oor/Bo/EpzAHVKrMz70z0liAf4jQVAXy17b+ov"
                    + "ZLM3gDq7/UBXaeGolz1m7aM2Qa+LsRnHxisgyVBuX8QkgLyZBZx1DSlAMjEjiQ4hEOaCJUFdx5O+"
                    + "WJRa92nCy0/JOxi3dqBtDw/EtT4S22O2q1foWfQY+6Hd6XB1Au49aCXzLcTSRqZZRbgMxtMlkRQx"
                    + "0W4H9AIIKsg4AywUiba1sIDz6ANEeybyZd0CAwEAAaNQME4wHQYDVR0OBBYEFFNHqZJw4z9siiK+"
                    + "rpLfbzUdpkE8MB8GA1UdIwQYMBaAFFNHqZJw4z9siiK+rpLfbzUdpkE8MAwGA1UdEwQFMAMBAf8w"
                    + "DQYJKoZIhvcNAQELBQADggEBAEfazNIdcqghcsAy5zPfJDXgvvui1zlBYpfF/mtxz6U3EMfXFj2f"
                    + "ACuJTqZFaCm+1uZicRhao36gLvOk0NGtmXAgNoLbTz9/xIdQvXWUEI5m1O0Iwnp+PpYbHLbzCr30"
                    + "aVjyf/Koh34ktrFS/YXx/vvu773Px+jipwWnxXLIOcCB4hifjHIjXX5dOqXrN99fChAIrUhsPlrL"
                    + "7V3tsXiLEywOLjwqEiUDTLm/6Sms2+HRFeQmmErnmbZjdXRIDJBjdcOs6dd60OPZpbppYVXijKC5"
                    + "GvnWfYyXys9Q1f54hqDyB+SzZl6DQ2xWSuVNrz1iB4jqwrZ1C9GDNDqrvmTVRKQ=";

    @Test
    @DisplayName("Без MAC поддельный CA с тем же subject DN не попадает в цепочку")
    void testForgedCaWithSameSubjectDnDropped() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf = createLeafSignedBy(params, ca);
        GostCertificate forgedCa = forgeRootCa(params, ca.subjectDn);

        KeyStore ks = newKeyStore();
        ks.setKeyEntry("leaf", new GostECPrivateKey(leaf.priv), PASSWORD, toJdk(leaf.cert));
        ks.setCertificateEntry("forged", toJdk(forgedCa)[0]);
        byte[] pfx = stripMacData(store(ks));

        GostPkcs12Loader.Result result =
                GostPkcs12Loader.load(
                        pfx,
                        PASSWORD,
                        true,
                        MIN_ITERATIONS,
                        GostPkcs12Loader.MacPolicy.ALLOW_MISSING);

        List<GostCertificate> chain = result.getCertificateChain();
        assertEquals(1, chain.size(), "в цепочке только конечный сертификат");
        assertArrayEquals(
                leaf.cert.getEncoded(),
                chain.get(0).getEncoded(),
                "первое звено — сертификат ключа");
        assertEquals(1, result.getDroppedCertificateCount(), "поддельный CA отброшен");
    }

    @Test
    @DisplayName("Без MAC легитимная цепочка [leaf, CA] сохраняется целиком")
    void testLegitimateChainKept() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf = createLeafSignedBy(params, ca);

        KeyStore ks = newKeyStore();
        ks.setKeyEntry(
                "leaf", new GostECPrivateKey(leaf.priv), PASSWORD, toJdk(leaf.cert, ca.cert));
        byte[] pfx = stripMacData(store(ks));

        GostPkcs12Loader.Result result =
                GostPkcs12Loader.load(
                        pfx,
                        PASSWORD,
                        true,
                        MIN_ITERATIONS,
                        GostPkcs12Loader.MacPolicy.ALLOW_MISSING);

        assertEquals(2, result.getCertificateChain().size(), "цепочка из двух звеньев");
        assertFalse(result.getCertificateChain().get(0).isCA(), "chain[0] — конечный");
        assertTrue(result.getCertificateChain().get(1).isCA(), "chain[1] — УЦ");
        assertEquals(0, result.getDroppedCertificateCount(), "ничего не отброшено");
    }

    @Test
    @DisplayName("Ключ не соответствует сертификату -> IllegalArgumentException")
    void testKeyMismatchRejected() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle keyOwner = PkixCertTestHelper.createCertWithKey(params);
        PkixCertTestHelper.CertBundle otherCert = PkixCertTestHelper.createCertWithKey(params);

        KeyStore ks = newKeyStore();
        ks.setKeyEntry(
                "mismatch", new GostECPrivateKey(keyOwner.priv), PASSWORD, toJdk(otherCert.cert));
        byte[] pfx = store(ks);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, MIN_ITERATIONS),
                "несовпадение ключа и сертификата должно отклоняться на JDK-пути");
    }

    @Test
    @DisplayName("ГОСТ-ключ и посторонний RSA trusted-сертификат: контейнер загружается")
    void testNonGostTrustedCertificateSkipped() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf = createLeafSignedBy(params, ca);
        X509Certificate rsaRoot =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509")
                                .generateCertificate(
                                        new ByteArrayInputStream(
                                                Base64.getDecoder().decode(RSA_ROOT_DER_BASE64)));

        KeyStore ks = newKeyStore();
        ks.setKeyEntry(
                "leaf", new GostECPrivateKey(leaf.priv), PASSWORD, toJdk(leaf.cert, ca.cert));
        ks.setCertificateEntry("rsa-root", rsaRoot);
        byte[] pfx = store(ks);

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, MIN_ITERATIONS);

        assertEquals(2, result.getCertificateChain().size(), "цепочка ГОСТ-ключа не пострадала");
        assertEquals(
                2, result.getAllCertificates().size(), "не-ГОСТ сертификат не входит в кандидаты");
    }

    @Test
    @DisplayName("Строгий режим отклоняет JDK-контейнер без MacData")
    void testRequiredMacRejectsMissingMac() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        KeyStore ks = newKeyStore();
        ks.setKeyEntry("key", new GostECPrivateKey(bundle.priv), PASSWORD, toJdk(bundle.cert));
        byte[] pfx = stripMacData(store(ks));

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, MIN_ITERATIONS),
                "по умолчанию MAC обязателен и на пути JDK-fallback");
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    private static PkixCertTestHelper.CertBundle createLeafSignedBy(
            ECParameters params, PkixCertTestHelper.CertBundle ca) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                ca.priv,
                ca.cert.getPublicKey(),
                ca.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                null,
                null,
                null,
                false,
                null);
    }

    /** Самоподписанный CA с заданным subject DN, но другим ключом. */
    private static GostCertificate forgeRootCa(ECParameters params, byte[] subjectDn)
            throws Exception {
        KeyPair keyPair = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = keyPair.getPrivate();
        byte[] basicConstraints = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(keyPair.getPublic())
                        .notBeforeNow()
                        .validForYears(100)
                        .additionalExtensions(basicConstraints)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(priv));
    }

    private static KeyStore newKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        return ks;
    }

    private static X509Certificate[] toJdk(GostCertificate... certs) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate[] result = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            result[i] =
                    (X509Certificate)
                            factory.generateCertificate(
                                    new ByteArrayInputStream(certs[i].getEncoded()));
        }
        return result;
    }

    private static byte[] store(KeyStore ks) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, PASSWORD);
        return out.toByteArray();
    }

    /** Удаляет MacData: версия и authSafe остаются, как у атакующего без пароля. */
    private static byte[] stripMacData(byte[] pfx) {
        byte[][] parts = DerCodec.parseSequenceContents(pfx, 0);
        assertEquals(3, parts.length, "JDK записывает версию, authSafe и MacData");
        return DerCodec.encodeSequence(parts[0], parts[1]);
    }
}
