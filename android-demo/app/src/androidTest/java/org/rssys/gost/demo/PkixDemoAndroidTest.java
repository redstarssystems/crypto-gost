package org.rssys.gost.demo;

import org.rssys.gost.pkix.cms.CAdESVerifier;
import org.rssys.gost.pkix.cms.VerifyOptions;
import org.rssys.gost.pkix.cms.SignerSelection;
import org.rssys.gost.pkix.cms.Revocation;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CertId;
import org.rssys.gost.pkix.cert.CertRevocationData;
import org.rssys.gost.pkix.cert.CertificatePolicy;
import org.rssys.gost.pkix.cert.CertificateTextFormatter;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostCsrBuilder;
import org.rssys.gost.pkix.cert.GostCsrParser;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostExtensionParser;
import org.rssys.gost.pkix.cert.GostOcspRequest;
import org.rssys.gost.pkix.cert.GostOcspRequestBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.ReasonCode;
import org.rssys.gost.pkix.cert.RevokedEntry;
import org.rssys.gost.pkix.cert.SingleOcspResponse;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CAdESSignerResult;
import org.rssys.gost.pkix.cms.CAdESXLongData;
import org.rssys.gost.pkix.cms.CertChainBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor;
import org.rssys.gost.pkix.cms.CmsSignedAndEnvelopedData;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
import org.rssys.gost.pkix.cms.GostPkcs7;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.pkix.cms.VerifiedSignedData;
import org.rssys.gost.pkix.tsp.TspRequest;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Адаптация {@code PkixDemo} для Android — 34 тестовых метода,
 * каждый проверяет одну секцию демонстрации.
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@LargeTest
public final class PkixDemoAndroidTest {

    // ========================================================================
    // Статические поля — ключи и сертификаты (общие для всех тестов)
    // ========================================================================

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    /**
     * Сертификат демо-УЦ с заданным серийным номером. CrlVerifier проверяет сам сертификат:
     * область CRL зависит от признака CA и от CDP, поэтому пары «номер + издатель» мало.
     */
    private static GostCertificate certWithSerial(byte[] serial) {
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, "CN=demo.example.com,O=DemoOrg,C=RU")
                        .publicKey(leafCert.getPublicKey())
                        .notBefore("250601000000Z")
                        .notAfter("270601000000Z")
                        .serial(new java.math.BigInteger(1, serial))
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(caKey));
    }
    private static final int DEMO_FILE_SIZE = 65536;

    private static PrivateKeyParameters caKey;
    private static PublicKeyParameters caPubKey;
    private static GostCertificate caCert;
    private static byte[] caSki;

    private static PrivateKeyParameters leafKey;
    private static PublicKeyParameters leafPubKey;
    private static GostCertificate leafCert;

    private static PrivateKeyParameters cmsKey;
    private static GostCertificate cmsCert;

    private static PrivateKeyParameters tsaKey;
    private static GostCertificate tsaCert;

    private static PrivateKeyParameters crlSignerKey;
    private static GostCertificate crlSignerCert;

    private static byte[] demoData;

    // ========================================================================
    // Инициализация — один раз на весь класс
    // ========================================================================

    @BeforeClass
    public static void setUp() {
        Security.removeProvider("RssysGostProvider");
        Security.addProvider(new RssysGostProvider());

        demoData = new byte[DEMO_FILE_SIZE];
        CryptoRandom.INSTANCE.nextBytes(demoData);
        System.out.println(
                "[подготовка] Сгенерировано " + demoData.length + " байт случайных данных");

        try {
            generateKeysAndCerts();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка инициализации ключей", e);
        }
    }

    // ========================================================================
    // Генерация ключевой инфраструктуры
    // ========================================================================

    private static void generateKeysAndCerts() throws Exception {
        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        caKey = caKp.getPrivate();
        caPubKey = caKp.getPublic();

        byte[] caKuExt = GostCertificateBuilder.buildKeyUsageExtension(
                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] caBcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, 0);
        byte[] caSkiExt = GostCertificateBuilder.buildSkiExtension(caPubKey);

        ByteArrayOutputStream caExts = new ByteArrayOutputStream();
        caExts.write(caKuExt);
        caExts.write(caBcExt);
        caExts.write(caSkiExt);

        caSki = Digest.digest256(GostDerCodec.subjectPublicKeyPointBytes(caPubKey));

        byte[] caTbs = GostCertificateBuilder.create(PARAMS, "CN=Demo Root CA,O=DemoOrg,C=RU")
                .publicKey(caPubKey)
                .randomSerial()
                .notBefore("260601000000Z")
                .notAfter("360601000000Z")
                .additionalExtensions(caExts.toByteArray())
                .buildTbs();
        caCert = GostCertificateBuilder.sign(caTbs, GostSigner.of(caKey));
        System.out.println("[подготовка] CA-сертификат создан: " + caCert.getSubjectDn());

        var leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leafKey = leafKp.getPrivate();
        leafPubKey = leafKp.getPublic();

        byte[] leafSkiExt = GostCertificateBuilder.buildSkiExtension(leafPubKey);
        byte[] leafKuExt = GostCertificateBuilder.buildKeyUsageExtension(
                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] leafEkuExt = GostCertificateBuilder.buildEkuExtension(
                new String[]{GostOids.EXT_SERVER_AUTH}, false);
        byte[] leafAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        ByteArrayOutputStream leafExts = new ByteArrayOutputStream();
        leafExts.write(leafKuExt);
        leafExts.write(leafEkuExt);
        leafExts.write(leafSkiExt);
        leafExts.write(leafAkiExt);

        byte[] leafTbs = GostCertificateBuilder.create(PARAMS, "CN=demo.example.com,O=DemoOrg,C=RU")
                .publicKey(leafPubKey)
                .randomSerial()
                .notBefore("250601000000Z")
                .notAfter("270601000000Z")
                .sanDns("demo.example.com")
                .additionalExtensions(leafExts.toByteArray())
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .buildTbs();
        leafCert = GostCertificateBuilder.sign(leafTbs, GostSigner.of(caKey));
        System.out.println("[подготовка] Leaf-сертификат создан: " + leafCert.getSubjectDn());

        var cmsKp = KeyGenerator.generateKeyPair(PARAMS);
        cmsKey = cmsKp.getPrivate();
        PublicKeyParameters cmsPubKey = cmsKp.getPublic();
        byte[] cmsTbs = GostCertificateBuilder.create(PARAMS, "CN=CMS Signer,O=DemoOrg,C=RU")
                .publicKey(cmsPubKey)
                .notBefore("250601000000Z")
                .notAfter("270601000000Z")
                .serial(BigInteger.TWO)
                .buildTbs();
        cmsCert = GostCertificateBuilder.sign(cmsTbs, GostSigner.of(cmsKey));
        System.out.println("[подготовка] CMS-сертификат создан (self-signed, serial="
                + cmsCert.getSerialNumberBigInt() + ")");

        var tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaKey = tsaKp.getPrivate();
        PublicKeyParameters tsaPubKey = tsaKp.getPublic();
        byte[] tsaTbs = GostCertificateBuilder.create(PARAMS, "CN=TSA,O=DemoOrg,C=RU")
                .publicKey(tsaPubKey)
                .notBefore("250601000000Z")
                .notAfter("270601000000Z")
                .serial(BigInteger.valueOf(3))
                .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                .buildTbs();
        tsaCert = GostCertificateBuilder.sign(tsaTbs, GostSigner.of(tsaKey));
        System.out.println("[подготовка] TSA-сертификат создан (self-signed, serial="
                + tsaCert.getSerialNumberBigInt() + ", EKU timeStamping)");

        var crlSignerKp = KeyGenerator.generateKeyPair(PARAMS);
        crlSignerKey = crlSignerKp.getPrivate();
        PublicKeyParameters crlSignerPubKey = crlSignerKp.getPublic();

        byte[] crlSignerKuExt = GostCertificateBuilder.buildKeyUsageExtension(
                GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] crlSignerSkiExt = GostCertificateBuilder.buildSkiExtension(crlSignerPubKey);
        byte[] crlSignerAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        ByteArrayOutputStream crlSignerExts = new ByteArrayOutputStream();
        crlSignerExts.write(crlSignerKuExt);
        crlSignerExts.write(crlSignerSkiExt);
        crlSignerExts.write(crlSignerAkiExt);

        byte[] crlSignerTbs = GostCertificateBuilder.create(PARAMS, "CN=CRL Signer,O=DemoOrg,C=RU")
                .publicKey(crlSignerPubKey)
                .issuerDn(caCert.getSubjectDnBytes())
                .notBefore("260601000000Z")
                .notAfter("360601000000Z")
                .serial(BigInteger.valueOf(4))
                .additionalExtensions(crlSignerExts.toByteArray())
                .buildTbs();
        crlSignerCert = GostCertificateBuilder.sign(crlSignerTbs, GostSigner.of(caKey));
        System.out.println("[подготовка] CRL-подписант создан: "
                + crlSignerCert.getSubjectDn() + " (cRLSign)");

        System.out.println();
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static GostCertificate makeSelfSignedCert(
            PrivateKeyParameters privKey, PublicKeyParameters pubKey, BigInteger serial) throws Exception {
        byte[] tbs = GostCertificateBuilder.create(PARAMS, "CN=Signer,O=DemoOrg,C=RU")
                .publicKey(pubKey)
                .notBefore("250601000000Z")
                .notAfter("270601000000Z")
                .serial(serial)
                .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(privKey));
    }

    private static byte[] concatDemoExtensions(byte[]... exts) {
        if (exts.length == 0) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            for (byte[] ext : exts) {
                out.write(ext);
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    private static void section(String title) {
        System.out.println("--- " + title + " ---");
    }

    // ========================================================================
    // §1 Быстрый старт
    // ========================================================================

    @Test
    public void test01_quickStart() throws Exception {
        section("§1 Быстрый старт: ключевая пара + самоподписанный сертификат");

        var kp = KeyGenerator.generateKeyPair(PARAMS);

        byte[] tbs = GostCertificateBuilder.create(PARAMS, "CN=Quick Start Test,O=MyOrg,C=RU")
                .publicKey(kp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForDays(365)
                .sanDns("gost.example.com")
                .buildTbs();

        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));
        String pem = cert.toPem();

        assertTrue("Сертификат создан и сериализован", cert.getEncoded().length > 0);
        assertFalse("PEM не пуст", pem.isEmpty());
        assertTrue("PEM начинается с BEGIN CERTIFICATE", pem.startsWith("-----BEGIN CERTIFICATE-----"));
        System.out.println("  OK: сертификат создан и экспортирован в PEM");
    }

    // ========================================================================
    // §2 GostCertificate
    // ========================================================================

    @Test
    public void test02_gostCertificate() throws Exception {
        section("§2 GostCertificate: загрузка, проверка подписи, срока, атрибутов");

        byte[] der = leafCert.getEncoded();
        byte[] pem = leafCert.toPem().getBytes(StandardCharsets.US_ASCII);

        GostCertificate fromPem = GostCertificate.fromPemOrDer(pem);
        assertEquals("fromPemOrDer: subject правильный",
                leafCert.getSubjectDn(), fromPem.getSubjectDn());

        GostCertificate fromDer = GostCertificate.fromDer(der);
        assertEquals("fromDer: серийный номер совпадает",
                leafCert.getSerialNumberBigInt(), fromDer.getSerialNumberBigInt());

        String chainPem = GostCertificate.chainToPem(List.of(leafCert, caCert));
        List<GostCertificate> chain =
                GostCertificate.listFromPem(chainPem.getBytes(StandardCharsets.US_ASCII));
        assertEquals("listFromPem: цепочка из 2 сертификатов", 2, chain.size());

        assertTrue("leaf.verifySignature(caPubKey) — подпись валидна",
                leafCert.verifySignature(caPubKey));
        assertFalse("leaf.verifySignature(leafPubKey) — чужая подпись невалидна",
                leafCert.verifySignature(leafPubKey));

        assertFalse("leaf.isExpired() — не истёк", leafCert.isExpired());
        assertTrue("leaf.isValidAt(now) — действителен сейчас", leafCert.isValidAt(Instant.now()));

        assertEquals("getSubjectDn()", "CN=demo.example.com, O=DemoOrg, C=RU", leafCert.getSubjectDn());
        assertEquals("getIssuerDn()", "CN=Demo Root CA, O=DemoOrg, C=RU", leafCert.getIssuerDn());

        assertTrue("CA.isSelfSigned() — true", caCert.isSelfSigned());
        assertTrue("CA.isSelfIssued() — true", caCert.isSelfIssued());
        assertFalse("leaf.isSelfSigned() — false", leafCert.isSelfSigned());

        assertTrue("CA.isCA() — true", caCert.isCA());
        assertEquals("CA.getPathLen() == 0", 0, caCert.getPathLen());
        assertFalse("leaf.isCA() — false", leafCert.isCA());

        assertTrue("getSerialNumberBigInt() — положительный",
                leafCert.getSerialNumberBigInt().signum() > 0);
        assertEquals("getSignatureAlgorithmOid() — SIGN_WITH_DIGEST_256",
                GostOids.SIGN_WITH_DIGEST_256, leafCert.getSignatureAlgorithmOid());

        assertTrue("verifyHostname('demo.example.com') — совпадает",
                leafCert.verifyHostname("demo.example.com"));
        assertFalse("verifyHostname('other.example.com') — не совпадает",
                leafCert.verifyHostname("other.example.com"));

        String pemOut = leafCert.toPem();
        assertTrue("toPem() — корректный PEM", pemOut.startsWith("-----BEGIN CERTIFICATE-----"));
        assertArrayEquals("getEncoded() — соответствует оригиналу", der, leafCert.getEncoded());
        assertTrue("getEncoded() — не пуст", leafCert.getEncoded().length > 0);

        assertEquals("getVersion() == 3", 3, leafCert.getVersion());
        assertEquals("getSubjectKeyIdentifier() — 32 байта", 32, leafCert.getSubjectKeyIdentifier().length);
        assertEquals("getAuthorityKeyIdentifier() — 32 байта", 32, leafCert.getAuthorityKeyIdentifier().length);

        assertTrue("matchesPrivateKey(leafKey) — true", leafCert.matchesPrivateKey(leafKey));
        assertFalse("matchesPrivateKey(caKey) — false", leafCert.matchesPrivateKey(caKey));

        System.out.println("  OK: все проверки GostCertificate пройдены");
    }

    // ========================================================================
    // §3 PKCS#12
    // ========================================================================

    @Test
    public void test03_pkcs12() throws Exception {
        section("§3 PKCS#12: построение и загрузка PFX");

        char[] password = "changeit".toCharArray();

        byte[] pfx = GostPkcs12Builder.create()
                .key(leafKey)
                .certificate(leafCert)
                .caCertificate(caCert)
                .password(password)
                .friendlyName("demo-leaf-cert")
                .build();
        assertTrue("PFX построен, размер " + pfx.length + " байт", pfx.length > 0);

        Path tmpPfx = Files.createTempFile("pkix-demo-", ".pfx");
        try {
            GostPkcs12Builder.create()
                    .key(leafKey)
                    .certificate(leafCert)
                    .password(password)
                    .friendlyName("demo-leaf-cert")
                    .buildAndWriteTo(tmpPfx);
            assertTrue("buildAndWriteTo: PFX записан в файл",
                    Files.exists(tmpPfx) && Files.size(tmpPfx) > 0);
        } finally {
            Files.deleteIfExists(tmpPfx);
        }

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, password, true);
        PrivateKeyParameters loadedKey = result.getPrivateKey();
        List<GostCertificate> loadedChain = result.getCertificateChain();

        assertNotNull("Закрытый ключ загружен", loadedKey);
        assertTrue("Цепочка загружена (не менее 1 сертификата)", loadedChain.size() >= 1);

        GostCertificate loadedLeaf = loadedChain.get(0);
        assertEquals("Сертификат из PFX совпадает с оригиналом",
                leafCert.getSubjectDn(), loadedLeaf.getSubjectDn());
        assertTrue("Загруженный ключ соответствует загруженному сертификату",
                loadedLeaf.matchesPrivateKey(loadedKey));

        try {
            GostPkcs12Loader.load(pfx, "wrong".toCharArray(), false);
            fail("Неверный пароль должен вызывать ошибку");
        } catch (Exception e) {
            assertTrue("Неверный пароль корректно отвергнут: " + e.getClass().getSimpleName(), true);
        }

        System.out.println("  OK: PKCS#12 — построение и загрузка успешны");
    }

    // ========================================================================
    // §4 CSR
    // ========================================================================

    @Test
    public void test04_csr() throws Exception {
        section("§4 CSR: построение, разбор и proof-of-possession");

        byte[] csrDer = GostCsrBuilder.create("CN=demo.example.com,O=DemoOrg,C=RU", leafPubKey)
                .sign(leafKey);
        assertTrue("CSR DER собран", csrDer.length > 0);

        byte[] csrExtDer = GostCsrBuilder.create("CN=demo-san.example.com,O=DemoOrg,C=RU", leafPubKey)
                .sanDns("demo-san.example.com", "www.demo-san.example.com")
                .sanRfc822Name("admin@example.com")
                .sanUpn("user@domain.ru")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                .sign(leafKey);
        assertTrue("CSR с расширениями DER собран", csrExtDer.length > 0);

        GostCsrParser csrExt = GostCsrParser.fromDer(csrExtDer);
        assertTrue("CSR с расширениями: proof-of-possession true", csrExt.verifySelf());
        assertTrue("CSR с расширениями: hasExtensions() true", csrExt.hasExtensions());
        GostExtensionParser.ExtensionsResult extResult = csrExt.getExtensions();
        assertTrue("CSR с расширениями: SAN распарсен",
                extResult.sanDnsNames != null && extResult.sanDnsNames.length > 0);
        assertEquals("CSR с расширениями: rfc822Name распарсен",
                "admin@example.com", extResult.sanRfc822Names[0]);
        assertTrue("CSR с расширениями: otherName (UPN) распарсен",
                extResult.sanOtherNames != null && extResult.sanOtherNames.length > 0);
        assertTrue("CSR с расширениями: OID SAN в списке",
                extResult.presentExtensionOids.contains(GostOids.EXT_SAN));
        assertTrue("CSR с расширениями: OID EKU в списке",
                extResult.presentExtensionOids.contains(GostOids.EXT_EKU));

        GostCsrParser csr = GostCsrParser.fromDer(csrDer);
        assertNotNull("CSR разобран из DER", csr);
        assertEquals("getSubjectDn(): " + csr.getSubjectDn(),
                "CN=demo.example.com, O=DemoOrg, C=RU", csr.getSubjectDn());

        String[] cn = csr.getSubjectDnField("2.5.4.3");
        assertEquals("getSubjectDnField(CN): " + Arrays.toString(cn),
                "demo.example.com", cn[0]);

        PublicKeyParameters csrPubKey = csr.getPublicKey();
        assertNotNull("getPublicKey() из CSR не null", csrPubKey);
        assertEquals("CSR getSignatureAlgorithmOid() — SIGN_WITH_DIGEST_256",
                GostOids.SIGN_WITH_DIGEST_256, csr.getSignatureAlgorithmOid());

        assertTrue("verifySelf() — proof-of-possession true", csr.verifySelf());
        assertTrue("verify(csrPubKey) — подпись валидна", csr.verify(csrPubKey));

        String csrPem = csr.toPem();
        assertTrue("toPem() — корректный PEM для CSR", csrPem.startsWith("-----BEGIN"));

        GostCsrParser fromPem = GostCsrParser.fromPemOrDer(
                csrPem.getBytes(StandardCharsets.US_ASCII));
        assertTrue("fromPemOrDer: verifySelf() true", fromPem.verifySelf());

        byte[] csrDnDer = csr.getSubjectDnDer();
        assertTrue("getSubjectDnDer() — байтово-точный DER subject DN из CSR",
                csrDnDer != null && csrDnDer.length > 0);
        assertTrue("getSubjectDn() возвращает исходный DN",
                csr.getSubjectDn().contains("CN=demo.example.com"));

        GostCertificateBuilder csrCertBuilder =
                GostCertificateBuilder.fromCsrIdentity(csr, caPubKey.getParams());
        GostCertificate csrIssuedCert = csrCertBuilder
                .issuerDn(caCert.getSubjectDnBytes())
                .notBefore("20250101000000Z")
                .notAfter("20260101000000Z")
                .randomSerial()
                .sign(GostSigner.of(caKey));
        assertNotNull("Сертификат из CSR выпущен через fromCsrIdentity", csrIssuedCert);
        assertEquals("Subject DN сертификата совпадает с DN из CSR",
                csr.getSubjectDn(), csrIssuedCert.getSubjectDn());
        assertArrayEquals("Публичный ключ сертификата из CSR корректен",
                GostDerCodec.subjectPublicKeyPointBytes(csr.getPublicKey()),
                GostDerCodec.subjectPublicKeyPointBytes(csrIssuedCert.getPublicKey()));

        System.out.println("  OK: CSR — построение, разбор и проверка успешны");
    }

    // ========================================================================
    // §5 ChainValidator
    // ========================================================================

    @Test
    public void test05_chainValidator() throws Exception {
        section("§5 ChainValidator: валидация цепочки CA->leaf");

        List<GostCertificate> chain = List.of(leafCert, caCert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(caCert);

        ChainValidator.validateChain(chain, anchors);
        assertTrue("validateChain(leaf->CA) — цепочка валидна", true);

        try {
            var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
            GostCertificate wrongRoot =
                    makeSelfSignedCert(
                            wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(1000));
            List<GostCertificate> leafOnly = List.of(leafCert);
            ChainValidator.validateChain(
                    leafOnly, TrustAnchors.ofCertificate(wrongRoot));
            fail("Цепочка без доверенного издателя должна падать");
        } catch (PkixException e) {
            assertTrue("Цепочка без доверенного корня корректно отвергнута: " + e.reason(), true);
        }

        try {
            byte[] badTbs = GostCertificateBuilder.create(PARAMS, "CN=Expired,O=DemoOrg,C=RU")
                    .publicKey(leafPubKey)
                    .randomSerial()
                    .notBefore("200101000000Z")
                    .notAfter("200201000000Z")
                    .issuerDn(caCert.getIssuerDnBytes())
                    .buildTbs();
            GostCertificate expiredCert = GostCertificateBuilder.sign(badTbs, GostSigner.of(caKey));
            ChainValidator.validateChain(List.of(expiredCert, caCert), anchors);
            fail("Просроченный сертификат должен вызывать ошибку");
        } catch (PkixException e) {
            assertEquals("Просроченный сертификат: reason = EXPIRED",
                    PkixException.Reason.EXPIRED, e.reason());
        }

        System.out.println("  OK: валидация цепочки сертификатов");
    }

    // ========================================================================
    // §5.1 ChainValidator с отзывом
    // ========================================================================

    @Test
    public void test05_1_chainValidatorWithRevocation() throws Exception {
        section("§5.1 ChainValidatorWithRevocation: цепочка + проверка отзыва");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();
        List<GostCertificate> chain = List.of(leafCert, caCert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(caCert);

        byte[] crlDer = GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                .nextUpdate("270801120000Z")
                .sign(caKey);
        ChainValidator.validateChainWithRevocation(
                chain, anchors, Arrays.asList(new CertRevocationData(null, crlDer), null));
        assertTrue("validateChainWithRevocation(CRL) — leaf не отозван, успешно", true);

        byte[] ocspGood = GostOcspResponseBuilder.create(serial)
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .good()
                .sign(caKey);
        ChainValidator.validateChainWithRevocation(
                chain, anchors, Arrays.asList(new CertRevocationData(ocspGood, null), null));
        assertTrue("validateChainWithRevocation(OCSP) — leaf good, успешно", true);

        ChainValidator.validateChainWithRevocation(
                chain, anchors, Arrays.asList(new CertRevocationData(ocspGood, crlDer), null));
        assertTrue("validateChainWithRevocation(OCSP+CRL) — OCSP приоритет, успешно", true);

        System.out.println("  OK: валидация цепочки с проверкой отзыва");
    }

    // ========================================================================
    // §6 CRL
    // ========================================================================

    @Test
    public void test06_crl() throws Exception {
        section("§6 CRL: построение списка отзыва и проверка");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();
        RevokedEntry entry = new RevokedEntry(serial, "260801120000Z",
                ReasonCode.KEY_COMPROMISE, null, null);

        byte[] crlDer = GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                .nextUpdate("270801120000Z")
                .addRevoked(List.of(entry))
                .sign(caKey);
        assertTrue("CRL построен, размер " + crlDer.length + " байт", crlDer.length > 0);

        try {
            CrlVerifier.verify(crlDer, certWithSerial(serial), caCert);
            fail("Отозванный сертификат должен вызывать PkixException");
        } catch (PkixException e) {
            assertEquals("Отозванный сертификат: reason = REVOKED",
                    PkixException.Reason.REVOKED, e.reason());
        }

        Instant nextUpdate = CrlVerifier.extractNextUpdate(crlDer);
        assertNotNull("extractNextUpdate() — дата получена", nextUpdate);

        System.out.println("  OK: CRL — построение и проверка");
    }

    // ========================================================================
    // §7 OCSP
    // ========================================================================

    @Test
    public void test07_ocsp() throws Exception {
        section("§7 OCSP: построение и проверка OCSP-ответа");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();

        byte[] ocspResp = GostOcspResponseBuilder.create(serial)
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .good()
                .sign(caKey);
        assertTrue("OCSP-ответ построен, размер " + ocspResp.length + " байт", ocspResp.length > 0);

        OcspVerifier.verify(ocspResp, serial, caCert);
        assertTrue("OcspVerifier.verify() — успешно", true);

        byte[] ocspByKey = GostOcspResponseBuilder.create(serial)
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .withResponderByKey()
                .good()
                .sign(caKey);
        assertTrue("OCSP-ответ byKey построен, размер " + ocspByKey.length + " байт",
                ocspByKey.length > 0);

        GostOcspResponse parsedByKey = GostOcspResponse.fromDer(ocspByKey);
        assertEquals("responderIdType = BY_KEY",
                GostOcspResponse.ResponderIdType.BY_KEY, parsedByKey.getResponderIdType());
        assertEquals("длина keyHash = 32 байта (Streebog-256)",
                32, parsedByKey.getResponderKeyHash().length);

        OcspVerifier.verify(ocspByKey, serial, caCert);
        assertTrue("OcspVerifier.verify() byKey — успешно", true);

        var responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responderCert = GostCertificateBuilder.create(
                        PARAMS, "CN=Delegated OCSP Responder,O=DemoOrg,C=RU")
                .publicKey(responderKp.getPublic())
                .randomSerial()
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .notBefore("20250101000000Z")
                .notAfter("20250103000000Z")
                .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)
                .ocspNoCheck()
                .sign(caKey);
        assertTrue("Делегированный responder-сертификат: EKU OCSPSigning + id-pkix-ocsp-nocheck",
                responderCert.isOcspSigning() && responderCert.hasOcspNoCheck());

        System.out.println("  OK: OCSP — построение и проверка");
    }

    // ========================================================================
    // §8 CMS SignedData
    // ========================================================================

    @Test
    public void test08_cmsSignedData() throws Exception {
        section("§8 CMS SignedData: инкапсулированная подпись с файлом");

        byte[] signed = CmsSignedDataBuilder.create()
                .data(demoData)
                .addSigner(cmsKey, cmsCert)
                .build();
        assertTrue("SignedData построен, размер " + signed.length + " байт", signed.length > 0);

        VerifiedSignedData result = CmsSignedDataVerifier.verify(signed, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));
        assertArrayEquals("Данные после верификации совпадают", demoData, result.data());
        assertNotNull("Сертификат подписанта извлечён", result.signerCertificate());

        byte[] detachedData = "Внешний документ".getBytes(StandardCharsets.UTF_8);
        byte[] detachedSigned = CmsSignedDataBuilder.create()
                .data(detachedData)
                .addSigner(cmsKey, cmsCert)
                .detached(true)
                .build();
        VerifiedSignedData detResult =
                CmsSignedDataVerifier.verify(detachedSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()).detached(detachedData));
        assertArrayEquals(
                "Detached: возвращённый документ совпадает с исходным",
                detachedData,
                detResult.data());

        byte[] chainSigned = CmsSignedDataBuilder.create()
                .data(demoData)
                .addSigner(cmsKey, cmsCert)
                .addCertificate(caCert)
                .build();
        VerifiedSignedData chainResult = CmsSignedDataVerifier.verify(chainSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));

        List<GostCertificate> p7bCerts = GostPkcs7.extractCertificates(chainSigned);
        boolean caPresent = p7bCerts.stream().anyMatch(
                c -> c.getSerialNumberBigInt().equals(caCert.getSerialNumberBigInt()));
        assertTrue("GostPkcs7.extractCertificates() — извлечено сертификатов: " + p7bCerts.size(),
                !p7bCerts.isEmpty() && caPresent);

        byte[] certsOnlyP7b = GostPkcs7.buildCertsOnly(cmsCert, caCert);
        List<GostCertificate> roundTrip = GostPkcs7.extractCertificates(certsOnlyP7b);
        assertEquals("GostPkcs7.buildCertsOnly() — round-trip сертификатов: " + roundTrip.size(),
                2, roundTrip.size());

        String p7bText = GostPkcs7.formatText(certsOnlyP7b);
        assertTrue("GostPkcs7.formatText() — человекочитаемый дамп с дисклеймером",
                p7bText.contains("PKCS#7") && p7bText.contains("ВНИМАНИЕ"));
        String certText = CertificateTextFormatter.format(cmsCert);
        assertFalse("CertificateTextFormatter — текст пустой", certText.isEmpty());
        assertTrue("CertificateTextFormatter — содержит CN подписанта",
                certText.contains("CN=CMS Signer"));
        System.out.println();
        System.out.println(certText);

        byte[] attrSigned = CmsSignedDataBuilder.create()
                .data(demoData)
                .addSigner(cmsKey, cmsCert)
                .addSignedAttribute(GostOids.ATTR_SIGNING_TIME,
                        DerCodec.encodeTime("260601120000Z"))
                .build();
        VerifiedSignedData attrResult = CmsSignedDataVerifier.verify(attrSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert = makeSelfSignedCert(
                wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(999));
        try {
            CmsSignedDataVerifier.verify(signed, VerifyOptions.trusting(TrustAnchors.ofCertificates(wrongCert), SignerSelection.ANY, Revocation.none()));
            fail("Верификация чужим сертификатом: ожидался PkixException");
        } catch (PkixException e) {
            assertTrue("Верификация чужим сертификатом: провал (как и ожидалось)", true);
        }

        byte[] tampered = Arrays.copyOf(signed, signed.length);
        tampered[signed.length / 2] ^= 0xFF;
        try {
            CmsSignedDataVerifier.verify(tampered, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));
            fail("Подмена данных: ожидался PkixException");
        } catch (PkixException e) {
            assertTrue("Подмена данных: верификация провалена", true);
        }

        System.out.println("  OK: CMS SignedData — инкапсулированная подпись");
    }

    // ========================================================================
    // §9 CMS EnvelopedData
    // ========================================================================

    @Test
    public void test09_cmsEnvelopedData() throws Exception {
        section("§9 CMS EnvelopedData: шифрование и расшифровка файла (ktri, с имитовставкой)");

        byte[] enveloped = CmsEnvelopedDataBuilder.create()
                .data(demoData)
                .addRecipient(cmsCert)
                .build();
        assertTrue("EnvelopedData построен, размер " + enveloped.length + " байт",
                enveloped.length > 0);

        byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert);
        assertArrayEquals("Расшифрованные данные совпадают с оригиналом (" + decrypted.length + " байт)",
                demoData, decrypted);

        try {
            byte[] badDecrypt = CmsEnvelopedDataDecryptor.decrypt(enveloped, caKey, caCert);
            assertFalse("Расшифрование чужим ключом: данные не совпадают или падает",
                    Arrays.equals(demoData, badDecrypt));
        } catch (Exception e) {
            assertTrue("Расшифрование чужим ключом: исключение ("
                    + e.getClass().getSimpleName() + ")", true);
        }

        System.out.println("  OK: CMS EnvelopedData (ktri) — шифрование и расшифровка");
    }

    // ========================================================================
    // §9.1 CMS EnvelopedData OMAC
    // ========================================================================

    @Test
    public void test09_1_cmsEnvelopedDataOmac() throws Exception {
        section("§9.1 CMS EnvelopedData (ktri): имитовставка по умолчанию и режим без неё");

        byte[] enveloped = CmsEnvelopedDataBuilder.create()
                .data(demoData)
                .addRecipient(cmsCert)
                .build();
        assertTrue("EnvelopedData+OMAC построен, размер " + enveloped.length + " байт",
                enveloped.length > 0);

        byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert);
        assertArrayEquals("Расшифрованные данные OMAC совпадают с оригиналом",
                demoData, decrypted);

        byte[] tampered = Arrays.copyOf(enveloped, enveloped.length);
        tampered[enveloped.length / 2] ^= 0xFF;
        try {
            CmsEnvelopedDataDecryptor.decrypt(tampered, cmsKey, cmsCert);
            fail("OMAC подмена: ожидался PkixException");
        } catch (PkixException e) {
            assertTrue("OMAC подмена: fail-closed — MAC проверка отклонила поддельные данные", true);
        }

        // Режим без имитовставки — только явный выбор; строгий decrypt его не принимает
        byte[] plain = CmsEnvelopedDataBuilder.create()
                .data(demoData)
                .addRecipient(cmsCert)
                .withoutIntegrity()
                .build();
        try {
            CmsEnvelopedDataDecryptor.decrypt(plain, cmsKey, cmsCert);
            fail("Контейнер без OMAC: ожидался отказ");
        } catch (PkixException e) {
            assertTrue("Контейнер без OMAC: decrypt требует имитовставку (INTEGRITY_REQUIRED)",
                    e.reason() == PkixException.Reason.INTEGRITY_REQUIRED);
        }
        assertArrayEquals("Контейнер без OMAC читается только через decryptAllowingNoIntegrity",
                demoData,
                CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(plain, cmsKey, cmsCert));

        System.out.println("  OK: CMS EnvelopedData + OMAC — шифрование с имитовставкой и fail-closed");
    }

    // ========================================================================
    // §10 CMS SignedAndEnvelopedData
    // ========================================================================

    @Test
    public void test10_cmsSignedAndEnvelopedData() throws Exception {
        section("§10 CMS Sign+Encrypt: совмещённая подпись и шифрование файла");

        byte[] sample = (demoData.length > 4096) ? Arrays.copyOf(demoData, 4096) : demoData;

        byte[] combined1 = CmsSignedAndEnvelopedData.signThenEncrypt(sample, cmsKey, cmsCert, cmsCert);
        assertTrue("signThenEncrypt построен, размер " + combined1.length + " байт",
                combined1.length > 0);

        VerifiedSignedData result1 = CmsSignedAndEnvelopedData.decryptAndVerify(
                combined1, cmsKey, cmsCert, cmsCert);
        assertArrayEquals("Данные после signThenEncrypt/decryptAndVerify совпадают", sample, result1.data());

        byte[] combined2 = CmsSignedAndEnvelopedData.encryptThenSign(sample, cmsKey, cmsCert, cmsCert);
        VerifiedSignedData result2 = CmsSignedAndEnvelopedData.verifyAndDecrypt(
                combined2, cmsKey, cmsCert, cmsCert);
        assertArrayEquals("Данные после encryptThenSign/verifyAndDecrypt совпадают", sample, result2.data());

        System.out.println("  OK: CMS — совмещённая подпись и шифрование");
    }

    // ========================================================================
    // §11 GostOids
    // ========================================================================

    @Test
    public void test11_gostOids() {
        section("§11 GostOids: реестр OID");

        assertEquals("CMS_SIGNED_DATA", "1.2.840.113549.1.7.2", GostOids.CMS_SIGNED_DATA);
        assertEquals("CMS_ENVELOPED_DATA", "1.2.840.113549.1.7.3", GostOids.CMS_ENVELOPED_DATA);
        assertEquals("ATTR_CONTENT_TYPE", "1.2.840.113549.1.9.3", GostOids.ATTR_CONTENT_TYPE);
        assertEquals("ATTR_MESSAGE_DIGEST", "1.2.840.113549.1.9.4", GostOids.ATTR_MESSAGE_DIGEST);
        assertEquals("ATTR_SIGNING_TIME", "1.2.840.113549.1.9.5", GostOids.ATTR_SIGNING_TIME);
        assertEquals("AGREEMENT_VKO_256", "1.2.643.7.1.1.6.1", GostOids.AGREEMENT_VKO_256);
        assertEquals("WRAP_KUZNYECHIK_KEXP15", "1.2.643.7.1.1.7.2.1", GostOids.WRAP_KUZNYECHIK_KEXP15);
        assertEquals("PUBLIC_KEY_256", "1.2.643.7.1.1.1.1", GostOids.PUBLIC_KEY_256);
        assertEquals("SIGN_WITH_DIGEST_256", "1.2.643.7.1.1.3.2", GostOids.SIGN_WITH_DIGEST_256);
        assertEquals("DIGEST_256", "1.2.643.7.1.1.2.2", GostOids.DIGEST_256);
        assertEquals("KUZ_CTR_ACPKM", "1.2.643.7.1.1.5.2.1", GostOids.KUZ_CTR_ACPKM);
        assertEquals("EXT_SAN", "2.5.29.17", GostOids.EXT_SAN);
        assertEquals("EXT_KU", "2.5.29.15", GostOids.EXT_KU);
        assertEquals("EXT_EKU", "2.5.29.37", GostOids.EXT_EKU);
        assertEquals("EXT_BC", "2.5.29.19", GostOids.EXT_BC);
        assertEquals("PBE_DEFAULT_ITERATIONS", 2000, GostOids.PBE_DEFAULT_ITERATIONS);

        System.out.println("  OK: GostOids");
    }

    // ========================================================================
    // §12 Certificate Policies
    // ========================================================================

    @Test
    public void test12_certificatePolicies() throws Exception {
        section("§12 Certificate Policies");

        String[] policies = leafCert.getCertificatePolicies();
        assertNull("getCertificatePolicies() — null (расширение отсутствует)", policies);

        List<GostCertificate> chain = List.of(leafCert, caCert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(caCert);
        ChainValidator.validateChain(chain, anchors);
        assertTrue("validateChain без политик — валидно", true);

        try {
            ChainValidator.validateChain(chain, anchors, GostOids.POLICY_KC1);
            fail("Ожидалась POLICY_VIOLATION");
        } catch (PkixException e) {
            assertEquals("POLICY_VIOLATION: leaf без CertificatePolicies — reject",
                    PkixException.Reason.POLICY_VIOLATION, e.reason());
        }

        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=PolicyDemo");
        byte[] cp = GostCertificateBuilder.buildCertificatePoliciesExtension(
                new String[]{GostOids.POLICY_KC1});
        byte[] additional = concatDemoExtensions(
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE),
                GostCertificateBuilder.buildSkiExtension(kp.getPublic()),
                GostCertificateBuilder.buildAkiExtension(caPubKey),
                cp);
        byte[] tbs = GostCertificateBuilder.create(PARAMS, subjectDn)
                .publicKey(kp.getPublic())
                .notBefore("20240501120000Z")
                .notAfter("21060101120000Z")
                .sanDns("policy.example.com")
                .additionalExtensions(additional)
                .issuerDn(caCert.getIssuerDnBytes())
                .serial(BigInteger.valueOf(99))
                .buildTbs();
        GostCertificate policyLeaf = GostCertificateBuilder.sign(tbs, GostSigner.of(caKey));

        List<GostCertificate> chain2 = List.of(policyLeaf, caCert);
        ChainValidator.validateChain(chain2, anchors, GostOids.POLICY_KC1);
        assertTrue("validateChain с KC1 — leaf содержит KC1, валидно", true);

        try {
            ChainValidator.validateChain(chain2, anchors, GostOids.POLICY_KC2);
            fail("Ожидалась POLICY_VIOLATION");
        } catch (PkixException e) {
            assertEquals("POLICY_VIOLATION: leaf с KC1, required=KC2 — reject",
                    PkixException.Reason.POLICY_VIOLATION, e.reason());
        }

        System.out.println("  OK: Certificate policies — политики сертификатов");

        byte[] tbs2 = GostCertificateBuilder.create(PARAMS, subjectDn)
                .publicKey(kp.getPublic())
                .notBefore("20240501120000Z")
                .notAfter("21060101120000Z")
                .sanDns("fluent-cp.example.com")
                .certificatePolicies(GostOids.POLICY_KC1, GostOids.POLICY_KC2)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caCert.getIssuerDnBytes())
                .serial(BigInteger.valueOf(100))
                .buildTbs();
        GostCertificate fluentLeaf = GostCertificateBuilder.sign(tbs2, GostSigner.of(caKey));

        CertificatePolicy[] cpInfos = fluentLeaf.getCertificatePolicyInfos();
        assertEquals("fluent API: 2 политики через getter", 2, cpInfos.length);
        assertNull("fluent API: без CPS — cpsUri == null", cpInfos[0].cpsUri());
        assertNull("fluent API: без CPS — cpsUri == null", cpInfos[1].cpsUri());

        String cpsUri = "https://ca.example.com/cps/russian-ca.html";
        byte[] tbs3 = GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn("CN=CpsDemo"))
                .publicKey(kp.getPublic())
                .notBefore("20240501120000Z")
                .notAfter("21060101120000Z")
                .sanDns("cps-demo.example.com")
                .certificatePolicyInfos(
                        new CertificatePolicy(GostOids.POLICY_KC1, cpsUri),
                        new CertificatePolicy(GostOids.POLICY_KC2))
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caCert.getIssuerDnBytes())
                .serial(BigInteger.valueOf(101))
                .buildTbs();
        GostCertificate cpsLeaf = GostCertificateBuilder.sign(tbs3, GostSigner.of(caKey));

        CertificatePolicy[] cpsInfos = cpsLeaf.getCertificatePolicyInfos();
        assertEquals("certificatePolicyInfos: 2 политики", 2, cpsInfos.length);
        assertEquals("certificatePolicyInfos: CPS URI round-trip", cpsUri, cpsInfos[0].cpsUri());
        assertNull("certificatePolicyInfos: вторая политика без CPS", cpsInfos[1].cpsUri());

        List<GostCertificate> chain3 = List.of(cpsLeaf, caCert);
        ChainValidator.validateChain(chain3, anchors, GostOids.POLICY_KC1);
        assertTrue("validateChain с KC1 через fluent API — валидно", true);

        System.out.println("  OK: Fluent-API certificatePolicies / certificatePolicyInfos");
    }

    // ========================================================================
    // §13 GostDnParser
    // ========================================================================

    @Test
    public void test13_gostDnParser() {
        section("§13 GostDnParser: кодирование DNs");

        byte[] dnDer = GostDnParser.encodeDn("CN=Test,O=Demo,L=Moscow,C=RU");
        assertTrue("encodeDn построен, размер " + dnDer.length + " байт", dnDer.length > 0);

        String[] cnFields = leafCert.getSubjectDnField("2.5.4.3");
        assertTrue("getSubjectDnField(CN) из leaf: " + String.join(",", cnFields), cnFields.length > 0);

        System.out.println("  OK: GostDnParser");
    }

    // ========================================================================
    // §14 PKCS#12 с кастомными итерациями
    // ========================================================================

    @Test
    public void test14_pkcs12WithCustomIterations() throws Exception {
        section("§14 PKCS#12 с кастомным числом итераций");

        char[] password = "customiter".toCharArray();
        byte[] pfx = GostPkcs12Builder.create()
                .key(leafKey)
                .certificate(leafCert)
                .password(password)
                .iterations(50_000)
                .friendlyName("high-iter-cert")
                .build();
        assertTrue("PFX с 50K итерациями построен", pfx.length > 0);

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, password, true);
        assertNotNull("Ключ из PFX с 50K итерациями загружен", result.getPrivateKey());

        System.out.println("  OK: PKCS#12 с кастомным числом итераций");
    }

    // ========================================================================
    // §15 CRL с несколькими записями
    // ========================================================================

    @Test
    public void test15_crlRevokedMultiple() throws Exception {
        section("§15 CRL: несколько отозванных сертификатов");

        byte[] serial1 = BigInteger.valueOf(12345).toByteArray();
        byte[] serial2 = BigInteger.valueOf(67890).toByteArray();

        RevokedEntry e1 = new RevokedEntry(serial1, "260801120000Z");
        RevokedEntry e2 = new RevokedEntry(serial2, "260901120000Z",
                ReasonCode.CESSATION_OF_OPERATION, null, null);

        byte[] crlDer = GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                .nextUpdate("270801120000Z")
                .addRevoked(List.of(e1, e2))
                .sign(caKey);
        assertTrue("CRL с 2 записями построен, размер " + crlDer.length + " байт", crlDer.length > 0);

        try {
            CrlVerifier.verify(crlDer, certWithSerial(serial1), caCert);
            fail("serial1 должен быть отозван");
        } catch (PkixException e) {
            assertEquals("serial1 отозван", PkixException.Reason.REVOKED, e.reason());
        }

        Instant nextUpdate = CrlVerifier.extractNextUpdate(crlDer);
        assertNotNull("nextUpdate извлечён: " + nextUpdate, nextUpdate);

        System.out.println("  OK: CRL — несколько отозванных записей");
    }

    // ========================================================================
    // §16 Detached подпись
    // ========================================================================

    @Test
    public void test16_cmsSignedDataDetached() throws Exception {
        section("§16 CMS SignedData: detached подпись с файлом");

        byte[] detachedSigned = CmsSignedDataBuilder.create()
                .data(demoData)
                .addSigner(cmsKey, cmsCert)
                .detached(true)
                .build();
        assertTrue("Detached SignedData построен, размер " + detachedSigned.length + " байт",
                detachedSigned.length > 0);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(detachedSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()).detached(demoData));
        assertArrayEquals(
                "Detached: возвращённый документ совпадает с исходным", demoData, result.data());

        System.out.println("  OK: CMS SignedData — отсоединённая подпись");
    }

    // ========================================================================
    // §17 SignedData с доп. сертификатами
    // ========================================================================

    @Test
    public void test17_cmsSignedDataExtraCerts() throws Exception {
        section("§17 CMS SignedData: дополнительные сертификаты цепочки");

        byte[] signed = CmsSignedDataBuilder.create()
                .data(demoData)
                .addSigner(cmsKey, cmsCert)
                .addCertificate(caCert)
                .build();

        VerifiedSignedData result = CmsSignedDataVerifier.verify(signed, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));
        assertArrayEquals("Данные совпадают", demoData, result.data());

        System.out.println("  OK: SignedData с дополнительными сертификатами");
    }

    // ========================================================================
    // §18 EnvelopedData с несколькими получателями
    // ========================================================================

    @Test
    public void test18_cmsEnvelopedDataMultiRecipients() throws Exception {
        section("§18 CMS EnvelopedData: несколько получателей");

        var bobKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate bobCert = makeSelfSignedCert(
                bobKp.getPrivate(), bobKp.getPublic(), BigInteger.TWO);

        byte[] enveloped = CmsEnvelopedDataBuilder.create()
                .data(demoData)
                .addRecipient(cmsCert)
                .addRecipient(bobCert)
                .build();

        byte[] cmsData = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert);
        assertArrayEquals("cmsKey расшифровал успешно", demoData, cmsData);

        byte[] bobData = CmsEnvelopedDataDecryptor.decrypt(
                enveloped, bobKp.getPrivate(), bobCert);
        assertArrayEquals("Bob расшифровал успешно", demoData, bobData);

        System.out.println("  OK: CMS EnvelopedData — несколько получателей");
    }

    // ========================================================================
    // §19 Sign+Encrypt с несколькими получателями
    // ========================================================================

    @Test
    public void test19_cmsSignEncryptMultiRecipients() throws Exception {
        section("§19 CMS Sign+Encrypt: несколько получателей");

        byte[] sample = (demoData.length > 4096) ? Arrays.copyOf(demoData, 4096) : demoData;

        var aliceKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate aliceCert = makeSelfSignedCert(
                aliceKp.getPrivate(), aliceKp.getPublic(), BigInteger.valueOf(3));

        byte[] combined = CmsSignedAndEnvelopedData.signThenEncrypt(
                sample, cmsKey, cmsCert, cmsCert, aliceCert);

        VerifiedSignedData cmsResult = CmsSignedAndEnvelopedData.decryptAndVerify(
                combined, cmsKey, cmsCert, cmsCert);
        assertArrayEquals("cmsKey: данные совпадают", sample, cmsResult.data());

        VerifiedSignedData aliceResult = CmsSignedAndEnvelopedData.decryptAndVerify(
                combined, aliceKp.getPrivate(), aliceCert, cmsCert);
        assertArrayEquals("Alice: данные совпадают", sample, aliceResult.data());

        System.out.println("  OK: CMS Sign+Encrypt — несколько получателей");
    }

    // ========================================================================
    // §20 CAdES-BES
    // ========================================================================

    @Test
    public void test20_cadesBes() throws Exception {
        section("§20 CAdES-BES: базовая долговременная подпись");

        byte[] data = "Документ для CAdES".getBytes(StandardCharsets.UTF_8);

        byte[] cadesBes = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(cmsKey, cmsCert)
                .withCAdES()
                .build();
        assertTrue("CAdES-BES подпись создана", cadesBes.length > 0);

        VerifiedCAdESData result = CAdESVerifier.verifyBES(cadesBes, TrustAnchors.ofCertificates(cmsCert));
        assertArrayEquals("CAdES-BES данные совпадают", data, result.data());
        assertEquals("CAdES-BES один подписант", 1, result.signers().size());
        assertNotNull("Сертификат подписанта извлечён",
                result.signers().get(0).signerCertificate());

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert = makeSelfSignedCert(
                wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(100));
        try {
            CAdESVerifier.verifyBES(cadesBes, TrustAnchors.ofCertificates(wrongCert));
            fail("CAdES-BES: чужая верификация должна падать");
        } catch (PkixException e) {
            assertTrue("CAdES-BES: чужая верификация отвергнута: " + e.reason(), true);
        }

        System.out.println("  OK: CAdES-BES — создание и верификация");
    }

    // ========================================================================
    // §21 OCSP-запрос
    // ========================================================================

    @Test
    public void test21_ocspRequest() throws Exception {
        section("§21 OCSP-запрос: построение и разбор");

        GostOcspRequestBuilder reqBuilder = GostOcspRequestBuilder.create()
                .targetCert(leafCert.getEncoded())
                .issuerCert(caCert.getEncoded());
        byte[] requestDer = reqBuilder.build();
        byte[] nonce = reqBuilder.getNonce();

        assertTrue("OCSP-запрос построен", requestDer.length > 0);
        assertTrue("Nonce автоматически сгенерирован", nonce != null && nonce.length > 0);

        GostOcspRequest request = GostOcspRequest.fromDer(requestDer);
        assertNotNull("OCSP-запрос разобран", request);

        List<CertId> certIds = request.getCertIds();
        assertEquals("Один CertId в запросе", 1, certIds.size());

        CertId cid = certIds.get(0);
        assertNotNull("CertId serialNumber не null", cid.serialNumber());
        assertEquals("CertId issuerNameHash — 32 байта",
                GostOids.STREEBOG_256_HASH_LEN, cid.issuerNameHash().length);
        assertEquals("CertId issuerKeyHash — 32 байта",
                GostOids.STREEBOG_256_HASH_LEN, cid.issuerKeyHash().length);

        byte[] parsedNonce = request.getNonce();
        assertArrayEquals("Nonce в ответе совпадает с запросом", nonce, parsedNonce);

        byte[] multiDer = GostOcspRequestBuilder.create()
                .targetCert(leafCert.getEncoded())
                .issuerCert(caCert.getEncoded())
                .addRequest(cmsCert.getEncoded(), cmsCert.getEncoded())
                .build();
        GostOcspRequest multiReq = GostOcspRequest.fromDer(multiDer);
        assertEquals("Multi-cert: 2 CertId", 2, multiReq.getCertIds().size());

        System.out.println("  OK: OCSP-запрос — построение и разбор");
    }

    // ========================================================================
    // §22 GostCrl — разбор CRL
    // ========================================================================

    @Test
    public void test22_gostCrlParse() throws Exception {
        section("§22 GostCrl: разбор CRL");

        byte[] crlDer = GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                .nextUpdate("270801120000Z")
                .addRevoked(new RevokedEntry(
                        leafCert.getSerialNumber(), "260801120000Z",
                        ReasonCode.KEY_COMPROMISE, null, null))
                .sign(caKey);

        GostCrl crl = GostCrl.fromDer(crlDer);
        assertNotNull("GostCrl.fromDer — разобран", crl);
        assertEquals("DN эмитента CRL", "CN=Demo Root CA, O=DemoOrg, C=RU", crl.getIssuerDn());
        assertNotNull("CRL thisUpdate не null", crl.getThisUpdate());
        assertNotNull("CRL nextUpdate не null", crl.getNextUpdate());

        crl.verify(caPubKey);
        assertTrue("isRevoked: сертификат в CRL", crl.isRevoked(leafCert.getSerialNumber()));

        List<RevokedEntry> revoked = crl.getRevokedCertificates();
        assertEquals("getRevokedCertificates: одна запись после verify", 1, revoked.size());
        assertArrayEquals("Серийный номер отозванного совпадает",
                leafCert.getSerialNumber(), revoked.get(0).serial());

        String crlPem = crl.toPem();
        assertTrue("toPem() — корректный PEM CRL", crlPem.startsWith("-----BEGIN X509 CRL-----"));

        System.out.println("  OK: GostCrl — разбор и экспорт");
    }

    // ========================================================================
    // §23 OCSP-ответ — разбор
    // ========================================================================

    @Test
    public void test23_ocspResponseParse() throws Exception {
        section("§23 GostOcspResponse: разбор OCSP-ответа");

        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert.getSerialNumber())
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .good()
                .sign(caKey);

        GostOcspResponse response = GostOcspResponse.fromDer(ocspDer);
        assertTrue("isSuccessful() — true", response.isSuccessful());
        assertNotNull("getProducedAt() не null", response.getProducedAt());

        var responses = response.getResponses();
        assertEquals("Один SingleOcspResponse", 1, responses.size());
        SingleOcspResponse sr = responses.get(0);
        assertTrue("Статус: good", sr.isGood());
        assertFalse("Не revoked", sr.isRevoked());
        assertFalse("Не unknown", sr.isUnknown());
        assertNotNull("thisUpdate не null", sr.thisUpdate());

        response.verify(caPubKey);
        assertTrue("Подпись OCSP-ответа валидна", response.isSignatureVerified());

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostOcspResponse wrongVerify = GostOcspResponse.fromDer(ocspDer);
        try {
            wrongVerify.verify(wrongKp.getPublic());
            fail("OCSP: чужая верификация должна падать");
        } catch (PkixException e) {
            assertTrue("OCSP: чужая верификация отвергнута", true);
        }

        System.out.println("  OK: GostOcspResponse — разбор и верификация");
    }

    // ========================================================================
    // §24 CertChainBuilder
    // ========================================================================

    @Test
    public void test24_certChainBuilder() throws Exception {
        section("§24 CertChainBuilder: построение цепочки из неупорядоченного пула");

        List<GostCertificate> chain = CertChainBuilder.buildChain(
                leafCert, List.of(caCert), List.of(caCert));

        assertEquals("Цепочка из 2 сертификатов", 2, chain.size());
        assertTrue("Первый — leaf", leafCert == chain.get(0));
        assertTrue("Второй — CA", caCert == chain.get(1));

        try {
            CertChainBuilder.buildChain(leafCert, List.of(), List.of());
            fail("Без корня должно падать");
        } catch (PkixException e) {
            assertTrue("Без корня: PkixException (" + e.reason() + ")", true);
        }

        System.out.println("  OK: CertChainBuilder — построение цепочки");
    }

    // ========================================================================
    // §25 TSP-сервер
    // ========================================================================

    @Test
    public void test25_tspServer() throws Exception {
        section("§25 TSP-сервер: разбор запроса и построение TimeStampResp");

        byte[] hash = Digest.digest256("time-stamp-data".getBytes(StandardCharsets.UTF_8));

        BigInteger nonce = BigInteger.valueOf(12345);
        byte[] reqDer = TspRequestBuilder.create()
                .messageImprint(hash, GostOids.DIGEST_256)
                .nonce(nonce)
                .build();
        assertTrue("TSP-запрос построен", reqDer.length > 0);

        TspRequest request = TspRequest.fromDer(reqDer);
        assertEquals("Алгоритм дайджеста в запросе",
                GostOids.DIGEST_256, request.messageImprintAlgOid());
        assertEquals("Nonce в запросе", nonce, request.nonce());

        byte[] rejectionDer = TspResponseBuilder.buildRejected(
                "Unsupported algorithm", GostOids.PKI_FAIL_BAD_ALG);
        assertTrue("Ответ-отказ с failInfo построен", rejectionDer.length > 0);
        try {
            TspResponse.fromDer(rejectionDer);
            fail("Rejection должен бросать PkixException");
        } catch (PkixException e) {
            assertTrue("PkixException содержит 'rejection': " + e.getMessage(),
                    e.getMessage().contains("rejection"));
        }

        byte[] responseDer = TspResponseBuilder.create(request)
                .signer(tsaKey, tsaCert)
                .policyOid("1.3.6.1.4.1.4146.1.2.1")
                .serialNumber(BigInteger.ONE)
                .accuracy(1, 500)
                .withCAdES()
                .ordering(true)
                .buildGranted();
        assertTrue("Granted ответ построен", responseDer.length > 0);

        TspResponse resp = TspResponse.fromDer(responseDer);
        assertEquals("Статус granted", GostOids.PKI_STATUS_GRANTED, resp.status());

        int accSec = resp.tstInfo().accuracySeconds();
        assertEquals("Accuracy seconds", 1, accSec);
        int accMs = resp.tstInfo().accuracyMillis();
        assertEquals("Accuracy millis", 500, accMs);
        assertTrue("Ordering = true", resp.tstInfo().ordering());
        assertEquals("Nonce echo", nonce, resp.tstInfo().nonce());
        resp.verify(hash, GostOids.DIGEST_256, nonce, tsaCert);
        assertTrue("Подпись TSA верифицирована", resp.isSignatureVerified());

        System.out.println("  OK: TSP-сервер — round-trip запрос->ответ->верификация");
    }

    // ========================================================================
    // §26 Delta CRL
    // ========================================================================

    @Test
    public void test26_deltaCrl() throws Exception {
        section("§26 Delta CRL: базовый + delta CRL с merge-верификацией");

        byte[] serial1 = leafCert.getSerialNumber();
        byte[] serial2 = new BigInteger("999999999").toByteArray();

        byte[] baseCrl = GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                .withCrlNumber(1)
                .withFreshestCrl("http://ca.example/delta.crl")
                .withAki(caSki)
                .nextUpdate("270801120000Z")
                .addRevoked(List.of(
                        new RevokedEntry(serial1, "260801120000Z",
                                ReasonCode.KEY_COMPROMISE, null, null),
                        new RevokedEntry(serial2, "260801120000Z",
                                ReasonCode.CERTIFICATE_HOLD, null, null)))
                .sign(caKey);
        assertTrue("Base CRL построен, cRLNumber=1", baseCrl.length > 0);

        byte[] deltaCrl = GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                .nextUpdate("270801120000Z")
                .withCrlNumber(2)
                .withDeltaCrlIndicator(1)
                .addRevoked(List.of(new RevokedEntry(
                        serial1, "260901120000Z", ReasonCode.REMOVE_FROM_CRL, null, null)))
                .sign(caKey);
        assertTrue("Delta CRL построен, ссылается на base cRLNumber=1", deltaCrl.length > 0);

        GostCrl base = GostCrl.fromDer(baseCrl);
        base.verify(caPubKey);
        assertEquals("Base CRL: getCrlNumber() = 1",
                BigInteger.valueOf(1), base.getCrlNumber());
        assertTrue("Base CRL: isFreshestCrl() = true", base.isFreshestCrl());
        assertEquals("Base CRL: getFreshestCrlUris()[0]",
                "http://ca.example/delta.crl", base.getFreshestCrlUris()[0]);

        byte[] akiFromCrl = base.getAuthorityKeyIdentifier();
        assertNotNull("Base CRL: getAuthorityKeyIdentifier() не null", akiFromCrl);
        assertArrayEquals("Base CRL: getAuthorityKeyIdentifier() совпадает с SKI CA",
                caSki, akiFromCrl);

        byte[] fcCertTbs = GostCertificateBuilder.create(
                        PARAMS, "CN=FreshestCRL Cert,O=DemoOrg,C=RU")
                .publicKey(caPubKey)
                .notBefore("250601000000Z")
                .notAfter("270601000000Z")
                .serial(BigInteger.valueOf(999))
                .freshestCrl("http://ca.example/delta.crl")
                .buildTbs();
        GostCertificate fcCert = GostCertificateBuilder.sign(fcCertTbs, GostSigner.of(caKey));
        assertNotNull("Сертификат: getFreshestCrlUris() не null", fcCert.getFreshestCrlUris());
        assertEquals("Сертификат: getFreshestCrlUris()[0] = ожидаемый URI",
                "http://ca.example/delta.crl", fcCert.getFreshestCrlUris()[0]);

        try {
            new GostCrl(deltaCrl).verify(caPubKey);
            fail("Delta CRL должен быть rejected");
        } catch (PkixException e) {
            assertTrue("Delta CRL rejected при изолированной верификации",
                    e.getMessage().contains("delta CRL not supported"));
        }

        CrlVerifier.verify(baseCrl, deltaCrl, certWithSerial(serial1), caCert);
        System.out.println("  serial1 прошёл — удалён из CRL через REMOVE_FROM_CRL");

        try {
            CrlVerifier.verify(baseCrl, deltaCrl, certWithSerial(serial2), caCert);
            fail("serial2 должен быть отозван");
        } catch (PkixException e) {
            assertEquals("serial2 отозван в base CRL, delta не удаляла",
                    PkixException.Reason.REVOKED, e.reason());
        }

        assertEquals("getReason(serial1) = KEY_COMPROMISE",
                ReasonCode.KEY_COMPROMISE, base.getReason(serial1));
        assertEquals("Base CRL: две записи в revoked-списке",
                2, base.getRevokedCertificates().size());

        System.out.println("  OK: Delta CRL — base+delta merge");
    }

    // ========================================================================
    // §27 CMS SignedData с CRL
    // ========================================================================

    @Test
    public void test27_cmsSignedDataWithCrl() throws Exception {
        section("§27 CMS SignedData: встраивание CRL в подпись (addCrl)");

        byte[] data = "Документ со встроенным CRL".getBytes(StandardCharsets.UTF_8);

        GostCrl crl = GostCrl.fromDer(
                GostCrlBuilder.create(cmsCert.getIssuerDnBytes())
                        .withCrlNumber(1)
                        .nextUpdate("270801120000Z")
                        .addRevoked(cmsCert.getSerialNumber(), "260801120000Z")
                        .sign(cmsKey));

        byte[] signedData = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(cmsKey, cmsCert)
                .addCrl(crl)
                .build();
        assertTrue("SignedData с CRL построен", signedData.length > 0);

        VerifiedSignedData result = CmsSignedDataVerifier.verify(signedData, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));
        assertArrayEquals("Данные совпадают", data, result.data());
        assertFalse("embeddedCrls доступны в результате", result.embeddedCrls().isEmpty());
        assertEquals("CRL issuer DN после round-trip совпадает",
                crl.getIssuerDn(), result.embeddedCrls().get(0).getIssuerDn());

        System.out.println("  OK: CMS SignedData со встроенным CRL");
    }

    // ========================================================================
    // §28 Автоматическая проверка отзыва
    // ========================================================================

    @Test
    public void test28_cmsSignedDataRevocationCheck() throws Exception {
        section("§28 CMS SignedData: автоматическая проверка отзыва");

        byte[] data = "Документ с проверкой отзыва".getBytes(StandardCharsets.UTF_8);

        GostCrl cleanCrl = GostCrl.fromDer(
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .withCrlNumber(2)
                        .nextUpdate("270801120000Z")
                        .sign(caKey));

        byte[] cleanSigned = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(leafKey, leafCert)
                .addCertificate(caCert)
                .addCrl(cleanCrl)
                .build();

        VerifiedSignedData cleanResult =
                CmsSignedDataVerifier.verify(cleanSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(caCert), SignerSelection.ANY, Revocation.required(List.of())));
        assertArrayEquals("Сертификат не в CRL — верификация прошла с проверкой отзыва",
                data, cleanResult.data());

        GostCrl revokingCrl = GostCrl.fromDer(
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .withCrlNumber(3)
                        .nextUpdate("270801120000Z")
                        .addRevoked(leafCert.getSerialNumber(), "260801120000Z")
                        .sign(caKey));

        byte[] revokedSigned = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(leafKey, leafCert)
                .addCertificate(caCert)
                .addCrl(revokingCrl)
                .build();

        try {
            CmsSignedDataVerifier.verify(revokedSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(caCert), SignerSelection.ANY, Revocation.required(List.of())));
            fail("Отозванный сертификат должен быть отклонён");
        } catch (PkixException e) {
            assertEquals("Revocation.required отклонил отозванный: " + e.reason(),
                    PkixException.Reason.REVOKED, e.reason());
        }

        byte[] externalData = "Внешний CRL".getBytes(StandardCharsets.UTF_8);
        byte[] noCrlSigned = CmsSignedDataBuilder.create()
                .data(externalData)
                .addSigner(leafKey, leafCert)
                .addCertificate(caCert)
                .build();

        try {
            CmsSignedDataVerifier.verify(noCrlSigned, VerifyOptions.trusting(TrustAnchors.ofCertificates(caCert), SignerSelection.ANY, Revocation.required(List.of(revokingCrl))));
            fail("Внешний CRL с отозванным сертификатом должен отклонить");
        } catch (PkixException e) {
            assertEquals("Внешний CRL отклонил отозванный: " + e.reason(),
                    PkixException.Reason.REVOKED, e.reason());
        }

        System.out.println("  OK: Автоматическая проверка отзыва");
    }

    // ========================================================================
    // §29 Делегированный CRL-подписант
    // ========================================================================

    @Test
    public void test29_delegatedCrlSigner() throws Exception {
        section("§29 Делегированный CRL-подписант (RFC 5280 §6.3.3)");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();
        byte[] signerCertDer = crlSignerCert.getEncoded();

        byte[] crlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .withCrlNumber(10)
                .nextUpdate("270801120000Z")
                .sign(crlSignerKey);
        assertTrue("CRL подписан делегированным ключом, размер " + crlDer.length, crlDer.length > 0);

        try {
            CrlVerifier.verify(crlDer, certWithSerial(serial), caCert);
            fail("CA-ключ не должен верифицировать делегированный CRL");
        } catch (PkixException e) {
            assertEquals("CA-ключ не верифицирует — SIGNATURE_INVALID, fallback к подписанту",
                    PkixException.Reason.SIGNATURE_INVALID, e.reason());
        }

        CrlVerifier.verifyDelegated(crlDer, certWithSerial(serial), caCert, List.of(signerCertDer));
        assertTrue("verifyDelegated принял CRL от делегированного подписанта", true);

        byte[] revokedCrlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .withCrlNumber(11)
                .nextUpdate("270801120000Z")
                .addRevoked(serial, "260801120000Z")
                .sign(crlSignerKey);
        try {
            CrlVerifier.verifyDelegated(revokedCrlDer, certWithSerial(serial), caCert, List.of(signerCertDer));
            fail("Отозванный сертификат должен быть отклонён verifyDelegated");
        } catch (PkixException e) {
            assertEquals("verifyDelegated отклонил отозванный через делегированный CRL: " + e.reason(),
                    PkixException.Reason.REVOKED, e.reason());
        }

        assertTrue("Сертификат подписанта: isCrlSigner() = true", crlSignerCert.isCrlSigner());
        assertFalse("Сертификат leaf без CRL_SIGN: isCrlSigner() = false", leafCert.isCrlSigner());

        byte[] badCrl = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .withCrlNumber(12)
                .nextUpdate("270801120000Z")
                .sign(leafKey);
        try {
            CrlVerifier.verifyDelegated(badCrl, certWithSerial(serial), caCert, List.of(signerCertDer));
            fail("CRL подписанный leaf-ключом не должен приниматься");
        } catch (PkixException e) {
            assertEquals("CRL от leaf-ключа (без cRLSign): SIGNATURE_INVALID",
                    PkixException.Reason.SIGNATURE_INVALID, e.reason());
        }

        byte[] idpCrl = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .withCrlNumber(13)
                .nextUpdate("270801120000Z")
                .withIdpExtension(true, false)
                .sign(caKey);
        GostCrl parsedIdp = GostCrl.fromDer(idpCrl);
        parsedIdp.verify(caPubKey);
        assertTrue("IDP присутствует", parsedIdp.isIdp());
        assertTrue("onlyContainsUserCerts=true", parsedIdp.isOnlyContainsUserCerts());
        assertFalse("onlyContainsCACerts=false", parsedIdp.isOnlyContainsCACerts());
        assertFalse("indirectCRL=false", parsedIdp.isIndirectCrl());

        System.out.println("  OK: Делегированный CRL-подписант");
    }

    // ========================================================================
    // §30 Countersignature
    // ========================================================================

    @Test
    public void test30_countersignature() throws Exception {
        section("§30 Countersignature: контрподпись (RFC 5652 §11.4)");

        byte[] data = "Документ для countersignature".getBytes(StandardCharsets.UTF_8);

        var csKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate csCert = makeSelfSignedCert(
                csKp.getPrivate(), csKp.getPublic(), BigInteger.valueOf(77));

        byte[] cadesBes = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(cmsKey, cmsCert)
                .withCAdES()
                .build();
        assertTrue("CAdES-BES подпись создана", cadesBes.length > 0);

        byte[] countersigned = CAdESExtender.embedCountersignature(
                cadesBes, csKp.getPrivate(), csCert);
        assertTrue("Countersignature создана", countersigned.length > 0);

        VerifiedCAdESData result = CAdESVerifier.verifyCountersignature(countersigned, TrustAnchors.ofCertificates(cmsCert, csCert));
        assertArrayEquals("Данные countersignature совпадают", data, result.data());
        assertEquals("Один подписант", 1, result.signers().size());
        assertEquals("Одна countersignature у подписанта",
                1, result.signers().get(0).countersignatures().size());
        assertTrue("Countersignature содержит signed-атрибуты",
                result.signers().get(0).countersignatures().get(0).signedAttributes().size() >= 1);
        assertTrue("Без TSP меток — timestamps пуст (countersignature на BES)",
                result.signers().get(0).timestamps().isEmpty());

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert = makeSelfSignedCert(
                wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(707));
        try {
            CAdESVerifier.verifyCountersignature(countersigned, TrustAnchors.ofCertificates(wrongCert, csCert));
            fail("Countersignature: чужой сертификат подписанта должен давать ошибку");
        } catch (PkixException e) {
            assertTrue("Countersignature: чужая верификация подписанта отвергнута: " + e.reason(), true);
        }

        try {
            CAdESVerifier.verifyCountersignature(countersigned, TrustAnchors.ofCertificates(cmsCert));
            fail("Countersignature: countersigner не в trusted должна быть ошибка");
        } catch (PkixException e) {
            assertTrue("Countersignature: countersigner не в trusted отвергнут: " + e.reason(), true);
        }

        System.out.println("  OK: Countersignature — контрподпись создана и проверена");
    }

    // ========================================================================
    // §31 GostSigner
    // ========================================================================

    @Test
    public void test31_gostSigner() throws Exception {
        section("§31 GostSigner: подпись через абстракцию (HSM-совместимость)");

        byte[] subjectDn = GostDnParser.encodeDn("CN=Signer Demo,O=DemoOrg,C=RU");
        String caDn = "CN=Demo Root CA,O=DemoOrg,C=RU";
        byte[] tbs = GostCertificateBuilder.create(PARAMS, subjectDn)
                .publicKey(caPubKey)
                .randomSerial()
                .notBefore("20240101000000Z")
                .notAfter("21060101000000Z")
                .issuerDn(caDn)
                .buildTbs();

        GostSigner memSigner = GostSigner.of(caKey);
        GostCertificate certViaMem = GostCertificateBuilder.sign(tbs, memSigner);
        assertTrue("cert через GostSigner.of(priv) верифицируется",
                certViaMem.verifySignature(caPubKey));

        // Нонс по умолчанию гибридный: подпись одного TBS каждый раз разная, поэтому побайтовое
        // совпадение проверяем в детерминированном режиме - это и есть контракт воспроизводимости
        GostCertificate certViaDet1 = GostCertificateBuilder.sign(
                tbs, GostSigner.of(caKey, NonceMode.DETERMINISTIC));
        GostCertificate certViaDet2 = GostCertificateBuilder.sign(
                tbs, GostSigner.of(caKey, NonceMode.DETERMINISTIC));
        assertArrayEquals("Детерминированный нонс: подпись одного TBS воспроизводится байт-в-байт",
                certViaDet1.getEncoded(), certViaDet2.getEncoded());

        GostSigner hsm = new DemoHsmSigner(caKey);
        GostCertificate certViaHsm = GostCertificateBuilder.sign(tbs, hsm);
        assertTrue("cert через внешний подписант верифицируется",
                certViaHsm.verifySignature(caPubKey));

        byte[] csrDer = GostCsrBuilder.create("CN=Signer Demo", caPubKey).sign(hsm);
        assertTrue("CSR через внешний подписант валиден",
                GostCsrParser.fromDer(csrDer).verify(caPubKey));

        byte[] crlDer = GostCrlBuilder.create(caDn).nextUpdate("20990101000000Z").sign(hsm);
        new GostCrl(crlDer).verify(caPubKey);
        assertTrue("CRL через внешний подписант верифицируется", true);

        // У CA KeyUsage ограничен keyCertSign/cRLSign, поэтому для CMS нужен
        // отдельный сертификат подписанта: иначе fail-closed проверка KeyUsage
        // справедливо отклонит подпись.
        GostSigner cmsHsm = new DemoHsmSigner(cmsKey);
        byte[] cmsPayload = "Hello GostSigner CMS".getBytes(StandardCharsets.UTF_8);
        byte[] cmsViaHsm = CmsSignedDataBuilder.create()
                .data(cmsPayload).addSigner(cmsHsm, cmsCert).build();
        VerifiedSignedData vsd = CmsSignedDataVerifier.verify(cmsViaHsm, VerifyOptions.trusting(TrustAnchors.ofCertificates(cmsCert), SignerSelection.ANY, Revocation.none()));
        assertArrayEquals("CMS SignedData через GostSigner: данные восстановлены",
                cmsPayload, vsd.data());

        byte[] caSerial = caCert.getSerialNumberBigInt().toByteArray();
        byte[] ocspViaHsm = GostOcspResponseBuilder.create(caSerial)
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .producedAt("20250101000000Z")
                .thisUpdate("20250101000000Z")
                .good()
                .sign(hsm);
        OcspVerifier.verify(ocspViaHsm, caSerial, caCert);
        assertTrue("OCSP-ответ через GostSigner: верификация прошла", true);

        var otherKp = KeyGenerator.generateKeyPair(PARAMS);
        GostSigner faulty = new MismatchedHsmSigner(caPubKey, otherKp.getPrivate());
        try {
            GostCertificateBuilder.sign(tbs, faulty);
            fail("неисправный подписант должен приводить к исключению");
        } catch (IllegalStateException e) {
            assertTrue("self-verify отверг подпись не тем ключом: " + e.getMessage(), true);
        }

        System.out.println("  OK: GostSigner — абстракция подписи и fail-closed проверки");
    }

    // ========================================================================
    // §32 Перевыпуск сертификата
    // ========================================================================

    @Test
    public void test32_certRenewal() throws Exception {
        section("§32 Перевыпуск сертификата: fromCertificate + getExtensions");

        byte[] subjectDn = GostDnParser.encodeDn("CN=Renewal Demo,O=DemoOrg,C=RU");
        GostCertificate original = GostCertificateBuilder.create(PARAMS, subjectDn)
                .publicKey(caPubKey)
                .notBefore("20240101000000Z")
                .notAfter("20250101000000Z")
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .randomSerial()
                .sanDns("demo.example.com")
                .keyUsage(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE,
                        GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT)
                .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                .basicConstraints(false, null)
                .sign(GostSigner.of(caKey));

        GostCertificateBuilder renewedBuilder =
                GostCertificateBuilder.fromCertificate(original, PARAMS);
        assertNotNull("fromCertificate вернул не-null билдер", renewedBuilder);

        GostExtensionParser.ExtensionsResult ext = original.getExtensions();
        assertTrue("оригинал содержит расширения", original.hasExtensions());

        if (ext.sanDnsNames != null && ext.sanDnsNames.length > 0) {
            renewedBuilder.sanDns(ext.sanDnsNames);
        }
        if (ext.keyUsageBits != 0) {
            renewedBuilder.keyUsage(
                    GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE,
                    GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT);
        }
        if (ext.isCA) {
            renewedBuilder.basicConstraints(true, ext.pathLen);
        }

        GostCertificate renewed = renewedBuilder
                .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                .notBeforeNow()
                .validForDays(365)
                .randomSerial()
                .sign(GostSigner.of(caKey));

        assertEquals("Subject DN перевыпущенного сертификата совпадает с оригиналом",
                original.getSubjectDn(), renewed.getSubjectDn());
        assertArrayEquals("Публичный ключ перевыпущенного сертификата совпадает с оригиналом",
                GostDerCodec.subjectPublicKeyPointBytes(renewed.getPublicKey()),
                GostDerCodec.subjectPublicKeyPointBytes(original.getPublicKey()));
        assertFalse("Серийный номер новый, не совпадает с оригиналом",
                renewed.getSerialNumberBigInt().equals(original.getSerialNumberBigInt()));
        assertTrue("Новый срок действия за пределами старого",
                renewed.getNotAfter().isAfter(original.getNotAfter()));

        String[] renewedSan = renewed.getSanDnsNames();
        assertTrue("SAN dNSName перенесён при перевыпуске",
                renewedSan != null && renewedSan.length == 1
                        && "demo.example.com".equals(renewedSan[0]));

        boolean renewedHasDs = GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE.isSetIn(
                renewed.getExtensions().keyUsageBits);
        assertTrue("KeyUsage DIGITAL_SIGNATURE перенесён при перевыпуске", renewedHasDs);

        System.out.println("  OK: перевыпуск сертификата через fromCertificate + getExtensions");
    }

    // ========================================================================
    // §33 CAdES-C
    // ========================================================================

    @Test
    public void test33_cadesC() throws Exception {
        section("§33 CAdES-C: Complete validation data references (RFC 5126 §6.2)");

        byte[] data = "Документ для CAdES-C".getBytes(StandardCharsets.UTF_8);

        byte[] cadesBes = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(leafKey, leafCert)
                .addCertificate(caCert)
                .withCAdES()
                .build();
        assertTrue("CAdES-BES подпись создана", cadesBes.length > 0);

        // CAdES-C строится на CAdES-T. Один cadesT на все варианты, чтобы
        // побайтовое сравнение C-перегрузок не зависело от разных меток.
        TspTransport localTsp =
                (req, url) -> {
                    try {
                        return TspResponseBuilder.create(req)
                                .signer(tsaKey, tsaCert)
                                .policyOid("1.3.6.1.4.1.4146.1.2.1")
                                .serialNumber(BigInteger.valueOf(1))
                                .withCAdES()
                                .buildGranted();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        byte[] cadesT = CAdESExtender.addTimestamp(cadesBes, "local://tsa", localTsp, tsaCert);
        assertTrue("CAdES-T больше BES (добавлена метка)", cadesT.length > cadesBes.length);

        byte[] crlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(30)
                .withCrlNumber(1)
                .sign(caKey);
        GostCrl signerCrl = new GostCrl(crlDer);
        assertNotNull("CRL создан", signerCrl);

        List<GostCertificate> chain = List.of(leafCert, caCert);
        List<GostCrl> crlsForChain = Arrays.asList(signerCrl, null);
        List<GostOcspResponse> ocspForChain = Arrays.asList(null, null);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(
                cadesT, chain, crlsForChain, ocspForChain);
        assertTrue("CAdES-C подпись создана", cadesC.length > 0);
        assertTrue("CAdES-C больше T (добавлены C-атрибуты)",
                cadesC.length > cadesT.length);

        List<CertRevocationData> revData = Arrays.asList(
                new CertRevocationData(null, crlDer), null);
        byte[] cadesCFromCRD = CAdESExtender.embedCompleteRefs(cadesT, chain, revData);
        assertArrayEquals("CertRevocationData-перегрузка даёт идентичный результат",
                cadesC, cadesCFromCRD);

        VerifiedCAdESData result = CAdESVerifier.verifyC(cadesC, TrustAnchors.ofCertificates(caCert, tsaCert));
        assertEquals("CAdES-C: один подписант", 1, result.signers().size());
        assertNotNull("CAdES-C: completeCertificateRefs не null",
                result.signers().get(0).completeCertRefs());
        assertFalse("CAdES-C: completeRevocationRefs заполнены",
                result.signers().get(0).completeRevocRefs().isEmpty());

        try {
            CAdESVerifier.verifyC(cadesT, TrustAnchors.ofCertificates(caCert, tsaCert));
            fail("CAdES-T без C-атрибутов должен падать");
        } catch (PkixException e) {
            assertTrue("CAdES-T без C-атрибутов отвергнут: " + e.reason(), true);
        }

        byte[] revokingCrlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(30)
                .withCrlNumber(2)
                .addRevoked(leafCert.getSerialNumberBigInt(),
                        GostSignatureHelper.nowGeneralizedTime())
                .sign(caKey);
        GostCrl revokingCrl = new GostCrl(revokingCrlDer);

        List<GostCrl> revokingCrlsForChain = Arrays.asList(revokingCrl, null);
        byte[] cadesCRevoked = CAdESExtender.embedCompleteRefs(
                cadesT, chain, revokingCrlsForChain, Arrays.asList(null, null));
        VerifiedCAdESData revokedResult = CAdESVerifier.verifyC(cadesCRevoked, TrustAnchors.ofCertificates(caCert, tsaCert));
        assertEquals("CAdES-C с отозванным сертификатом — верификация прошла (так и задумано)",
                1, revokedResult.signers().size());

        System.out.println("  OK: CAdES-C — создание и верификация");
    }

    // ========================================================================
    // §34 CAdES-X Long Type 1
    // ========================================================================

    @Test
    public void test34_cadesXLongType1() throws Exception {
        section("§34 CAdES-X Long Type 1: построение и верификация (RFC 5126 §6.3)");

        byte[] data = "Документ для CAdES-X Long Type 1".getBytes(StandardCharsets.UTF_8);

        byte[] cadesBes = CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(leafKey, leafCert)
                .addCertificate(caCert)
                .withCAdES()
                .build();
        assertTrue("CAdES-BES подпись создана", cadesBes.length > 0);

        TspTransport localTsp =
                (req, url) -> {
                    try {
                        return TspResponseBuilder.create(req)
                                .signer(tsaKey, tsaCert)
                                .policyOid("1.3.6.1.4.1.4146.1.2.1")
                                .serialNumber(BigInteger.valueOf(1))
                                .withCAdES()
                                .buildGranted();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        byte[] cadesT =
                CAdESExtender.addTimestamp(cadesBes, "local://tsa", localTsp, tsaCert);
        assertTrue("CAdES-T больше BES (добавлена метка)", cadesT.length > cadesBes.length);

        List<GostCertificate> chain = CertChainBuilder.buildChain(
                leafCert, List.of(caCert), List.of(caCert));
        byte[] crlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(30)
                .withCrlNumber(1)
                .sign(caKey);
        GostCrl crl = new GostCrl(crlDer);

        List<GostCrl> crlsForChain = Arrays.asList(crl, null);
        List<GostOcspResponse> ocspForChain = Arrays.asList(null, null);
        byte[] cadesXLong = CAdESExtender.embedXLongType1(
                cadesT, chain, crlsForChain, ocspForChain, "local://tsa", localTsp, tsaCert);
        assertTrue("CAdES-X Long больше CAdES-T", cadesXLong.length > cadesT.length);
        System.out.println("  Размер CAdES-X Long: " + cadesXLong.length + " байт");

        VerifiedCAdESData result = CAdESVerifier.verifyXLong(cadesXLong, TrustAnchors.ofCertificates(caCert, tsaCert));
        assertEquals("CAdES-X Long: один подписант", 1, result.signers().size());
        assertArrayEquals("CAdES-X Long: данные совпадают", data, result.data());

        CAdESSignerResult sr = result.signers().get(0);
        assertFalse("CAdES-X Long: certificateValues заполнены",
                sr.certificateValues().isEmpty());

        CAdESXLongData.RevocationValuesDecoded revocValues = sr.revocationValues();
        assertFalse("CAdES-X Long: revocationValues.crls заполнены",
                revocValues.crls().isEmpty());
        assertNotNull("CAdES-X Long: есть CRL для подписанта",
                revocValues.crls().get(0));

        byte[] revokedCrlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(30)
                .withCrlNumber(2)
                .addRevoked(leafCert.getSerialNumberBigInt(),
                        GostSignatureHelper.nowGeneralizedTime())
                .sign(caKey);
        GostCrl revokedCrl = new GostCrl(revokedCrlDer);

        List<GostCrl> revokedCrlList = Arrays.asList(revokedCrl, null);
        try {
            CAdESExtender.embedXLongType1(
                    cadesT, chain, revokedCrlList, ocspForChain, "local://tsa", localTsp, tsaCert);
            fail("CAdES-X Long с отозванным сертификатом должен падать");
        } catch (PkixException e) {
            assertTrue("CAdES-X Long: отозванный сертификат отвергнут: " + e.reason(), true);
        }

        System.out.println("  OK: CAdES-X Long Type 1 — построение и верификация");
    }

    // ========================================================================
    // Внутренние классы: HSM-подписанты (демонстрационные)
    // ========================================================================

    /**
     * Демонстрационный подписант, эмулирующий внешний модуль (HSM).
     */
    private static final class DemoHsmSigner implements GostSigner {
        private final PrivateKeyParameters key;

        DemoHsmSigner(PrivateKeyParameters key) {
            this.key = key;
        }

        @Override
        public byte[] signHash(byte[] hash) {
            return Signature.signHash(hash, key);
        }

        @Override
        public ECParameters getParams() {
            return key.getParams();
        }

        @Override
        public PublicKeyParameters getPublicKey() {
            return Signature.derivePublicKey(key);
        }
    }

    /**
     * Неисправный подписант: заявляет один открытый ключ, а подписывает другим.
     */
    private static final class MismatchedHsmSigner implements GostSigner {
        private final PublicKeyParameters declaredPublic;
        private final PrivateKeyParameters actualPrivate;

        MismatchedHsmSigner(
                PublicKeyParameters declaredPublic, PrivateKeyParameters actualPrivate) {
            this.declaredPublic = declaredPublic;
            this.actualPrivate = actualPrivate;
        }

        @Override
        public byte[] signHash(byte[] hash) {
            return Signature.signHash(hash, actualPrivate);
        }

        @Override
        public ECParameters getParams() {
            return actualPrivate.getParams();
        }

        @Override
        public PublicKeyParameters getPublicKey() {
            return declaredPublic;
        }
    }
}
