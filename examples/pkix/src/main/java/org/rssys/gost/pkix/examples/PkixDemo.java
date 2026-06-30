package org.rssys.gost.pkix.examples;

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
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CertId;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostCsrBuilder;
import org.rssys.gost.pkix.cert.ReasonCode;
import org.rssys.gost.pkix.cert.GostCsrParser;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspRequest;
import org.rssys.gost.pkix.cert.GostOcspRequestBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.ReasonCode;
import org.rssys.gost.pkix.cert.RevokedEntry;
import org.rssys.gost.pkix.cert.SingleOcspResponse;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CertChainBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor;
import org.rssys.gost.pkix.cms.CmsKeyWrap;
import org.rssys.gost.pkix.cms.CmsSignedAndEnvelopedData;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
import org.rssys.gost.pkix.cms.Kexp15CmsKeyWrap;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.pkix.cms.VerifiedSignedData;
import org.rssys.gost.pkix.tsp.TspRequest;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Демонстрация всех возможностей модуля {@code crypto-gost-pkix}.
 *
 * <p>Последовательно выполняет все примеры из README.adoc модуля pkix,
 * проверяя каждый результат assert'ами. Для CMS-операций генерируются
 * случайные тестовые данные.</p>
 *
 * <p>Покрываемые разделы:</p>
 * <ol>
 *   <li>Быстрый старт — ключевая пара + самоподписанный сертификат</li>
 *   <li>GostCertificate — загрузка PEM/DER, проверка подписи, срока, атрибутов, hostname</li>
 *   <li>PKCS#12 — построение (включая buildAndWriteTo) и загрузка PFX-контейнера</li>
 *   <li>CSR (PKCS#10) — построение, разбор, proof-of-possession</li>
 *   <li>ChainValidator — валидация цепочки CA->leaf</li>
 *   <li>CRL — построение, проверка и разбор (GostCrl.fromDer)</li>
 *   <li>OCSP — построение/проверка ответа, построение/разбор запроса, разбор ответа</li>
 *   <li>CAdES-BES — базовая долговременная подпись (signingCertificateV2)</li>
 *   <li>CMS SignedData — подпись (инкапсулированная, detached, signed-атрибуты)</li>
 *   <li>CMS EnvelopedData — шифрование и расшифровка</li>
 *   <li>CMS SignedAndEnvelopedData — совмещённая подпись и шифрование</li>
 *   <li>CertChainBuilder — построение цепочки из неупорядоченного пула</li>
 *   <li>GostOids — реестр OID</li>
 * </ol>
 */
public final class PkixDemo {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int DEMO_FILE_SIZE = 65536;

    // Ключи и сертификаты
    private static PrivateKeyParameters caKey;
    private static PublicKeyParameters caPubKey;
    private static GostCertificate caCert;
    private static byte[] caSki;

    private static PrivateKeyParameters leafKey;
    private static PublicKeyParameters leafPubKey;
    private static GostCertificate leafCert;

    // Самоподписанный сертификат для CMS (buildTbs даёт serial=0x01 —
    // нужен уникальный серийный для корректной работы в одном certificates SET)
    private static PrivateKeyParameters cmsKey;
    private static GostCertificate cmsCert;

    // TSA-ключ и сертификат (с критическим EKU timeStamping)
    private static PrivateKeyParameters tsaKey;
    private static GostCertificate tsaCert;

    // Случайные тестовые данные для CMS-операций
    private static byte[] demoData;

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Демонстрация модуля crypto-gost-pkix ===");
        System.out.println();

        Security.insertProviderAt(new RssysGostProvider(), 1);
        demoData = new byte[DEMO_FILE_SIZE];
        CryptoRandom.INSTANCE.nextBytes(demoData);
        System.out.println(
                "[подготовка] Сгенерировано " + demoData.length + " байт случайных данных");
        generateKeysAndCerts();

        try {
            section1_quickStart();
            section2_gostCertificate();
            section3_pkcs12();
            section4_csr();
            section5_chainValidator();
            section6_crl();
            section7_ocsp();
            section8_cmsSignedData();
            section9_cmsEnvelopedData();
            section10_cmsSignedAndEnvelopedData();
            section11_gostOids();
            section12_certificatePolicies();
            section13_gostDnParser();
            section14_pkcs12WithCustomIterations();
            section15_crlRevokedMultiple();
            section16_cmsSignedDataDetached();
            section17_cmsSignedDataExtraCerts();
            section18_cmsEnvelopedDataMultiRecipients();
            section19_cmsSignEncryptMultiRecipients();
            section20_cadesBes();
            section21_ocspRequest();
            section22_gostCrlParse();
            section23_ocspResponseParse();
            section24_certChainBuilder();
            section25_tspServer();
            section26_deltaCrl();
        } catch (Exception e) {
            System.out.println();
            System.out.println("!!! АВАРИЙНОЕ ЗАВЕРШЕНИЕ: " + e.getMessage());
            e.printStackTrace(System.out);
            failed++;
        }

        System.out.println();
        System.out.println("=== ИТОГО ===");
        System.out.println("  Пройдено: " + passed);
        System.out.println("  Провалено: " + failed);
        if (failed == 0) {
            System.out.println("  ВСЕ ПРОВЕРКИ УСПЕШНЫ!");
        }
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static void generateKeysAndCerts() throws Exception {
        // CA
        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        caKey = caKp.getPrivate();
        caPubKey = caKp.getPublic();

        byte[] caKuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] caBcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, 0);
        byte[] caSkiExt = GostCertificateBuilder.buildSkiExtension(caPubKey);

        ByteArrayOutputStream caExts = new ByteArrayOutputStream();
        caExts.write(caKuExt);
        caExts.write(caBcExt);
        caExts.write(caSkiExt);

        caSki = Digest.digest256(GostDerCodec.subjectPublicKeyPointBytes(caPubKey));

        byte[] caTbs =
                GostCertificateBuilder.create(PARAMS, "CN=Demo Root CA,O=DemoOrg,C=RU")
                        .publicKey(caPubKey)
                        .notBefore("260601000000Z")
                        .notAfter("360601000000Z")
                        .additionalExtensions(caExts.toByteArray())
                        .buildTbs();
        caCert = GostCertificateBuilder.assembleCert(caTbs, caKey, PARAMS);
        System.out.println("[подготовка] CA-сертификат создан: " + caCert.getSubjectDn());

        // Leaf (подписан CA)
        var leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leafKey = leafKp.getPrivate();
        leafPubKey = leafKp.getPublic();

        byte[] leafSkiExt = GostCertificateBuilder.buildSkiExtension(leafPubKey);
        byte[] leafKuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] leafEkuExt =
                GostCertificateBuilder.buildEkuExtension(new String[] {GostOids.EXT_SERVER_AUTH});
        byte[] leafAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        ByteArrayOutputStream leafExts = new ByteArrayOutputStream();
        leafExts.write(leafKuExt);
        leafExts.write(leafEkuExt);
        leafExts.write(leafSkiExt);
        leafExts.write(leafAkiExt);

        byte[] leafTbs =
                GostCertificateBuilder.create(PARAMS, "CN=demo.example.com,O=DemoOrg,C=RU")
                        .publicKey(leafPubKey)
                        .notBefore("250601000000Z")
                        .notAfter("270601000000Z")
                        .sanDns("demo.example.com")
                        .additionalExtensions(leafExts.toByteArray())
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .buildTbs();
        leafCert = GostCertificateBuilder.assembleCert(leafTbs, caKey, PARAMS);
        System.out.println("[подготовка] Leaf-сертификат создан: " + leafCert.getSubjectDn());

        // Самоподписанный сертификат для CMS (с уникальным серийным номером)
        var cmsKp = KeyGenerator.generateKeyPair(PARAMS);
        cmsKey = cmsKp.getPrivate();
        PublicKeyParameters cmsPubKey = cmsKp.getPublic();
        byte[] cmsTbs =
                GostCertificateBuilder.create(PARAMS, "CN=CMS Signer,O=DemoOrg,C=RU")
                        .publicKey(cmsPubKey)
                        .notBefore("250601000000Z")
                        .notAfter("270601000000Z")
                        .serial(BigInteger.TWO)
                        .buildTbs();
        GostCertificate cmsGost = GostCertificateBuilder.assembleCert(cmsTbs, cmsKey, PARAMS);
        cmsCert = cmsGost;
        System.out.println(
                "[подготовка] CMS-сертификат создан (self-signed, serial="
                        + cmsCert.getSerialNumberBigInt()
                        + ")");

        // TSA-сертификат с критическим EKU timeStamping
        var tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaKey = tsaKp.getPrivate();
        PublicKeyParameters tsaPubKey = tsaKp.getPublic();
        byte[] tsaTbs =
                GostCertificateBuilder.create(PARAMS, "CN=TSA,O=DemoOrg,C=RU")
                        .publicKey(tsaPubKey)
                        .notBefore("250601000000Z")
                        .notAfter("270601000000Z")
                        .serial(BigInteger.valueOf(3))
                        .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                        .buildTbs();
        tsaCert = GostCertificateBuilder.assembleCert(tsaTbs, tsaKey, PARAMS);
        System.out.println(
                "[подготовка] TSA-сертификат создан (self-signed, serial="
                        + tsaCert.getSerialNumberBigInt()
                        + ", EKU timeStamping)");
        System.out.println();
    }

    /**
     * Создаёт самоподписанный GostCertificate через buildTbs + assembleCert
     * с заданным серийным номером.
     */
    private static GostCertificate makeSelfSignedCert(
            PrivateKeyParameters privKey, PublicKeyParameters pubKey, BigInteger serial)
            throws Exception {
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, "CN=Signer,O=DemoOrg,C=RU")
                        .publicKey(pubKey)
                        .notBefore("250601000000Z")
                        .notAfter("270601000000Z")
                        .serial(serial)
                        .buildTbs();
        return GostCertificateBuilder.assembleCert(tbs, privKey, PARAMS);
    }

    private static void check(boolean condition, String label) {
        if (condition) {
            passed++;
        } else {
            failed++;
            System.out.println("  [ПРОВАЛ] " + label);
        }
    }

    private static void checkEq(Object expected, Object actual, String label) {
        check(
                Objects.equals(expected, actual),
                label + " (ожидалось: " + expected + ", получено: " + actual + ")");
    }

    private static void section(String title) {
        System.out.println("--- " + title + " ---");
    }

    // ========================================================================
    // §1 Быстрый старт
    // ========================================================================

    private static void section1_quickStart() throws Exception {
        section("§1 Быстрый старт: ключевая пара + самоподписанный сертификат");

        var kp = KeyGenerator.generateKeyPair(PARAMS);

        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, "CN=Quick Start Test,O=MyOrg,C=RU")
                        .publicKey(kp.getPublic())
                        .notBefore("260701120000Z")
                        .notAfter("270701120000Z")
                        .sanDns("gost.example.com")
                        .buildTbs();

        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), PARAMS);
        String pem = cert.toPem();

        check(cert.getEncoded().length > 0, "Сертификат создан и сериализован");
        check(!pem.isEmpty(), "PEM не пуст");
        check(pem.startsWith("-----BEGIN CERTIFICATE-----"), "PEM начинается с BEGIN CERTIFICATE");
        System.out.println("  OK: сертификат создан и экспортирован в PEM");
    }

    // ========================================================================
    // §2 GostCertificate — загрузка и верификация
    // ========================================================================

    private static void section2_gostCertificate() throws Exception {
        section("§2 GostCertificate: загрузка, проверка подписи, срока, атрибутов");

        byte[] der = leafCert.getEncoded();
        byte[] pem = leafCert.toPem().getBytes(StandardCharsets.US_ASCII);

        // Загрузка из PEM
        GostCertificate fromPem = GostCertificate.fromPemOrDer(pem);
        checkEq(
                leafCert.getSubjectDn(),
                fromPem.getSubjectDn(),
                "fromPemOrDer: subject правильный");

        // Загрузка из DER
        GostCertificate fromDer = GostCertificate.fromDer(der);
        checkEq(
                leafCert.getSerialNumberBigInt(),
                fromDer.getSerialNumberBigInt(),
                "fromDer: серийный номер совпадает");

        // Чтение цепочки из PEM
        String chainPem = GostCertificate.chainToPem(List.of(leafCert, caCert));
        List<GostCertificate> chain =
                GostCertificate.listFromPem(chainPem.getBytes(StandardCharsets.US_ASCII));
        check(chain.size() == 2, "listFromPem: цепочка из 2 сертификатов");

        // Проверка подписи (leaf подписан CA)
        check(
                leafCert.verifySignature(caPubKey),
                "leaf.verifySignature(caPubKey) — подпись валидна");

        check(
                !leafCert.verifySignature(leafPubKey),
                "leaf.verifySignature(leafPubKey) — чужая подпись невалидна");
        // Срок
        check(!leafCert.isExpired(), "leaf.isExpired() — не истёк");
        check(leafCert.isValidAt(Instant.now()), "leaf.isValidAt(now) — действителен сейчас");

        // Атрибуты
        checkEq("CN=demo.example.com, O=DemoOrg, C=RU", leafCert.getSubjectDn(), "getSubjectDn()");
        checkEq("CN=Demo Root CA, O=DemoOrg, C=RU", leafCert.getIssuerDn(), "getIssuerDn()");

        // Самоподпись
        check(caCert.isSelfSigned(), "CA.isSelfSigned() — true");
        check(caCert.isSelfIssued(), "CA.isSelfIssued() — true");
        check(!leafCert.isSelfSigned(), "leaf.isSelfSigned() — false");

        // CA-атрибуты
        check(caCert.isCA(), "CA.isCA() — true");
        check(caCert.getPathLen() == 0, "CA.getPathLen() == 0");
        check(!leafCert.isCA(), "leaf.isCA() — false");

        // Серийный номер
        check(
                leafCert.getSerialNumberBigInt().signum() > 0,
                "getSerialNumberBigInt() — положительный");

        // Algorithm identifier
        check(
                GostOids.SIGN_ALG_256.equals(leafCert.getSignatureAlgorithmOid()),
                "getSignatureAlgorithmOid() — SIGN_ALG_256");

        // Hostname verification
        check(
                leafCert.verifyHostname("demo.example.com"),
                "verifyHostname('demo.example.com') — совпадает");
        check(
                !leafCert.verifyHostname("other.example.com"),
                "verifyHostname('other.example.com') — не совпадает");

        // Экспорт
        String pemOut = leafCert.toPem();
        check(pemOut.startsWith("-----BEGIN CERTIFICATE-----"), "toPem() — корректный PEM");
        byte[] derOut = leafCert.getEncoded();
        check(Arrays.equals(der, derOut), "getEncoded() — соответствует оригиналу");
        check(leafCert.getEncoded().length > 0, "getEncoded() — не пуст");

        // Версия
        check(leafCert.getVersion() == 3, "getVersion() == 3");

        // SKI/AKI
        check(
                leafCert.getSubjectKeyIdentifier().length == 32,
                "getSubjectKeyIdentifier() — 32 байта");
        check(
                leafCert.getAuthorityKeyIdentifier().length == 32,
                "getAuthorityKeyIdentifier() — 32 байта");

        // matchesPrivateKey
        check(leafCert.matchesPrivateKey(leafKey), "matchesPrivateKey(leafKey) — true");
        check(!leafCert.matchesPrivateKey(caKey), "matchesPrivateKey(caKey) — false");

        System.out.println("  OK: все проверки GostCertificate пройдены");
    }

    // ========================================================================
    // §3 PKCS#12 — хранение ключей и сертификатов
    // ========================================================================

    private static void section3_pkcs12() throws Exception {
        section("§3 PKCS#12: построение и загрузка PFX");

        char[] password = "changeit".toCharArray();

        // Построение
        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(leafKey)
                        .certificate(leafCert)
                        .caCertificate(caCert)
                        .password(password)
                        .friendlyName("demo-leaf-cert")
                        .build();
        check(pfx.length > 0, "PFX построен, размер " + pfx.length + " байт");

        // buildAndWriteTo — запись PFX напрямую в файл без промежуточного byte[]
        Path tmpPfx = Files.createTempFile("pkix-demo-", ".pfx");
        try {
            GostPkcs12Builder.create()
                    .key(leafKey)
                    .certificate(leafCert)
                    .password(password)
                    .friendlyName("demo-leaf-cert")
                    .buildAndWriteTo(tmpPfx);
            check(
                    Files.exists(tmpPfx) && Files.size(tmpPfx) > 0,
                    "buildAndWriteTo: PFX записан в файл");
        } finally {
            Files.deleteIfExists(tmpPfx);
        }

        // Загрузка
        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, password, true);
        PrivateKeyParameters loadedKey = result.getPrivateKey();
        List<GostCertificate> loadedChain = result.getCertificateChain();

        check(loadedKey != null, "Закрытый ключ загружен");
        check(loadedChain.size() >= 1, "Цепочка загружена (не менее 1 сертификата)");

        GostCertificate loadedLeaf = loadedChain.get(0);
        checkEq(
                leafCert.getSubjectDn(),
                loadedLeaf.getSubjectDn(),
                "Сертификат из PFX совпадает с оригиналом");

        // Проверка, что загруженный ключ соответствует сертификату
        check(
                loadedLeaf.matchesPrivateKey(loadedKey),
                "Загруженный ключ соответствует загруженному сертификату");

        // Неверный пароль
        try {
            GostPkcs12Loader.load(pfx, "wrong".toCharArray(), false);
            check(false, "Неверный пароль должен вызывать ошибку");
        } catch (Exception e) {
            check(true, "Неверный пароль корректно отвергнут: " + e.getClass().getSimpleName());
        }

        System.out.println("  OK: PKCS#12 — построение и загрузка успешны");
    }

    // ========================================================================
    // §4 CSR (PKCS#10)
    // ========================================================================

    private static void section4_csr() throws Exception {
        section("§4 CSR: построение, разбор и proof-of-possession");

        // Построение CSR
        byte[] csrDer =
                GostCsrBuilder.buildCsr(leafKey, leafPubKey, "CN=demo.example.com,O=DemoOrg,C=RU");
        check(csrDer.length > 0, "CSR DER собран");

        // Разбор из DER
        GostCsrParser csr = GostCsrParser.fromDer(csrDer);
        check(csr != null, "CSR разобран из DER");

        // DN
        check(
                "CN=demo.example.com, O=DemoOrg, C=RU".equals(csr.getSubjectDn()),
                "getSubjectDn(): " + csr.getSubjectDn());
        String[] cn = csr.getSubjectDnField("2.5.4.3");
        check(
                cn.length == 1 && "demo.example.com".equals(cn[0]),
                "getSubjectDnField(CN): " + Arrays.toString(cn));

        // SPKI и алгоритм
        PublicKeyParameters csrPubKey = csr.getPublicKey();
        check(csrPubKey != null, "getPublicKey() из CSR не null");
        check(
                GostOids.SIGN_ALG_256.equals(csr.getSignatureAlgorithmOid()),
                "CSR getSignatureAlgorithmOid() — SIGN_ALG_256");

        // Proof-of-possession
        check(csr.verifySelf(), "verifySelf() — proof-of-possession true");
        check(csr.verify(csrPubKey), "verify(csrPubKey) — подпись валидна");

        // PEM
        String csrPem = csr.toPem();
        check(csrPem.startsWith("-----BEGIN"), "toPem() — корректный PEM для CSR");

        // Разбор из PEM
        GostCsrParser fromPem =
                GostCsrParser.fromPemOrDer(csrPem.getBytes(StandardCharsets.US_ASCII));
        check(fromPem.verifySelf(), "fromPemOrDer: verifySelf() true");

        System.out.println("  OK: CSR — построение, разбор и проверка успешны");
    }

    // ========================================================================
    // §5 Цепочки сертификатов — ChainValidator
    // ========================================================================

    private static void section5_chainValidator() throws Exception {
        section("§5 ChainValidator: валидация цепочки CA->leaf");

        List<GostCertificate> chain = List.of(leafCert, caCert);
        List<PublicKeyParameters> trustedKeys = List.of(caPubKey);

        // CA самоподписан — его публичный ключ в trustedKeys
        ChainValidator.validateChain(chain, trustedKeys);
        check(true, "validateChain(leaf->CA) — цепочка валидна");

        // Цепочка без доверенного корня
        try {
            List<GostCertificate> leafOnly = List.of(leafCert);
            ChainValidator.validateChain(leafOnly, List.of(leafPubKey));
            check(false, "Цепочка без доверенного издателя должна падать");
        } catch (PkixException e) {
            check(true, "Цепочка без доверенного корня корректно отвергнута: " + e.reason());
        }

        // Просроченный сертификат
        try {
            byte[] badTbs =
                    GostCertificateBuilder.create(PARAMS, "CN=Expired,O=DemoOrg,C=RU")
                            .publicKey(leafPubKey)
                            .notBefore("200101000000Z")
                            .notAfter("200201000000Z")
                            .issuerDn(caCert.getIssuerDnBytes())
                            .buildTbs();
            GostCertificate expiredCert =
                    GostCertificateBuilder.assembleCert(badTbs, caKey, PARAMS);
            ChainValidator.validateChain(List.of(expiredCert, caCert), trustedKeys);
            check(false, "Просроченный сертификат должен вызывать ошибку");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.EXPIRED,
                    "Просроченный сертификат: reason = EXPIRED");
        }

        System.out.println("  OK: валидация цепочки сертификатов");
    }

    // ========================================================================
    // §6 CRL
    // ========================================================================

    private static void section6_crl() throws Exception {
        section("§6 CRL: построение списка отзыва и проверка");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();

        RevokedEntry entry =
                new RevokedEntry(serial, "260801120000Z", ReasonCode.KEY_COMPROMISE, null, null);

        // Построение CRL
        byte[] crlDer =
                GostCrlBuilder.create(caKey, "CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .addRevoked(List.of(entry))
                        .build();
        check(crlDer.length > 0, "CRL построен, размер " + crlDer.length + " байт");

        // Проверка: сертификат отозван
        try {
            CrlVerifier.verify(crlDer, serial, caPubKey);
            check(false, "Отозванный сертификат должен вызывать PkixException");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.REVOKED,
                    "Отозванный сертификат: reason = REVOKED");
        }

        // nextUpdate
        Instant nextUpdate = CrlVerifier.extractNextUpdate(crlDer);
        check(nextUpdate != null, "extractNextUpdate() — дата получена");

        System.out.println("  OK: CRL — построение и проверка");
    }

    // ========================================================================
    // §7 OCSP
    // ========================================================================

    private static void section7_ocsp() throws Exception {
        section("§7 OCSP: построение и проверка OCSP-ответа");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();

        // Построение OCSP-ответа
        byte[] ocspResp =
                GostOcspResponseBuilder.create(serial)
                        .signer(caKey, caPubKey)
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .good()
                        .build();
        check(ocspResp.length > 0, "OCSP-ответ построен, размер " + ocspResp.length + " байт");

        // Проверка
        OcspVerifier.verify(ocspResp, serial, caPubKey);
        check(true, "OcspVerifier.verify() — успешно");

        System.out.println("  OK: OCSP — построение и проверка");
    }

    // ========================================================================
    // §8 CMS SignedData — подпись
    // ========================================================================

    private static void section8_cmsSignedData() throws Exception {
        section("§8 CMS SignedData: инкапсулированная подпись с файлом");

        // Инкапсулированная подпись (cmsCert — самоподписанный, уникальный serial)
        byte[] signed =
                CmsSignedDataBuilder.create().data(demoData).addSigner(cmsKey, cmsCert).build();
        check(
                signed.length > 0,
                "SignedData построен, размер "
                        + signed.length
                        + " байт (файл "
                        + demoData.length
                        + " байт)");

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signed, cmsCert);
        check(Arrays.equals(demoData, result.data()), "Данные после верификации совпадают");
        check(result.signerCertificate() != null, "Сертификат подписанта извлечён");

        // Detached подпись
        byte[] detachedData = "Внешний документ".getBytes(StandardCharsets.UTF_8);
        byte[] detachedSigned =
                CmsSignedDataBuilder.create()
                        .data(detachedData)
                        .addSigner(cmsKey, cmsCert)
                        .detached(true)
                        .build();
        VerifiedSignedData detResult = CmsSignedDataVerifier.verifyAny(detachedSigned, cmsCert);
        check(detResult.data() == null, "Detached: данных в CMS нет (data == null)");

        // Дополнительные сертификаты в цепочке — добавляем CA
        byte[] chainSigned =
                CmsSignedDataBuilder.create()
                        .data(demoData)
                        .addSigner(cmsKey, cmsCert)
                        .addCertificate(caCert)
                        .build();
        VerifiedSignedData chainResult = CmsSignedDataVerifier.verifyAny(chainSigned, cmsCert);

        // Пользовательские signed-атрибуты
        byte[] attrSigned =
                CmsSignedDataBuilder.create()
                        .data(demoData)
                        .addSigner(cmsKey, cmsCert)
                        .addSignedAttribute(
                                GostOids.ATTR_SIGNING_TIME, DerCodec.encodeTime("260601120000Z"))
                        .build();
        VerifiedSignedData attrResult = CmsSignedDataVerifier.verifyAny(attrSigned, cmsCert);

        // Неверный сертификат — создаём чужой самоподписанный
        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                makeSelfSignedCert(
                        wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(999));
        try {
            CmsSignedDataVerifier.verifyAny(signed, wrongCert);
            check(false, "Верификация чужим сертификатом: ожидался PkixException");
        } catch (PkixException e) {
            check(true, "Верификация чужим сертификатом: провал (как и ожидалось)");
        }

        // Подмена данных
        byte[] tampered = Arrays.copyOf(signed, signed.length);
        tampered[signed.length / 2] ^= 0xFF;
        try {
            CmsSignedDataVerifier.verifyAny(tampered, cmsCert);
            check(false, "Подмена данных: ожидался PkixException");
        } catch (PkixException e) {
            check(true, "Подмена данных: верификация провалена");
        }

        System.out.println("  OK: CMS SignedData — инкапсулированная подпись");
    }

    // ========================================================================
    // §9 CMS EnvelopedData — шифрование
    // ========================================================================

    private static void section9_cmsEnvelopedData() throws Exception {
        section("§9 CMS EnvelopedData: шифрование и расшифровка файла");

        CmsKeyWrap keyWrap = new Kexp15CmsKeyWrap();

        // Шифрование
        byte[] enveloped =
                CmsEnvelopedDataBuilder.create()
                        .data(demoData)
                        .addRecipient(cmsCert)
                        .keyWrap(keyWrap)
                        .build();
        check(enveloped.length > 0, "EnvelopedData построен, размер " + enveloped.length + " байт");

        // Расшифрование
        byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert, keyWrap);
        check(
                Arrays.equals(demoData, decrypted),
                "Расшифрованные данные совпадают с оригиналом (" + decrypted.length + " байт)");

        // Неверный ключ
        try {
            byte[] badDecrypt =
                    CmsEnvelopedDataDecryptor.decrypt(enveloped, caKey, caCert, keyWrap);
            check(
                    !Arrays.equals(demoData, badDecrypt),
                    "Расшифрование чужим ключом: данные не совпадают или падает");
        } catch (Exception e) {
            check(
                    true,
                    "Расшифрование чужим ключом: исключение ("
                            + e.getClass().getSimpleName()
                            + ")");
        }

        System.out.println("  OK: CMS EnvelopedData — шифрование и расшифровка");
    }

    // ========================================================================
    // §10 CMS SignedAndEnvelopedData
    // ========================================================================

    private static void section10_cmsSignedAndEnvelopedData() throws Exception {
        section("§10 CMS Sign+Encrypt: совмещённая подпись и шифрование файла");

        byte[] sample = (demoData.length > 4096) ? Arrays.copyOf(demoData, 4096) : demoData;

        // sign-then-encrypt — подписывает cmsKey, шифрует для cmsCert
        byte[] combined1 =
                CmsSignedAndEnvelopedData.signThenEncrypt(sample, cmsKey, cmsCert, cmsCert);
        check(
                combined1.length > 0,
                "signThenEncrypt построен, размер " + combined1.length + " байт");

        VerifiedSignedData result1 =
                CmsSignedAndEnvelopedData.decryptAndVerify(combined1, cmsKey, cmsCert, cmsCert);
        check(
                Arrays.equals(sample, result1.data()),
                "Данные после signThenEncrypt/decryptAndVerify совпадают");

        // encrypt-then-sign
        byte[] combined2 =
                CmsSignedAndEnvelopedData.encryptThenSign(sample, cmsKey, cmsCert, cmsCert);
        VerifiedSignedData result2 =
                CmsSignedAndEnvelopedData.verifyAndDecrypt(combined2, cmsKey, cmsCert, cmsCert);
        check(
                Arrays.equals(sample, result2.data()),
                "Данные после encryptThenSign/verifyAndDecrypt совпадают");

        System.out.println("  OK: CMS — совмещённая подпись и шифрование");
    }

    // ========================================================================
    // §11 GostOids
    // ========================================================================

    private static void section11_gostOids() {
        section("§11 GostOids: реестр OID");

        check(GostOids.CMS_SIGNED_DATA.equals("1.2.840.113549.1.7.2"), "CMS_SIGNED_DATA");
        check(GostOids.CMS_ENVELOPED_DATA.equals("1.2.840.113549.1.7.3"), "CMS_ENVELOPED_DATA");
        check(GostOids.ATTR_CONTENT_TYPE.equals("1.2.840.113549.1.9.3"), "ATTR_CONTENT_TYPE");
        check(GostOids.ATTR_MESSAGE_DIGEST.equals("1.2.840.113549.1.9.4"), "ATTR_MESSAGE_DIGEST");
        check(GostOids.ATTR_SIGNING_TIME.equals("1.2.840.113549.1.9.5"), "ATTR_SIGNING_TIME");
        check(GostOids.AGREEMENT_VKO_256.equals("1.2.643.7.1.1.6.1"), "AGREEMENT_VKO_256");
        check(
                GostOids.WRAP_KUZNYECHIK_KEXP15.equals("1.2.643.7.1.1.7.2.1"),
                "WRAP_KUZNYECHIK_KEXP15");
        check(GostOids.SIG_WITH_DIGEST_256.equals("1.2.643.7.1.1.1.1"), "SIG_WITH_DIGEST_256");
        check(GostOids.SIGN_ALG_256.equals("1.2.643.7.1.1.3.2"), "SIGN_ALG_256");
        check(GostOids.DIGEST_256.equals("1.2.643.7.1.1.2.2"), "DIGEST_256");
        check(GostOids.KUZ_CTR_ACPKM.equals("1.2.643.7.1.1.5.2.1"), "KUZ_CTR_ACPKM");
        check(GostOids.EXT_SAN.equals("2.5.29.17"), "EXT_SAN");
        check(GostOids.EXT_KU.equals("2.5.29.15"), "EXT_KU");
        check(GostOids.EXT_EKU.equals("2.5.29.37"), "EXT_EKU");
        check(GostOids.EXT_BC.equals("2.5.29.19"), "EXT_BC");
        check(GostOids.PBE_DEFAULT_ITERATIONS == 2000, "PBE_DEFAULT_ITERATIONS = 2000");

        System.out.println("  OK: GostOids");
    }

    // ========================================================================
    // §12 Certificate Policies (дополнительно)
    // ========================================================================

    private static void section12_certificatePolicies() {
        section("§12 Certificate Policies");

        String[] policies = leafCert.getCertificatePolicies();
        check(true, "getCertificatePolicies() доступен");

        System.out.println("  OK: Certificate policies — политики сертификатов");
    }

    // ========================================================================
    // §13 GostDnParser (дополнительно)
    // ========================================================================

    private static void section13_gostDnParser() {
        section("§13 GostDnParser: кодирование DNs");

        byte[] dnDer = GostDnParser.encodeDn("CN=Test,O=Demo,L=Moscow,C=RU");
        check(dnDer.length > 0, "encodeDn построен, размер " + dnDer.length + " байт");

        String[] cnFields = leafCert.getSubjectDnField("2.5.4.3");
        check(cnFields.length > 0, "getSubjectDnField(CN) из leaf: " + String.join(",", cnFields));

        System.out.println("  OK: GostDnParser");
    }

    // ========================================================================
    // §14 PKCS#12 с кастомным числом итераций
    // ========================================================================

    private static void section14_pkcs12WithCustomIterations() throws Exception {
        section("§14 PKCS#12 с кастомным числом итераций");

        char[] password = "customiter".toCharArray();
        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(leafKey)
                        .certificate(leafCert)
                        .password(password)
                        .iterations(50_000)
                        .friendlyName("high-iter-cert")
                        .build();
        check(pfx.length > 0, "PFX с 50K итерациями построен");

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, password, true);
        check(result.getPrivateKey() != null, "Ключ из PFX с 50K итерациями загружен");

        System.out.println("  OK: PKCS#12 с кастомным числом итераций");
    }

    // ========================================================================
    // §15 CRL с несколькими отозванными записями
    // ========================================================================

    private static void section15_crlRevokedMultiple() throws Exception {
        section("§15 CRL: несколько отозванных сертификатов");

        byte[] serial1 = BigInteger.valueOf(12345).toByteArray();
        byte[] serial2 = BigInteger.valueOf(67890).toByteArray();

        RevokedEntry e1 = new RevokedEntry(serial1, "260801120000Z");
        RevokedEntry e2 =
                new RevokedEntry(
                        serial2, "260901120000Z", ReasonCode.CESSATION_OF_OPERATION, null, null);

        byte[] crlDer =
                GostCrlBuilder.create(caKey, "CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .addRevoked(List.of(e1, e2))
                        .build();
        check(crlDer.length > 0, "CRL с 2 записями построен, размер " + crlDer.length + " байт");

        // Проверка первой записи
        try {
            CrlVerifier.verify(crlDer, serial1, caPubKey);
            check(false, "serial1 должен быть отозван");
        } catch (PkixException e) {
            check(e.reason() == PkixException.Reason.REVOKED, "serial1 отозван");
        }

        // nextUpdate
        Instant nextUpdate = CrlVerifier.extractNextUpdate(crlDer);
        check(nextUpdate != null, "nextUpdate извлечён: " + nextUpdate);

        System.out.println("  OK: CRL — несколько отозванных записей");
    }

    // ========================================================================
    // §16 Detached подпись с отдельным файлом
    // ========================================================================

    private static void section16_cmsSignedDataDetached() throws Exception {
        section("§16 CMS SignedData: detached подпись с файлом");

        byte[] detachedSigned =
                CmsSignedDataBuilder.create()
                        .data(demoData)
                        .addSigner(cmsKey, cmsCert)
                        .detached(true)
                        .build();
        check(
                detachedSigned.length > 0,
                "Detached SignedData построен, размер "
                        + detachedSigned.length
                        + " байт (данные "
                        + demoData.length
                        + " байт вне CMS)");

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(detachedSigned, cmsCert);
        check(result.data() == null, "Detached: data == null (данные вне CMS)");

        System.out.println("  OK: CMS SignedData — отсоединённая подпись");
    }

    // ========================================================================
    // §17 SignedData с дополнительными сертификатами цепочки
    // ========================================================================

    private static void section17_cmsSignedDataExtraCerts() throws Exception {
        section("§17 CMS SignedData: дополнительные сертификаты цепочки");

        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(demoData)
                        .addSigner(cmsKey, cmsCert)
                        .addCertificate(caCert)
                        .build();

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signed, cmsCert);
        check(Arrays.equals(demoData, result.data()), "Данные совпадают");

        System.out.println("  OK: SignedData с дополнительными сертификатами");
    }

    // ========================================================================
    // §18 EnvelopedData с несколькими получателями
    // ========================================================================

    private static void section18_cmsEnvelopedDataMultiRecipients() throws Exception {
        section("§18 CMS EnvelopedData: несколько получателей");

        // Второй получатель — с уникальным серийным номером
        var bobKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate bobCert =
                makeSelfSignedCert(bobKp.getPrivate(), bobKp.getPublic(), BigInteger.TWO);

        CmsKeyWrap keyWrap = new Kexp15CmsKeyWrap();

        // Шифрование для двух получателей
        byte[] enveloped =
                CmsEnvelopedDataBuilder.create()
                        .data(demoData)
                        .addRecipient(cmsCert)
                        .addRecipient(bobCert)
                        .keyWrap(keyWrap)
                        .build();

        // Расшифровывает cmsKey
        byte[] cmsData = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert, keyWrap);
        check(Arrays.equals(demoData, cmsData), "cmsKey расшифровал успешно");

        // Bob расшифровывает
        byte[] bobData =
                CmsEnvelopedDataDecryptor.decrypt(enveloped, bobKp.getPrivate(), bobCert, keyWrap);
        check(Arrays.equals(demoData, bobData), "Bob расшифровал успешно");

        System.out.println("  OK: CMS EnvelopedData — несколько получателей");
    }

    // ========================================================================
    // §19 Sign+Encrypt с несколькими получателями
    // ========================================================================

    private static void section19_cmsSignEncryptMultiRecipients() throws Exception {
        section("§19 CMS Sign+Encrypt: несколько получателей");

        byte[] sample = (demoData.length > 4096) ? Arrays.copyOf(demoData, 4096) : demoData;

        // Третий получатель для sign-then-encrypt — уникальный serial
        var aliceKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate aliceCert =
                makeSelfSignedCert(
                        aliceKp.getPrivate(), aliceKp.getPublic(), BigInteger.valueOf(3));

        // sign-then-encrypt с двумя получателями
        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        sample, cmsKey, cmsCert, cmsCert, aliceCert);

        // cmsKey расшифровывает и проверяет
        VerifiedSignedData cmsResult =
                CmsSignedAndEnvelopedData.decryptAndVerify(combined, cmsKey, cmsCert, cmsCert);
        check(Arrays.equals(sample, cmsResult.data()), "cmsKey: данные совпадают");

        // Alice расшифровывает и проверяет
        VerifiedSignedData aliceResult =
                CmsSignedAndEnvelopedData.decryptAndVerify(
                        combined, aliceKp.getPrivate(), aliceCert, cmsCert);
        check(Arrays.equals(sample, aliceResult.data()), "Alice: данные совпадают");

        System.out.println("  OK: CMS Sign+Encrypt — несколько получателей");
    }

    // ========================================================================
    // §20 CAdES-BES — базовая долговременная подпись
    // ========================================================================

    private static void section20_cadesBes() throws Exception {
        section("§20 CAdES-BES: базовая долговременная подпись");

        byte[] data = "Документ для CAdES".getBytes(StandardCharsets.UTF_8);

        // Создание CAdES-BES — signingCertificateV2 добавляется автоматически
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(cmsKey, cmsCert)
                        .withCAdES()
                        .build();
        check(cadesBes.length > 0, "CAdES-BES подпись создана");

        // Верификация через CAdESExtender (AND-семантика, проверяет signingCertificateV2)
        VerifiedCAdESData result = CAdESExtender.verifyCAdESBES(cadesBes, cmsCert);
        check(Arrays.equals(data, result.data()), "CAdES-BES данные совпадают");
        check(result.signers().size() == 1, "CAdES-BES один подписант");
        check(
                result.signers().get(0).signerCertificate() != null,
                "Сертификат подписанта извлечён");

        // Неверный сертификат — верификация должна провалиться
        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                makeSelfSignedCert(
                        wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(100));
        try {
            CAdESExtender.verifyCAdESBES(cadesBes, wrongCert);
            check(false, "CAdES-BES: чужая верификация должна падать");
        } catch (PkixException e) {
            check(true, "CAdES-BES: чужая верификация отвергнута: " + e.reason());
        }

        System.out.println("  OK: CAdES-BES — создание и верификация");
    }

    // ========================================================================
    // §21 OCSP-запрос — построение и разбор
    // ========================================================================

    private static void section21_ocspRequest() throws Exception {
        section("§21 OCSP-запрос: построение и разбор");

        // Построение запроса
        GostOcspRequestBuilder reqBuilder =
                GostOcspRequestBuilder.create()
                        .targetCert(leafCert.getEncoded())
                        .issuerCert(caCert.getEncoded());
        byte[] requestDer = reqBuilder.build();
        byte[] nonce = reqBuilder.getNonce();

        check(requestDer.length > 0, "OCSP-запрос построен");
        check(nonce != null && nonce.length > 0, "Nonce автоматически сгенерирован");

        // Разбор запроса
        GostOcspRequest request = GostOcspRequest.fromDer(requestDer);
        check(request != null, "OCSP-запрос разобран");

        List<CertId> certIds = request.getCertIds();
        check(certIds.size() == 1, "Один CertId в запросе");

        CertId cid = certIds.get(0);
        check(cid.serialNumber() != null, "CertId serialNumber не null");
        check(
                cid.issuerNameHash().length == GostOids.STREEBOG_256_HASH_LEN,
                "CertId issuerNameHash — 32 байта");
        check(
                cid.issuerKeyHash().length == GostOids.STREEBOG_256_HASH_LEN,
                "CertId issuerKeyHash — 32 байта");

        // Nonce совпадает
        byte[] parsedNonce = request.getNonce();
        check(Arrays.equals(nonce, parsedNonce), "Nonce в ответе совпадает с запросом");

        // Multi-cert запрос
        byte[] multiDer =
                GostOcspRequestBuilder.create()
                        .targetCert(leafCert.getEncoded())
                        .issuerCert(caCert.getEncoded())
                        .addRequest(cmsCert.getEncoded(), cmsCert.getEncoded())
                        .build();
        GostOcspRequest multiReq = GostOcspRequest.fromDer(multiDer);
        check(multiReq.getCertIds().size() == 2, "Multi-cert: 2 CertId");

        System.out.println("  OK: OCSP-запрос — построение и разбор");
    }

    // ========================================================================
    // §22 GostCrl — разбор CRL без верификации
    // ========================================================================

    private static void section22_gostCrlParse() throws Exception {
        section("§22 GostCrl: разбор CRL");

        // Строим CRL
        byte[] crlDer =
                GostCrlBuilder.create(caKey, "CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .addRevoked(
                                new RevokedEntry(
                                        leafCert.getSerialNumber(),
                                        "260801120000Z",
                                        ReasonCode.KEY_COMPROMISE,
                                        null,
                                        null))
                        .build();

        // Разбор через GostCrl.fromDer()
        GostCrl crl = GostCrl.fromDer(crlDer);
        check(crl != null, "GostCrl.fromDer — разобран");

        // Метаданные
        checkEq("CN=Demo Root CA, O=DemoOrg, C=RU", crl.getIssuerDn(), "CRL issuer DN");
        check(crl.getThisUpdate() != null, "CRL thisUpdate не null");
        check(crl.getNextUpdate() != null, "CRL nextUpdate не null");

        // Верификация подписи + парсинг revoked-списка (порядок обязателен)
        crl.verify(caPubKey);

        check(crl.isRevoked(leafCert.getSerialNumber()), "isRevoked: сертификат в CRL");

        List<RevokedEntry> revoked = crl.getRevokedCertificates();
        check(revoked.size() == 1, "getRevokedCertificates: одна запись после verify");
        check(
                Arrays.equals(leafCert.getSerialNumber(), revoked.get(0).serial()),
                "Серийный номер отозванного совпадает");

        // Экспорт в PEM
        String crlPem = crl.toPem();
        check(crlPem.startsWith("-----BEGIN X509 CRL-----"), "toPem() — корректный PEM CRL");

        System.out.println("  OK: GostCrl — разбор и экспорт");
    }

    // ========================================================================
    // §23 GostOcspResponse — разбор OCSP-ответа
    // ========================================================================

    private static void section23_ocspResponseParse() throws Exception {
        section("§23 GostOcspResponse: разбор OCSP-ответа");

        // Строим OCSP-ответ
        byte[] ocspDer =
                GostOcspResponseBuilder.create(leafCert.getSerialNumber())
                        .signer(caKey, caPubKey)
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .good()
                        .build();

        // Разбор через fromDer()
        GostOcspResponse response = GostOcspResponse.fromDer(ocspDer);
        check(response.isSuccessful(), "isSuccessful() — true");
        check(response.getProducedAt() != null, "getProducedAt() не null");

        // SingleOcspResponse
        var responses = response.getResponses();
        check(responses.size() == 1, "Один SingleOcspResponse");
        SingleOcspResponse sr = responses.get(0);
        check(sr.isGood(), "Статус: good");
        check(!sr.isRevoked(), "Не revoked");
        check(!sr.isUnknown(), "Не unknown");
        check(sr.thisUpdate() != null, "thisUpdate не null");

        // Верификация подписи
        response.verify(caPubKey);
        check(response.isSignatureVerified(), "Подпись OCSP-ответа валидна");

        // Неверный ключ
        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostOcspResponse wrongVerify = GostOcspResponse.fromDer(ocspDer);
        try {
            wrongVerify.verify(wrongKp.getPublic());
            check(false, "OCSP: чужая верификация должна падать");
        } catch (PkixException e) {
            check(true, "OCSP: чужая верификация отвергнута");
        }

        System.out.println("  OK: GostOcspResponse — разбор и верификация");
    }

    // ========================================================================
    // §24 CertChainBuilder — построение цепочки из пула
    // ========================================================================

    private static void section24_certChainBuilder() throws Exception {
        section("§24 CertChainBuilder: построение цепочки из неупорядоченного пула");

        // pool — неупорядоченный набор промежуточных сертификатов
        // trustedRoots — доверенные корни
        List<GostCertificate> chain =
                CertChainBuilder.buildChain(
                        leafCert,
                        List.of(caCert), // промежуточные
                        List.of(caCert)); // доверенные корни (CA самоподписан)

        check(chain.size() == 2, "Цепочка из 2 сертификатов");
        check(chain.get(0) == leafCert, "Первый — leaf");
        check(chain.get(1) == caCert, "Второй — CA");

        // Без доверенного корня — ожидается ошибка
        try {
            CertChainBuilder.buildChain(leafCert, List.of(), List.of());
            check(false, "Без корня должно падать");
        } catch (PkixException e) {
            check(true, "Без корня: PkixException (" + e.reason() + ")");
        }

        System.out.println("  OK: CertChainBuilder — построение цепочки");
    }

    // ========================================================================
    // §25 TSP-сервер — разбор запроса и построение TimeStampResp
    // ========================================================================

    private static void section25_tspServer() throws Exception {
        section("§25 TSP-сервер: разбор запроса и построение TimeStampResp");

        byte[] hash = Digest.digest256("time-stamp-data".getBytes(StandardCharsets.UTF_8));

        // Клиент: строим запрос
        BigInteger nonce = BigInteger.valueOf(12345);
        byte[] reqDer = TspRequestBuilder.create()
                .messageImprint(hash, GostOids.DIGEST_256)
                .nonce(nonce)
                .build();
        check(reqDer.length > 0, "TSP-запрос построен");

        // Сервер: разбираем запрос
        TspRequest request = TspRequest.fromDer(reqDer);
        check(request.messageImprintAlgOid().equals(GostOids.DIGEST_256),
                "Алгоритм дайджеста в запросе");
        check(request.nonce().equals(nonce), "Nonce в запросе");

        // Given алгоритм — отклоняем с failInfo
        byte[] rejectionDer = TspResponseBuilder.buildRejected(
                "Unsupported algorithm", GostOids.PKI_FAIL_BAD_ALG);
        check(rejectionDer.length > 0, "Rejection с failInfo построен");
        try {
            TspResponse.fromDer(rejectionDer);
            check(false, "Rejection должен бросать PkixException");
        } catch (PkixException e) {
            check(e.getMessage().contains("rejection"),
                    "PkixException содержит 'rejection': " + e.getMessage());
        }

        // Granted: строим ответ с accuracy и ordering
        byte[] responseDer = TspResponseBuilder.create(request)
                .signer(tsaKey, tsaCert)
                .policyOid("1.3.6.1.4.1.4146.1.2.1")
                .serialNumber(BigInteger.ONE)
                .accuracy(1, 500)
                .withCAdES()
                .ordering(true)
                .buildGranted();
        check(responseDer.length > 0, "Granted ответ построен");

        // Клиент: разбираем и верифицируем ответ
        TspResponse resp = TspResponse.fromDer(responseDer);
        check(resp.status() == GostOids.PKI_STATUS_GRANTED, "Статус granted");
        check(resp.tstInfo().accuracySeconds() == 1, "Accuracy seconds");
        check(resp.tstInfo().accuracyMillis() == 500, "Accuracy millis");
        check(resp.tstInfo().ordering(), "Ordering = true");
        check(resp.tstInfo().nonce().equals(nonce), "Nonce echo");
        resp.verify(hash, GostOids.DIGEST_256, nonce, tsaCert);
        check(resp.isSignatureVerified(), "Подпись TSA верифицирована");

        System.out.println("  OK: TSP-сервер — round-trip запрос→ответ→верификация");
    }

    // ========================================================================
    // §26 Delta CRL
    // ========================================================================

    private static void section26_deltaCrl() throws Exception {
        section("§26 Delta CRL: базовый + delta CRL с merge-верификацией");

        byte[] serial1 = leafCert.getSerialNumber();     // отозван в base, удалён в delta
        byte[] serial2 = new BigInteger("999999999").toByteArray(); // отозван в base, не в delta

        // 1. Базовый CRL: два отозванных сертификата + cRLNumber
        byte[] baseCrl =
                GostCrlBuilder.create(caKey, "CN=Demo Root CA,O=DemoOrg,C=RU")
                        .withCrlNumber(1)
                        .nextUpdate("270801120000Z")
                        .addRevoked(List.of(
                                new RevokedEntry(serial1, "260801120000Z",
                                        ReasonCode.KEY_COMPROMISE, null, null),
                                new RevokedEntry(serial2, "260801120000Z",
                                        ReasonCode.CERTIFICATE_HOLD, null, null)))
                        .build();
        check(baseCrl.length > 0, "Base CRL построен, cRLNumber=1");

        // 2. Delta CRL: serial1 удалён (REMOVE_FROM_CRL)
        byte[] deltaCrl =
                GostCrlBuilder.create(caKey, "CN=Demo Root CA,O=DemoOrg,C=RU")
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .addRevoked(List.of(
                                new RevokedEntry(serial1, "260901120000Z",
                                        ReasonCode.REMOVE_FROM_CRL, null, null)))
                        .build();
        check(deltaCrl.length > 0, "Delta CRL построен, ссылается на base cRLNumber=1");

        // 3. GostCrl: чтение метаданных (cRLNumber доступен без verify)
        GostCrl base = GostCrl.fromDer(baseCrl);
        base.verify(caPubKey);
        check(base.getCrlNumber().equals(BigInteger.valueOf(1)),
                "Base CRL: getCrlNumber() = 1");

        // Delta CRL: изолированная верификация — rejected
        try {
            new GostCrl(deltaCrl).verify(caPubKey);
            check(false, "Delta CRL должен быть rejected");
        } catch (PkixException e) {
            check(e.getMessage().contains("delta CRL not supported"),
                    "Delta CRL rejected при изолированной верификации");
        }

        // 4. Merge-верификация: serial1 удалён → не отозван
        CrlVerifier.verify(baseCrl, deltaCrl, serial1, caPubKey);
        System.out.println("  serial1 прошёл — удалён из CRL через REMOVE_FROM_CRL");

        // 5. serial2 остался только в base → отозван
        try {
            CrlVerifier.verify(baseCrl, deltaCrl, serial2, caPubKey);
            check(false, "serial2 должен быть отозван");
        } catch (PkixException e) {
            check(e.reason() == PkixException.Reason.REVOKED,
                    "serial2 отозван в base CRL, delta не удаляла");
        }

        // 6. Base CRL: getReason читает причину из entry extensions
        check(base.getReason(serial1) == ReasonCode.KEY_COMPROMISE,
                "getReason(serial1) = KEY_COMPROMISE");
        check(base.getRevokedCertificates().size() == 2,
                "Base CRL: две записи в revoked-списке");

        System.out.println("  OK: Delta CRL — base+delta merge");
    }
}
