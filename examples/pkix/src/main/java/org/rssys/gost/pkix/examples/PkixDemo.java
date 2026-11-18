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
import org.rssys.gost.pkix.cms.CAdESVerifier;
import org.rssys.gost.pkix.cms.CAdESXLongData;
import org.rssys.gost.pkix.cms.CertChainBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor;
import org.rssys.gost.pkix.cms.CmsSignedAndEnvelopedData;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
import org.rssys.gost.pkix.cms.GostPkcs7;
import org.rssys.gost.pkix.cms.Revocation;
import org.rssys.gost.pkix.cms.SignerSelection;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.pkix.cms.VerifiedSignedData;
import org.rssys.gost.pkix.cms.VerifyOptions;
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
 *   <li>Countersignature — контрподпись (RFC 5652 §11.4)</li>
 *   <li>CMS SignedData — подпись (инкапсулированная, detached, signed-атрибуты)</li>
 *   <li>CMS EnvelopedData — шифрование и расшифровка</li>
 *   <li>CMS SignedAndEnvelopedData — совмещённая подпись и шифрование</li>
 *   <li>CertChainBuilder — построение цепочки из неупорядоченного пула</li>
 *   <li>GostOids — реестр OID</li>
 *   <li>CMS SignedData с встроенным CRL — addCrl в CmsSignedDataBuilder</li>
 *   <li>Автоматическая проверка отзыва — Revocation.required</li>
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

    // CRL-подписант — делегированный ключ с cRLSign (не CA)
    private static PrivateKeyParameters crlSignerKey;
    private static GostCertificate crlSignerCert;

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
            section5_1_chainValidatorWithRevocation();
            section6_crl();
            section7_ocsp();
            section8_cmsSignedData();
            section9_cmsEnvelopedData();
            section9_1_cmsEnvelopedDataOmac();
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
            section27_cmsSignedDataWithCrl();
            section28_cmsSignedDataRevocationCheck();
            section29_delegatedCrlSigner();
            section30_countersignature();
            section31_gostSigner();
            section32_certRenewal();
            section33_cadesC();
            section34_cadesXLongType1();
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
                        .randomSerial()
                        .notBefore("260601000000Z")
                        .notAfter("360601000000Z")
                        .additionalExtensions(caExts.toByteArray())
                        .buildTbs();
        caCert = GostCertificateBuilder.sign(caTbs, GostSigner.of(caKey));
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
                GostCertificateBuilder.buildEkuExtension(
                        new String[] {GostOids.EXT_SERVER_AUTH}, false);
        byte[] leafAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        ByteArrayOutputStream leafExts = new ByteArrayOutputStream();
        leafExts.write(leafKuExt);
        leafExts.write(leafEkuExt);
        leafExts.write(leafSkiExt);
        leafExts.write(leafAkiExt);

        byte[] leafTbs =
                GostCertificateBuilder.create(PARAMS, "CN=demo.example.com,O=DemoOrg,C=RU")
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
        GostCertificate cmsGost = GostCertificateBuilder.sign(cmsTbs, GostSigner.of(cmsKey));
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
        tsaCert = GostCertificateBuilder.sign(tsaTbs, GostSigner.of(tsaKey));
        System.out.println(
                "[подготовка] TSA-сертификат создан (self-signed, serial="
                        + tsaCert.getSerialNumberBigInt()
                        + ", EKU timeStamping)");

        // CRL-подписант — не CA, только cRLSign
        var crlSignerKp = KeyGenerator.generateKeyPair(PARAMS);
        crlSignerKey = crlSignerKp.getPrivate();
        PublicKeyParameters crlSignerPubKey = crlSignerKp.getPublic();

        byte[] crlSignerKuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] crlSignerSkiExt = GostCertificateBuilder.buildSkiExtension(crlSignerPubKey);
        byte[] crlSignerAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        ByteArrayOutputStream crlSignerExts = new ByteArrayOutputStream();
        crlSignerExts.write(crlSignerKuExt);
        crlSignerExts.write(crlSignerSkiExt);
        crlSignerExts.write(crlSignerAkiExt);

        byte[] crlSignerTbs =
                GostCertificateBuilder.create(PARAMS, "CN=CRL Signer,O=DemoOrg,C=RU")
                        .publicKey(crlSignerPubKey)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBefore("260601000000Z")
                        .notAfter("360601000000Z")
                        .serial(BigInteger.valueOf(4))
                        .additionalExtensions(crlSignerExts.toByteArray())
                        .buildTbs();
        crlSignerCert = GostCertificateBuilder.sign(crlSignerTbs, GostSigner.of(caKey));
        System.out.println(
                "[подготовка] CRL-подписант создан: "
                        + crlSignerCert.getSubjectDn()
                        + " (cRLSign)");

        System.out.println();
    }

    /**
     * Создаёт самоподписанный GostCertificate через buildTbs + sign
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
        return GostCertificateBuilder.sign(tbs, GostSigner.of(privKey));
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

        // Удобный способ: notBeforeNow() + validForDays(365)
        // Альтернативно с явными датами: .notBefore("260701120000Z").notAfter("270701120000Z")
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, "CN=Quick Start Test,O=MyOrg,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sanDns("gost.example.com")
                        .buildTbs();

        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));
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

        // Идентификатор алгоритма
        check(
                GostOids.SIGN_WITH_DIGEST_256.equals(leafCert.getSignatureAlgorithmOid()),
                "getSignatureAlgorithmOid() — SIGN_WITH_DIGEST_256");

        // Проверка hostname
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

        // Построение CSR без расширений (статический API — обратная совместимость)
        byte[] csrDer =
                GostCsrBuilder.create("CN=demo.example.com,O=DemoOrg,C=RU", leafPubKey)
                        .sign(leafKey);
        check(csrDer.length > 0, "CSR DER собран");

        // Построение CSR с extensionRequest (fluent API)
        byte[] csrExtDer =
                GostCsrBuilder.create("CN=demo-san.example.com,O=DemoOrg,C=RU", leafPubKey)
                        .sanDns("demo-san.example.com", "www.demo-san.example.com")
                        .sanRfc822Name("admin@example.com")
                        .sanUpn("user@domain.ru")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .sign(leafKey);
        check(csrExtDer.length > 0, "CSR с расширениями DER собран");

        // Разбор CSR с расширениями
        GostCsrParser csrExt = GostCsrParser.fromDer(csrExtDer);
        check(csrExt.verifySelf(), "CSR с расширениями: proof-of-possession true");
        check(csrExt.hasExtensions(), "CSR с расширениями: hasExtensions() true");
        GostExtensionParser.ExtensionsResult extResult = csrExt.getExtensions();
        check(
                extResult.sanDnsNames != null && extResult.sanDnsNames.length > 0,
                "CSR с расширениями: SAN распарсен");
        check(
                extResult.sanRfc822Names != null
                        && extResult.sanRfc822Names[0].equals("admin@example.com"),
                "CSR с расширениями: rfc822Name распарсен");
        check(
                extResult.sanOtherNames != null && extResult.sanOtherNames.length > 0,
                "CSR с расширениями: otherName (UPN) распарсен");
        check(
                extResult.presentExtensionOids.contains(GostOids.EXT_SAN),
                "CSR с расширениями: OID SAN в списке");
        check(
                extResult.presentExtensionOids.contains(GostOids.EXT_EKU),
                "CSR с расширениями: OID EKU в списке");

        // Разбор из DER (базовый CSR)
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
                GostOids.SIGN_WITH_DIGEST_256.equals(csr.getSignatureAlgorithmOid()),
                "CSR getSignatureAlgorithmOid() — SIGN_WITH_DIGEST_256");

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

        // Выпуск сертификата из CSR через fromCsrIdentity
        // fromCsrIdentity: проверяет PoP, копирует DN (байтово-точно) и publicKey
        // Расширения не копируются — УЦ явно решает, что переносить
        byte[] csrDnDer = csr.getSubjectDnDer();
        check(
                csrDnDer != null && csrDnDer.length > 0,
                "getSubjectDnDer() — байтово-точный DER subject DN из CSR");
        check(
                csr.getSubjectDn().contains("CN=demo.example.com"),
                "getSubjectDn() возвращает исходный DN");

        // fromCsrIdentity с авто-проверкой PoP (бросает PkixException при провале)
        GostCertificateBuilder csrCertBuilder =
                GostCertificateBuilder.fromCsrIdentity(csr, caPubKey.getParams());
        // УЦ задаёт issuer-поля, срок и подписывает
        GostCertificate csrIssuedCert =
                csrCertBuilder
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBefore("20250101000000Z")
                        .notAfter("20260101000000Z")
                        .randomSerial()
                        .sign(GostSigner.of(caKey));
        check(csrIssuedCert != null, "Сертификат из CSR выпущен через fromCsrIdentity");
        check(
                csrIssuedCert.getSubjectDn().equals(csr.getSubjectDn()),
                "Subject DN сертификата совпадает с DN из CSR");
        check(
                Arrays.equals(
                        GostDerCodec.subjectPublicKeyPointBytes(csr.getPublicKey()),
                        GostDerCodec.subjectPublicKeyPointBytes(csrIssuedCert.getPublicKey())),
                "Публичный ключ сертификата из CSR корректен");

        System.out.println("  OK: CSR — построение, разбор и проверка успешны");
    }

    // ========================================================================
    // §5 Цепочки сертификатов — ChainValidator
    // ========================================================================

    private static void section5_chainValidator() throws Exception {
        section("§5 ChainValidator: валидация цепочки CA->leaf");

        List<GostCertificate> chain = List.of(leafCert, caCert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(caCert);

        ChainValidator.validateChain(chain, anchors);
        check(true, "validateChain(leaf->CA) — цепочка валидна");

        // Цепочка без доверенного корня
        try {
            var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
            GostCertificate wrongRoot =
                    makeSelfSignedCert(
                            wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(1000));
            List<GostCertificate> leafOnly = List.of(leafCert);
            ChainValidator.validateChain(leafOnly, TrustAnchors.ofCertificate(wrongRoot));
            check(false, "Цепочка без доверенного издателя должна падать");
        } catch (PkixException e) {
            check(true, "Цепочка без доверенного корня корректно отвергнута: " + e.reason());
        }

        // Просроченный сертификат
        try {
            byte[] badTbs =
                    GostCertificateBuilder.create(PARAMS, "CN=Expired,O=DemoOrg,C=RU")
                            .publicKey(leafPubKey)
                            .randomSerial()
                            .notBefore("200101000000Z")
                            .notAfter("200201000000Z")
                            .issuerDn(caCert.getIssuerDnBytes())
                            .buildTbs();
            GostCertificate expiredCert = GostCertificateBuilder.sign(badTbs, GostSigner.of(caKey));
            ChainValidator.validateChain(List.of(expiredCert, caCert), anchors);
            check(false, "Просроченный сертификат должен вызывать ошибку");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.EXPIRED,
                    "Просроченный сертификат: reason = EXPIRED");
        }

        System.out.println("  OK: валидация цепочки сертификатов");
    }

    // ========================================================================
    // §5.1 ChainValidatorWithRevocation — цепочка + отзыв в одном вызове
    // ========================================================================

    private static void section5_1_chainValidatorWithRevocation() throws Exception {
        section("§5.1 ChainValidatorWithRevocation: цепочка + проверка отзыва");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();
        List<GostCertificate> chain = List.of(leafCert, caCert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(caCert);

        // Проверка отзыва через CRL: leaf не отозван
        byte[] crlDer =
                GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .sign(caKey);
        ChainValidator.validateChainWithRevocation(
                chain, anchors, Arrays.asList(new CertRevocationData(null, crlDer), null));
        check(true, "validateChainWithRevocation(CRL) — leaf не отозван, успешно");

        // Проверка отзыва через OCSP: leaf имеет статус good
        byte[] ocspGood =
                GostOcspResponseBuilder.create(serial)
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .good()
                        .sign(caKey);
        ChainValidator.validateChainWithRevocation(
                chain, anchors, Arrays.asList(new CertRevocationData(ocspGood, null), null));
        check(true, "validateChainWithRevocation(OCSP) — leaf good, успешно");

        // OCSP-приоритет: если есть и OCSP и CRL, OCSP проверяется первым
        ChainValidator.validateChainWithRevocation(
                chain, anchors, Arrays.asList(new CertRevocationData(ocspGood, crlDer), null));
        check(true, "validateChainWithRevocation(OCSP+CRL) — OCSP приоритет, успешно");

        System.out.println("  OK: валидация цепочки с проверкой отзыва");
    }

    // ========================================================================
    // §6 CRL
    // ========================================================================

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
                        .serial(new BigInteger(1, serial))
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(caKey));
    }

    private static void section6_crl() throws Exception {
        section("§6 CRL: построение списка отзыва и проверка");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();

        RevokedEntry entry =
                new RevokedEntry(serial, "260801120000Z", ReasonCode.KEY_COMPROMISE, null, null);

        // Построение CRL
        byte[] crlDer =
                GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .addRevoked(List.of(entry))
                        .sign(caKey);
        check(crlDer.length > 0, "CRL построен, размер " + crlDer.length + " байт");

        // Проверка: сертификат отозван
        try {
            CrlVerifier.verify(crlDer, certWithSerial(serial), caCert);
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
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .good()
                        .sign(caKey);
        check(ocspResp.length > 0, "OCSP-ответ построен, размер " + ocspResp.length + " байт");

        // Проверка
        OcspVerifier.verify(ocspResp, serial, caCert);
        check(true, "OcspVerifier.verify() — успешно");

        // byKey responder ID — хэш Streebog-256 от публичного ключа подписанта
        byte[] ocspByKey =
                GostOcspResponseBuilder.create(serial)
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .withResponderByKey()
                        .good()
                        .sign(caKey);
        check(
                ocspByKey.length > 0,
                "OCSP-ответ byKey построен, размер " + ocspByKey.length + " байт");

        GostOcspResponse parsedByKey = GostOcspResponse.fromDer(ocspByKey);
        check(
                parsedByKey.getResponderIdType() == GostOcspResponse.ResponderIdType.BY_KEY,
                "responderIdType = BY_KEY");
        check(
                parsedByKey.getResponderKeyHash().length == 32,
                "длина keyHash = 32 байта (Streebog-256)");

        OcspVerifier.verify(ocspByKey, serial, caCert);
        check(true, "OcspVerifier.verify() byKey — успешно");

        // Выпуск сертификата делегированного OCSP-респондера.
        // Такой сертификат короткоживущий и несёт id-pkix-ocsp-nocheck (RFC 6960
        // §4.2.2.2.1): проверяющая сторона не проверяет его отзыв рекурсивно, иначе
        // возникла бы циклическая зависимость (для проверки OCSP-ответа понадобился бы
        // ещё один OCSP-запрос про подписанта). Расширение допустимо только вместе с
        // EKU id-kp-OCSPSigning — иначе builder бросит IllegalStateException.
        var responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responderCert =
                GostCertificateBuilder.create(PARAMS, "CN=Delegated OCSP Responder,O=DemoOrg,C=RU")
                        .publicKey(responderKp.getPublic())
                        .randomSerial()
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)
                        .ocspNoCheck()
                        .sign(caKey);
        check(
                responderCert.isOcspSigning() && responderCert.hasOcspNoCheck(),
                "Делегированный responder-сертификат: EKU OCSPSigning + id-pkix-ocsp-nocheck");

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

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signed,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cmsCert),
                                SignerSelection.ANY,
                                Revocation.none()));
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
        VerifiedSignedData detResult =
                CmsSignedDataVerifier.verify(
                        detachedSigned,
                        VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(cmsCert),
                                        SignerSelection.ANY,
                                        Revocation.none())
                                .detached(detachedData));
        check(
                Arrays.equals(detachedData, detResult.data()),
                "Detached: возвращённый документ совпадает с исходным");

        // Дополнительные сертификаты в цепочке — добавляем CA
        byte[] chainSigned =
                CmsSignedDataBuilder.create()
                        .data(demoData)
                        .addSigner(cmsKey, cmsCert)
                        .addCertificate(caCert)
                        .build();
        VerifiedSignedData chainResult =
                CmsSignedDataVerifier.verify(
                        chainSigned,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cmsCert),
                                SignerSelection.ANY,
                                Revocation.none()));

        // Извлечение встроенных сертификатов через GostPkcs7 (обратная операция к addCertificate)
        List<GostCertificate> p7bCerts = GostPkcs7.extractCertificates(chainSigned);
        boolean caPresent =
                p7bCerts.stream()
                        .anyMatch(
                                c ->
                                        c.getSerialNumberBigInt()
                                                .equals(caCert.getSerialNumberBigInt()));
        check(
                !p7bCerts.isEmpty() && caPresent,
                "GostPkcs7.extractCertificates() — извлечено сертификатов: " + p7bCerts.size());

        // Формирование certs-only .p7b (обратная операция к extractCertificates)
        byte[] certsOnlyP7b = GostPkcs7.buildCertsOnly(cmsCert, caCert);
        List<GostCertificate> roundTrip = GostPkcs7.extractCertificates(certsOnlyP7b);
        check(
                roundTrip.size() == 2,
                "GostPkcs7.buildCertsOnly() — round-trip сертификатов: " + roundTrip.size());

        // Человекочитаемый дамп .p7b-контейнера (GostPkcs7.formatText) и одного
        // сертификата (CertificateTextFormatter.format) — структурный разбор без верификации.
        String p7bText = GostPkcs7.formatText(certsOnlyP7b);
        check(
                p7bText.contains("PKCS#7") && p7bText.contains("ВНИМАНИЕ"),
                "GostPkcs7.formatText() — человекочитаемый дамп с дисклеймером");
        System.out.println();
        System.out.println(CertificateTextFormatter.format(cmsCert));

        // Пользовательские signed-атрибуты
        byte[] attrSigned =
                CmsSignedDataBuilder.create()
                        .data(demoData)
                        .addSigner(cmsKey, cmsCert)
                        .addSignedAttribute(
                                GostOids.ATTR_SIGNING_TIME, DerCodec.encodeTime("260601120000Z"))
                        .build();
        VerifiedSignedData attrResult =
                CmsSignedDataVerifier.verify(
                        attrSigned,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cmsCert),
                                SignerSelection.ANY,
                                Revocation.none()));

        // Неверный сертификат — создаём чужой самоподписанный
        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                makeSelfSignedCert(
                        wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(999));
        try {
            CmsSignedDataVerifier.verify(
                    signed,
                    VerifyOptions.trusting(
                            TrustAnchors.ofCertificates(wrongCert),
                            SignerSelection.ANY,
                            Revocation.none()));
            check(false, "Верификация чужим сертификатом: ожидался PkixException");
        } catch (PkixException e) {
            check(true, "Верификация чужим сертификатом: провал (как и ожидалось)");
        }

        // Подмена данных
        byte[] tampered = Arrays.copyOf(signed, signed.length);
        tampered[signed.length / 2] ^= 0xFF;
        try {
            CmsSignedDataVerifier.verify(
                    tampered,
                    VerifyOptions.trusting(
                            TrustAnchors.ofCertificates(cmsCert),
                            SignerSelection.ANY,
                            Revocation.none()));
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
        section("§9 CMS EnvelopedData: шифрование и расшифровка файла (ktri, с имитовставкой)");

        // Шифрование
        byte[] enveloped =
                CmsEnvelopedDataBuilder.create().data(demoData).addRecipient(cmsCert).build();
        check(enveloped.length > 0, "EnvelopedData построен, размер " + enveloped.length + " байт");

        // Расшифрование
        byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert);
        check(
                Arrays.equals(demoData, decrypted),
                "Расшифрованные данные совпадают с оригиналом (" + decrypted.length + " байт)");

        // Неверный ключ
        try {
            byte[] badDecrypt = CmsEnvelopedDataDecryptor.decrypt(enveloped, caKey, caCert);
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

        System.out.println("  OK: CMS EnvelopedData (ktri) — шифрование и расшифровка");
    }

    // §9.1 CMS EnvelopedData OMAC — шифрование с имитовставкой (ТК26 §8.3.1)

    private static void section9_1_cmsEnvelopedDataOmac() throws Exception {
        section("§9.1 CMS EnvelopedData (ktri): имитовставка по умолчанию и режим без неё");

        // Шифрование с имитовставкой (Encrypt-then-MAC)
        byte[] enveloped =
                CmsEnvelopedDataBuilder.create().data(demoData).addRecipient(cmsCert).build();
        check(
                enveloped.length > 0,
                "EnvelopedData+OMAC построен, размер " + enveloped.length + " байт");

        // Расшифрование — MAC проверяется автоматически, прозрачно
        byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert);
        check(
                Arrays.equals(demoData, decrypted),
                "Расшифрованные данные OMAC совпадают с оригиналом");

        // Fail-closed: подмена данных → PkixException
        byte[] tampered = Arrays.copyOf(enveloped, enveloped.length);
        tampered[enveloped.length / 2] ^= 0xFF;
        try {
            CmsEnvelopedDataDecryptor.decrypt(tampered, cmsKey, cmsCert);
            check(false, "OMAC подмена: ожидался PkixException");
        } catch (PkixException e) {
            check(true, "OMAC подмена: fail-closed — MAC проверка отклонила поддельные данные");
        }

        // Режим без имитовставки — только явный выбор; строгий decrypt его не принимает
        byte[] plain =
                CmsEnvelopedDataBuilder.create()
                        .data(demoData)
                        .addRecipient(cmsCert)
                        .withoutIntegrity()
                        .build();
        try {
            CmsEnvelopedDataDecryptor.decrypt(plain, cmsKey, cmsCert);
            check(false, "Контейнер без OMAC: ожидался отказ");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.INTEGRITY_REQUIRED,
                    "Контейнер без OMAC: decrypt требует имитовставку (INTEGRITY_REQUIRED)");
        }
        check(
                Arrays.equals(
                        demoData,
                        CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                                plain, cmsKey, cmsCert)),
                "Контейнер без OMAC читается только через decryptAllowingNoIntegrity");

        System.out.println(
                "  OK: CMS EnvelopedData + OMAC — шифрование с имитовставкой и fail-closed");
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
        check(GostOids.PUBLIC_KEY_256.equals("1.2.643.7.1.1.1.1"), "PUBLIC_KEY_256");
        check(GostOids.SIGN_WITH_DIGEST_256.equals("1.2.643.7.1.1.3.2"), "SIGN_WITH_DIGEST_256");
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

    private static void section12_certificatePolicies() throws Exception {
        section("§12 Certificate Policies");

        // Демо-сертификат не содержит CertificatePolicies — getter возвращает null
        String[] policies = leafCert.getCertificatePolicies();
        check(policies == null, "getCertificatePolicies() — null (расширение отсутствует)");

        // validateChain без политик — работает как раньше
        List<GostCertificate> chain = List.of(leafCert, caCert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(caCert);
        ChainValidator.validateChain(chain, anchors);
        check(true, "validateChain без политик — валидно");

        // validateChain с требуемой политикой — POLICY_VIOLATION (leaf без CertificatePolicies)
        try {
            ChainValidator.validateChain(chain, anchors, GostOids.POLICY_KC1);
            check(false, "Ожидалась POLICY_VIOLATION");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.POLICY_VIOLATION,
                    "POLICY_VIOLATION: leaf без CertificatePolicies — reject");
        }

        // Строим сертификат с CertificatePolicies: POLICY_KC1
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=PolicyDemo");
        byte[] cp =
                GostCertificateBuilder.buildCertificatePoliciesExtension(
                        new String[] {GostOids.POLICY_KC1});
        byte[] additional =
                concatDemoExtensions(
                        GostCertificateBuilder.buildKeyUsageExtension(
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE),
                        GostCertificateBuilder.buildSkiExtension(kp.getPublic()),
                        GostCertificateBuilder.buildAkiExtension(caPubKey),
                        cp);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("policy.example.com")
                        .additionalExtensions(additional)
                        .issuerDn(caCert.getIssuerDnBytes())
                        .serial(BigInteger.valueOf(99))
                        .buildTbs();
        GostCertificate policyLeaf = GostCertificateBuilder.sign(tbs, GostSigner.of(caKey));

        // validateChain с KC1 — leaf содержит KC1, проверка проходит
        List<GostCertificate> chain2 = List.of(policyLeaf, caCert);
        ChainValidator.validateChain(chain2, anchors, GostOids.POLICY_KC1);
        check(true, "validateChain с KC1 — leaf содержит KC1, валидно");

        // validateChain с KC2 — leaf содержит KC1, а требуют KC2 — POLICY_VIOLATION
        try {
            ChainValidator.validateChain(chain2, anchors, GostOids.POLICY_KC2);
            check(false, "Ожидалась POLICY_VIOLATION");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.POLICY_VIOLATION,
                    "POLICY_VIOLATION: leaf с KC1, required=KC2 — reject");
        }

        System.out.println("  OK: Certificate policies — политики сертификатов");

        // Новый fluent API: certificatePolicies(String...) — без квалификаторов
        byte[] tbs2 =
                GostCertificateBuilder.create(PARAMS, subjectDn)
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
        check(cpInfos != null && cpInfos.length == 2, "fluent API: 2 политики через getter");
        check(
                cpInfos[0].cpsUri() == null && cpInfos[1].cpsUri() == null,
                "fluent API: без CPS — cpsUri == null");

        // Новый fluent API: certificatePolicyInfos(CertificatePolicy...) — с CPS-квалификатором
        String cpsUri = "https://ca.example.com/cps/russian-ca.html";
        byte[] tbs3 =
                GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn("CN=CpsDemo"))
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
        check(cpsInfos != null && cpsInfos.length == 2, "certificatePolicyInfos: 2 политики");
        check(cpsUri.equals(cpsInfos[0].cpsUri()), "certificatePolicyInfos: CPS URI round-trip");
        check(cpsInfos[1].cpsUri() == null, "certificatePolicyInfos: вторая политика без CPS");

        // Валидация с политиками (только OID, CPS не влияет)
        List<GostCertificate> chain3 = List.of(cpsLeaf, caCert);
        ChainValidator.validateChain(chain3, anchors, GostOids.POLICY_KC1);
        check(true, "validateChain с KC1 через fluent API — валидно");

        System.out.println("  OK: Fluent-API certificatePolicies / certificatePolicyInfos");
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
                GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .addRevoked(List.of(e1, e2))
                        .sign(caKey);
        check(crlDer.length > 0, "CRL с 2 записями построен, размер " + crlDer.length + " байт");

        // Проверка первой записи
        try {
            CrlVerifier.verify(crlDer, certWithSerial(serial1), caCert);
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

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        detachedSigned,
                        VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(cmsCert),
                                        SignerSelection.ANY,
                                        Revocation.none())
                                .detached(demoData));
        check(
                Arrays.equals(demoData, result.data()),
                "Detached: возвращённый документ совпадает с исходным");

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

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signed,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cmsCert),
                                SignerSelection.ANY,
                                Revocation.none()));
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

        // Шифрование для двух получателей
        byte[] enveloped =
                CmsEnvelopedDataBuilder.create()
                        .data(demoData)
                        .addRecipient(cmsCert)
                        .addRecipient(bobCert)
                        .build();

        // Расшифровывает cmsKey
        byte[] cmsData = CmsEnvelopedDataDecryptor.decrypt(enveloped, cmsKey, cmsCert);
        check(Arrays.equals(demoData, cmsData), "cmsKey расшифровал успешно");

        // Bob расшифровывает
        byte[] bobData = CmsEnvelopedDataDecryptor.decrypt(enveloped, bobKp.getPrivate(), bobCert);
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
        VerifiedCAdESData result =
                CAdESVerifier.verifyBES(cadesBes, TrustAnchors.ofCertificates(cmsCert));
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
            CAdESVerifier.verifyBES(cadesBes, TrustAnchors.ofCertificates(wrongCert));
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
                GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .addRevoked(
                                new RevokedEntry(
                                        leafCert.getSerialNumber(),
                                        "260801120000Z",
                                        ReasonCode.KEY_COMPROMISE,
                                        null,
                                        null))
                        .sign(caKey);

        // Разбор через GostCrl.fromDer()
        GostCrl crl = GostCrl.fromDer(crlDer);
        check(crl != null, "GostCrl.fromDer — разобран");

        // Метаданные
        checkEq("CN=Demo Root CA, O=DemoOrg, C=RU", crl.getIssuerDn(), "DN эмитента CRL");
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
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .good()
                        .sign(caKey);

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
        byte[] reqDer =
                TspRequestBuilder.create()
                        .messageImprint(hash, GostOids.DIGEST_256)
                        .nonce(nonce)
                        .build();
        check(reqDer.length > 0, "TSP-запрос построен");

        // Сервер: разбираем запрос
        TspRequest request = TspRequest.fromDer(reqDer);
        check(
                request.messageImprintAlgOid().equals(GostOids.DIGEST_256),
                "Алгоритм дайджеста в запросе");
        check(request.nonce().equals(nonce), "Nonce в запросе");

        // Неподдерживаемый алгоритм — отклоняем с failInfo
        byte[] rejectionDer =
                TspResponseBuilder.buildRejected(
                        "Unsupported algorithm", GostOids.PKI_FAIL_BAD_ALG);
        check(rejectionDer.length > 0, "Ответ-отказ с failInfo построен");
        try {
            TspResponse.fromDer(rejectionDer);
            check(false, "Rejection должен бросать PkixException");
        } catch (PkixException e) {
            check(
                    e.getMessage().contains("rejection"),
                    "PkixException содержит 'rejection': " + e.getMessage());
        }

        // Успешный ответ: строим ответ с accuracy и ordering
        byte[] responseDer =
                TspResponseBuilder.create(request)
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

        System.out.println("  OK: TSP-сервер — round-trip запрос->ответ->верификация");
    }

    // ========================================================================
    // §26 Delta CRL
    // ========================================================================

    private static void section26_deltaCrl() throws Exception {
        section("§26 Delta CRL: базовый + delta CRL с merge-верификацией");

        byte[] serial1 = leafCert.getSerialNumber(); // отозван в base, удалён в delta
        byte[] serial2 = new BigInteger("999999999").toByteArray(); // отозван в base, не в delta

        // 1. Базовый CRL: два отозванных сертификата + cRLNumber
        byte[] baseCrl =
                GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .withCrlNumber(1)
                        .withFreshestCrl("http://ca.example/delta.crl")
                        .withAki(caSki)
                        .nextUpdate("270801120000Z")
                        .addRevoked(
                                List.of(
                                        new RevokedEntry(
                                                serial1,
                                                "260801120000Z",
                                                ReasonCode.KEY_COMPROMISE,
                                                null,
                                                null),
                                        new RevokedEntry(
                                                serial2,
                                                "260801120000Z",
                                                ReasonCode.CERTIFICATE_HOLD,
                                                null,
                                                null)))
                        .sign(caKey);
        check(baseCrl.length > 0, "Base CRL построен, cRLNumber=1");

        // 2. Delta CRL: serial1 удалён (REMOVE_FROM_CRL)
        byte[] deltaCrl =
                GostCrlBuilder.create("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .nextUpdate("270801120000Z")
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .addRevoked(
                                List.of(
                                        new RevokedEntry(
                                                serial1,
                                                "260901120000Z",
                                                ReasonCode.REMOVE_FROM_CRL,
                                                null,
                                                null)))
                        .sign(caKey);
        check(deltaCrl.length > 0, "Delta CRL построен, ссылается на base cRLNumber=1");

        // 3. GostCrl: чтение метаданных (cRLNumber доступен без verify)
        GostCrl base = GostCrl.fromDer(baseCrl);
        base.verify(caPubKey);
        check(base.getCrlNumber().equals(BigInteger.valueOf(1)), "Base CRL: getCrlNumber() = 1");

        // FreshestCRL — чтение URI для delta CRL (RFC 5280 §5.2.6)
        check(base.isFreshestCrl(), "Base CRL: isFreshestCrl() = true");
        checkEq(
                "http://ca.example/delta.crl",
                base.getFreshestCrlUris()[0],
                "Base CRL: getFreshestCrlUris()[0]");

        // AuthorityKeyIdentifier (2.5.29.35) — keyIdentifier подписанта CRL
        byte[] akiFromCrl = base.getAuthorityKeyIdentifier();
        check(akiFromCrl != null, "Base CRL: getAuthorityKeyIdentifier() не null");
        check(
                java.util.Arrays.equals(caSki, akiFromCrl),
                "Base CRL: getAuthorityKeyIdentifier() совпадает с SKI CA");

        // FreshestCRL в сертификате — fluent-сеттер + read-path (RFC 5280 §5.2.6)
        byte[] fcCertTbs =
                GostCertificateBuilder.create(PARAMS, "CN=FreshestCRL Cert,O=DemoOrg,C=RU")
                        .publicKey(caPubKey)
                        .notBefore("250601000000Z")
                        .notAfter("270601000000Z")
                        .serial(BigInteger.valueOf(999))
                        .freshestCrl("http://ca.example/delta.crl")
                        .buildTbs();
        GostCertificate fcCert = GostCertificateBuilder.sign(fcCertTbs, GostSigner.of(caKey));
        check(fcCert.getFreshestCrlUris() != null, "Сертификат: getFreshestCrlUris() не null");
        checkEq(
                "http://ca.example/delta.crl",
                fcCert.getFreshestCrlUris()[0],
                "Сертификат: getFreshestCrlUris()[0] = ожидаемый URI");

        // Delta CRL: изолированная верификация — rejected
        try {
            new GostCrl(deltaCrl).verify(caPubKey);
            check(false, "Delta CRL должен быть rejected");
        } catch (PkixException e) {
            check(
                    e.getMessage().contains("delta CRL not supported"),
                    "Delta CRL rejected при изолированной верификации");
        }

        // 4. Merge-верификация: serial1 удалён -> не отозван
        CrlVerifier.verify(baseCrl, deltaCrl, certWithSerial(serial1), caCert);
        System.out.println("  serial1 прошёл — удалён из CRL через REMOVE_FROM_CRL");

        // 5. serial2 остался только в base -> отозван
        try {
            CrlVerifier.verify(baseCrl, deltaCrl, certWithSerial(serial2), caCert);
            check(false, "serial2 должен быть отозван");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.REVOKED,
                    "serial2 отозван в base CRL, delta не удаляла");
        }

        // 6. Base CRL: getReason читает причину из entry extensions
        check(
                base.getReason(serial1) == ReasonCode.KEY_COMPROMISE,
                "getReason(serial1) = KEY_COMPROMISE");
        check(base.getRevokedCertificates().size() == 2, "Base CRL: две записи в revoked-списке");

        System.out.println("  OK: Delta CRL — base+delta merge");
    }

    // ========================================================================
    // §27 CMS SignedData — встраивание CRL в подпись (addCrl)
    // ========================================================================

    private static void section27_cmsSignedDataWithCrl() throws Exception {
        section("§27 CMS SignedData: встраивание CRL в подпись (addCrl)");

        byte[] data = "Документ со встроенным CRL".getBytes(StandardCharsets.UTF_8);

        // Строим CRL, отзывающий cmsCert
        GostCrl crl =
                GostCrl.fromDer(
                        GostCrlBuilder.create(cmsCert.getIssuerDnBytes())
                                .withCrlNumber(1)
                                .nextUpdate("270801120000Z")
                                .addRevoked(cmsCert.getSerialNumber(), "260801120000Z")
                                .sign(cmsKey));

        // CMS SignedData со встроенным CRL
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(cmsKey, cmsCert)
                        .addCrl(crl)
                        .build();
        check(signedData.length > 0, "SignedData с CRL построен");

        // Верификация без проверки отзыва — CRL доступен в результате
        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cmsCert),
                                SignerSelection.ANY,
                                Revocation.none()));
        check(Arrays.equals(data, result.data()), "Данные совпадают");
        check(!result.embeddedCrls().isEmpty(), "embeddedCrls доступны в результате");
        checkEq(
                crl.getIssuerDn(),
                result.embeddedCrls().get(0).getIssuerDn(),
                "CRL issuer DN после round-trip совпадает");

        System.out.println("  OK: CMS SignedData со встроенным CRL");
    }

    // ========================================================================
    // §28 Автоматическая проверка отзыва в CMS SignedData
    // ========================================================================

    private static void section28_cmsSignedDataRevocationCheck() throws Exception {
        section("§28 CMS SignedData: автоматическая проверка отзыва");

        byte[] data = "Документ с проверкой отзыва".getBytes(StandardCharsets.UTF_8);

        // 1. Чистый CRL (leaf NOT отозван) — верификация с проверкой отзыва
        //    trust anchor не проверяется на отзыв по design (javadoc validateRevocation),
        //    поэтому используем CA+leaf цепочку, а не самоподписанный cmsCert.
        GostCrl cleanCrl =
                GostCrl.fromDer(
                        GostCrlBuilder.create(caCert.getSubjectDnBytes())
                                .withCrlNumber(2)
                                .nextUpdate("270801120000Z")
                                .sign(caKey));

        byte[] cleanSigned =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(leafKey, leafCert)
                        .addCertificate(caCert)
                        .addCrl(cleanCrl)
                        .build();

        VerifiedSignedData cleanResult =
                CmsSignedDataVerifier.verify(
                        cleanSigned,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(caCert),
                                SignerSelection.ANY,
                                Revocation.required(List.of())));
        check(
                Arrays.equals(data, cleanResult.data()),
                "Сертификат не в CRL — верификация прошла с проверкой отзыва");

        // 2. CRL с отозванным leafCert — автоматическая проверка отклоняет
        GostCrl revokingCrl =
                GostCrl.fromDer(
                        GostCrlBuilder.create(caCert.getSubjectDnBytes())
                                .withCrlNumber(3)
                                .nextUpdate("270801120000Z")
                                .addRevoked(leafCert.getSerialNumber(), "260801120000Z")
                                .sign(caKey));

        byte[] revokedSigned =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(leafKey, leafCert)
                        .addCertificate(caCert)
                        .addCrl(revokingCrl)
                        .build();

        try {
            CmsSignedDataVerifier.verify(
                    revokedSigned,
                    VerifyOptions.trusting(
                            TrustAnchors.ofCertificates(caCert),
                            SignerSelection.ANY,
                            Revocation.required(List.of())));
            check(false, "Отозванный сертификат должен быть отклонён");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.REVOKED,
                    "Revocation.required отклонил отозванный: " + e.reason());
        }

        // 3. Внешний CRL — передаётся параметром
        byte[] externalData = "Внешний CRL".getBytes(StandardCharsets.UTF_8);
        byte[] noCrlSigned =
                CmsSignedDataBuilder.create()
                        .data(externalData)
                        .addSigner(leafKey, leafCert)
                        .addCertificate(caCert)
                        .build();

        try {
            CmsSignedDataVerifier.verify(
                    noCrlSigned,
                    VerifyOptions.trusting(
                            TrustAnchors.ofCertificates(caCert),
                            SignerSelection.ANY,
                            Revocation.required(List.of(revokingCrl))));
            check(false, "Внешний CRL с отозванным сертификатом должен отклонить");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.REVOKED,
                    "Внешний CRL отклонил отозванный: " + e.reason());
        }

        System.out.println("  OK: Автоматическая проверка отзыва");
    }

    // ========================================================================
    // §29 Делегированный CRL-подписант
    // ========================================================================

    private static void section29_delegatedCrlSigner() throws Exception {
        section("§29 Делегированный CRL-подписант (RFC 5280 §6.3.3)");

        byte[] serial = leafCert.getSerialNumberBigInt().toByteArray();
        byte[] signerCertDer = crlSignerCert.getEncoded();

        // CRL без отзыва — подписан делегированным ключом
        byte[] crlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .withCrlNumber(10)
                        .nextUpdate("270801120000Z")
                        .sign(crlSignerKey);
        check(crlDer.length > 0, "CRL подписан делегированным ключом, размер " + crlDer.length);

        // Проверка 1: ключ CA (fast path) — не подходит, SIGNATURE_INVALID
        try {
            CrlVerifier.verify(crlDer, certWithSerial(serial), caCert);
            check(false, "CA-ключ не должен верифицировать делегированный CRL");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.SIGNATURE_INVALID,
                    "CA-ключ не верифицирует — SIGNATURE_INVALID, fallback к подписанту");
        }

        // Проверка 2: verifyDelegated — делегированный подписант принимается
        CrlVerifier.verifyDelegated(crlDer, certWithSerial(serial), caCert, List.of(signerCertDer));
        check(true, "verifyDelegated принял CRL от делегированного подписанта");

        // Проверка 3: отзыв через делегированный CRL детектится корректно
        byte[] revokedCrlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .withCrlNumber(11)
                        .nextUpdate("270801120000Z")
                        .addRevoked(serial, "260801120000Z")
                        .sign(crlSignerKey);
        try {
            CrlVerifier.verifyDelegated(
                    revokedCrlDer, certWithSerial(serial), caCert, List.of(signerCertDer));
            check(false, "Отозванный сертификат должен быть отклонён verifyDelegated");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.REVOKED,
                    "verifyDelegated отклонил отозванный через делегированный CRL: " + e.reason());
        }

        // isCrlSigner() — проверка KeyUsage
        check(crlSignerCert.isCrlSigner(), "Сертификат подписанта: isCrlSigner() = true");
        check(!leafCert.isCrlSigner(), "Сертификат leaf без CRL_SIGN: isCrlSigner() = false");

        // Негативный: CRL подписан ключом leaf (без cRLSign) — должен быть rejected
        byte[] badCrl =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .withCrlNumber(12)
                        .nextUpdate("270801120000Z")
                        .sign(leafKey);
        try {
            CrlVerifier.verifyDelegated(
                    badCrl, certWithSerial(serial), caCert, List.of(signerCertDer));
            check(false, "CRL подписанный leaf-ключом не должен приниматься");
        } catch (PkixException e) {
            check(
                    e.reason() == PkixException.Reason.SIGNATURE_INVALID,
                    "CRL от leaf-ключа (без cRLSign): SIGNATURE_INVALID");
        }

        // IDP: onlyContainsUserCerts
        byte[] idpCrl =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .withCrlNumber(13)
                        .nextUpdate("270801120000Z")
                        .withIdpExtension(true, false)
                        .sign(caKey);
        GostCrl parsedIdp = GostCrl.fromDer(idpCrl);
        parsedIdp.verify(caPubKey);
        check(parsedIdp.isIdp(), "IDP присутствует");
        check(parsedIdp.isOnlyContainsUserCerts(), "onlyContainsUserCerts=true");
        check(!parsedIdp.isOnlyContainsCACerts(), "onlyContainsCACerts=false");
        check(!parsedIdp.isIndirectCrl(), "indirectCRL=false");

        System.out.println("  OK: Делегированный CRL-подписант");
    }

    // ========================================================================
    // §30 Countersignature — контрподпись (RFC 5652 §11.4)
    // ========================================================================

    private static void section30_countersignature() throws Exception {
        section("§30 Countersignature: контрподпись (RFC 5652 §11.4)");

        byte[] data = "Документ для countersignature".getBytes(StandardCharsets.UTF_8);

        // Генерируем ключ и сертификат countersigner'а (нотариуса)
        var csKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate csCert =
                makeSelfSignedCert(csKp.getPrivate(), csKp.getPublic(), BigInteger.valueOf(77));

        // Создаём CAdES-BES подпись
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(cmsKey, cmsCert)
                        .withCAdES()
                        .build();
        check(cadesBes.length > 0, "CAdES-BES подпись создана");

        // Встраиваем countersignature — получаем countersigned signature
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp.getPrivate(), csCert);
        check(countersigned.length > 0, "Countersignature создана");

        // Верифицируем countersignature — trusted: подписант + countersigner
        VerifiedCAdESData result =
                CAdESVerifier.verifyCountersignature(
                        countersigned, TrustAnchors.ofCertificates(cmsCert, csCert));
        check(Arrays.equals(data, result.data()), "Данные countersignature совпадают");
        check(result.signers().size() == 1, "Один подписант");
        check(
                result.signers().get(0).countersignatures().size() == 1,
                "Одна countersignature у подписанта");
        check(
                result.signers().get(0).countersignatures().get(0).signedAttributes().size() >= 1,
                "Countersignature содержит signed-атрибуты");

        // Countersignature без timestamp тоже валиден (CAdES-BES + CS)
        check(
                result.signers().get(0).timestamps().isEmpty(),
                "Без TSP меток — timestamps пуст (countersignature на BES)");

        // Невалидная countersignature: проверяем с чужим trusted-сертификатом
        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                makeSelfSignedCert(
                        wrongKp.getPrivate(), wrongKp.getPublic(), BigInteger.valueOf(707));
        try {
            CAdESVerifier.verifyCountersignature(
                    countersigned, TrustAnchors.ofCertificates(wrongCert, csCert));
            check(false, "Countersignature: чужой сертификат подписанта должен давать ошибку");
        } catch (PkixException e) {
            check(true, "Countersignature: чужая верификация подписанта отвергнута: " + e.reason());
        }

        // Countersigner не в trusted — chain не построится
        try {
            CAdESVerifier.verifyCountersignature(
                    countersigned, TrustAnchors.ofCertificates(cmsCert));
            check(false, "Countersignature: countersigner не в trusted должна быть ошибка");
        } catch (PkixException e) {
            check(true, "Countersignature: countersigner не в trusted отвергнут: " + e.reason());
        }

        System.out.println("  OK: Countersignature — контрподпись создана и проверена");
    }

    // ========================================================================
    // §31 Абстракция подписанта — GostSigner (HSM/PKCS#11)
    // ========================================================================

    private static void section31_gostSigner() throws Exception {
        section("§31 GostSigner: подпись через абстракцию (HSM-совместимость)");

        byte[] subjectDn = GostDnParser.encodeDn("CN=Signer Demo,O=DemoOrg,C=RU");
        String caDn = "CN=Demo Root CA,O=DemoOrg,C=RU";
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(caPubKey)
                        .randomSerial()
                        .notBefore("20240101000000Z")
                        .notAfter("21060101000000Z")
                        .issuerDn(caDn)
                        .buildTbs();

        // Дефолтный подписант поверх ключа в памяти — тонкий мост для не-HSM сценариев.
        GostSigner memSigner = GostSigner.of(caKey);
        GostCertificate certViaMem = GostCertificateBuilder.sign(tbs, memSigner);
        check(
                certViaMem.verifySignature(caPubKey),
                "cert через GostSigner.of(priv) верифицируется");

        // Нонс по умолчанию гибридный: подпись одного TBS каждый раз разная, поэтому побайтовое
        // совпадение проверяем в детерминированном режиме - это и есть контракт воспроизводимости.
        GostCertificate certViaDet1 =
                GostCertificateBuilder.sign(tbs, GostSigner.of(caKey, NonceMode.DETERMINISTIC));
        GostCertificate certViaDet2 =
                GostCertificateBuilder.sign(tbs, GostSigner.of(caKey, NonceMode.DETERMINISTIC));
        check(
                Arrays.equals(certViaDet1.getEncoded(), certViaDet2.getEncoded()),
                "Детерминированный нонс: подпись одного TBS воспроизводится байт-в-байт");

        // Кастомный подписант, эмулирующий внешний модуль (HSM/PKCS#11): закрытый ключ
        // не передаётся билдеру напрямую — билдер отдаёт хэш и получает готовую подпись.
        GostSigner hsm = new DemoHsmSigner(caKey);
        GostCertificate certViaHsm = GostCertificateBuilder.sign(tbs, hsm);
        check(certViaHsm.verifySignature(caPubKey), "cert через внешний подписант верифицируется");

        // CSR и CRL — тот же паттерн.
        byte[] csrDer = GostCsrBuilder.create("CN=Signer Demo", caPubKey).sign(hsm);
        check(
                GostCsrParser.fromDer(csrDer).verify(caPubKey),
                "CSR через внешний подписант валиден");

        byte[] crlDer = GostCrlBuilder.create(caDn).nextUpdate("20990101000000Z").sign(hsm);
        new GostCrl(crlDer).verify(caPubKey);
        check(true, "CRL через внешний подписант верифицируется");

        // CMS SignedData через GostSigner — HSM/PKCS#11: закрытый ключ не покидает
        // аппаратный модуль, билдер отдаёт хэш и получает готовую подпись
        byte[] cmsPayload = "Hello GostSigner CMS".getBytes(StandardCharsets.UTF_8);
        GostSigner cmsHsm = new DemoHsmSigner(cmsKey);
        byte[] cmsViaHsm =
                CmsSignedDataBuilder.create().data(cmsPayload).addSigner(cmsHsm, cmsCert).build();
        VerifiedSignedData vsd =
                CmsSignedDataVerifier.verify(
                        cmsViaHsm,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cmsCert),
                                SignerSelection.ANY,
                                Revocation.none()));
        check(
                Arrays.equals(vsd.data(), cmsPayload),
                "CMS SignedData через GostSigner: данные восстановлены");

        // OCSP-ответ через GostSigner — тот же HSM-паттерн: signer(hsm) вместо
        // signer(privKey, pubKey), закрытый ключ не попадает в кучу JVM
        byte[] caSerial = caCert.getSerialNumberBigInt().toByteArray();
        byte[] ocspViaHsm =
                GostOcspResponseBuilder.create(caSerial)
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .producedAt("20250101000000Z")
                        .thisUpdate("20250101000000Z")
                        .good()
                        .sign(hsm);
        OcspVerifier.verify(ocspViaHsm, caSerial, caCert);
        check(true, "OCSP-ответ через GostSigner: верификация прошла");

        // Fail-closed: неисправный подписант, вернувший подпись не тем ключом — self-verify ловит.
        var otherKp = KeyGenerator.generateKeyPair(PARAMS);
        GostSigner faulty = new MismatchedHsmSigner(caPubKey, otherKp.getPrivate());
        try {
            GostCertificateBuilder.sign(tbs, faulty);
            check(false, "неисправный подписант должен приводить к исключению");
        } catch (IllegalStateException e) {
            check(true, "self-verify отверг подпись не тем ключом: " + e.getMessage());
        }

        System.out.println("  OK: GostSigner — абстракция подписи и fail-closed проверки");
    }

    // ========================================================================
    // §32 Перевыпуск сертификата — fromCertificate + getExtensions (renewal)
    // ========================================================================

    private static void section32_certRenewal() throws Exception {
        section("§32 Перевыпуск сертификата: fromCertificate + getExtensions");

        // Сертификат, который мы будем перевыпускать
        byte[] subjectDn = GostDnParser.encodeDn("CN=Renewal Demo,O=DemoOrg,C=RU");
        GostCertificate original =
                GostCertificateBuilder.create(PARAMS, subjectDn)
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

        // Identity-мост: DN и ключ из старого сертификата
        GostCertificateBuilder renewedBuilder =
                GostCertificateBuilder.fromCertificate(original, PARAMS);
        check(renewedBuilder != null, "fromCertificate вернул не-null билдер");

        // Оператор явно читает расширения и решает, что переносить
        GostExtensionParser.ExtensionsResult ext = original.getExtensions();
        check(original.hasExtensions(), "оригинал содержит расширения");

        if (ext.sanDnsNames != null && ext.sanDnsNames.length > 0) {
            renewedBuilder.sanDns(ext.sanDnsNames); // владение доменом перепроверено
        }
        if (ext.keyUsageBits != 0) {
            // Переносим KeyUsage: проверяем каждый бит осознанно.
            // keyUsage — сеттер (ExtensionsAccumulator, строка 80), поэтому все биты
            // передаются одним вызовом, иначе второй вызов затрёт первый.
            renewedBuilder.keyUsage(
                    GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE,
                    GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT);
        }
        if (ext.isCA) {
            renewedBuilder.basicConstraints(true, ext.pathLen);
        }
        // И так далее для каждого типа расширения — осознанное решение оператора

        // Новые сроки и серийник, issuer тот же
        GostCertificate renewed =
                renewedBuilder
                        .issuerDn("CN=Demo Root CA,O=DemoOrg,C=RU")
                        .notBeforeNow()
                        .validForDays(365)
                        .randomSerial()
                        .sign(GostSigner.of(caKey));

        check(
                renewed.getSubjectDn().equals(original.getSubjectDn()),
                "Subject DN перевыпущенного сертификата совпадает с оригиналом");
        check(
                Arrays.equals(
                        GostDerCodec.subjectPublicKeyPointBytes(renewed.getPublicKey()),
                        GostDerCodec.subjectPublicKeyPointBytes(original.getPublicKey())),
                "Публичный ключ перевыпущенного сертификата совпадает с оригиналом");
        check(
                !renewed.getSerialNumberBigInt().equals(original.getSerialNumberBigInt()),
                "Серийный номер новый, не совпадает с оригиналом");
        check(
                renewed.getNotAfter().isAfter(original.getNotAfter()),
                "Новый срок действия за пределами старого");

        // Проверяем, что расширения перенесены корректно
        String[] renewedSan = renewed.getSanDnsNames();
        check(
                renewedSan != null
                        && renewedSan.length == 1
                        && "demo.example.com".equals(renewedSan[0]),
                "SAN dNSName перенесён при перевыпуске");

        boolean renewedHasDs =
                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE.isSetIn(
                        renewed.getExtensions().keyUsageBits);
        check(renewedHasDs, "KeyUsage DIGITAL_SIGNATURE перенесён при перевыпуске");

        System.out.println("  OK: перевыпуск сертификата через fromCertificate + getExtensions");
    }

    /**
     * Демонстрационный подписант, эмулирующий внешний модуль (HSM). В реальном коде
     * signHash() вызывал бы PKCS#11/внешний CSP, не извлекая закрытый ключ в память JVM.
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
     * Неисправный подписант: заявляет один открытый ключ, а подписывает другим —
     * имитация неверно сконфигурированного слота HSM. Ловится self-verify билдера.
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

    // ========================================================================
    // §33 CAdES-C — Complete validation data references
    // ========================================================================

    private static void section33_cadesC() throws Exception {
        section("§33 CAdES-C: Complete validation data references (RFC 5126 §6.2)");

        byte[] data = "Документ для CAdES-C".getBytes(StandardCharsets.UTF_8);

        // Строим CAdES-BES — используем CA+leaf цепочку для совместимости с verifyC
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(leafKey, leafCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();
        check(cadesBes.length > 0, "CAdES-BES подпись создана");

        // CAdES-C строится на CAdES-T: добавляем метку через локальный TSP.
        // Один cadesT на все варианты, чтобы побайтовое сравнение C-перегрузок
        // не зависело от разных nonce/serial меток.
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
        check(cadesT.length > cadesBes.length, "CAdES-T больше BES (добавлена метка)");

        // Строим CRL для сертификата подписанта
        byte[] crlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(caKey);
        GostCrl signerCrl = new GostCrl(crlDer);
        check(signerCrl != null, "CRL создан");

        // Расширяем до CAdES-C — добавляем ссылки на сертификаты и отзыв
        List<GostCertificate> chain = List.of(leafCert, caCert);
        List<GostCrl> crlsForChain = Arrays.asList(signerCrl, null);
        List<GostOcspResponse> ocspForChain = Arrays.asList(null, null);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crlsForChain, ocspForChain);
        check(cadesC.length > 0, "CAdES-C подпись создана");
        check(cadesC.length > cadesT.length, "CAdES-C больше T (добавлены C-атрибуты)");

        // Convenience-перегрузка через CertRevocationData
        List<CertRevocationData> revData =
                Arrays.asList(new CertRevocationData(null, crlDer), null);
        byte[] cadesCFromCRD = CAdESExtender.embedCompleteRefs(cadesT, chain, revData);
        check(
                java.util.Arrays.equals(cadesC, cadesCFromCRD),
                "CertRevocationData-перегрузка даёт идентичный результат");

        // Верификация CAdES-C
        VerifiedCAdESData result =
                CAdESVerifier.verifyC(cadesC, TrustAnchors.ofCertificates(caCert, tsaCert));
        check(result.signers().size() == 1, "CAdES-C: один подписант");
        // Для цепочки [leaf, root] из двух элементов нет intermediate CA,
        // поэтому completeCertificateRefs пуст по спецификации CAdES-C RFC 5126 §6.2
        check(
                result.signers().get(0).completeCertRefs() != null,
                "CAdES-C: completeCertificateRefs не null");
        check(
                !result.signers().get(0).completeRevocRefs().isEmpty(),
                "CAdES-C: completeRevocationRefs заполнены");

        // CAdES-T без C-атрибутов — верификация должна провалиться
        try {
            CAdESVerifier.verifyC(cadesT, TrustAnchors.ofCertificates(caCert, tsaCert));
            check(false, "CAdES-T без C-атрибутов должен падать");
        } catch (PkixException e) {
            check(true, "CAdES-T без C-атрибутов отвергнут: " + e.reason());
        }

        // Revoked сертификат всё равно проходит CAdES-C (отзыв проверяется в X-Long)
        byte[] revokingCrlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(2)
                        .addRevoked(
                                leafCert.getSerialNumberBigInt(),
                                GostSignatureHelper.nowGeneralizedTime())
                        .sign(caKey);
        GostCrl revokingCrl = new GostCrl(revokingCrlDer);

        List<GostCrl> revokingCrlsForChain = Arrays.asList(revokingCrl, null);
        byte[] cadesCRevoked =
                CAdESExtender.embedCompleteRefs(
                        cadesT, chain, revokingCrlsForChain, Arrays.asList(null, null));
        VerifiedCAdESData revokedResult =
                CAdESVerifier.verifyC(cadesCRevoked, TrustAnchors.ofCertificates(caCert, tsaCert));
        check(
                revokedResult.signers().size() == 1,
                "CAdES-C с отозванным сертификатом — верификация прошла (так и задумано)");

        System.out.println("  OK: CAdES-C — создание и верификация");
    }

    // §34 CAdES-X Long Type 1 — долгосрочная подпись с проверкой отзыва

    private static void section34_cadesXLongType1() throws Exception {
        section("§34 CAdES-X Long Type 1: построение и верификация (RFC 5126 §6.3)");

        byte[] data = "Документ для CAdES-X Long Type 1".getBytes(StandardCharsets.UTF_8);

        // 1. Строим CAdES-BES — используем CA+leaf цепочку для совместимости с verifyXLong
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(leafKey, leafCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();
        check(cadesBes.length > 0, "CAdES-BES подпись создана");

        // 2. Добавляем метку времени (CAdES-BES -> CAdES-T) через локальный TSP.
        //    addTimestamp внутри строит messageImprint = hash(signatureValue).
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
        check(cadesT.length > cadesBes.length, "CAdES-T больше BES (добавлена метка)");

        // 3. Строим цепочку и данные отзыва
        List<GostCertificate> chain =
                CertChainBuilder.buildChain(leafCert, List.of(caCert), List.of(caCert));
        byte[] crlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(caKey);
        GostCrl crl = new GostCrl(crlDer);

        // 4. Строим CAdES-X Long Type 1; TSP нужен для escTimeStamp
        //    crlsForChain параллелен chain: [signerCrl, caCrl] — без корневого CRL
        List<GostCrl> crlsForChain = Arrays.asList(crl, null);
        List<GostOcspResponse> ocspForChain = Arrays.asList(null, null);
        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(
                        cadesT,
                        chain,
                        crlsForChain,
                        ocspForChain,
                        "local://tsa",
                        localTsp,
                        tsaCert);
        check(cadesXLong.length > cadesT.length, "CAdES-X Long больше CAdES-T");
        System.out.println("  Размер CAdES-X Long: " + cadesXLong.length + " байт");

        // 5. Верификация CAdES-X Long Type 1
        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(cadesXLong, TrustAnchors.ofCertificates(caCert, tsaCert));
        check(result.signers().size() == 1, "CAdES-X Long: один подписант");
        check(Arrays.equals(data, result.data()), "CAdES-X Long: данные совпадают");

        CAdESSignerResult sr = result.signers().get(0);
        check(!sr.certificateValues().isEmpty(), "CAdES-X Long: certificateValues заполнены");

        CAdESXLongData.RevocationValuesDecoded revocValues = sr.revocationValues();
        check(!revocValues.crls().isEmpty(), "CAdES-X Long: revocationValues.crls заполнены");
        check(revocValues.crls().get(0) != null, "CAdES-X Long: есть CRL для подписанта");

        // 6. Revoked сертификат → жёсткая ошибка (fail-closed)
        byte[] revokedCrlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(2)
                        .addRevoked(
                                leafCert.getSerialNumberBigInt(),
                                GostSignatureHelper.nowGeneralizedTime())
                        .sign(caKey);
        GostCrl revokedCrl = new GostCrl(revokedCrlDer);

        List<GostCrl> revokedCrlList = Arrays.asList(revokedCrl, null);
        try {
            CAdESExtender.embedXLongType1(
                    cadesT, chain, revokedCrlList, ocspForChain, "local://tsa", localTsp, tsaCert);
            check(false, "CAdES-X Long с отозванным сертификатом должен падать");
        } catch (PkixException e) {
            check(true, "CAdES-X Long: отозванный сертификат отвергнут: " + e.reason());
        }

        System.out.println("  OK: CAdES-X Long Type 1 — построение и верификация");
    }
}
