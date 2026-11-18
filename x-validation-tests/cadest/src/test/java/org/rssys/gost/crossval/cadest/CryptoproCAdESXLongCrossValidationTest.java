package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Семантическая кросс-валидация CAdES-X Long Type 1 с КриптоПро:
 * crypto-gost создаёт X-Long → cryptcp -verify проверяет (exit=0).
 *
 * <p>Два уровня:
 * <ul>
 *   <li><b>Ядро</b> — {@code cryptcp -verify -nochain}: базовая проверка
 *       CMS-подписи. X-Long обратно совместим с CMS SignedData —
 *       дополнительные unsigned-атрибуты не мешают базовой проверке подписи.</li>
 *   <li><b>CAdES opt-in</b> — {@code -xlongtype1} (если доступен):
 *       полная семантика CAdES-X Long Type 1 по КриптоПро (для КриптоПро CAdES API
 *       это флаг {@code CADES_X_LONG_TYPE_1 = 0x5D} по ETSI TS 101 733).</li>
 * </ul>
 */
@DisplayName("КриптоПРО: кросс-валидация CAdES-X Long Type 1")
class CryptoproCAdESXLongCrossValidationTest {

    private static CryptoproFixtureGenerator.Fixture leaf;
    private static PrivateKeyParameters leafKey;
    private static GostCertificate leafCert;
    private static CryptoproFixtureGenerator.Fixture ca;
    private static CryptoproFixtureGenerator.Fixture tsa;
    private static PrivateKeyParameters tsaKey;
    private static GostCertificate tsaCert;

    private static Path leafCertDer;
    private static boolean signerInstalled;
    private static Path crlFile;
    private static boolean crlInstalled;
    private static Path tsaCertDer;
    private static boolean tsaInstalled;

    /** Хранилища до прогона: после уборки сверяем с ними, чужое не должно измениться. */
    private static CryptoproFixtureCleanup.Snapshot storesBefore;

    /** Тестовый корень в uRoot на время прогона класса. */
    private static CryptoproRootTrust rootTrust = CryptoproRootTrust.disabled();

    /** Подпись, которую КриптоПро принял с корнем: после снятия корня её отвергают. */
    private static byte[] verifiedWithRoot;

    // RFC 3161 §2.4.2: serialNumber уникален для каждого штампа одного TSA.
    // Повтор serial у signature-time-stamp и escTimeStamp КриптоПро отвергает.
    private static final AtomicLong TSA_SERIAL = new AtomicLong(1);

    @BeforeAll
    static void setUp() throws Exception {
        if (CryptoProChecker.cryptcpAvailable()) {
            storesBefore = CryptoproFixtureCleanup.snapshot();
        }
        ca = CryptoproFixtureGenerator.buildCa();
        leaf = CryptoproFixtureGenerator.buildLeaf(ca);
        leafKey = leaf.key();
        leafCert = leaf.cert();
        tsa = CryptoproFixtureGenerator.buildTsa(ca);
        tsaKey = tsa.key();
        tsaCert = tsa.cert();

        if (CryptoProChecker.cryptcpAvailable()) {
            leafCertDer = Files.createTempFile("cp-xlong-leaf-", ".cer");
            CryptoProChecker.installCert(
                    leafCertDer.getParent(),
                    leafCert.getEncoded(),
                    leafCertDer.getFileName().toString());
            signerInstalled = true;
        }

        if (cadesTrustAvailable()) {
            rootTrust = CryptoproRootTrust.open(ca.cert());
        }
        if (rootTrust.isAvailable()) {
            crlFile = Files.createTempFile("cp-xlong-crl-", ".crl");
            Files.write(crlFile, CryptoproFixtureGenerator.buildCrl(ca));
            CryptoProChecker.installCrl(crlFile);
            crlInstalled = true;

            tsaCertDer = Files.createTempFile("cp-xlong-tsa-", ".cer");
            CryptoProChecker.installCert(
                    tsaCertDer.getParent(),
                    tsaCert.getEncoded(),
                    tsaCertDer.getFileName().toString());
            tsaInstalled = true;
        }
    }

    @AfterAll
    static void tearDown() throws Exception {
        List<String> problems = new ArrayList<>();
        try {
            // Корень снимаем первым: сразу проверяем, что доверие действительно снято
            rootTrust.close();
            if (verifiedWithRoot != null) {
                problems.addAll(
                        CryptoproRootTrust.chainFailsWithoutRoot(
                                CryptoproRootTrust.SIGNATURE_NOT_VALID,
                                verifiedWithRoot,
                                leafCertDer,
                                "-xlongtype1"));
            }
        } catch (Exception e) {
            problems.add("не удалось снять тестовый корень: " + e.getMessage());
        }
        problems.addAll(cleanPersonalStore());
        if (storesBefore != null) {
            problems.addAll(CryptoproFixtureCleanup.compareWith(storesBefore));
        }
        assertTrue(problems.isEmpty(), String.join("; ", problems));
    }

    /** Убирает свои сертификаты и CRL из uMy по keyid и возвращает нарушения (пусто - чисто). */
    private static List<String> cleanPersonalStore() throws IOException {
        List<byte[]> keyIds = new ArrayList<>();
        if (signerInstalled) {
            keyIds.add(leafCert.getSubjectKeyIdentifier());
            Files.deleteIfExists(leafCertDer);
        }
        if (tsaInstalled) {
            keyIds.add(tsaCert.getSubjectKeyIdentifier());
            Files.deleteIfExists(tsaCertDer);
        }
        if (crlInstalled) {
            Files.deleteIfExists(crlFile);
        }
        return CryptoproFixtureCleanup.remove(
                keyIds, crlInstalled ? ca.cert().getSubjectKeyIdentifier() : null);
    }

    // ========================================================================
    // Ядро: 2 теста — положительный и отрицательный (искажённая подпись)
    // ========================================================================

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-X Long Type 1 -> cryptcp -verify: подпись принята (exit=0)")
    void cadesXLongAcceptedCore() throws Exception {
        byte[] cadesXLong = buildCAdESXLongType1("cryptcp X-Long core".getBytes());

        TempDirUtils.withTempDir(
                "cp-xlong-core-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "xlong.p7s", cadesXLong);
                    Path outPath = dir.resolve("out.bin");
                    CryptoProChecker.Result r =
                            CryptoProChecker.runWithConfirm(
                                    CryptoProChecker.resolveCryptcpBinary(),
                                    "-verify",
                                    "-nochain",
                                    "-f",
                                    leafCertDer.toString(),
                                    signedPath.toString(),
                                    outPath.toString());

                    assertEquals(
                            0,
                            r.exitCode(),
                            "КриптоПро должен принять CAdES-X Long Type 1: " + r.output());
                    return null;
                });
    }

    // ========================================================================
    // CAdES opt-in: -xlongtype1 (если libcades доступна)
    // ========================================================================

    @Test
    @EnabledIf("cadesTrustAvailable")
    @DisplayName("CAdES-X Long Type 1 -> cryptcp -xlongtype1: принята")
    void cadesXLongAcceptedWithFlag() throws Exception {
        rootTrust.requireAvailable();
        byte[] cadesXLong = buildCAdESXLongType1("cryptcp X-Long cades".getBytes());

        TempDirUtils.withTempDir(
                "cp-xlong-flag-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "xlong-cades.p7s", cadesXLong);
                    Path outPath = dir.resolve("out.bin");
                    CryptoProChecker.Result r =
                            CryptoProChecker.runWithConfirm(
                                    CryptoProChecker.resolveCryptcpBinary(),
                                    "-verify",
                                    "-xlongtype1",
                                    "-f",
                                    leafCertDer.toString(),
                                    signedPath.toString(),
                                    outPath.toString());

                    assertEquals(
                            0,
                            r.exitCode(),
                            "КриптоПро должен принять CAdES-X Long Type 1 с флагом: " + r.output());
                    verifiedWithRoot = cadesXLong;
                    return null;
                });
    }

    private static byte[] buildCAdEST() throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES("cryptcp enhance".getBytes(), leafKey, leafCert);
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tspReq =
                org.rssys.gost.pkix.tsp.TspRequestBuilder.create()
                        .messageImprint(sigHash, hashOid)
                        .certReq(true)
                        .build();
        byte[] tspResp =
                org.rssys.gost.pkix.tsp.TspResponseBuilder.create(tspReq)
                        .signer(tsaKey, tsaCert)
                        .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                        .serialNumber(java.math.BigInteger.valueOf(TSA_SERIAL.getAndIncrement()))
                        .accuracy(1)
                        .withCAdES()
                        .buildGranted();
        byte[] tsToken = org.rssys.gost.pkix.tsp.TspResponse.fromDer(tspResp).timeStampTokenDer();
        return TestData.buildCAdEST(cadesBes, tsToken);
    }

    // ========================================================================
    // Построение CAdES-X Long Type 1
    // ========================================================================

    private static byte[] buildCAdESXLongType1(byte[] data) throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);

        byte[] tspReq =
                org.rssys.gost.pkix.tsp.TspRequestBuilder.create()
                        .messageImprint(sigHash, hashOid)
                        .certReq(true)
                        .build();
        byte[] tspResp =
                org.rssys.gost.pkix.tsp.TspResponseBuilder.create(tspReq)
                        .signer(tsaKey, tsaCert)
                        .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                        .serialNumber(java.math.BigInteger.valueOf(TSA_SERIAL.getAndIncrement()))
                        .accuracy(1)
                        .withCAdES()
                        .buildGranted();
        byte[] tsToken = org.rssys.gost.pkix.tsp.TspResponse.fromDer(tspResp).timeStampTokenDer();
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        // chain = [leaf, ca] (без корня — ca самоподписан, он же корень)
        List<GostCertificate> chain = Arrays.asList(leafCert, ca.cert());
        // КриптоПро в режиме -xlongtype1 принимает для подписанта только OCSP-ответ,
        // подписанный делегированным ответчиком с ocsp-nocheck (CRL для него не используется).
        GostOcspResponse leafOcsp =
                CryptoproFixtureGenerator.buildOcsp(
                        ca, CryptoproFixtureGenerator.buildOcspResponder(ca), leafCert);
        List<GostCrl> crls = Arrays.asList(null, null);
        List<GostOcspResponse> ocsp = Arrays.asList(leafOcsp, null);

        return CAdESExtender.embedXLongType1(
                cadesT, chain, crls, ocsp, "local://tsa", localTsp(), ca.cert());
    }

    private static org.rssys.gost.pkix.tsp.TspTransport localTsp() {
        return (req, url) -> {
            try {
                // escTimeStamp обязан быть позже signature-time-stamp (RFC 3161
                // §2.4.2/RFC 5126). Реальный TSA отвечает с разницей в секунды;
                // локальный отвечает мгновенно и попал бы в ту же секунду.
                Thread.sleep(1500);
                return org.rssys.gost.pkix.tsp.TspResponseBuilder.create(req)
                        .signer(tsaKey, tsaCert)
                        .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                        .serialNumber(java.math.BigInteger.valueOf(TSA_SERIAL.getAndIncrement()))
                        .accuracy(1)
                        .withCAdES()
                        .buildGranted();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    // ========================================================================
    // Условия запуска
    // ========================================================================

    static boolean cryptcpAvailable() {
        return CryptoProChecker.cryptcpAvailable();
    }

    static boolean cadesTrustAvailable() {
        return CryptoProChecker.cadesLibraryAvailable() && CryptoProChecker.trustRootEnabled();
    }
}
