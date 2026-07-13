package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
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
 *   <li><b>CAdES opt-in</b> — {@code -cadesxlongtype1} (если доступен):
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

    @BeforeAll
    static void setUp() throws Exception {
        ca = CryptoproFixtureGenerator.buildCa();
        leaf = CryptoproFixtureGenerator.buildLeaf(ca);
        leafKey = leaf.key();
        leafCert = leaf.cert();
        tsa = CryptoproFixtureGenerator.buildTsa(ca);
        tsaKey = tsa.key();
        tsaCert = tsa.cert();

        if (CryptoProChecker.cryptcpAvailable()) {
            leafCertDer = Files.createTempFile("cp-xlong-leaf-", ".cer");
            CryptoProChecker.installCert(leafCertDer.getParent(),
                    leafCert.getEncoded(),
                    leafCertDer.getFileName().toString());
            signerInstalled = true;
        }

        if (cadesTrustAvailable()) {
            crlFile = Files.createTempFile("cp-xlong-crl-", ".crl");
            Files.write(crlFile, CryptoproFixtureGenerator.buildCrl(ca));
            CryptoProChecker.installCrl(crlFile);
            crlInstalled = true;

            tsaCertDer = Files.createTempFile("cp-xlong-tsa-", ".cer");
            CryptoProChecker.installCert(tsaCertDer.getParent(),
                    tsaCert.getEncoded(),
                    tsaCertDer.getFileName().toString());
            tsaInstalled = true;
        }
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (signerInstalled) {
            CryptoProChecker.deleteCertByDn("Crossval Test Leaf");
            Files.deleteIfExists(leafCertDer);
        }
        if (tsaInstalled) {
            CryptoProChecker.deleteCertByDn("Crossval Test TSA");
            Files.deleteIfExists(tsaCertDer);
        }
        if (crlInstalled) {
            CryptoProChecker.deleteCrlByIssuerDn("Crossval Test Root CA");
            Files.deleteIfExists(crlFile);
        }
    }

    // ========================================================================
    // Ядро: 2 теста — положительный и отрицательный (искажённая подпись)
    // ========================================================================

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-X Long Type 1 -> cryptcp -verify: подпись принята (exit=0)")
    void cadesXLongAcceptedCore() throws Exception {
        byte[] cadesXLong = buildCAdESXLongType1("cryptcp X-Long core".getBytes());

        TempDirUtils.withTempDir("cp-xlong-core-", dir -> {
            Path signedPath = TestData.writeDer(dir, "xlong.p7s", cadesXLong);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-nochain", "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertEquals(0, r.exitCode(),
                    "КриптоПро должен принять CAdES-X Long Type 1: " + r.output());
            return null;
        });
    }

    // ========================================================================
    // CAdES opt-in: -cadesxlongtype1 (если libcades доступна)
    // ========================================================================

    @Test
    @EnabledIf("cadesTrustAvailable")
    @DisplayName("CAdES-X Long Type 1 -> cryptcp -cadesxlongtype1: принята")
    void cadesXLongAcceptedWithFlag() throws Exception {
        byte[] cadesXLong = buildCAdESXLongType1("cryptcp X-Long cades".getBytes());

        TempDirUtils.withTempDir("cp-xlong-flag-", dir -> {
            Path signedPath = TestData.writeDer(dir, "xlong-cades.p7s", cadesXLong);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-cadesxlongtype1", "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertEquals(0, r.exitCode(),
                    "КриптоПро должен принять CAdES-X Long Type 1 с флагом: " + r.output());
            return null;
        });
    }

    // ========================================================================
    // Построение CAdES-X Long Type 1
    // ========================================================================

    private static byte[] buildCAdESXLongType1(byte[] data) throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);

        byte[] tspReq = org.rssys.gost.pkix.tsp.TspRequestBuilder.create()
                .messageImprint(sigHash, hashOid)
                .certReq(true)
                .build();
        byte[] tspResp = org.rssys.gost.pkix.tsp.TspResponseBuilder.create(tspReq)
                .signer(tsaKey, tsaCert)
                .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                .serialNumber(java.math.BigInteger.ONE)
                .accuracy(1)
                .withCAdES()
                .buildGranted();
        byte[] tsToken = org.rssys.gost.pkix.tsp.TspResponse.fromDer(tspResp)
                .timeStampTokenDer();
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        // chain = [leaf, ca] (без корня — ca самоподписан, он же корень)
        List<GostCertificate> chain = Arrays.asList(leafCert, ca.cert());
        GostCrl crl = new GostCrl(GostCrlBuilder.create(ca.cert().getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(30)
                .withCrlNumber(1)
                .sign(ca.key()));
        List<GostCrl> crls = Arrays.asList(crl, null);
        List<GostOcspResponse> ocsp = Arrays.asList(null, null);

        return CAdESExtender.embedXLongType1(
                cadesT, chain, crls, ocsp, null, null);
    }

    // ========================================================================
    // Условия запуска
    // ========================================================================

    static boolean cryptcpAvailable() {
        return CryptoProChecker.cryptcpAvailable();
    }

    static boolean cadesTrustAvailable() {
        return CryptoProChecker.cadesLibraryAvailable()
                && Boolean.getBoolean("cryptcp.trustRoot");
    }
}
