package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
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
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Обратная кросс-валидация CAdES-X Long Type 1:
 * crypto-gost подписывает Crossval-ключом → cryptcp проверяет (прямое) +
 * crypto-gost проверяет (обратное).
 *
 * <p>Оба направления из одного теста: exit=0 от cryptcp и
 * verifyCAdESXLong без исключений.
 */
@DisplayName("Обратная кросс-валидация CAdES-X Long Type 1")
class ReverseCAdESXLongCrossValidationTest {

    private static CryptoproFixtureGenerator.Fixture leaf;
    private static PrivateKeyParameters leafKey;
    private static GostCertificate leafCert;
    private static CryptoproFixtureGenerator.Fixture ca;
    private static CryptoproFixtureGenerator.Fixture tsa;
    private static PrivateKeyParameters tsaKey;
    private static GostCertificate tsaCert;

    @BeforeAll
    static void setUp() {
        ca = CryptoproFixtureGenerator.buildCa();
        leaf = CryptoproFixtureGenerator.buildLeaf(ca);
        leafKey = leaf.key();
        leafCert = leaf.cert();
        tsa = CryptoproFixtureGenerator.buildTsa(ca);
        tsaKey = tsa.key();
        tsaCert = tsa.cert();
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("X-Long Type 1: cryptcp принимает, verifyCAdESXLong принимает")
    void bothDirectionsAcceptXLongType1() throws Exception {
        byte[] data = "reverse-xlong".getBytes();
        byte[] cadesXLong = buildCAdESXLongType1(data);
        java.nio.file.Path leafCertDer = java.nio.file.Files.createTempFile("rev-leaf-", ".cer");
        java.nio.file.Files.write(leafCertDer, leafCert.getEncoded());

        try {
            // Прямое направление: cryptcp -verify принимает
            TempDirUtils.withTempDir("cp-rev-", dir -> {
                java.nio.file.Path signedPath = TestData.writeDer(dir, "xlong.p7s", cadesXLong);
                java.nio.file.Path outPath = dir.resolve("out.bin");
                CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                        CryptoProChecker.resolveCryptcpBinary(),
                        "-verify", "-nochain", "-f", leafCertDer.toString(),
                        signedPath.toString(), outPath.toString());
                assertEquals(0, r.exitCode(),
                        "cryptcp должен принять X-Long: " + r.output());
                return null;
            });

            // Обратное направление: crypto-gost verifyCAdESXLong принимает
            VerifiedCAdESData result = CAdESExtender.verifyCAdESXLong(cadesXLong, ca.cert());
            assertEquals(1, result.signers().size(), "один подписант");
            assertArrayEquals(data, result.data(), "данные совпадают");
            assertFalse(result.signers().get(0).certificateValues().isEmpty(),
                    "certificateValues заполнены");
        } finally {
            java.nio.file.Files.deleteIfExists(leafCertDer);
        }
    }

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

        List<GostCertificate> chain = Arrays.asList(leafCert, ca.cert());
        GostCrl crl = new GostCrl(GostCrlBuilder.create(ca.cert().getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(30)
                .withCrlNumber(1)
                .sign(ca.key()));
        List<GostCrl> crls = Arrays.asList(crl, null);
        List<GostOcspResponse> ocsp = Arrays.asList(null, null);

        return CAdESExtender.embedXLongType1(cadesT, chain, crls, ocsp, null, null);
    }

    static boolean cryptcpAvailable() {
        return CryptoProChecker.cryptcpAvailable();
    }
}
