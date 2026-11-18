package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CAdESVerifier;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Двойная проверка CAdES-X Long Type 1, собранного самой библиотекой: файл строит
 * crypto-gost, затем его проверяют оба верификатора - {@code cryptcp} и
 * {@code verifyXLong}.
 *
 * <p>Файл КриптоПро здесь не участвует: подпись, созданную КриптоПро, проверяют тесты
 * готовых векторов в модуле pkix ({@code CryptoproCreatedXLong*VectorTest}).
 */
@DisplayName("CAdES-X Long Type 1, собранный библиотекой: проверка cryptcp и verifyXLong")
class CAdESXLongBuiltByLibraryCrossValidationTest {

    // RFC 3161 §2.4.2: serialNumber уникален для каждого штампа одного TSA,
    // а здесь выпускаются два штампа (подпись и escTimeStamp).
    private static final AtomicLong TSA_SERIAL = new AtomicLong(1);

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
    @DisplayName("X-Long Type 1: cryptcp и verifyXLong принимают файл")
    void bothDirectionsAcceptXLongType1() throws Exception {
        byte[] data = "reverse-xlong".getBytes();
        byte[] cadesXLong = buildCAdESXLongType1(data);
        java.nio.file.Path leafCertDer = java.nio.file.Files.createTempFile("rev-leaf-", ".cer");
        java.nio.file.Files.write(leafCertDer, leafCert.getEncoded());

        try {
            // cryptcp -verify принимает
            TempDirUtils.withTempDir(
                    "cp-rev-",
                    dir -> {
                        java.nio.file.Path signedPath =
                                TestData.writeDer(dir, "xlong.p7s", cadesXLong);
                        java.nio.file.Path outPath = dir.resolve("out.bin");
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
                                0, r.exitCode(), "cryptcp должен принять X-Long: " + r.output());
                        return null;
                    });

            // verifyXLong принимает
            VerifiedCAdESData result =
                    CAdESVerifier.verifyXLong(cadesXLong, TrustAnchors.ofCertificates(ca.cert()));
            assertEquals(1, result.signers().size(), "один подписант");
            assertArrayEquals(data, result.data(), "данные совпадают");
            assertFalse(
                    result.signers().get(0).certificateValues().isEmpty(),
                    "certificateValues заполнены");
        } finally {
            java.nio.file.Files.deleteIfExists(leafCertDer);
        }
    }

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

    static boolean cryptcpAvailable() {
        return CryptoProChecker.cryptcpAvailable();
    }
}
