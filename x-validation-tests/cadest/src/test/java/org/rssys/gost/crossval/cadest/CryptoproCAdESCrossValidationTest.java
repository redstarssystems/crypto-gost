package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CmsTestUtils;

/**
 * Семантическая кросс-валидация: crypto-gost создаёт CMS/CAdES -> КриптоПро
 * cryptcp проверяет и возвращает настоящий exit-code.
 *
 * <p>Два уровня строгости:
 * <ul>
 *   <li><b>Ядро</b> — {@code cryptcp -verify} (без CAdES-флага) с {@code -nochain}:
 *       семантическая проверка самой CMS-подписи (алгоритм, дайджест, signedAttrs).
 *       Работает без доверенного корня; требует лишь установку сертификата
 *       подписанта в личное хранилище {@code uMy}. Это доказывает, что КриптоПро
 *       принимает подпись crypto-gost.</li>
 *   <li><b>CAdES opt-in</b> — {@code -cadesbes/-cadest}: дополнительно проверяют
 *       CAdES-атрибуты (signingCertificateV2, метки времени). Эти флаги
 *       ИГНОРИРУЮТ {@code -nochain} и всегда строят цепочку до доверенного корня.
 *       Включаются свойством {@code -Dcryptcp.trustRoot=true} после ручной
 *       установки тест-корня в доверенное хранилище.</li>
 * </ul>
 *
 * <p>Предусловие: установлен КриптоПро CSP + ЭЦП SDK ({@code libcades}).
 */
@DisplayName("КриптоПРО: семантическая кросс-валидация CMS / CAdES")
class CryptoproCAdESCrossValidationTest {

    // Основной подписант — ФИКСИРОВАННЫЙ leaf из CryptoproFixtureGenerator.
    // Его CA заранее вручную установлен в доверенный корень КриптоПро (uRoot),
    // что позволяет opt-in CAdES-тестам (-cadesbes/-cadest) строить цепочку.
    private static PrivateKeyParameters leafKey;
    private static GostCertificate leafCert;

    // TSA — ФИКСИРОВАННЫЙ, выпущен тем же тест-CA, с EKU id-kp-timeStamping.
    // Нужен для полной семантики -cadest: КриптоПро проверяет метку времени,
    // требуя валидную TSA-цепочку до доверенного корня и timeStamping-EKU.
    private static PrivateKeyParameters tsaKey;
    private static GostCertificate tsaCert;
    private static KeyPair csKp256;
    private static GostCertificate csCert256;

    /** DER-файл сертификата подписанта, установленного в личное хранилище uMy. */
    private static Path leafCertDer;
    private static boolean signerInstalled;
    /** CRL-файл, установленный в uMy для opt-in CAdES-проверок статуса отзыва. */
    private static Path crlFile;
    private static boolean crlInstalled;
    /** DER-файл TSA-сертификата, установленного в uMy для -cadest. */
    private static Path tsaCertDer;
    private static boolean tsaInstalled;

    @BeforeAll
    static void setUp() throws Exception {
        CryptoproFixtureGenerator.Fixture ca = CryptoproFixtureGenerator.buildCa();
        CryptoproFixtureGenerator.Fixture leaf = CryptoproFixtureGenerator.buildLeaf(ca);
        CryptoproFixtureGenerator.Fixture tsa = CryptoproFixtureGenerator.buildTsa(ca);
        leafKey = leaf.key();
        leafCert = leaf.cert();
        tsaKey = tsa.key();
        tsaCert = tsa.cert();

        csKp256 = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        csCert256 = CmsTestUtils.createSelfSignedCert(
                csKp256.getPrivate(), csKp256.getPublic());

        // Сертификат подписанта обязан быть в хранилище, иначе cryptcp даёт
        // 0x200001fb «Signers certificates are not in certificate criterion»
        // и не доходит до проверки подписи. uMy — личное хранилище, установка
        // без подтверждения thumbprint (в отличие от корневого uRoot).
        if (CryptoProChecker.cryptcpAvailable()) {
            leafCertDer = Files.createTempFile("cp-leaf-", ".cer");
            CryptoProChecker.installCert(leafCertDer.getParent(),
                    leafCert.getEncoded(),
                    leafCertDer.getFileName().toString());
            signerInstalled = true;
        }

        // В режиме opt-in (-cadesbes/-cadest) КриптоПро проверяет статус отзыва.
        // Пустой CRL от тест-CA делает статус известным, иначе проверка падает
        // с 0x800B010E. Ставим CRL только когда доступен доверенный корень.
        // Также ставим TSA-сертификат — для -cadest КриптоПро строит цепочку
        // метки времени и должен найти сертификат TSA в хранилище.
        if (cadesTrustAvailable()) {
            crlFile = Files.createTempFile("cp-crl-", ".crl");
            Files.write(crlFile, CryptoproFixtureGenerator.buildCrl(ca));
            CryptoProChecker.installCrl(crlFile);
            crlInstalled = true;

            tsaCertDer = Files.createTempFile("cp-tsa-", ".cer");
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
            // CRL издан тест-CA — удаляем из uMy по DN издателя, чтобы не оседал
            // в личном хранилище машины после прогона.
            CryptoProChecker.deleteCrlByIssuerDn("Crossval Test Root CA");
            Files.deleteIfExists(crlFile);
        }
    }

    // ========================================================================
    // Ядро: crypto-gost CMS -> cryptcp -verify (семантически, exit=0)
    // ========================================================================

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-BES attached -> cryptcp -verify: подпись принята (exit=0)")
    void cadesBesAttachedAccepted() throws Exception {
        byte[] data = "cryptcp BES semantic".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);

        TempDirUtils.withTempDir("cp-bes-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed.p7s", cadesBes);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-nochain", "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertEquals(0, r.exitCode(),
                    "КриптоПро должен принять CMS-подпись crypto-gost: " + r.output());
            return null;
        });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-T attached -> cryptcp -verify: подпись принята (exit=0)")
    void cadesTAccepted() throws Exception {
        byte[] cadesT = buildCadesT("cryptcp CAdES-T semantic".getBytes());

        TempDirUtils.withTempDir("cp-cadest-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-cadest.p7s", cadesT);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-nochain", "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertEquals(0, r.exitCode(),
                    "КриптоПро должен принять базовую подпись CAdES-T: " + r.output());
            return null;
        });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("BES + countersignature -> cryptcp -verify: базовая подпись валидна")
    void countersignatureKeepsBaseSignatureValid() throws Exception {
        byte[] data = "cryptcp BES + CS".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);
        byte[] countersigned = CAdESExtender.embedCountersignature(
                cadesBes, csKp256.getPrivate(), csCert256);

        TempDirUtils.withTempDir("cp-bes-cs-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed.p7s", countersigned);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-nochain", "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            // добавление countersignature (unsigned-атрибут) не должно ломать
            // проверку базовой подписи
            assertEquals(0, r.exitCode(),
                    "базовая подпись должна остаться валидной после countersign: "
                            + r.output());
            return null;
        });
    }

    // ========================================================================
    // Negative: искажения отклоняются (exit != 0)
    // ========================================================================

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("Negative: искажённая подпись -> cryptcp отклоняет (exit!=0)")
    void tamperedSignatureRejected() throws Exception {
        byte[] data = "tampered test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);
        byte[] tampered = cadesBes.clone();
        // искажаем область значения подписи (ближе к концу структуры)
        tampered[tampered.length - 10] ^= 0xFF;

        TempDirUtils.withTempDir("cp-tampered-", dir -> {
            Path signedPath = TestData.writeDer(dir, "tampered.p7s", tampered);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-nochain", "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertNotEquals(0, r.exitCode(),
                    "cryptcp должен отклонить искажённую подпись: " + r.output());
            return null;
        });
    }

    // ========================================================================
    // CAdES opt-in: семантика CAdES-атрибутов (требует доверенный тест-корень)
    //
    // Флаги -cadesbes/-cadest игнорируют -nochain и всегда строят цепочку до
    // доверенного корня, а также проверяют статус отзыва. У тестовых
    // сертификатов нет точек распространения CRL/OCSP, поэтому добавлен -norev:
    // иначе проверка падает с 0x800B010E (revocation offline), что не относится
    // к предмету теста — семантике CAdES-подписи.
    // ========================================================================

    @Test
    @EnabledIf("cadesTrustAvailable")
    @DisplayName("[opt-in] CAdES-BES -> cryptcp -cadesbes: атрибуты валидны (exit=0)")
    void cadesBesSemanticWithTrust() throws Exception {
        byte[] data = "cryptcp cadesbes trust".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);

        TempDirUtils.withTempDir("cp-cadesbes-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed.p7s", cadesBes);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-attached", "-cadesbes", "-norev",
                    "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertEquals(0, r.exitCode(),
                    "cryptcp -cadesbes должен принять CAdES-BES crypto-gost: "
                            + r.output());
            return null;
        });
    }

    @Test
    @EnabledIf("cadesTrustAvailable")
    @DisplayName("[opt-in] CAdES-T -> cryptcp -cadest: подпись+метка времени валидны (exit=0)")
    void cadesTSemanticWithTrust() throws Exception {
        byte[] cadesT = buildCadesT("cryptcp cadest trust".getBytes());

        TempDirUtils.withTempDir("cp-cadest-trust-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-cadest.p7s", cadesT);
            Path outPath = dir.resolve("out.bin");
            CryptoProChecker.Result r = CryptoProChecker.runWithConfirm(
                    CryptoProChecker.resolveCryptcpBinary(),
                    "-verify", "-attached", "-cadest", "-norev",
                    "-f", leafCertDer.toString(),
                    signedPath.toString(), outPath.toString());

            assertEquals(0, r.exitCode(),
                    "cryptcp -cadest должен принять CAdES-T с реальной меткой TSA: "
                            + r.output());
            return null;
        });
    }

    // ========================================================================
    // TSP: crypto-gost <-> tsputil
    // ========================================================================

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("crypto-gost TimeStampReq -> tsputil reqinfo: парсинг принят")
    void tspReqToTsputilReqinfo() throws Exception {
        byte[] hash = Digest.digest256("TSP request test".getBytes());
        byte[] tspReq = TestData.buildTspRequest(hash, GostOids.DIGEST_256);

        TempDirUtils.withTempDir("cp-tsreq-", dir -> {
            Path reqPath = TestData.writeDer(dir, "request.tsq", tspReq);
            int code = CryptoProChecker.run(
                    tsputilBinary(), "-e", "reqinfo", reqPath.toString());
            assertEquals(0, code, "tsputil должен распарсить TimeStampReq");
            return null;
        });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("tsputil makereq на ГОСТ-хэш -> файл запроса создан")
    void tsputilMakereqForGostHash() throws Exception {
        byte[] hash = Digest.digest256("tsputil makereq test".getBytes());

        TempDirUtils.withTempDir("cp-tsmakereq-", dir -> {
            Path dataPath = TestData.writeDer(dir, "data.bin", hash);
            Path reqPath = dir.resolve("request.tsq");
            CryptoProChecker.run(
                    tsputilBinary(), "-e", "makereq", "-t", "hash",
                    "-a", "1.2.643.7.1.1.2.2",
                    dataPath.toString(), reqPath.toString());
            assertTrue(reqPath.toFile().exists() && reqPath.toFile().length() > 0,
                    "tsputil makereq должен создать файл запроса");
            return null;
        });
    }

    // ========================================================================
    // Вспомогательное
    // ========================================================================

    private static byte[] buildCadesT(byte[] data) throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);

        // Полноценный RFC 3161 TimeStampToken через реальный TSP-стек crypto-gost:
        // TSA (с EKU timeStamping) подписывает TSTInfo по messageImprint = хэш
        // значения подписи. withCAdES() добавляет signingCertificateV2 в токен.
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
        return TestData.buildCAdEST(cadesBes, tsToken);
    }

    // ========================================================================
    // Условия запуска (EnabledIf)
    // ========================================================================

    static boolean cryptcpAvailable() {
        return CryptoProChecker.cryptcpAvailable();
    }

    /**
     * CAdES opt-in доступен только когда есть libcades И явно указано, что
     * тест-корень установлен в доверенное хранилище ({@code -Dcryptcp.trustRoot=true}).
     */
    static boolean cadesTrustAvailable() {
        return CryptoProChecker.cadesLibraryAvailable()
                && Boolean.getBoolean("cryptcp.trustRoot");
    }

    static boolean tsputilAvailable() {
        try {
            Process p = new ProcessBuilder(tsputilBinary(), "--help")
                    .redirectErrorStream(true).start();
            p.getOutputStream().close();
            int exit = p.waitFor();
            return exit == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static String tsputilBinary() {
        return System.getProperty("tsputil.binary",
                "/opt/cprocsp/bin/amd64/tsputil");
    }
}
