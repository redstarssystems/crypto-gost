package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
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
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.pkix.tsp.TspRequest;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.signature.PrivateKeyParameters;

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
 *       Включаются свойством {@code -Dcrossval.cryptopro.trustRoot=true}: тест-корень ставится
 *       в доверенное хранилище на время прогона и снимается после него.</li>
 * </ul>
 *
 * <p>Предусловие: установлен КриптоПро CSP + ЭЦП SDK ({@code libcades}).
 */
@DisplayName("КриптоПРО: семантическая кросс-валидация CMS / CAdES")
class CryptoproCAdESCrossValidationTest {

    // RFC 3161 §2.4.2: serialNumber уникален для каждого штампа одного TSA
    private static final AtomicLong TSA_SERIAL = new AtomicLong(1);

    // Маркеры вывода `tsputil stampinfo`: по ним, а не по exit-code, различаем исходы
    private static final String STAMP_MATCHES_DATA = "Stamp is corresponding to the data";
    private static final String STAMP_NOT_MATCHES_DATA = "Stamp is NOT corresponding to the data";
    private static final String STAMP_SIGNATURE_VALID = "Verification of time-stamp: succeed.";

    // Основной подписант — ФИКСИРОВАННЫЙ leaf из CryptoproFixtureGenerator.
    // Его CA ставится в доверенный корень КриптоПро (uRoot) только на время прогона
    // (-Dcrossval.cryptopro.trustRoot=true), что позволяет opt-in CAdES-тестам
    // (-cadesbes/-cadest) строить цепочку.
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

    /** Идентификатор ключа тест-CA: по нему убирается CRL из uMy. */
    private static byte[] caKeyId;

    /** Хранилища до прогона: после уборки сверяем с ними, чужое не должно измениться. */
    private static CryptoproFixtureCleanup.Snapshot storesBefore;

    /** Тестовый корень в uRoot на время прогона класса. */
    private static CryptoproRootTrust rootTrust = CryptoproRootTrust.disabled();

    /** Подпись, которую КриптоПро принял с корнем: после снятия корня её отвергают. */
    private static byte[] verifiedWithRoot;

    @BeforeAll
    static void setUp() throws Exception {
        if (CryptoProChecker.cryptcpAvailable()) {
            storesBefore = CryptoproFixtureCleanup.snapshot();
        }
        CryptoproFixtureGenerator.Fixture ca = CryptoproFixtureGenerator.buildCa();
        caKeyId = ca.cert().getSubjectKeyIdentifier();
        CryptoproFixtureGenerator.Fixture leaf = CryptoproFixtureGenerator.buildLeaf(ca);
        CryptoproFixtureGenerator.Fixture tsa = CryptoproFixtureGenerator.buildTsa(ca);
        leafKey = leaf.key();
        leafCert = leaf.cert();
        tsaKey = tsa.key();
        tsaCert = tsa.cert();

        csKp256 = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        csCert256 = CmsTestUtils.createSelfSignedCert(csKp256.getPrivate(), csKp256.getPublic());

        // Сертификат подписанта обязан быть в хранилище, иначе cryptcp даёт
        // 0x200001fb «Signers certificates are not in certificate criterion»
        // и не доходит до проверки подписи. uMy — личное хранилище; тестовый корень ставится
        // отдельно, в доверенное хранилище uRoot, и только по явному флагу.
        if (CryptoProChecker.cryptcpAvailable()) {
            leafCertDer = Files.createTempFile("cp-leaf-", ".cer");
            CryptoProChecker.installCert(
                    leafCertDer.getParent(),
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
            rootTrust = CryptoproRootTrust.open(ca.cert());
        }
        if (rootTrust.isAvailable()) {
            crlFile = Files.createTempFile("cp-crl-", ".crl");
            Files.write(crlFile, CryptoproFixtureGenerator.buildCrl(ca));
            CryptoProChecker.installCrl(crlFile);
            crlInstalled = true;

            tsaCertDer = Files.createTempFile("cp-tsa-", ".cer");
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
                                CryptoproRootTrust.CHAIN_NOT_BUILT,
                                verifiedWithRoot,
                                leafCertDer,
                                "-attached",
                                "-cadesbes"));
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
                keyIds, crlInstalled ? caKeyId : null);
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

        TempDirUtils.withTempDir(
                "cp-bes-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "signed.p7s", cadesBes);
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
                            "КриптоПро должен принять CMS-подпись crypto-gost: " + r.output());
                    return null;
                });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-T attached -> cryptcp -verify: подпись принята (exit=0)")
    void cadesTAccepted() throws Exception {
        byte[] cadesT = buildCadesT("cryptcp CAdES-T semantic".getBytes());

        TempDirUtils.withTempDir(
                "cp-cadest-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "signed-cadest.p7s", cadesT);
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
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        TempDirUtils.withTempDir(
                "cp-bes-cs-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "signed.p7s", countersigned);
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

                    // добавление countersignature (unsigned-атрибут) не должно ломать
                    // проверку базовой подписи
                    assertEquals(
                            0,
                            r.exitCode(),
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

        TempDirUtils.withTempDir(
                "cp-tampered-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "tampered.p7s", tampered);
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

                    assertNotEquals(
                            0,
                            r.exitCode(),
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
        rootTrust.requireAvailable();
        byte[] data = "cryptcp cadesbes trust".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);

        TempDirUtils.withTempDir(
                "cp-cadesbes-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "signed.p7s", cadesBes);
                    Path outPath = dir.resolve("out.bin");
                    CryptoProChecker.Result r =
                            CryptoProChecker.runWithConfirm(
                                    CryptoProChecker.resolveCryptcpBinary(),
                                    "-verify",
                                    "-attached",
                                    "-cadesbes",
                                    "-norev",
                                    "-f",
                                    leafCertDer.toString(),
                                    signedPath.toString(),
                                    outPath.toString());

                    assertEquals(
                            0,
                            r.exitCode(),
                            "cryptcp -cadesbes должен принять CAdES-BES crypto-gost: "
                                    + r.output());
                    verifiedWithRoot = cadesBes;
                    return null;
                });
    }

    @Test
    @EnabledIf("cadesTrustAvailable")
    @DisplayName("[opt-in] CAdES-T -> cryptcp -cadest: подпись+метка времени валидны (exit=0)")
    void cadesTSemanticWithTrust() throws Exception {
        rootTrust.requireAvailable();
        byte[] cadesT = buildCadesT("cryptcp cadest trust".getBytes());

        TempDirUtils.withTempDir(
                "cp-cadest-trust-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "signed-cadest.p7s", cadesT);
                    Path outPath = dir.resolve("out.bin");
                    CryptoProChecker.Result r =
                            CryptoProChecker.runWithConfirm(
                                    CryptoProChecker.resolveCryptcpBinary(),
                                    "-verify",
                                    "-attached",
                                    "-cadest",
                                    "-norev",
                                    "-f",
                                    leafCertDer.toString(),
                                    signedPath.toString(),
                                    outPath.toString());

                    assertEquals(
                            0,
                            r.exitCode(),
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

        TempDirUtils.withTempDir(
                "cp-tsreq-",
                dir -> {
                    Path reqPath = TestData.writeDer(dir, "request.tsq", tspReq);
                    int code =
                            CryptoProChecker.run(
                                    tsputilBinary(), "-e", "reqinfo", reqPath.toString());
                    assertEquals(0, code, "tsputil должен распарсить TimeStampReq");
                    return null;
                });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("tsputil makereq на ГОСТ-хэш -> запрос создан и разбирается библиотекой")
    void tsputilMakereqForGostHash() throws Exception {
        byte[] hash = Digest.digest256("tsputil makereq test".getBytes());

        TempDirUtils.withTempDir(
                "cp-tsmakereq-",
                dir -> {
                    Path hashPath = TestData.writeDer(dir, "data.bin", hash);
                    Path reqPath = dir.resolve("request.tsq");
                    CryptoProChecker.Result result =
                            CryptoProChecker.runResult(
                                    tsputilBinary(),
                                    "-e",
                                    "makereq",
                                    "-t",
                                    "hash",
                                    "-a",
                                    GostOids.DIGEST_256,
                                    hashPath.toString(),
                                    reqPath.toString());
                    assertEquals(
                            0,
                            result.exitCode(),
                            "tsputil makereq должен завершиться успешно: " + result.output());
                    assertTrue(
                            Files.size(reqPath) > 0, "tsputil makereq должен создать файл запроса");

                    // запрос КриптоПро обязан читаться нашим разбором: иначе ГОСТ-хэш в нём
                    // закодирован иначе
                    TspRequest parsed = TspRequest.fromDer(Files.readAllBytes(reqPath));
                    assertEquals(
                            GostOids.DIGEST_256,
                            parsed.messageImprintAlgOid(),
                            "OID хэша в запросе tsputil должен быть Стрибог-256");
                    assertArrayEquals(
                            hash,
                            parsed.messageImprintHash(),
                            "хэш в запросе tsputil должен совпасть с исходным");
                    return null;
                });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName(
            "штамп crypto-gost -> tsputil stampinfo: подпись штампа проверена, данные соответствуют")
    void tsputilStampinfoVerifiesData() throws Exception {
        byte[] data = "tsputil stampinfo test".getBytes();

        TempDirUtils.withTempDir(
                "cp-tsstamp-",
                dir -> {
                    CryptoProChecker.Result result =
                            runStampinfo(dir, buildTimeStampTokenFor(data), data);
                    // exit-code не используем: он отражает проверку цепочки TSA и отзыва, которая
                    // офлайн
                    // недоступна; соответствие данным и подпись штампа tsputil сообщает отдельными
                    // строками
                    assertTrue(
                            result.output().contains(STAMP_MATCHES_DATA),
                            "tsputil должен подтвердить соответствие штампа данным: "
                                    + result.output());
                    assertTrue(
                            result.output().contains(STAMP_SIGNATURE_VALID),
                            "tsputil должен принять подпись штампа crypto-gost: "
                                    + result.output());
                    return null;
                });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName(
            "Negative: штамп crypto-gost не соответствует подменённым данным -> tsputil отклоняет")
    void tsputilStampinfoRejectsOtherData() throws Exception {
        byte[] data = "tsputil stampinfo test".getBytes();
        byte[] otherData = "tsputil stampinfo TEST".getBytes();

        TempDirUtils.withTempDir(
                "cp-tsstamp-neg-",
                dir -> {
                    CryptoProChecker.Result result =
                            runStampinfo(dir, buildTimeStampTokenFor(data), otherData);
                    assertTrue(
                            result.output().contains(STAMP_NOT_MATCHES_DATA),
                            "tsputil должен сообщить, что штамп не соответствует чужим данным: "
                                    + result.output());
                    assertFalse(
                            result.output().contains(STAMP_MATCHES_DATA),
                            "tsputil не должен подтверждать соответствие чужим данным");
                    return null;
                });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("Negative: искажённый TimeStampReq -> tsputil reqinfo отклоняет (exit!=0)")
    void tsputilReqinfoRejectsGarbage() throws Exception {
        TempDirUtils.withTempDir(
                "cp-tsbad-",
                dir -> {
                    Path reqPath = TestData.writeDer(dir, "bad.tsq", new byte[] {0x01, 0x02, 0x03});
                    CryptoProChecker.Result result =
                            CryptoProChecker.runResult(
                                    tsputilBinary(), "-e", "reqinfo", reqPath.toString());
                    assertNotEquals(
                            0,
                            result.exitCode(),
                            "tsputil должен отклонить мусор вместо TimeStampReq: "
                                    + result.output());
                    return null;
                });
    }

    // ========================================================================
    // Вспомогательное
    // ========================================================================

    /** Сохраняет токен и данные во временный каталог и запускает {@code tsputil stampinfo --verify-data}. */
    private static CryptoProChecker.Result runStampinfo(Path dir, byte[] token, byte[] data)
            throws Exception {
        Path stampPath = TestData.writeDer(dir, "stamp.tsr", token);
        Path dataPath = TestData.writeDer(dir, "data.bin", data);
        return CryptoProChecker.runResult(
                tsputilBinary(),
                "-e",
                "stampinfo",
                "--verify-data=" + dataPath,
                stampPath.toString());
    }

    /**
     * TimeStampToken на Стрибог-256 хэш данных, подписанный тестовой TSA.
     * Токен отдаётся как есть, без {@link DerAlgorithmIdentifierNormalizer}: проверку подписи штампа
     * {@code tsputil} проходит именно в таком виде, а нормализованный отвергает (наблюдение
     * при кросс-валидации, причина не выяснена).
     */
    private static byte[] buildTimeStampTokenFor(byte[] data) throws Exception {
        byte[] request = TestData.buildTspRequest(Digest.digest256(data), GostOids.DIGEST_256);
        byte[] response =
                TspResponseBuilder.create(request)
                        .signer(tsaKey, tsaCert)
                        .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                        .serialNumber(BigInteger.valueOf(TSA_SERIAL.getAndIncrement()))
                        .accuracy(1)
                        .withCAdES()
                        .buildGranted();
        return TspResponse.fromDer(response).timeStampTokenDer();
    }

    private static byte[] buildCadesT(byte[] data) throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES(data, leafKey, leafCert);
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);

        // Полноценный RFC 3161 TimeStampToken через реальный TSP-стек crypto-gost:
        // TSA (с EKU timeStamping) подписывает TSTInfo по messageImprint = хэш
        // значения подписи. withCAdES() добавляет signingCertificateV2 в токен.
        byte[] tspReq =
                org.rssys.gost.pkix.tsp.TspRequestBuilder.create()
                        .messageImprint(sigHash, hashOid)
                        .certReq(true)
                        .build();
        byte[] tspResp =
                org.rssys.gost.pkix.tsp.TspResponseBuilder.create(tspReq)
                        .signer(tsaKey, tsaCert)
                        .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                        .serialNumber(java.math.BigInteger.ONE)
                        .accuracy(1)
                        .withCAdES()
                        .buildGranted();
        byte[] tsToken = org.rssys.gost.pkix.tsp.TspResponse.fromDer(tspResp).timeStampTokenDer();
        return TestData.buildCAdEST(cadesBes, tsToken);
    }

    // ========================================================================
    // Условия запуска (EnabledIf)
    // ========================================================================

    static boolean cryptcpAvailable() {
        return CryptoProChecker.cryptcpAvailable();
    }

    /**
     * CAdES opt-in доступен только когда есть libcades И явно разрешено поставить тест-корень в
     * доверенное хранилище на время прогона ({@code -Dcrossval.cryptopro.trustRoot=true}).
     */
    static boolean cadesTrustAvailable() {
        return CryptoProChecker.cadesLibraryAvailable() && CryptoProChecker.trustRootEnabled();
    }

    static boolean tsputilAvailable() {
        try {
            Process p =
                    new ProcessBuilder(tsputilBinary(), "--help").redirectErrorStream(true).start();
            p.getOutputStream().close();
            int exit = p.waitFor();
            return exit == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static String tsputilBinary() {
        return System.getProperty("tsputil.binary", "/opt/cprocsp/bin/amd64/tsputil");
    }
}
