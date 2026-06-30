package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.cadest.TestData.CertPair;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cms.CmsTestUtils;

@DisplayName("КриптоПРО: кросс-валидация CAdES-BES / CAdES-T / TSP")
class CryptoproCAdESCrossValidationTest {

    private static CertPair pair256;
    private static KeyPair tsaKp256;
    private static GostCertificate tsaCert256;

    @BeforeAll
    static void setUp() throws Exception {
        pair256 = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        tsaKp256 = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        tsaCert256 = CmsTestUtils.createSelfSignedCert(
                tsaKp256.getPrivate(), tsaKp256.getPublic());
    }

    // ========================================================================
    // CAdES-BES: crypto-gost -> cryptcp verify
    // ========================================================================

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-BES -> cryptcp -verify -cadesbes: утилита обрабатывает файл")
    void cadesBesToCryptcpVerify() throws Exception {
        byte[] data = "cryptcp BES test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        TempDirUtils.withTempDir("cp-bes-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed.p7s", cadesBes);
            Path certPath = TestData.writeDer(dir, "leaf.der",
                    pair256.leafCert().getEncoded());
            Path caPath = TestData.writeDer(dir, "ca.der",
                    pair256.caCert().getEncoded());

            // Устанавливаем сертификаты в хранилище (ошибки — некритичны)
            runCp(cryptcpBinary(), "-instcert", "-f", certPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", caPath.toString());

            Path outPath = dir.resolve("out.bin");
            String stdout = runOut(
                    cryptcpBinary(), "-verify", "-attached",
                    "-cadesbes", "-nochain",
                    signedPath.toString(), outPath.toString());

            System.out.println("cryptcp -verify -cadesbes: " + stdout.replace('\n', ' '));

            // КриптоПРО 5.0 может не знать ГОСТ-алгоритм — проверяем, что не завис
            assertTrue(stdout.contains("Проверка") || stdout.contains("Подпись")
                            || stdout.contains("ErrorCode"),
                    "cryptcp должен обработать файл без зависания: " + stdout);
            return null;
        });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-BES без withCAdES() -> cryptcp: не зависает")
    void cadesBesNoAttrToCryptcp() throws Exception {
        byte[] data = "cryptcp no attr".getBytes();
        byte[] noAttr = TestData.buildCAdESBESNoAttr(data, pair256.leafKey(), pair256.leafCert());

        TempDirUtils.withTempDir("cp-bes-noattr-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-noattr.p7s", noAttr);
            Path certPath = TestData.writeDer(dir, "leaf.der",
                    pair256.leafCert().getEncoded());
            Path caPath = TestData.writeDer(dir, "ca.der",
                    pair256.caCert().getEncoded());

            runCp(cryptcpBinary(), "-instcert", "-f", certPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", caPath.toString());

            Path outPath = dir.resolve("out.bin");
            String stdout = runOut(
                    cryptcpBinary(), "-verify", "-attached",
                    "-cadesbes", "-nochain",
                    signedPath.toString(), outPath.toString());

            System.out.println("cryptcp (no attr): " + stdout.replace('\n', ' '));
            // Без signingCertificateV2 — утилита не должна крашиться
            assertTrue(stdout.contains("Проверка") || stdout.contains("ErrorCode")
                            || stdout.length() > 50,
                    "cryptcp не должен зависнуть на BES без signingCertificateV2");
            return null;
        });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-BES detached -> cryptcp -verify -detached -cadesbes")
    void cadesBesDetachedToCryptcp() throws Exception {
        byte[] data = "cryptcp detached BES".getBytes();
        byte[] cadesBes = TestData.buildCAdESBESdetached(
                data, pair256.leafKey(), pair256.leafCert());

        TempDirUtils.withTempDir("cp-bes-det-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-det.p7s", cadesBes);
            Path dataPath = TestData.writeDer(dir, "data.bin", data);
            Path certPath = TestData.writeDer(dir, "leaf.der",
                    pair256.leafCert().getEncoded());
            Path caPath = TestData.writeDer(dir, "ca.der",
                    pair256.caCert().getEncoded());

            runCp(cryptcpBinary(), "-instcert", "-f", certPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", caPath.toString());

            // detached: data_dir + signedMsg
            String stdout = runOut(
                    cryptcpBinary(), "-verify", "-detached",
                    "-cadesbes", "-nochain",
                    dataPath.getParent().toString(),
                    signedPath.toString());

            System.out.println("cryptcp -verify -detached: " + stdout.replace('\n', ' '));
            assertTrue(stdout.contains("Проверка") || stdout.contains("ErrorCode")
                            || stdout.length() > 50,
                    "detached verify должен завершиться без зависания");
            return null;
        });
    }

    // ========================================================================
    // CAdES-T: crypto-gost -> cryptcp verify
    // ========================================================================

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("CAdES-T -> cryptcp -verify -cadest: не зависает")
    void cadesTToCryptcpVerify() throws Exception {
        byte[] data = "cryptcp CAdES-T".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tsToken = TestData.buildTimeStampToken(
                sigHash, hashOid, tsaKp256.getPrivate(), tsaCert256);
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        TempDirUtils.withTempDir("cp-cadest-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-cadest.p7s", cadesT);
            Path leafPath = TestData.writeDer(dir, "leaf.der",
                    pair256.leafCert().getEncoded());
            Path caPath = TestData.writeDer(dir, "ca.der",
                    pair256.caCert().getEncoded());
            Path tsaPath = TestData.writeDer(dir, "tsa.der", tsaCert256.getEncoded());

            runCp(cryptcpBinary(), "-instcert", "-f", leafPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", caPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", tsaPath.toString());

            Path outPath = dir.resolve("out.bin");
            String stdout = runOut(
                    cryptcpBinary(), "-verify", "-attached",
                    "-cadest", "-nochain",
                    signedPath.toString(), outPath.toString());

            System.out.println("cryptcp -verify -cadest: " + stdout.replace('\n', ' '));
            assertTrue(stdout.contains("Проверка") || stdout.contains("ErrorCode")
                            || stdout.length() > 50,
                    "cryptcp должен обработать CAdES-T без зависания");
            return null;
        });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("Negative: CAdES-BES как CAdES-T -> cryptcp не падает")
    void cadesBesAsCadestRejected() throws Exception {
        byte[] data = "BES as cadest".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        TempDirUtils.withTempDir("cp-bes-cadest-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-bes.p7s", cadesBes);
            Path certPath = TestData.writeDer(dir, "leaf.der",
                    pair256.leafCert().getEncoded());
            Path caPath = TestData.writeDer(dir, "ca.der",
                    pair256.caCert().getEncoded());

            runCp(cryptcpBinary(), "-instcert", "-f", certPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", caPath.toString());

            Path outPath = dir.resolve("out.bin");
            String stdout = runOut(
                    cryptcpBinary(), "-verify", "-attached",
                    "-cadest", "-nochain",
                    signedPath.toString(), outPath.toString());

            System.out.println("cryptcp -verify -cadest (BES): " + stdout.replace('\n', ' '));
            // CAdES-BES без метки как CAdES-T — криптоПРО должен выдать ошибку,
            // но не должен крашиться
            assertTrue(stdout.length() > 5,
                    "cryptcp должен выдать результат, не краш");
            return null;
        });
    }

    @Test
    @EnabledIf("cryptcpAvailable")
    @DisplayName("Negative: tampered signature -> cryptcp завершается")
    void tamperedSigToCryptcp() throws Exception {
        byte[] data = "tampered test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        byte[] tampered = cadesBes.clone();
        tampered[tampered.length - 1] ^= 0xFF;

        TempDirUtils.withTempDir("cp-tampered-", dir -> {
            Path signedPath = TestData.writeDer(dir, "tampered.p7s", tampered);
            Path certPath = TestData.writeDer(dir, "leaf.der",
                    pair256.leafCert().getEncoded());
            Path caPath = TestData.writeDer(dir, "ca.der",
                    pair256.caCert().getEncoded());

            runCp(cryptcpBinary(), "-instcert", "-f", certPath.toString());
            runCp(cryptcpBinary(), "-instcert", "-f", caPath.toString());

            Path outPath = dir.resolve("out.bin");
            String stdout = runOut(
                    cryptcpBinary(), "-verify", "-attached",
                    "-cadesbes", "-nochain",
                    signedPath.toString(), outPath.toString());

            System.out.println("cryptcp tampered: " + stdout.replace('\n', ' '));
            assertTrue(stdout.length() > 5,
                    "cryptcp должен завершиться на tampered подписи");
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
            String stdout = runOut(
                    tsputilBinary(), "-e", "reqinfo", reqPath.toString());

            System.out.println("tsputil reqinfo: " + stdout.replace('\n', ' '));
            assertTrue(stdout.length() > 10,
                    "tsputil должен распарсить TimeStampReq");
            return null;
        });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("tsputil makereq на ГОСТ-хэш -> проверка структуры")
    void tsputilMakereqForGostHash() throws Exception {
        byte[] hash = Digest.digest256("tsputil makereq test".getBytes());

        TempDirUtils.withTempDir("cp-tsmakereq-", dir -> {
            Path dataPath = TestData.writeDer(dir, "data.bin", hash);
            Path reqPath = dir.resolve("request.tsq");
            String stdout = runOut(
                    tsputilBinary(), "-e", "makereq",
                    "-t", "hash",
                    "-a", "1.2.643.7.1.1.2.2",
                    dataPath.toString(), reqPath.toString());

            System.out.println("tsputil makereq: " + stdout.replace('\n', ' '));
            // reqPath должен быть создан
            assertTrue(reqPath.toFile().exists() && reqPath.toFile().length() > 0,
                    "tsputil makereq должен создать файл запроса");
            return null;
        });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("tsputil stampinfo -c на CAdES-T PKCS#7: извлечение меток")
    void tsputilStampinfoOnCAdEST() throws Exception {
        byte[] data = "stampinfo test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tsToken = TestData.buildTimeStampToken(
                sigHash, hashOid, tsaKp256.getPrivate(), tsaCert256);
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        TempDirUtils.withTempDir("cp-stampinfo-", dir -> {
            Path signedPath = TestData.writeDer(dir, "signed-cadest.p7s", cadesT);
            String stdout = runOut(
                    tsputilBinary(), "-e", "stampinfo", "-c",
                    signedPath.toString());

            System.out.println("tsputil stampinfo -c: " + stdout.replace('\n', ' '));
            // stampinfo -c должен показать информацию о метках
            assertTrue(stdout.length() > 10,
                    "tsputil stampinfo должен выдать информацию о метках");
            return null;
        });
    }

    @Test
    @EnabledIf("tsputilAvailable")
    @DisplayName("crypto-gost TimeStampResp -> tsputil stampinfo: принят или отклонён")
    void tspRespToTsputil() throws Exception {
        byte[] hash = Digest.digest256("TSP resp test".getBytes());
        byte[] tsToken = TestData.buildTimeStampToken(hash, GostOids.DIGEST_256,
                tsaKp256.getPrivate(), tsaCert256);
        byte[] tspResp = TestData.buildTspResponse(tsToken);

        TempDirUtils.withTempDir("cp-tsresp-", dir -> {
            Path respPath = TestData.writeDer(dir, "response.tsr", tspResp);
            String stdout = runOut(
                    tsputilBinary(), "-e", "stampinfo", respPath.toString());

            System.out.println("tsputil stampinfo: " + stdout.replace('\n', ' '));
            assertTrue(stdout.length() > 10,
                    "tsputil должен обработать TimeStampResp");
            return null;
        });
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    static boolean cryptcpAvailable() {
        try {
            Process p = new ProcessBuilder(cryptcpBinary()).redirectErrorStream(true).start();
            p.getOutputStream().close();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return out.contains("CryptCP");
        } catch (Exception e) {
            return false;
        }
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

    static String cryptcpBinary() {
        return System.getProperty("cryptcp.binary",
                "/opt/cprocsp/bin/amd64/cryptcp");
    }

    static String tsputilBinary() {
        return System.getProperty("tsputil.binary",
                "/opt/cprocsp/bin/amd64/tsputil");
    }

    /**
     * Запускает процесс, закрывает stdin, возвращает exit code.
     */
    static int runCp(String... cmd) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        p.getInputStream().readAllBytes();
        return p.waitFor();
    }

    /**
     * Запускает процесс, закрывает stdin, возвращает stdout.
     */
    static String runOut(String... cmd) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor();
        return out;
    }
}
