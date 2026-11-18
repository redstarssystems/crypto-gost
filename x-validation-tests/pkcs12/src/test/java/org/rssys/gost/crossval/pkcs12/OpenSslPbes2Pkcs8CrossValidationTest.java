package org.rssys.gost.crossval.pkcs12;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPbes2;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.GostPkcs12Parser;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Двусторонняя кросс-валидация PBES2 (RFC 9337) c {@code openssl pkcs8 -v2}.
 * <p>
 * Два набора:
 * <ul>
 *   <li>{@code kuznyechik-ctr-acpkm} - системный OpenSSL с gost-engine ({@code openssl.system.binary},
 *       по умолчанию /usr/bin/openssl), engine подключается флагом {@code -engine gost};</li>
 *   <li>{@code kuznyechik-ctr-acpkm-omac} - эталонный gost-engine master (RFC 9337 / 9548):
 *       системный engine 3.0.x не умеет OMAC в PKCS#8. Нужны свойства
 *       {@code openssl.reference.binary} (по умолчанию /opt/openssl-3.6.0-gost/bin/openssl),
 *       {@code openssl.reference.engines} (каталог с собранным {@code gost.so}) и
 *       {@code openssl.reference.conf} (конфиг с {@code engines = gost}). Без них набор
 *       пропускается. Сборка engine: cmake из дерева gost-engine с
 *       {@code -DGOST_BUILD_ENGINE=ON -DGOST_BUILD_PROVIDER=OFF} против OpenSSL 3.6.</li>
 * </ul>
 * PRF задаётся OID HMAC-Streebog-512, так как библиотека поддерживает только ГОСТ PRF.
 * Не используется /opt-провайдер gostprov: он не регистрирует OID шифра в PBES2
 * ("cipher has no object identifier").
 */
@DisplayName("PBES2/PKCS#8 CTR-ACPKM(-OMAC): кросс-валидация GostPbes2 <-> openssl pkcs8")
class OpenSslPbes2Pkcs8CrossValidationTest {

    private static final String PASSWORD = "crossval-pbes2";
    private static final int ITERATIONS = 2_000;
    private static final String PRF_OID_ARG = GostOids.HMAC_STREEBOG_512;

    /** Инструмент OpenSSL: бинарник, флаги подключения engine и переменные окружения. */
    record Toolchain(
            String name,
            String binary,
            List<String> engineFlags,
            java.util.Map<String, String> env,
            String cipherArg,
            String schemeOid) {
        @Override
        public String toString() {
            return name;
        }

        boolean available() throws Exception {
            if (!Files.isExecutable(Path.of(binary))) {
                return false;
            }
            Path tmp = Files.createTempDirectory("pbes2-probe-");
            try {
                Path key = tmp.resolve("k.pem");
                if (run(this, genpkeyArgs(this, "gost2012_256", "A", key)) != 0) {
                    return false;
                }
                return run(
                                this,
                                pkcs8Args(
                                        this,
                                        "-topk8", "-in", key.toString(),
                                        "-v2", cipherArg, "-v2prf", PRF_OID_ARG,
                                        "-passout", "pass:" + PASSWORD,
                                        "-out", tmp.resolve("p.der").toString(),
                                        "-outform", "DER"))
                        == 0;
            } finally {
                TempDirUtils.deleteRecursively(tmp);
            }
        }
    }

    static Toolchain systemCtrAcpkm() {
        return new Toolchain(
                "system/ctr-acpkm",
                System.getProperty("openssl.system.binary", "/usr/bin/openssl"),
                List.of("-engine", "gost"),
                java.util.Map.of(),
                "kuznyechik-ctr-acpkm",
                GostOids.KUZ_CTR_ACPKM);
    }

    static Toolchain referenceOmac() {
        String binary =
                System.getProperty(
                        "openssl.reference.binary", "/opt/openssl-3.6.0-gost/bin/openssl");
        String engines = System.getProperty("openssl.reference.engines", "");
        String conf = System.getProperty("openssl.reference.conf", "");
        java.util.Map<String, String> env = new java.util.HashMap<>();
        env.put("OPENSSL_ENGINES", engines);
        env.put("OPENSSL_CONF", conf);
        Path root = Path.of(binary).toAbsolutePath().getParent().getParent();
        env.put("LD_LIBRARY_PATH", root.resolve("lib").toString());
        return new Toolchain(
                "reference/ctr-acpkm-omac",
                binary,
                List.of(),
                env,
                "kuznyechik-ctr-acpkm-omac",
                GostOids.KUZ_CTR_ACPKM_OMAC);
    }

    /** Доступные наборы; недоступные пропускаются с понятной причиной. */
    static List<Toolchain> toolchains() throws Exception {
        List<Toolchain> list = new ArrayList<>();
        Toolchain sys = systemCtrAcpkm();
        if (sys.available()) {
            list.add(sys);
        }
        Toolchain ref = referenceOmac();
        if (!ref.env().get("OPENSSL_ENGINES").isEmpty() && ref.available()) {
            list.add(ref);
        }
        Assumptions.assumeFalse(list.isEmpty(), "Ни один OpenSSL с PBES2 CTR-ACPKM недоступен");
        return list;
    }

    record KeySpec(String name, String algo, String paramset) {
        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<org.junit.jupiter.params.provider.Arguments> cases() throws Exception {
        List<KeySpec> keys =
                List.of(
                        new KeySpec("gost2012_256/A", "gost2012_256", "A"),
                        new KeySpec("gost2012_256/B", "gost2012_256", "B"),
                        new KeySpec("gost2012_512/A", "gost2012_512", "A"));
        List<org.junit.jupiter.params.provider.Arguments> out = new ArrayList<>();
        for (Toolchain tc : toolchains()) {
            for (KeySpec key : keys) {
                out.add(org.junit.jupiter.params.provider.Arguments.of(tc, key));
            }
        }
        return out.stream();
    }

    @ParameterizedTest
    @MethodSource("cases")
    @DisplayName("Направление B: openssl pkcs8 шифрует -> GostPbes2 расшифровывает")
    void opensslEncrypts_libraryDecrypts(Toolchain tc, KeySpec spec) throws Exception {
        TempDirUtils.withTempDir("pbes2-b-", dir -> {
            Path pem = dir.resolve("key.pem");
            opensslGenpkey(tc, spec.algo(), spec.paramset(), pem);
            Path plainDer = dir.resolve("plain.der");
            opensslPkcs8(
                    tc,
                    "-topk8", "-nocrypt", "-in", pem.toString(),
                    "-out", plainDer.toString(), "-outform", "DER");
            Path encDer = dir.resolve("enc.der");
            opensslPkcs8(
                    tc,
                    "-topk8", "-in", pem.toString(),
                    "-v2", tc.cipherArg(), "-v2prf", PRF_OID_ARG, "-iter", String.valueOf(ITERATIONS),
                    "-passout", "pass:" + PASSWORD,
                    "-out", encDer.toString(), "-outform", "DER");

            PrivateKeyParameters expected =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(plainDer));
            PrivateKeyParameters actual =
                    GostPkcs12Loader.decryptPrivateKey(
                            Files.readAllBytes(encDer), PASSWORD.toCharArray());

            assertSameKey(tc, spec, expected, actual, "расшифрованный библиотекой");
            assertOpensslParams(tc, Files.readAllBytes(encDer));
            expected.destroy();
            actual.destroy();
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("cases")
    @DisplayName("Направление A: GostPbes2 шифрует -> openssl pkcs8 расшифровывает")
    void libraryEncrypts_opensslDecrypts(Toolchain tc, KeySpec spec) throws Exception {
        TempDirUtils.withTempDir("pbes2-a-", dir -> {
            Path pem = dir.resolve("key.pem");
            opensslGenpkey(tc, spec.algo(), spec.paramset(), pem);
            Path plainDer = dir.resolve("plain.der");
            opensslPkcs8(
                    tc,
                    "-topk8", "-nocrypt", "-in", pem.toString(),
                    "-out", plainDer.toString(), "-outform", "DER");
            PrivateKeyParameters original =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(plainDer));

            byte[] enc =
                    GostPbes2.encryptKey(
                            original,
                            PASSWORD.getBytes(StandardCharsets.UTF_8),
                            tc.schemeOid(),
                            ITERATIONS);
            Path encDer = dir.resolve("lib-enc.der");
            Files.write(encDer, enc);

            Path decDer = dir.resolve("lib-dec.der");
            opensslPkcs8(
                    tc,
                    "-in", encDer.toString(), "-inform", "DER",
                    "-passin", "pass:" + PASSWORD,
                    "-out", decDer.toString(), "-outform", "DER");

            PrivateKeyParameters viaOpenssl =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(decDer));
            assertSameKey(tc, spec, original, viaOpenssl, "расшифрованный openssl");
            original.destroy();
            viaOpenssl.destroy();
            return null;
        });
    }

    /** Совпадают закрытое значение, кривая и открытая точка d*G: одинаковый D на другой кривой не пройдёт. */
    private static void assertSameKey(
            Toolchain tc,
            KeySpec spec, PrivateKeyParameters expected, PrivateKeyParameters actual, String who) {
        assertEquals(expected.getD(), actual.getD(), tc + " " + spec + ": d, " + who + ", должно совпасть");
        ECParameters pe = expected.getParams();
        ECParameters pa = actual.getParams();
        assertEquals(pe.p, pa.p, tc + " " + spec + ": модуль кривой, " + who + ", должен совпасть");
        assertEquals(pe.gx, pa.gx, tc + " " + spec + ": gx кривой, " + who + ", должен совпасть");
        assertEquals(pe.gy, pa.gy, tc + " " + spec + ": gy кривой, " + who + ", должен совпасть");
        ECPoint qe = ECPoint.affine(pe.gx, pe.gy, pe).multiply(expected.getD()).normalize();
        ECPoint qa = ECPoint.affine(pa.gx, pa.gy, pa).multiply(actual.getD()).normalize();
        assertEquals(qe.getX(), qa.getX(), tc + " " + spec + ": X точки d*G, " + who + ", должен совпасть");
        assertEquals(qe.getY(), qa.getY(), tc + " " + spec + ": Y точки d*G, " + who + ", должен совпасть");
    }

    /** Файл OpenSSL: OID шифра набора, PRF HMAC-Streebog-512 с параметрами NULL, UKM 16 байт. */
    private static void assertOpensslParams(Toolchain tc, byte[] encryptedKeyInfoDer) {
        GostPkcs12Parser.EncryptedPrivateKeyInfo epki =
                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(encryptedKeyInfoDer);
        GostPkcs12Parser.Pbes2Params params =
                GostPkcs12Parser.parsePbes2Params(epki.getEncryptionParams(), 1);
        assertEquals(tc.schemeOid(), params.getEncryptionSchemeOid(), "OID шифра у OpenSSL");
        assertEquals(GostOids.HMAC_STREEBOG_512, params.getPrfOid(), "OID PRF у OpenSSL");
        assertEquals(GostOids.PBES2_UKM_LEN, params.getUkm().length, "Длина UKM у OpenSSL");

        byte[][] top = DerCodec.parseSequenceContents(epki.getEncryptionParams(), 0);
        byte[][] kdfAlg = DerCodec.parseSequenceContents(top[0], 0);
        byte[][] kdfParams = DerCodec.parseSequenceContents(kdfAlg[1], 0);
        // PRF - единственный SEQUENCE среди полей; необязательный keyLength (INTEGER) сдвигал бы индекс
        byte[] prfField = null;
        for (byte[] field : kdfParams) {
            if ((field[0] & 0xFF) == DerCodec.TAG_SEQUENCE) {
                prfField = field;
            }
        }
        assertNotNull(prfField, "В PBKDF2-params должен быть AlgorithmIdentifier PRF");
        byte[][] prf = DerCodec.parseSequenceContents(prfField, 0);
        assertEquals(2, prf.length, "AlgorithmIdentifier PRF у OpenSSL: OID и параметры");
        assertEquals(DerCodec.TAG_NULL, prf[1][0] & 0xFF, "OpenSSL пишет параметры PRF как NULL");
        assertEquals(0, prf[1][1] & 0xFF, "NULL имеет нулевую длину");
    }

    private static void opensslPkcs8(Toolchain tc, String... args) throws Exception {
        exec(tc, pkcs8Args(tc, args));
    }

    private static void opensslGenpkey(Toolchain tc, String algo, String paramset, Path out)
            throws Exception {
        exec(tc, genpkeyArgs(tc, algo, paramset, out));
    }

    private static List<String> pkcs8Args(Toolchain tc, String... args) {
        return command(tc, "pkcs8", args);
    }

    private static List<String> genpkeyArgs(Toolchain tc, String algo, String paramset, Path out) {
        return command(
                tc,
                "genpkey",
                "-algorithm", algo, "-pkeyopt", "paramset:" + paramset, "-out", out.toString());
    }

    private static List<String> command(Toolchain tc, String subcommand, String... args) {
        List<String> cmd = new ArrayList<>();
        cmd.add(tc.binary());
        cmd.add(subcommand);
        cmd.addAll(tc.engineFlags());
        cmd.addAll(List.of(args));
        return cmd;
    }

    private static Process start(Toolchain tc, List<String> cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        pb.environment().putAll(tc.env());
        return pb.start();
    }

    private static int run(Toolchain tc, List<String> cmd) throws Exception {
        Process p = start(tc, cmd);
        p.getInputStream().readAllBytes();
        return p.waitFor();
    }

    private static void exec(Toolchain tc, List<String> cmd) throws Exception {
        Process p = start(tc, cmd);
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        int code = p.waitFor();
        if (code != 0) {
            throw new IllegalStateException(
                    "Команда завершилась с кодом " + code + ": " + String.join(" ", cmd) + "\n" + out);
        }
    }
}
