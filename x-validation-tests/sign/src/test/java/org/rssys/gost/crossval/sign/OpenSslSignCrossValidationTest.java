package org.rssys.gost.crossval.sign;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.util.CrossValAssertions;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Кросс-валидация подписи ГОСТ Р 34.10-2012: crypto-gost <-> OpenSSL.
 *
 * Для каждой кривой (CryptoPro-A/B/C и TC26-A/B/C-512):
 * — crypto-gost подписывает -> openssl dgst -verify верифицирует (10 сообщений);
 * — openssl dgst -sign подписывает -> crypto-gost верифицирует (10 сообщений);
 * — испорченная подпись отклоняется OpenSSL (tamper-тест).
 * Тест пропускается, если OpenSSL или engine gost недоступны.
 */
class OpenSslSignCrossValidationTest {

    private static final Map<TestData.CurveSpec, OpenSslCtx> ctx = new HashMap<>();

    private static String OPENSSL_BIN;
    private static String[] ENGINE_FLAG;

    private record OpenSslCtx(PrivateKeyParameters priv, PublicKeyParameters pub,
                              byte[] derPub, byte[] osslPrivPem,
                              PublicKeyParameters osslPub) {}

    static Stream<TestData.CurveSpec> opensslCurveParams() {
        return Stream.of(TestData.CURVES)
                .filter(c -> c.opensslSupported());
    }

    @BeforeAll
    static void setUp() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeEngineGost();
        OpenSslChecker.assumeStreebog();
        OPENSSL_BIN = OpenSslChecker.resolveOpenSslBinary();
        ENGINE_FLAG = OpenSslChecker.resolveEngineFlag();

        for (TestData.CurveSpec spec : TestData.CURVES) {
            if (spec.opensslSupported()) {
                try {
                    KeyPair pair = KeyGenerator.generateKeyPair(spec.paramsFn().get());
                    byte[] derPub = GostDerCodec.encodePublicKey(pair.getPublic());

                    Path tmpKey = null;
                    Path tmpPub = null;
                    try {
                        tmpKey = Files.createTempFile("ossl-key-", ".pem");
                        exec("genpkey",
                                "-algorithm", spec.opensslAlgo(),
                                "-pkeyopt", "paramset:" + spec.opensslParamset(),
                                "-out", tmpKey.toAbsolutePath().toString());
                        byte[] osslPrivPem = Files.readAllBytes(tmpKey);

                        tmpPub = Files.createTempFile("ossl-pub-", ".der");
                        exec("pkey", "-in", tmpKey.toAbsolutePath().toString(),
                                "-pubout", "-outform", "DER",
                                "-out", tmpPub.toAbsolutePath().toString());
                        byte[] osslPubDer = Files.readAllBytes(tmpPub);
                        PublicKeyParameters osslPub = GostDerCodec.decodePublicKey(osslPubDer);

                        ctx.put(spec, new OpenSslCtx(
                                pair.getPrivate(), pair.getPublic(), derPub,
                                osslPrivPem, osslPub));
                    } finally {
                        if (tmpKey != null) Files.deleteIfExists(tmpKey);
                        if (tmpPub != null) Files.deleteIfExists(tmpPub);
                    }
                } catch (Exception e) {
                    fail("Генерация ключей не удалась для "
                            + spec.name() + ": " + e.getMessage());
                }
            }
        }
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("OpenSSL: crypto-gost подписывает -> openssl верифицирует")
    void crossValidateOpenssl(TestData.CurveSpec spec) throws Exception {
        OpenSslCtx c = ctx.get(spec);
        byte[][] msgs = TestData.randomMessages(TestData.OPENSSL_NUM_MESSAGES, TestData.MSG_SIZE);

        CrossValAssertions.assertForEachMessage(msgs, msg -> {
            byte[] sig = Signature.sign(msg, c.priv);
            TempDirUtils.withTempDir("ossl-test-", tmpDir -> {
                Path msgFile = tmpDir.resolve("msg.bin");
                Path sigFile = tmpDir.resolve("sig.bin");
                Path pubFile = tmpDir.resolve("pub.der");
                Files.write(msgFile, msg);
                Files.write(sigFile, sig);
                Files.write(pubFile, c.derPub);

                boolean ok = runOpensslVerify(pubFile, sigFile, msgFile, spec.rolen());
                assertTrue(ok, spec.name() + ": crypto-gost подписал, OpenSSL не верифицировал");
                return null;
            });
        });
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("OpenSSL tamper: испорченная подпись отклоняется openssl")
    void crossValidateTamper(TestData.CurveSpec spec) throws Exception {
        OpenSslCtx c = ctx.get(spec);
        byte[][] msgs = TestData.randomMessages(TestData.OPENSSL_NUM_MESSAGES, TestData.MSG_SIZE);

        CrossValAssertions.assertForEachMessage(msgs, msg -> {
            byte[] sig = Signature.sign(msg, c.priv);
            byte[] sigBad = sig.clone();
            sigBad[0] ^= 0x01;

            TempDirUtils.withTempDir("ossl-tamper-", tmpDir -> {
                Path msgFile = tmpDir.resolve("msg.bin");
                Path sigBadFile = tmpDir.resolve("sig_bad.bin");
                Path pubFile = tmpDir.resolve("pub.der");
                Files.write(msgFile, msg);
                Files.write(sigBadFile, sigBad);
                Files.write(pubFile, c.derPub);

                boolean rejected = !runOpensslVerify(pubFile, sigBadFile, msgFile, spec.rolen());
                assertTrue(rejected, spec.name() + ": OpenSSL не отклонил испорченную подпись");
                return null;
            });
        });
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("OpenSSL dir2: openssl подписывает -> crypto-gost верифицирует")
    void crossValidateOpensslDir2(TestData.CurveSpec spec) throws Exception {
        OpenSslCtx c = ctx.get(spec);
        byte[][] msgs = TestData.randomMessages(TestData.OPENSSL_NUM_MESSAGES, TestData.MSG_SIZE);

        TempDirUtils.withTempDir("ossl-sign-", tmpDir -> {
            Path privPem = tmpDir.resolve("priv.pem");
            Files.write(privPem, c.osslPrivPem);

            CrossValAssertions.assertForEachMessage(msgs, msg -> {
                Path msgFile = tmpDir.resolve("msg.bin");
                Path sigFile = tmpDir.resolve("sig.bin");
                Files.write(msgFile, msg);

                runOpensslSign(privPem, sigFile, msgFile, spec.rolen());

                byte[] sig = Files.readAllBytes(sigFile);
                assertTrue(Signature.verify(msg, sig, c.osslPub),
                        spec.name() + ": OpenSSL подписал, crypto-gost не верифицировал");
            });
            return null;
        });
    }

    private static void runOpensslSign(Path privPem, Path sigFile, Path msgFile, int rolen)
            throws Exception {
        String hash = rolen == 64 ? "-md_gost12_512" : "-md_gost12_256";
        exec("dgst",
                hash,
                "-sign", privPem.toAbsolutePath().toString(),
                "-out", sigFile.toAbsolutePath().toString(),
                msgFile.toAbsolutePath().toString());
    }

    private static boolean runOpensslVerify(Path pubFile, Path sigFile, Path msgFile, int rolen)
            throws Exception {
        String hash = rolen == 64 ? "-md_gost12_512" : "-md_gost12_256";
        String[] full = CrossValUtils.concat(
                new String[]{OPENSSL_BIN, "dgst", hash},
                ENGINE_FLAG,
                new String[]{"-verify", pubFile.toAbsolutePath().toString(),
                        "-signature", sigFile.toAbsolutePath().toString(),
                        msgFile.toAbsolutePath().toString()});
        ProcessBuilder pb = new ProcessBuilder(full);
        pb.redirectErrorStream(true);
        pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        p.waitFor();
        return out.contains("Verified OK");
    }

    private static void exec(String... cmd) throws Exception {
        String[] full = CrossValUtils.concat(new String[]{OPENSSL_BIN, cmd[0]}, ENGINE_FLAG,
                java.util.Arrays.copyOfRange(cmd, 1, cmd.length));
        OpenSslChecker.exec(full);
    }


}
