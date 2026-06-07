package org.rssys.gost.crossval.keys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация ECDH (KeyAgreement) между crypto-gost и OpenSSL engine gost.
 * <p>
 * Для каждой кривой, совместимой с OpenSSL, три сценария:
 * <ol>
 *   <li>Обе стороны — crypto-gost: KeyAgreement = pkeyutl -derive;</li>
 *   <li>Обе стороны — OpenSSL: pkeyutl -derive = KeyAgreement;</li>
 *   <li>Смешанный: crypto-gost A × OpenSSL B (сквозная совместимость).</li>
 * </ol>
 * Тест пропускается, если OpenSSL или engine gost недоступны.
 */
class OpenSslEcdhCrossValidationTest {

    private static String OPENSSL;
    private static String[] ENGINE_FLAG;

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeEngineGost();
        OpenSslChecker.assumeGostDerive();
        OPENSSL = OpenSslChecker.resolveOpenSslBinary();
        ENGINE_FLAG = OpenSslChecker.resolveEngineFlag();
    }

    static Stream<TestData.CurveSpec> opensslCurveParams() {
        return Stream.of(TestData.CURVES)
                .filter(c -> c.ecdhSupported());
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("crypto-gost обе стороны: KeyAgreement = pkeyutl -derive")
    void crossValidateGostBoth(TestData.CurveSpec spec) throws Exception {
        ECParameters params = spec.paramsFn().get();
        TempDirUtils.withTempDir("ecdh-gost-", tmpDir -> {
            KeyPair pairA = KeyGenerator.generateKeyPair(params);
            KeyPair pairB = KeyGenerator.generateKeyPair(params);
            try {
                byte[] sharedGost = KeyAgreement.computeSharedSecret(
                        pairA.getPrivate(), pairB.getPublic());

                Path privA = tmpDir.resolve("privA.der");
                Path pubB  = tmpDir.resolve("pubB.der");
                Files.write(privA, GostDerCodec.encodePrivateKey(pairA.getPrivate()));
                Files.write(pubB,  GostDerCodec.encodePublicKey(pairB.getPublic()));

                byte[] sharedOssl = derive(privA, pubB);

                assertArrayEquals(sharedGost, sharedOssl,
                        () -> spec.name() + ": shared secret не совпадает\n"
                                + CrossValUtils.diffContext(sharedGost, sharedOssl));
                return null;
            } finally {
                pairA.getPrivate().destroy();
                pairB.getPrivate().destroy();
            }
        });
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("OpenSSL обе стороны: pkeyutl -derive = KeyAgreement")
    void crossValidateOpenSslBoth(TestData.CurveSpec spec) throws Exception {
        TempDirUtils.withTempDir("ecdh-ossl-", tmpDir -> {
            Path privA = tmpDir.resolve("privA.der");
            Path pubA  = tmpDir.resolve("pubA.der");
            Path privB = tmpDir.resolve("privB.der");
            Path pubB  = tmpDir.resolve("pubB.der");

            genKey(privA, spec);
            extractPub(privA, pubA);
            genKey(privB, spec);
            extractPub(privB, pubB);

            byte[] sharedOssl = derive(privA, pubB);

            PrivateKeyParameters osslPrivA = GostDerCodec.decodePrivateKey(
                    Files.readAllBytes(privA));
            PublicKeyParameters osslPubB = GostDerCodec.decodePublicKey(
                    Files.readAllBytes(pubB));
            byte[] sharedGost = KeyAgreement.computeSharedSecret(
                    osslPrivA, osslPubB);

            osslPrivA.destroy();

            assertArrayEquals(sharedOssl, sharedGost,
                    () -> spec.name() + ": shared secret не совпадает\n"
                            + CrossValUtils.diffContext(sharedOssl, sharedGost));
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("crypto-gost A × OpenSSL B: сквозная совместимость")
    void crossValidateMixed(TestData.CurveSpec spec) throws Exception {
        ECParameters params = spec.paramsFn().get();
        TempDirUtils.withTempDir("ecdh-mix-", tmpDir -> {
            KeyPair pairA = KeyGenerator.generateKeyPair(params);

            Path privA = tmpDir.resolve("privA.der");
            Files.write(privA, GostDerCodec.encodePrivateKey(pairA.getPrivate()));

            Path privB = tmpDir.resolve("privB.der");
            Path pubB  = tmpDir.resolve("pubB.der");
            genKey(privB, spec);
            extractPub(privB, pubB);

            // crypto-gost считает c OpenSSL-ключом B
            PublicKeyParameters osslPubB = GostDerCodec.decodePublicKey(
                    Files.readAllBytes(pubB));
            byte[] sharedGost = KeyAgreement.computeSharedSecret(
                    pairA.getPrivate(), osslPubB);

            // OpenSSL считает с crypto-gost ключом A
            byte[] sharedOssl = derive(privA, pubB);

            // Симметричность: B×A (OpenSSL priv + crypto-gost pub)
            PrivateKeyParameters osslPrivB = GostDerCodec.decodePrivateKey(
                    Files.readAllBytes(privB));
            byte[] sharedGostRev = KeyAgreement.computeSharedSecret(
                    osslPrivB, pairA.getPublic());
            osslPrivB.destroy();

            pairA.getPrivate().destroy();

            assertArrayEquals(sharedGost, sharedOssl,
                    () -> spec.name() + ": crypto-gost A → OpenSSL B не совпадает\n"
                            + CrossValUtils.diffContext(sharedGost, sharedOssl));
            assertArrayEquals(sharedGost, sharedGostRev,
                    () -> spec.name() + ": симметричность нарушена (A·B ≠ B·A)");
            return null;
        });
    }

    // ========================================================================
    // OpenSSL subprocess helpers
    // ========================================================================

    /** openssl genpkey ENGINE_FLAG -algorithm ... -pkeyopt paramset:... -outform DER -out file.der */
    private static void genKey(Path outFile, TestData.CurveSpec spec) throws Exception {
        OpenSslChecker.exec(fullCmd("genpkey",
                "-algorithm", spec.opensslAlgo(),
                "-pkeyopt", "paramset:" + spec.opensslParamset(),
                "-outform", "DER",
                "-out", outFile.toString()));
    }

    /** openssl pkey ENGINE_FLAG -in priv.der -inform DER -pubout -outform DER -out pub.der */
    private static void extractPub(Path privFile, Path pubFile) throws Exception {
        OpenSslChecker.exec(fullCmd("pkey",
                "-in", privFile.toString(),
                "-inform", "DER",
                "-pubout",
                "-outform", "DER",
                "-out", pubFile.toString()));
    }

    /**
     * openssl pkeyutl -derive ENGINE_FLAG -inkey priv.der -keyform DER
     *     -peerkey peer.der -peerform DER -out shared.bin
     * Возвращает содержимое shared.bin.
     */
    private static byte[] derive(Path privFile, Path peerFile) throws Exception {
        Path outFile = privFile.resolveSibling("shared.bin");
        OpenSslChecker.exec(fullCmd("pkeyutl", "-derive",
                "-inkey", privFile.toString(),
                "-keyform", "DER",
                "-peerkey", peerFile.toString(),
                "-peerform", "DER",
                "-out", outFile.toString()));
        return Files.readAllBytes(outFile);
    }

    /** Собирает полную команду: openssl subcommand ENGINE_FLAG args... */
    private static String[] fullCmd(String subcommand, String... args) {
        return CrossValUtils.concat(new String[]{OPENSSL, subcommand}, ENGINE_FLAG, args);
    }


}
