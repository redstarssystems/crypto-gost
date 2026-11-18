package org.rssys.gost.crossval.keys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Кросс-валидация ключей: crypto-gost -> OpenSSL engine gost.
 *
 * Для каждой кривой, совместимой с OpenSSL (CryptoPro-A/B/C, TC26-A/B/C-512):
 * — OpenSSL genpkey -> crypto-gost читает DER -> Q = d·G;
 * — crypto-gost gen -> DER -> openssl pkey читает DER.
 * Тест пропускается, если OpenSSL или engine gost недоступны.
 */
class OpenSslKeysCrossValidationTest {

    private static String OPENSSL_BIN;
    private static String[] ENGINE_FLAG;

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeEngineGost();
        OPENSSL_BIN = OpenSslChecker.resolveOpenSslBinary();
        ENGINE_FLAG = OpenSslChecker.resolveEngineFlag();
    }

    static Stream<TestData.CurveSpec> opensslCurveParams() {
        return Stream.of(TestData.CURVES)
                .filter(c -> c.opensslGenSupported());
    }

    static Stream<TestData.CurveSpec> opensslReadParams() {
        return opensslCurveParams().filter(c -> c.opensslReadSupported());
    }

    @ParameterizedTest
    @MethodSource("opensslCurveParams")
    @DisplayName("OpenSSL gen->crypto-gost: Q = d·G совпадает с открытым ключом, выданным OpenSSL")
    void crossValidateGenToGost(TestData.CurveSpec spec) throws Exception {
        TempDirUtils.withTempDir("ossl-key-", tmpDir -> {
            Path privFile = tmpDir.resolve("priv.der");
            Path pubFile = tmpDir.resolve("pub.der");

            exec(OPENSSL_BIN, "genpkey",
                    "-algorithm", spec.opensslAlgo(),
                    "-pkeyopt", "paramset:" + spec.opensslParamset(),
                    "-outform", "DER",
                    "-out", privFile.toAbsolutePath().toString());

            byte[] der = Files.readAllBytes(privFile);
            PrivateKeyParameters priv = GostDerCodec.decodePrivateKey(der);
            ECParameters decodedParams = priv.getParams();
            ECPoint g = ECPoint.affine(decodedParams.gx, decodedParams.gy, decodedParams);
            ECPoint q = g.multiply(priv.getD()).normalize();
            priv.destroy();

            // Открытый ключ выдаёт сам OpenSSL из того же закрытого: сверяем его с нашим d·G,
            // иначе вычисленный q ничем не проверялся бы
            exec(OPENSSL_BIN, "pkey",
                    "-in", privFile.toAbsolutePath().toString(),
                    "-inform", "DER",
                    "-pubout", "-outform", "DER",
                    "-out", pubFile.toAbsolutePath().toString());
            PublicKeyParameters osslPub = GostDerCodec.decodePublicKey(Files.readAllBytes(pubFile));
            assertEquals(osslPub.getQ().getX(), q.getX(), "x открытого ключа OpenSSL и d·G");
            assertEquals(osslPub.getQ().getY(), q.getY(), "y открытого ключа OpenSSL и d·G");
            assertEquals(decodedParams, osslPub.getParams(), "кривая открытого ключа OpenSSL");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("opensslReadParams")
    @DisplayName("crypto-gost->OpenSSL pkey: gost gen -> DER -> openssl pkey")
    void crossValidateGostToPkey(TestData.CurveSpec spec) throws Exception {
        ECParameters params = spec.paramsFn().get();
        TempDirUtils.withTempDir("ossl-pkey-", tmpDir -> {
            KeyPair pair = KeyGenerator.generateKeyPair(params);
            byte[] gostPrivDer = GostDerCodec.encodePrivateKey(pair.getPrivate());

            Path gostPrivFile = tmpDir.resolve("gost_priv.der");
            Files.write(gostPrivFile, gostPrivDer);

            exec(OPENSSL_BIN, "pkey",
                    "-in", gostPrivFile.toAbsolutePath().toString(),
                    "-inform", "DER",
                    "-noout", "-text");
            return null;
        });
    }

    /** openssl subcommand ENGINE_FLAG args... */
    private static void exec(String... cmd) throws Exception {
        String[] full = CrossValUtils.concat(new String[]{OPENSSL_BIN, cmd[1]}, ENGINE_FLAG,
                java.util.Arrays.copyOfRange(cmd, 2, cmd.length));
        OpenSslChecker.exec(full);
    }


}
