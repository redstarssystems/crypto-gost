package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Все 7 зарегистрированных кривых против КриптоПро: ключ создаётся на кривой, выбранной явно
 * ({@code -signoid}), а не той, что провайдер берёт по умолчанию.
 *
 * <p>Два условия вместе доказывают, что кривая у КриптоПро та же, что и у библиотеки:
 * OID в сертификате даёт именно наш зарегистрированный экземпляр, и подпись КриптоПро
 * проверяется нашими параметрами (p, a, b, G, n). Одно совпадение OID не доказало бы, что
 * константы равны, а одна проверка подписи не доказала бы, что взята нужная кривая.
 * Для кривых с кофактором 4 (TC26-A-256, TC26-C-512) открытый ключ КриптоПро дополнительно
 * проходит нашу проверку принадлежности подгруппе порядка n в конструкторе ключа.
 */
@DisplayName("Кривые: ключ КриптоПро на каждой из 7 кривых совпадает с параметрами библиотеки")
class CryptoproCurvesInteropTest {

    private static final byte[] PAYLOAD =
            "curves interop payload".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
    }

    static Stream<Arguments> curves() {
        String p256 = CspContainer.PROVIDER_TYPE_256;
        String p512 = CspContainer.PROVIDER_TYPE_512;
        return Stream.of(
                Arguments.of("TC26-A-256", p256, "GOST12_256", GostCurves.OID_TC26_A_256,
                        (Supplier<ECParameters>) ECParameters::tc26a256),
                Arguments.of("CryptoPro-A", p256, "GOST12_256", GostCurves.OID_CRYPTOPRO_A,
                        (Supplier<ECParameters>) ECParameters::cryptoProA),
                Arguments.of("CryptoPro-B", p256, "GOST12_256", GostCurves.OID_CRYPTOPRO_B,
                        (Supplier<ECParameters>) ECParameters::cryptoProB),
                Arguments.of("CryptoPro-C", p256, "GOST12_256", GostCurves.OID_CRYPTOPRO_C,
                        (Supplier<ECParameters>) ECParameters::cryptoProC),
                Arguments.of("TC26-A-512", p512, "GOST12_512", GostCurves.OID_TC26_A_512,
                        (Supplier<ECParameters>) ECParameters::tc26a512),
                Arguments.of("TC26-B-512", p512, "GOST12_512", GostCurves.OID_TC26_B_512,
                        (Supplier<ECParameters>) ECParameters::tc26b512),
                Arguments.of("TC26-C-512", p512, "GOST12_512", GostCurves.OID_TC26_C_512,
                        (Supplier<ECParameters>) ECParameters::tc26c512));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Кривая сертификата КриптоПро равна нашей, подпись КриптоПро проверяется")
    void cryptoproCurveMatchesLibrary(
            String name,
            String providerType,
            String hashAlg,
            String signOid,
            Supplier<ECParameters> expected)
            throws Exception {
        try (CspContainer container =
                CspContainer.create("cv" + name, providerType, false, signOid)) {
            TempDirUtils.withTempDir("cp-curve-", dir -> {
                Path input = dir.resolve("data.bin");
                Files.write(input, PAYLOAD);
                Path signatureFile = dir.resolve("sig.bin");
                Path certFile = dir.resolve("key.cer");
                container.exportCertificate(certFile, providerType);
                CspContainer.runOk("csptest -sign", CryptoProChecker.resolveCsptestBinary(),
                        "-notime", "-keyset", "-sign", hashAlg, "-container", container.path(),
                        "-provtype", providerType, "-keytype", "signature",
                        "-in", input.toString(), "-out", signatureFile.toString(),
                        "-password", CspContainer.PASSWORD);

                GostCertificate certificate = new GostCertificate(Files.readAllBytes(certFile));
                PublicKeyParameters key = certificate.getPublicKey();
                assertSame(expected.get(), key.getParams(),
                        "кривая сертификата КриптоПро не совпала с " + name);

                byte[] cryptoproSignature = Files.readAllBytes(signatureFile);
                byte[] libraryForm = reversed(cryptoproSignature);
                assertTrue(Signature.verify(PAYLOAD, libraryForm, key),
                        "подпись КриптоПро на кривой " + name + " не проверилась нашими параметрами");
                // контроль: подпись под другими данными не принимается
                assertFalse(
                        Signature.verify(
                                "other payload".getBytes(StandardCharsets.UTF_8), libraryForm, key),
                        "подпись не должна проходить для других данных на кривой " + name);
                assertEquals(
                        2 * expected.get().hlen,
                        cryptoproSignature.length,
                        "длина сырой подписи на кривой " + name);
                return null;
            });
        }
    }

    private static byte[] reversed(byte[] source) {
        byte[] result = new byte[source.length];
        for (int i = 0; i < source.length; i++) {
            result[i] = source[source.length - 1 - i];
        }
        return result;
    }
}
