package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;

/**
 * Интероп примитивов: хэш Стрибога и сырая подпись ГОСТ Р 34.10-2012 {@code csptest -keyset}.
 *
 * <p>Направление «подпись КриптоПро -> наш {@code Signature.verify}» работает без правок
 * хэширования: сырая подпись КриптоПро - это {@code r‖s} в little-endian, а у библиотеки
 * {@code s‖r} в big-endian, то есть блок отличается полным разворотом байтов. Версия о том, что
 * КриптоПро считает «big-endian хэш», не подтвердилась: хэш совпадает побайтно, различается
 * только порядок байтов подписи.
 *
 * <p>Обратное направление («наша подпись -> проверка КриптоПро») не покрыто: {@code csptest
 * -verify} проверяет по импортированному ключу, а импорт ключа в этой установке недоступен.
 */
@DisplayName("Ключи и подпись: csptest -keyset и csptest -hash против crypto-gost")
class CryptoproKeysetInteropTest {

    private static final String HASH_OID_256 = "1.2.643.7.1.1.2.2";
    private static final String HASH_OID_512 = "1.2.643.7.1.1.2.3";
    private static final int DIGEST_SIZE_256 = 32;
    private static final int DIGEST_SIZE_512 = 64;
    private static final byte[] PAYLOAD =
            "keyset interop payload".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
    }

    @ParameterizedTest(name = "Стрибог {1} бит")
    @CsvSource({HASH_OID_256 + ", 256", HASH_OID_512 + ", 512"})
    @DisplayName("csptest -hash: хэш КриптоПро совпадает с Digest побайтно")
    void hashMatches(String hashOid, int bits) throws Exception {
        TempDirUtils.withTempDir("cp-hash-", dir -> {
            Path input = dir.resolve("data.bin");
            Files.write(input, PAYLOAD);
            Path output = dir.resolve("hash.bin");
            CspContainer.runOk("csptest -hash", CryptoProChecker.resolveCsptestBinary(),
                    "-notime", "-hash", "-alg", hashOid,
                    "-in", input.toString(), "-out", output.toString());

            // csptest кладёт хэш в конец DigestedData (PKCS#7): берём последние байты
            int size = bits == 256 ? DIGEST_SIZE_256 : DIGEST_SIZE_512;
            byte[] encoded = Files.readAllBytes(output);
            byte[] cryptoproDigest =
                    Arrays.copyOfRange(encoded, encoded.length - size, encoded.length);
            byte[] ourDigest = bits == 256 ? Digest.digest256(PAYLOAD) : Digest.digest512(PAYLOAD);
            assertArrayEquals(ourDigest, cryptoproDigest,
                    "Стрибог-" + bits + " КриптоПро и crypto-gost должны давать один хэш");
            return null;
        });
    }

    @ParameterizedTest(name = "{2} бит")
    @CsvSource({
        CspContainer.PROVIDER_TYPE_256 + ", GOST12_256, 256, 64",
        CspContainer.PROVIDER_TYPE_512 + ", GOST12_512, 512, 128"
    })
    @DisplayName("csptest -keyset -sign: подпись КриптоПро проверяется Signature.verify (после разворота байтов)")
    void cryptoproSignatureVerifiesWithLibrary(
            String providerType, String hashAlg, int bits, int signatureSize) throws Exception {
        try (CspContainer container = CspContainer.create("ks" + bits, providerType, false)) {
            TempDirUtils.withTempDir("cp-sign-", dir -> {
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

                byte[] cryptoproSignature = Files.readAllBytes(signatureFile);
                assertEquals(signatureSize, cryptoproSignature.length,
                        "сырая подпись " + bits + " бит должна быть " + signatureSize + " байт");
                GostCertificate certificate = new GostCertificate(Files.readAllBytes(certFile));
                // кривая здесь не задаётся, её выбирает провайдер; фиксируем ожидаемую, чтобы
                // смена умолчания КриптоПро не прошла незамеченной (все 7 кривых с явным выбором
                // проверяет CryptoproCurvesInteropTest)
                assertSame(
                        bits == 256 ? ECParameters.cryptoProA() : ECParameters.tc26a512(),
                        certificate.getPublicKey().getParams(),
                        "провайдер по умолчанию создал ключ на другой кривой");

                byte[] libraryForm = reversed(cryptoproSignature);
                assertTrue(Signature.verify(PAYLOAD, libraryForm, certificate.getPublicKey()),
                        "подпись КриптоПро (r‖s, little-endian) после полного разворота"
                                + " должна проверяться как s‖r big-endian");

                // контроль: те же байты без разворота и подпись под другими данными не принимаются,
                // иначе положительный результат выше ничего не доказывает
                assertFalse(Signature.verify(PAYLOAD, cryptoproSignature, certificate.getPublicKey()),
                        "подпись КриптоПро без разворота байтов не должна проходить");
                byte[] otherPayload = "other payload".getBytes(StandardCharsets.UTF_8);
                assertFalse(Signature.verify(otherPayload, libraryForm, certificate.getPublicKey()),
                        "подпись не должна проходить для других данных");
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
