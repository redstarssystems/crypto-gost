package org.rssys.gost.crossval.pkcs12;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.pkcs12.OpenSslToolchain.Result;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.GostPkcs12Mac;
import org.rssys.gost.pkix.cert.GostPkcs12Parser;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.MacData;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.PfxData;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Кросс-валидация MAC и шифрования ключа PFX (RFC 9548) на доступных сборках OpenSSL.
 * <p>
 * Каждый тест параметризован сборкой OpenSSL; версия сборки видна в имени запуска. Что умеет
 * сборка, определяется пробой на эталонном PFX из RFC 9548: сборки без проверки ГОСТ MAC в PKCS#12
 * пропускаются с причиной. Пароль везде кириллический, как в RFC: стандарт требует UTF-8.
 */
@DisplayName("PKCS#12: MAC и шифрование ключа по RFC 9548 <-> OpenSSL (по сборкам)")
class OpenSslPkcs12GostMacCrossValidationTest {

    private static final String PASSWORD = OpenSslToolchain.RFC_PASSWORD;
    private static final int ITERATIONS = 2000;
    private static final Pattern PEM_KEY =
            Pattern.compile("-----BEGIN PRIVATE KEY-----([^-]+)-----END PRIVATE KEY-----");

    /** Все доступные сборки OpenSSL. */
    static Stream<OpenSslToolchain> toolchains() {
        List<OpenSslToolchain> available = OpenSslToolchain.available();
        assumeTrue(!available.isEmpty(), "ни одна сборка OpenSSL с ГОСТ недоступна");
        return available.stream();
    }

    /** Сборки в сочетании со схемами шифрования ключа, которые пишет наша библиотека. */
    static Stream<Arguments> toolchainsAndSchemes() {
        return toolchains()
                .flatMap(
                        tc ->
                                Stream.of(GostOids.KUZ_CTR_ACPKM, GostOids.KUZ_CTR_ACPKM_OMAC)
                                        .map(scheme -> Arguments.of(tc, scheme)));
    }

    /**
     * Сторож от тихого пропуска: если все проверки ГОСТ MAC уходят в пропуск, прогон выглядит
     * зелёным, а проверка не выполнялась (так ошибка с OID MacData прожила до обнаружения).
     * На машине с включённым требованием отсутствие сборки с ГОСТ MAC - ошибка, а не пропуск.
     */
    @org.junit.jupiter.api.Test
    @DisplayName("сторож: найдена сборка OpenSSL, проверяющая и создающая ГОСТ MAC в PKCS#12")
    void atLeastOneBuildHandlesGostMac() {
        List<OpenSslToolchain> builds = OpenSslToolchain.available();
        boolean verifies = builds.stream().anyMatch(OpenSslToolchain::canVerifyGostMac);
        boolean exports = builds.stream().anyMatch(OpenSslToolchain::canExportGostMac);
        if (OpenSslToolchain.gostMacRequired()) {
            assertTrue(
                    verifies,
                    "требуется (-D" + OpenSslToolchain.REQUIRE_GOST_MAC_PROPERTY
                            + "=true), но ни одна сборка не проверяет ГОСТ MAC в PKCS#12; найдены: " + builds);
            assertTrue(
                    exports,
                    "требуется (-D" + OpenSslToolchain.REQUIRE_GOST_MAC_PROPERTY
                            + "=true), но ни одна сборка не создаёт PFX с ГОСТ MAC; найдены: " + builds);
        } else {
            assumeTrue(
                    verifies && exports,
                    "нет сборки с ГОСТ MAC в PKCS#12 (проверки пропущены); найдены: " + builds);
        }
    }

    /** Наш PFX и исходный закрытый ключ. */
    private record OurPfx(byte[] pfx, PrivateKeyParameters key) {}

    private static OurPfx buildOurPfx(String encSchemeOid, String commonName) throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair keyPair = KeyGenerator.generateKeyPair(params);
        GostCertificate cert =
                GostCertificateBuilder.create(params, "CN=" + commonName)
                        .publicKey(keyPair.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .serial(BigInteger.valueOf(7))
                        .sign(keyPair.getPrivate());
        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(keyPair.getPrivate())
                        .certificate(cert)
                        .password(PASSWORD.toCharArray())
                        .iterations(ITERATIONS)
                        .encScheme(encSchemeOid)
                        .friendlyName(commonName)
                        .build();
        return new OurPfx(pfx, keyPair.getPrivate());
    }

    private static void assumeCanVerifyGostMac(OpenSslToolchain tc) {
        assumeTrue(
                tc.canVerifyGostMac(),
                tc + ": сборка не проверяет ГОСТ MAC в PKCS#12 (проба на эталонном PFX из RFC 9548)");
    }

    // ========================================================================
    // Наш PFX -> OpenSSL
    // ========================================================================

    @ParameterizedTest(name = "{0}, схема {1}")
    @MethodSource("toolchainsAndSchemes")
    @DisplayName("наш PFX: OpenSSL проверяет MAC без -nomacver (кириллический пароль, соль 32)")
    void ourPfxMacIsVerifiedByOpenSsl(OpenSslToolchain tc, String encSchemeOid) throws Exception {
        assumeCanVerifyGostMac(tc);
        TempDirUtils.withTempDir(
                "pkcs12-mac-",
                dir -> {
                    OurPfx ours = buildOurPfx(encSchemeOid, "crossval-mac");
                    try {
                        Path pfxFile = dir.resolve("ours.pfx");
                        Files.write(pfxFile, ours.pfx());

                        Result result =
                                tc.pkcs12(
                                        pfxFile,
                                        OpenSslToolchain.passwordFile(dir, PASSWORD),
                                        "-nokeys",
                                        "-nocerts",
                                        "-noout");

                        assertTrue(
                                result.ok(),
                                tc + ": OpenSSL не проверил MAC нашего PFX: " + result.output());
                    } finally {
                        ours.key().destroy();
                    }
                    return null;
                });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("toolchains")
    @DisplayName("наш PFX (CTR-ACPKM): OpenSSL извлекает ключ, он совпадает с исходным")
    void ourPfxKeyIsExtractedByOpenSsl(OpenSslToolchain tc) throws Exception {
        assumeCanVerifyGostMac(tc);
        TempDirUtils.withTempDir(
                "pkcs12-key-",
                dir -> {
                    OurPfx ours = buildOurPfx(GostOids.KUZ_CTR_ACPKM, "crossval-key");
                    Path pfxFile = dir.resolve("ours.pfx");
                    Files.write(pfxFile, ours.pfx());

                    Result result =
                            tc.pkcs12(
                                    pfxFile,
                                    OpenSslToolchain.passwordFile(dir, PASSWORD),
                                    "-nocerts",
                                    "-nodes");

                    assertTrue(
                            result.ok(),
                            tc + ": OpenSSL не извлёк ключ нашего PFX: " + result.output());
                    PrivateKeyParameters extracted = decodePemKey(result.output());
                    try {
                        assertArrayEquals(
                                ours.key().getDBytes(),
                                extracted.getDBytes(),
                                tc + ": ключ, извлечённый OpenSSL, должен совпадать с исходным");
                    } finally {
                        extracted.destroy();
                        ours.key().destroy();
                    }
                    return null;
                });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("toolchains")
    @DisplayName("наш PFX: MAC воспроизводится независимо через openssl kdf и dgst")
    void ourPfxMacIsReproducedByKdfAndDgst(OpenSslToolchain tc) throws Exception {
        TempDirUtils.withTempDir(
                "pkcs12-kdf-",
                dir -> {
                    OurPfx ours = buildOurPfx(GostOids.KUZ_CTR_ACPKM_OMAC, "crossval-kdf");
                    // исходный ключ здесь не нужен, а закрытый ключ не оставляем в памяти до GC
                    ours.key().destroy();
                    PfxData data = GostPkcs12Parser.parsePfx(ours.pfx(), ITERATIONS);
                    MacData macData = data.getMacData();
                    byte[] password = PASSWORD.getBytes(StandardCharsets.UTF_8);
                    HexFormat hex = HexFormat.of();

                    // PBKDF2(P, S, c, 96) на PRF HMAC-Стрибог-512: ключ MAC - последние 32 байта
                    Result kdf =
                            tc.runWithProvider(
                                    "kdf",
                                    "-keylen",
                                    "96",
                                    "-kdfopt",
                                    "digest:md_gost12_512",
                                    "-kdfopt",
                                    "hexpass:" + hex.formatHex(password),
                                    "-kdfopt",
                                    "hexsalt:" + hex.formatHex(macData.getSalt()),
                                    "-kdfopt",
                                    "iter:" + macData.getIterations(),
                                    "PBKDF2");
                    assumeTrue(kdf.ok(), tc + ": сборка не выполняет PBKDF2 на md_gost12_512: " + kdf.output());
                    String derived = kdf.output().replace(":", "").replace("\n", "").trim();
                    assertEquals(192, derived.length(), tc + ": PBKDF2 должен вернуть 96 байт");
                    String hmacKeyHex = derived.substring(derived.length() - 64);

                    Path authSafeFile = dir.resolve("authsafe.der");
                    Files.write(authSafeFile, data.getAuthSafeRawContent());
                    Result dgst =
                            tc.runWithProvider(
                                    "dgst",
                                    "-md_gost12_512",
                                    "-mac",
                                    "HMAC",
                                    "-macopt",
                                    "hexkey:" + hmacKeyHex,
                                    authSafeFile.toString());
                    assumeTrue(dgst.ok(), tc + ": сборка не считает HMAC на md_gost12_512: " + dgst.output());
                    String computed = dgst.output().substring(dgst.output().lastIndexOf('=') + 1).trim();

                    assertEquals(
                            hex.formatHex(macData.getDigestValue()),
                            computed.toLowerCase(),
                            tc + ": MAC из нашего PFX должен совпасть с MAC, посчитанным OpenSSL");
                    return null;
                });
    }

    // ========================================================================
    // Эталонные PFX из RFC 9548 -> OpenSSL (независимая проверка того, что проверяем мы)
    // ========================================================================

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("toolchainsAndRfcFiles")
    @DisplayName("эталонный PFX из RFC 9548: OpenSSL проверяет MAC")
    void rfcPfxMacIsVerifiedByOpenSsl(OpenSslToolchain tc, String example) throws Exception {
        assumeCanVerifyGostMac(tc);
        TempDirUtils.withTempDir(
                "pkcs12-rfc-",
                dir -> {
                    Path pfxFile = dir.resolve(example + ".pfx");
                    Files.write(pfxFile, "A.2".equals(example) ? RfcPfx.a2() : RfcPfx.a3());

                    Result result =
                            tc.pkcs12(
                                    pfxFile,
                                    OpenSslToolchain.passwordFile(dir, PASSWORD),
                                    "-nokeys",
                                    "-nocerts",
                                    "-noout");

                    assertFalse(
                            result.output().contains("Mac verify error"),
                            tc + ": OpenSSL отверг MAC примера " + example + ": " + result.output());
                    // В A.3 сертификат лежит в EncryptedData под Магмой CTR-ACPKM-OMAC: OpenSSL
                    // проверяет MAC до расшифровки, а расшифровка этой схемы ему недоступна.
                    // Поэтому для A.3 допустим только отказ на выводе ключей и сертификатов
                    assertTrue(
                            result.ok()
                                    || ("A.3".equals(example)
                                            && result.output()
                                                    .contains("Error outputting keys and certificates")),
                            tc + ": неожиданный отказ OpenSSL на примере " + example + ": " + result.output());
                    return null;
                });
    }

    static Stream<Arguments> toolchainsAndRfcFiles() {
        return toolchains().flatMap(tc -> Stream.of("A.2", "A.3").map(ex -> Arguments.of(tc, ex)));
    }

    // ========================================================================
    // OpenSSL -> мы: единственная внешняя проверка нашего чтения MacData
    // ========================================================================

    @ParameterizedTest(name = "{0}")
    @MethodSource("toolchains")
    @DisplayName("PFX от OpenSSL (-macalg md_gost12_512): наша проверка MAC проходит")
    void openSslPfxMacIsVerifiedByOurVerifier(OpenSslToolchain tc) throws Exception {
        assumeTrue(tc.canExportGostMac(), tc + ": сборка не создаёт PFX с ГОСТ MAC (-macalg md_gost12_512)");
        TempDirUtils.withTempDir(
                "pkcs12-ossl-",
                dir -> {
                    Path pfxFile = dir.resolve("ossl.pfx");
                    Result export = tc.exportGostMacPfx(dir, pfxFile, PASSWORD);
                    assertTrue(export.ok(), tc + ": экспорт PFX с ГОСТ MAC не удался: " + export.output());

                    byte[] pfx = Files.readAllBytes(pfxFile);
                    PfxData data = GostPkcs12Parser.parsePfx(pfx, 1);
                    MacData macData = data.getMacData();

                    assertEquals(
                            GostOids.DIGEST_512,
                            macData.getDigestAlgorithm(),
                            tc + ": OpenSSL должен писать OID хэша id-tc26-gost3411-12-512");
                    // Это единственный тест на чтение NULL в параметрах алгоритма на реальном файле:
                    // если OpenSSL перестанет писать NULL, тест должен сообщить, что потерял смысл
                    assertTrue(
                            contains(pfx, DerCodec.encodeSequence(
                                    DerCodec.encodeOid(GostOids.DIGEST_512), DerCodec.encodeNull())),
                            tc + ": AlgorithmIdentifier в MacData должен содержать OID и параметры NULL (05 00)");
                    assertEquals(
                            GostOids.MIN_PBKDF2_SALT_LEN,
                            macData.getSalt().length,
                            tc + ": соль MacData от OpenSSL - нижняя граница RFC (8 байт)");
                    assertTrue(
                            contains(pfx, DerCodec.encodeOid(GostOids.KUZ_CTR_ACPKM)),
                            tc + ": ключ в PFX должен быть зашифрован ГОСТ PBES2 (Кузнечик CTR-ACPKM)");
                    byte[] password = PASSWORD.getBytes(StandardCharsets.UTF_8);
                    assertDoesNotThrow(
                            () ->
                                    GostPkcs12Mac.verify(
                                            macData, password, data.getAuthSafeRawContent()),
                            tc + ": наша проверка MAC PFX, созданного OpenSSL, должна проходить");
                    return null;
                });
    }

    // ========================================================================
    // Вспомогательное
    // ========================================================================

    private static PrivateKeyParameters decodePemKey(String openSslOutput) {
        Matcher matcher = PEM_KEY.matcher(openSslOutput);
        assertTrue(matcher.find(), "в выводе OpenSSL нет блока PRIVATE KEY");
        byte[] der = Base64.getMimeDecoder().decode(matcher.group(1));
        try {
            return GostDerCodec.decodePrivateKey(der);
        } finally {
            java.util.Arrays.fill(der, (byte) 0);
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
