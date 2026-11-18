package org.rssys.gost.crossval.pkcs12;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.pkcs12.OpenSslPkcs12Helper.PfxBundle;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * Кросс-валидация PKCS12: GostPkcs12Loader <-> OpenSSL gost-engine.
 * <p>
 * Для каждой ГОСТ-кривой, поддерживаемой OpenSSL:
 * — OpenSSL генерирует ключ + сертификат + PFX;
 * — GostPkcs12Loader загружает PFX;
 * — верифицируется соответствие ключа, подпись, реакция на повреждённые данные.
 * <p>
 * Тест пропускается, если OpenSSL или gost-engine недоступны.
 * <p>
 * Важно: PFX, который {@code openssl pkcs12 -export} создаёт без {@code -keypbe}/{@code -macalg},
 * не ГОСТ (AES-256-CBC, SHA-256), и читается загрузчиком через откат на JDK KeyStore. Такие тесты
 * названы «откат на JDK» и проверяют именно его; ГОСТ MAC и шифрование ключа проверяют
 * {@link OpenSslPkcs12GostMacCrossValidationTest} и сценарий 7.
 */
@DisplayName("PKCS12: кросс-валидация GostPkcs12Loader <-> OpenSSL gost-engine")
class OpenSslPkcs12CrossValidationTest {

    private static final Pattern PEM_KEY =
            Pattern.compile("-----BEGIN PRIVATE KEY-----([^-]+)-----END PRIVATE KEY-----");
    private static final char[] PASSWORD       = "crossval-test".toCharArray();
    private static final char[] WRONG_PASSWORD = "wrong".toCharArray();
    private static final char[] EMPTY_PASSWORD = new char[0];
    private static final String PASSWORD_STR   = "crossval-test";

    record PkcsSpec(String name, String algo, String paramset) {
        @Override public String toString() { return name; }
    }

    static Stream<PkcsSpec> curves() {
        return Stream.of(
            new PkcsSpec("gost2012_256/A", "gost2012_256", "A"),
            new PkcsSpec("gost2012_256/B", "gost2012_256", "B"),
            new PkcsSpec("gost2012_256/C", "gost2012_256", "C"),
            new PkcsSpec("gost2012_512/A", "gost2012_512", "A"),
            new PkcsSpec("gost2012_512/B", "gost2012_512", "B")
        );
    }

    private static ECParameters specToParams(PkcsSpec spec) {
        return switch (spec.algo()) {
            case "gost2012_256" -> switch (spec.paramset()) {
                case "A" -> ECParameters.cryptoProA();
                case "B" -> ECParameters.cryptoProB();
                case "C" -> ECParameters.cryptoProC();
                default -> throw new IllegalArgumentException("Unknown paramset: " + spec.paramset());
            };
            case "gost2012_512" -> switch (spec.paramset()) {
                case "A" -> ECParameters.tc26a512();
                case "B" -> ECParameters.tc26b512();
                default -> throw new IllegalArgumentException("Unknown paramset: " + spec.paramset());
            };
            default -> throw new IllegalArgumentException("Unknown algo: " + spec.algo());
        };
    }

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeGostPkcs12();
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("откат на JDK: OpenSSL -> PFX (не ГОСТ) -> load -> ключ и сертификат")
    void testRoundtrip(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-rt-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD, true);

            assertNotNull(r.getPrivateKey(),            spec + ": privateKey null");
            assertNotNull(r.getCertificateChain(),      spec + ": chain null");
            assertFalse(r.getCertificateChain().isEmpty(), spec + ": chain empty");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("откат на JDK: ключи совпадают, загруженный ключ даёт ту же точку Q, что и исходный DER")
    void testKeyCorrespondence(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-key-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);

            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD, true);
            PrivateKeyParameters loaded = r.getPrivateKey();
            ECParameters params = loaded.getParams();
            ECPoint g = ECPoint.affine(params.gx, params.gy, params);

            // Валидация против сертификата: Q_cert == d_loaded * G
            PublicKeyParameters pub = r.getCertificateChain().get(0).getPublicKey();
            ECPoint qCert = pub.getQ();
            ECPoint qFromD = g.multiply(loaded.getD()).normalize();
            assertEquals(qCert.getX(), qFromD.getX(),
                spec + ": X координата Q из сертификата не совпадает с d*G");
            assertEquals(qCert.getY(), qFromD.getY(),
                spec + ": Y координата Q из сертификата не совпадает с d*G");

            loaded.destroy();
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("откат на JDK: загруженный ключ подписывает, публичный из PFX верифицирует")
    void testSignVerify(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-sig-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD, true);

            PrivateKeyParameters priv = r.getPrivateKey();
            PublicKeyParameters pub   = r.getCertificateChain().get(0).getPublicKey();

            byte[] msg = "test message for sign".getBytes(StandardCharsets.UTF_8);
            byte[] sig = Signature.sign(msg, priv);
            assertTrue(Signature.verify(msg, sig, pub),
                spec + ": подпись не верифицирована");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("откат на JDK: повреждённые данные -> IllegalArgumentException")
    void testCorruptedData(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-cor-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            byte[] corrupted = b.pfx().clone();
            corrupted[corrupted.length / 2] ^= 0xFF;

            assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(corrupted, PASSWORD, true),
                spec + ": повреждённый PFX должен отклоняться");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("откат на JDK: неверный пароль -> IllegalArgumentException")
    void testWrongPassword(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-wp-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(b.pfx(), WRONG_PASSWORD, true),
                spec + ": неверный пароль должен отклоняться");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("откат на JDK: пустой пароль, OpenSSL создаёт PFX, loader загружает успешно")
    void testEmptyPassword(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-ep-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), "");
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), EMPTY_PASSWORD, true);
            assertNotNull(r.getPrivateKey(), spec + ": privateKey null при пустом пароле");
            return null;
        });
    }

    // ========================================================================
    // Reverse: GostPkcs12Builder -> PFX -> OpenSSL
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("структура нашего PFX: GostPkcs12Builder -> OpenSSL разбирает (MAC проверяют отдельные тесты)")
    void testBuilderToOpenSsl(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-rev-", tmpDir -> {
            // Генерируем ключ + сертификат через OpenSSL
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);

            // Загружаем нашим loader'ом
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD, true);
            assertNotNull(r.getPrivateKey(), spec + ": privateKey");

            // Перепаковываем нашим builder'ом
            byte[] ourPfx = GostPkcs12Builder.create()
                    .key(r.getPrivateKey())
                    .certificate(r.getCertificateChain().get(0))
                    .password(PASSWORD)
                    .iterations(100)
                    .build();

            Path ourPfxFile = tmpDir.resolve("our.pfx");
            Files.write(ourPfxFile, ourPfx);

            // Проверяем, что OpenSSL может разобрать структуру нашего PFX
            OpenSslPkcs12Helper.verifyPfxStructureWithOpenSsl(ourPfxFile, PASSWORD_STR);

            // Roundtrip: наш PFX -> loader -> ключ и подпись
            GostPkcs12Loader.Result r2 = GostPkcs12Loader.load(ourPfx, PASSWORD, true, 50);
            assertNotNull(r2.getPrivateKey(), spec + ": roundtrip privateKey");

            byte[] msg = "cross-validation".getBytes(StandardCharsets.UTF_8);
            byte[] sig = org.rssys.gost.api.Signature.sign(msg, r2.getPrivateKey());
            assertTrue(org.rssys.gost.api.Signature.verify(msg, sig,
                    r2.getCertificateChain().get(0).getPublicKey()),
                    spec + ": sign/verify после roundtrip");

            return null;
        });
    }

    /**
     * Наш PFX (Streebog-512, Кузнечик CTR-ACPKM) читают сборки OpenSSL, умеющие проверять ГОСТ MAC:
     * MAC проверяется без {@code -nomacver}, ключ извлекается и совпадает с исходным. Сборки,
     * которые ГОСТ MAC не проверяют, пропускаются по пробе на эталонном PFX из RFC 9548.
     */
    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("Сценарий 7: библиотека генерирует ключ+сертификат -> PFX (Streebog-512) -> сборки OpenSSL с ГОСТ MAC читают")
    void testLibraryKeyPfxToOpenSsl(PkcsSpec spec) throws Exception {
        List<OpenSslToolchain> capable = OpenSslToolchain.available().stream()
                .filter(OpenSslToolchain::canVerifyGostMac)
                .toList();
        assumeFalse(capable.isEmpty(),
                "ни одна сборка OpenSSL не проверяет ГОСТ MAC в PKCS#12: " + OpenSslToolchain.available());
        TempDirUtils.withTempDir("pkcs12-lib-", tmpDir -> {
            ECParameters params = specToParams(spec);

            KeyPair keyPair = KeyGenerator.generateKeyPair(params);
            PrivateKeyParameters privKey = keyPair.getPrivate();
            PublicKeyParameters pubKey = keyPair.getPublic();

            GostCertificate cert = GostCertificateBuilder.create(params, "CN=crossval-library")
                    .publicKey(pubKey)
                    .notBefore("20250101000000Z")
                    .notAfter("21010101000000Z")
                    .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                    .serial(BigInteger.valueOf(1))
                    .sign(privKey);

            byte[] pfx = GostPkcs12Builder.create()
                    .key(privKey)
                    .certificate(cert)
                    .password(PASSWORD)
                    .encScheme(GostOids.KUZ_CTR_ACPKM)
                    .friendlyName("crossval-library")
                    .build();

            Path pfxFile = tmpDir.resolve("library.pfx");
            Files.write(pfxFile, pfx);
            Path passwordFile = OpenSslToolchain.passwordFile(tmpDir, PASSWORD_STR);

            try {
                for (OpenSslToolchain toolchain : capable) {
                    OpenSslToolchain.Result result =
                            toolchain.pkcs12(pfxFile, passwordFile, "-nocerts", "-nodes");
                    assertTrue(result.ok(),
                            spec + ", " + toolchain + ": OpenSSL не прочитал PFX, созданный библиотекой: "
                                    + result.output());
                    Matcher matcher = PEM_KEY.matcher(result.output());
                    assertTrue(matcher.find(), spec + ", " + toolchain + ": в выводе OpenSSL нет ключа");
                    byte[] der = Base64.getMimeDecoder().decode(matcher.group(1));
                    PrivateKeyParameters extracted = GostDerCodec.decodePrivateKey(der);
                    try {
                        assertArrayEquals(privKey.getDBytes(), extracted.getDBytes(),
                                spec + ", " + toolchain + ": ключ, извлечённый OpenSSL, не совпал с исходным");
                    } finally {
                        extracted.destroy();
                        Arrays.fill(der, (byte) 0);
                    }
                }
            } finally {
                privKey.destroy();
            }
            return null;
        });
    }
}
