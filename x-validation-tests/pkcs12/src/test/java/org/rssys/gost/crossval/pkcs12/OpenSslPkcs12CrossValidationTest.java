package org.rssys.gost.crossval.pkcs12;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.pkcs12.OpenSslPkcs12Helper.PfxBundle;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.GostPkcs12Builder;
import org.rssys.gost.tls13.cert.GostPkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Кросс-валидация PKCS12: GostPkcs12Loader ↔ OpenSSL gost-engine.
 * <p>
 * Для каждой ГОСТ-кривой, поддерживаемой OpenSSL:
 * — OpenSSL генерирует ключ + сертификат + PFX;
 * — GostPkcs12Loader загружает PFX;
 * — верифицируется соответствие ключа, подпись, реакция на повреждённые данные.
 * <p>
 * Тест пропускается, если OpenSSL или gost-engine недоступны.
 */
@DisplayName("PKCS12: кросс-валидация GostPkcs12Loader ↔ OpenSSL gost-engine")
class OpenSslPkcs12CrossValidationTest {

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

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeGostPkcs12();
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("roundtrip: OpenSSL -> PFX -> load -> ключ и сертификат")
    void testRoundtrip(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-rt-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD);

            assertNotNull(r.getPrivateKey(),            spec + ": privateKey null");
            assertNotNull(r.getCertificateChain(),      spec + ": chain null");
            assertFalse(r.getCertificateChain().isEmpty(), spec + ": chain empty");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("ключи совпадают: загруженный ключ даёт ту же точку Q, что и исходный DER")
    void testKeyCorrespondence(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-key-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);

            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD);
            PrivateKeyParameters loaded = r.getPrivateKey();
            ECParameters params = loaded.getParams();
            ECPoint g = ECPoint.affine(params.gx, params.gy, params);

            // Валидация против сертификата: Q_cert == d_loaded * G
            PublicKeyParameters pub = r.getCertificateChain().get(0).getPublicKey();
            ECPoint qCert = pub.getQ().normalize();
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
    @DisplayName("подпись/проверка: загруженный ключ подписывает, публичный из PFX верифицирует")
    void testSignVerify(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-sig-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD);

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
    @DisplayName("повреждённые данные -> IllegalArgumentException")
    void testCorruptedData(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-cor-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            byte[] corrupted = b.pfx().clone();
            corrupted[corrupted.length / 2] ^= 0xFF;

            assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(corrupted, PASSWORD),
                spec + ": повреждённый PFX должен отклоняться");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("неверный пароль -> IllegalArgumentException")
    void testWrongPassword(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-wp-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);
            assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(b.pfx(), WRONG_PASSWORD),
                spec + ": неверный пароль должен отклоняться");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("пустой пароль: OpenSSL создаёт PFX, loader загружает успешно")
    void testEmptyPassword(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-ep-", tmpDir -> {
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), "");
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), EMPTY_PASSWORD);
            assertNotNull(r.getPrivateKey(), spec + ": privateKey null при пустом пароле");
            return null;
        });
    }

    // ========================================================================
    // Reverse: GostPkcs12Builder → PFX → OpenSSL
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @DisplayName("reverse: GostPkcs12Builder -> PFX -> OpenSSL читает")
    void testBuilderToOpenSsl(PkcsSpec spec) throws Exception {
        TempDirUtils.withTempDir("pkcs12-rev-", tmpDir -> {
            // Генерируем ключ + сертификат через OpenSSL
            PfxBundle b = OpenSslPkcs12Helper.buildPfxWithKey(
                    tmpDir, spec.algo(), spec.paramset(), PASSWORD_STR);

            // Загружаем нашим loader'ом
            GostPkcs12Loader.Result r = GostPkcs12Loader.load(b.pfx(), PASSWORD);
            assertNotNull(r.getPrivateKey(), spec + ": privateKey");

            // Перепаковываем нашим builder'ом
            byte[] ourPfx = GostPkcs12Builder.newBuilder()
                    .key(r.getPrivateKey())
                    .certificate(r.getCertificateChain().get(0))
                    .password(PASSWORD)
                    .iterations(100)
                    .build();

            Path ourPfxFile = tmpDir.resolve("our.pfx");
            Files.write(ourPfxFile, ourPfx);

            // Проверяем, что OpenSSL может разобрать структуру нашего PFX
            OpenSslPkcs12Helper.verifyPfxStructureWithOpenSsl(ourPfxFile, PASSWORD_STR);

            // Roundtrip: наш PFX → loader → ключ и подпись
            GostPkcs12Loader.Result r2 = GostPkcs12Loader.load(ourPfx, PASSWORD);
            assertNotNull(r2.getPrivateKey(), spec + ": roundtrip privateKey");

            byte[] msg = "cross-validation".getBytes(StandardCharsets.UTF_8);
            byte[] sig = org.rssys.gost.api.Signature.sign(msg, r2.getPrivateKey());
            assertTrue(org.rssys.gost.api.Signature.verify(msg, sig,
                    r2.getCertificateChain().get(0).getPublicKey()),
                    spec + ": sign/verify после roundtrip");

            return null;
        });
    }
}
