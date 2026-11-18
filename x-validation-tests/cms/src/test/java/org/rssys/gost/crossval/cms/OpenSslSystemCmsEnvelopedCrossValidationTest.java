package org.rssys.gost.crossval.cms;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Двусторонняя кросс-валидация CMS EnvelopedData между crypto-gost и референсной
 * реализацией GOST — <b>системным</b> OpenSSL (ГОСТ-движок {@code -engine gost}),
 * а НЕ провайдером из {@code /opt} (gostprov не реализует asym-cipher для GOST,
 * поэтому CMS EnvelopedData через него невозможен).
 *
 * <p>Проверяются оба направления:
 * <ul>
 *   <li>A: crypto-gost шифрует -> {@code openssl cms -decrypt} расшифровывает;</li>
 *   <li>B: {@code openssl cms -encrypt} шифрует -> crypto-gost расшифровывает.</li>
 * </ul>
 * Получатель — GOST 34.10-2012-256 ключ+сертификат на кривой XchA
 * ({@code paramset:XA}), сгенерированные системным OpenSSL.
 *
 * <p>Тесты активируются только при наличии системного OpenSSL с ГОСТ-движком
 * (см. {@link #systemOpensslGostCmsAvailable()}); иначе — пропуск.
 */
@DisplayName("CMS EnvelopedData: двусторонняя кросс-валидация с системным OpenSSL (engine gost)")
class OpenSslSystemCmsEnvelopedCrossValidationTest {

    // Системный OpenSSL, а не /opt: gostprov-провайдер не умеет GOST asym-cipher.
    private static final String SYS_OPENSSL =
            System.getProperty("openssl.system.binary", "/usr/bin/openssl");

    private static final String ENGINE_OPT = "-engine";
    private static final String ENGINE_GOST = "gost";
    private static final String MD_GOST_2012_256 = "-md_gost12_256";
    private static final String CIPHER_KUZ_CTR_ACPKM = "-kuznyechik-ctr-acpkm";
    private static final String CIPHER_KUZ_CTR_ACPKM_OMAC = "-kuznyechik-ctr-acpkm-omac";
    private static final String ALG_GOST_2012_256 = "gost2012_256";
    private static final String PKEYOPT_PARAMSET_XA = "paramset:XA";
    // Получателю задан KeyUsage явно, чтобы тест не зависел от openssl.cnf на машине:
    // сертификат без назначения ключа принимался бы всегда, а с ним проверяется и новое правило
    private static final String ADDEXT_OPT = "-addext";
    private static final String RECIPIENT_KEY_USAGE =
            "keyUsage=critical,keyEncipherment,dataEncipherment";

    private static final byte[] SHORT = "Привет, мир!\n".getBytes(StandardCharsets.UTF_8);

    // ------------------------------------------------------------------
    // Проверка версии и поддержки CMS/GOST
    // ------------------------------------------------------------------

    @Test
    @EnabledIf("systemOpensslAvailable")
    @DisplayName("Системный OpenSSL: версия >= 3.x, gost engine и поддержка cms -encrypt/-decrypt")
    void systemOpensslVersionAndCmsSupport() throws Exception {
        Captured version = runRaw(SYS_OPENSSL, "version");
        System.out.println("System OpenSSL: " + version.output().trim());
        assertTrue(
                version.output().startsWith("OpenSSL"),
                "вывод `openssl version` должен начинаться с OpenSSL");

        Matcher m = Pattern.compile("OpenSSL\\s+(\\d+)\\.").matcher(version.output());
        assertTrue(m.find(), "не удалось распарсить мажорную версию OpenSSL");
        assertTrue(
                Integer.parseInt(m.group(1)) >= 3,
                "для CMS-кросс-валидации нужна OpenSSL >= 3.x, найдена: " + version.output().trim());

        Captured engine = runRaw(SYS_OPENSSL, "engine", "gost");
        assertTrue(
                engine.output().contains("(gost)"),
                "ГОСТ-движок должен быть доступен (`openssl engine gost`), вывод: " + engine.output());

        // `cms -help` печатает usage в stderr и завершается ненулевым кодом — проверяем текст.
        Captured cmsHelp = runRaw(SYS_OPENSSL, "cms", "-help");
        assertTrue(
                cmsHelp.output().contains("-encrypt") && cmsHelp.output().contains("-decrypt"),
                "`openssl cms` должен поддерживать -encrypt/-decrypt");
    }

    // ------------------------------------------------------------------
    // Направление A: crypto-gost encrypt -> openssl decrypt
    // ------------------------------------------------------------------

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("Направление A: crypto-gost шифрует -> openssl cms -decrypt расшифровывает")
    void cryptoGostEncrypt_opensslDecrypt() throws Exception {
        TempDirUtils.withTempDir("cms-xval-a-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);
            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));

            // Обычный режим без имитовставки: именно его принимает OpenSSL как non-OMAC контейнер
            byte[] enveloped =
                    CmsEnvelopedDataBuilder.create()
                            .data(SHORT)
                            .addRecipient(recipientCert)
                            .withoutIntegrity()
                            .build();
            assertPlainContainer(enveloped);
            Path p7e = dir.resolve("cg-enc.p7e");
            Files.write(p7e, enveloped);

            Path out = dir.resolve("a-out.bin");
            runOk(
                    SYS_OPENSSL, "cms", ENGINE_OPT, ENGINE_GOST, "-decrypt",
                    "-inform", "DER", "-in", p7e.toString(),
                    "-recip", rcpt.certPem().toString(),
                    "-inkey", rcpt.keyPem().toString(),
                    "-out", out.toString());

            assertArrayEquals(
                    SHORT,
                    Files.readAllBytes(out),
                    "openssl (engine gost) должен расшифровать контейнер crypto-gost байт-в-байт");
            return null;
        });
    }

    // ------------------------------------------------------------------
    // Направление B: openssl encrypt -> crypto-gost decrypt
    // ------------------------------------------------------------------

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("Направление B: openssl cms -encrypt шифрует -> crypto-gost расшифровывает")
    void opensslEncrypt_cryptoGostDecrypt() throws Exception {
        TempDirUtils.withTempDir("cms-xval-b-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);

            Path plain = dir.resolve("plain.bin");
            Files.write(plain, SHORT);
            Path p7e = dir.resolve("ossl-enc.p7e");
            // -binary: без S/MIME CRLF-канонизации, иначе \n -> \r\n и контент отличается.
            runOk(
                    SYS_OPENSSL, "cms", ENGINE_OPT, ENGINE_GOST, "-encrypt", "-binary",
                    CIPHER_KUZ_CTR_ACPKM,
                    "-in", plain.toString(),
                    "-outform", "DER", "-out", p7e.toString(),
                    rcpt.certPem().toString());

            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));
            PrivateKeyParameters priv =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(rcpt.keyDer()));

            // Контейнер OpenSSL без имитовставки строгий decrypt не принимает
            byte[] opensslContainer = Files.readAllBytes(p7e);
            PkixException strictRefusal =
                    assertThrows(
                            PkixException.class,
                            () ->
                                    CmsEnvelopedDataDecryptor.decrypt(
                                            opensslContainer, priv, recipientCert),
                            "строгий decrypt должен отвергать контейнер OpenSSL без OMAC");
            assertEquals(
                    PkixException.Reason.INTEGRITY_REQUIRED,
                    strictRefusal.reason(),
                    "причина отказа строгого decrypt для контейнера OpenSSL");

            byte[] decrypted =
                    CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                            Files.readAllBytes(p7e), priv, recipientCert);

            assertArrayEquals(
                    SHORT,
                    decrypted,
                    "crypto-gost должен расшифровать контейнер openssl (engine gost) байт-в-байт");
            return null;
        });
    }

    // ------------------------------------------------------------------
    // OMAC: двусторонняя кросс-валидация
    // ------------------------------------------------------------------

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("Направление A (omac): crypto-gost шифрует с OMAC -> openssl cms -decrypt расшифровывает")
    void cryptoGostEncryptOmac_opensslDecrypt() throws Exception {
        TempDirUtils.withTempDir("cms-xval-a-omac-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);
            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));

            byte[] enveloped =
                    CmsEnvelopedDataBuilder.create()
                            .data(SHORT)
                            .addRecipient(recipientCert)
                            .build();
            assertOmacContainer(enveloped);
            Path p7e = dir.resolve("cg-enc-omac.p7e");
            Files.write(p7e, enveloped);

            Path out = dir.resolve("a-out-omac.bin");
            runOk(
                    SYS_OPENSSL, "cms", ENGINE_OPT, ENGINE_GOST, "-decrypt",
                    "-inform", "DER", "-in", p7e.toString(),
                    "-recip", rcpt.certPem().toString(),
                    "-inkey", rcpt.keyPem().toString(),
                    "-out", out.toString());

            assertArrayEquals(
                    SHORT,
                    Files.readAllBytes(out),
                    "openssl (engine gost) должен расшифровать OMAC-контейнер crypto-gost байт-в-байт");
            return null;
        });
    }

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("Направление B (omac): openssl cms -encrypt с OMAC -> crypto-gost расшифровывает")
    void opensslEncryptOmac_cryptoGostDecrypt() throws Exception {
        TempDirUtils.withTempDir("cms-xval-b-omac-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);

            Path plain = dir.resolve("plain.bin");
            Files.write(plain, SHORT);
            Path p7e = dir.resolve("ossl-enc-omac.p7e");
            runOk(
                    SYS_OPENSSL, "cms", ENGINE_OPT, ENGINE_GOST, "-encrypt", "-binary",
                    CIPHER_KUZ_CTR_ACPKM_OMAC,
                    "-in", plain.toString(),
                    "-outform", "DER", "-out", p7e.toString(),
                    rcpt.certPem().toString());

            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));
            PrivateKeyParameters priv =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(rcpt.keyDer()));

            byte[] decrypted =
                    CmsEnvelopedDataDecryptor.decrypt(
                            Files.readAllBytes(p7e), priv, recipientCert);

            assertArrayEquals(
                    SHORT,
                    decrypted,
                    "crypto-gost должен расшифровать OMAC-контейнер openssl (engine gost) байт-в-байт");
            return null;
        });
    }

    // ------------------------------------------------------------------
    // ACPKM-рекейинг: файлы > 256 КБ (пересечение границы секции)
    //
    // ВНИМАНИЕ: openssl gost engine имеет баг — self-roundtrip ломается
    // на данных > 4096 байт (encrypt использует section_size=256×1024,
    // а decrypt — 4096). Поэтому A-направление (crypto-gost → openssl)
    // не тестируется — это ошибка openssl, не наша. B-направление
    // (openssl → crypto-gost) работает корректно и подтверждает
    // совместимость с эталонным форматом CMS EnvelopedData.
    // ------------------------------------------------------------------

    private static byte[] randomLargeData(int size) {
        byte[] data = new byte[size];
        CryptoRandom.INSTANCE.nextBytes(data);
        return data;
    }

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("ACPKM B (non-OMAC): openssl cms -encrypt 300 КБ -> crypto-gost расшифровывает")
    void opensslEncryptLarge_cryptoGostDecrypt() throws Exception {
        TempDirUtils.withTempDir("cms-xval-acpkm-b-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);

            byte[] large = randomLargeData(300 * 1024);
            Path plain = dir.resolve("plain-large.bin");
            Files.write(plain, large);
            Path p7e = dir.resolve("ossl-enc-large.p7e");
            runOk(
                    SYS_OPENSSL, "cms", ENGINE_OPT, ENGINE_GOST, "-encrypt", "-binary",
                    CIPHER_KUZ_CTR_ACPKM,
                    "-in", plain.toString(),
                    "-outform", "DER", "-out", p7e.toString(),
                    rcpt.certPem().toString());

            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));
            PrivateKeyParameters priv =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(rcpt.keyDer()));

            byte[] decrypted =
                    CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                            Files.readAllBytes(p7e), priv, recipientCert);

            assertArrayEquals(
                    large,
                    decrypted,
                    "crypto-gost должен расшифровать 300 КБ контейнер openssl байт-в-байт (ACPKM рекейинг)");
            return null;
        });
    }

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("ACPKM B (OMAC): openssl cms -encrypt OMAC 300 КБ -> crypto-gost расшифровывает")
    void opensslEncryptLargeOmac_cryptoGostDecrypt() throws Exception {
        TempDirUtils.withTempDir("cms-xval-acpkm-b-omac-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);

            byte[] large = randomLargeData(300 * 1024);
            Path plain = dir.resolve("plain-large-omac.bin");
            Files.write(plain, large);
            Path p7e = dir.resolve("ossl-enc-large-omac.p7e");
            runOk(
                    SYS_OPENSSL, "cms", ENGINE_OPT, ENGINE_GOST, "-encrypt", "-binary",
                    CIPHER_KUZ_CTR_ACPKM_OMAC,
                    "-in", plain.toString(),
                    "-outform", "DER", "-out", p7e.toString(),
                    rcpt.certPem().toString());

            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));
            PrivateKeyParameters priv =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(rcpt.keyDer()));

            byte[] decrypted =
                    CmsEnvelopedDataDecryptor.decrypt(
                            Files.readAllBytes(p7e), priv, recipientCert);

            assertArrayEquals(
                    large,
                    decrypted,
                    "crypto-gost должен расшифровать 300 КБ OMAC-контейнер openssl байт-в-байт (OMAC+ACPKM рекейинг)");
            return null;
        });
    }

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("ACPKM: crypto-gost self-roundtrip 300 КБ non-OMAC")
    void cryptoGostSelfRoundtripLarge() throws Exception {
        TempDirUtils.withTempDir("cms-xval-self-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);
            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));
            PrivateKeyParameters priv =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(rcpt.keyDer()));

            byte[] large = randomLargeData(300 * 1024);
            byte[] enveloped =
                    CmsEnvelopedDataBuilder.create()
                            .data(large)
                            .addRecipient(recipientCert)
                            .withoutIntegrity()
                            .build();
            assertPlainContainer(enveloped);
            PkixException strictRefusal =
                    assertThrows(
                            PkixException.class,
                            () -> CmsEnvelopedDataDecryptor.decrypt(enveloped, priv, recipientCert),
                            "строгий decrypt должен отвергать контейнер без имитовставки");
            assertEquals(
                    PkixException.Reason.INTEGRITY_REQUIRED,
                    strictRefusal.reason(),
                    "причина отказа строгого decrypt");

            byte[] decrypted =
                    CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                            enveloped, priv, recipientCert);

            assertArrayEquals(
                    large,
                    decrypted,
                    "crypto-gost self-roundtrip 300 КБ должен быть байт-в-байт (ACPKM рекейинг)");
            return null;
        });
    }

    @Test
    @EnabledIf("systemOpensslGostCmsAvailable")
    @DisplayName("ACPKM: crypto-gost self-roundtrip 300 КБ с OMAC")
    void cryptoGostSelfRoundtripLargeOmac() throws Exception {
        TempDirUtils.withTempDir("cms-xval-self-omac-", dir -> {
            OpensslRecipient rcpt = makeOpensslRecipient(dir);
            GostCertificate recipientCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(rcpt.certDer()));
            PrivateKeyParameters priv =
                    GostDerCodec.decodePrivateKey(Files.readAllBytes(rcpt.keyDer()));

            byte[] large = randomLargeData(300 * 1024);
            byte[] enveloped =
                    CmsEnvelopedDataBuilder.create()
                            .data(large)
                            .addRecipient(recipientCert)
                            .build();

            byte[] decrypted =
                    CmsEnvelopedDataDecryptor.decrypt(
                            enveloped, priv, recipientCert);

            assertArrayEquals(
                    large,
                    decrypted,
                    "crypto-gost саморасшифровка 300 КБ с OMAC должна быть байт-в-байт (OMAC по умолчанию)");
            return null;
        });
    }

    // ------------------------------------------------------------------
    // Генерация получателя средствами системного OpenSSL (engine gost)
    // ------------------------------------------------------------------

    /** Пути к получателю, сгенерированному OpenSSL: сертификат (PEM/DER) и приватный ключ (PEM/PKCS8 DER). */
    private record OpensslRecipient(Path certPem, Path certDer, Path keyPem, Path keyDer) {}

    private static OpensslRecipient makeOpensslRecipient(Path dir) throws Exception {
        Path keyPem = dir.resolve("rkey.pem");
        Path certPem = dir.resolve("rcert.pem");
        Path certDer = dir.resolve("rcert.der");
        Path keyDer = dir.resolve("rkey.der");

        runOk(
                SYS_OPENSSL, "genpkey", ENGINE_OPT, ENGINE_GOST,
                "-algorithm", ALG_GOST_2012_256, "-pkeyopt", PKEYOPT_PARAMSET_XA,
                "-out", keyPem.toString());
        runOk(
                SYS_OPENSSL, "req", ENGINE_OPT, ENGINE_GOST, "-new", "-x509",
                "-key", keyPem.toString(), MD_GOST_2012_256,
                "-subj", "/CN=OpenSSL GOST Recipient/O=crossval/C=RU",
                ADDEXT_OPT, RECIPIENT_KEY_USAGE,
                "-days", "3650", "-out", certPem.toString());
        runOk(SYS_OPENSSL, "x509", "-in", certPem.toString(), "-outform", "DER", "-out", certDer.toString());
        runOk(
                SYS_OPENSSL, "pkey", ENGINE_OPT, ENGINE_GOST, "-in", keyPem.toString(),
                "-outform", "DER", "-out", keyDer.toString());

        return new OpensslRecipient(certPem, certDer, keyPem, keyDer);
    }

    // ------------------------------------------------------------------
    // Guard-условия и запуск процессов
    // ------------------------------------------------------------------

    static boolean systemOpensslAvailable() {
        try {
            return Files.isExecutable(Path.of(SYS_OPENSSL)) && runRaw(SYS_OPENSSL, "version").exit() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean systemOpensslGostCmsAvailable() {
        if (!systemOpensslAvailable()) {
            return false;
        }
        try {
            Captured version = runRaw(SYS_OPENSSL, "version");
            if (!version.output().startsWith("OpenSSL")) {
                return false;
            }
            Captured engine = runRaw(SYS_OPENSSL, "engine", "gost");
            if (!engine.output().contains("(gost)")) {
                return false;
            }
            Captured cmsHelp = runRaw(SYS_OPENSSL, "cms", "-help");
            return cmsHelp.output().contains("-encrypt") && cmsHelp.output().contains("-decrypt");
        } catch (Exception e) {
            return false;
        }
    }

    /** Результат запуска процесса: код возврата и объединённый stdout+stderr. */
    private record Captured(int exit, String output) {}

    private static Captured runRaw(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        return new Captured(code, out);
    }

    private static void runOk(String... cmd) throws Exception {
        Captured c = runRaw(cmd);
        if (c.exit() != 0) {
            throw new IllegalStateException(
                    "команда завершилась с кодом " + c.exit() + ": " + String.join(" ", cmd) + "\n" + c.output());
        }
    }

    /**
     * Проверяет, что контейнер собран с имитовставкой: OID OMAC-шифра и атрибут unprotectedAttrs.
     * OpenSSL расшифрует контейнер любого режима, поэтому сам успех расшифрования не доказывает,
     * что построитель по умолчанию выдаёт OMAC.
     */
    private static void assertOmacContainer(byte[] enveloped) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(enveloped);
        byte[][] envParts = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);
        assertEquals(
                GostOids.KUZ_CTR_ACPKM_OMAC,
                DerCodec.parseOid(algParts[0], 0),
                "OID шифра по умолчанию должен быть точно kuznyechik-ctr-acpkm-omac");
        assertEquals(4, envParts.length, "OMAC-контейнер должен содержать unprotectedAttrs");
    }

    /**
     * Проверяет, что контейнер собран без имитовставки: OID обычного шифра и нет unprotectedAttrs.
     * Без этого тест «обычного режима» прошёл бы и на OMAC-контейнере, если бы
     * {@code withoutIntegrity()} перестал действовать.
     */
    private static void assertPlainContainer(byte[] enveloped) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(enveloped);
        byte[][] envParts = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);
        assertEquals(
                GostOids.KUZ_CTR_ACPKM,
                DerCodec.parseOid(algParts[0], 0),
                "OID шифра обычного режима должен быть точно kuznyechik-ctr-acpkm");
        assertEquals(
                3, envParts.length, "обычный контейнер не должен содержать unprotectedAttrs");
    }
}
