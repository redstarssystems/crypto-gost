package org.rssys.gost.crossval.keys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyExport;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация KExp15/KImp15 (RFC 9189 §8.2.1) с OpenSSL.
 *
 * <p>KExp15 состоит из двух примитивов: OMAC(CMAC) на kuznyechik-cbc и
 * CTR-Encrypt на kuznyechik-ctr. OpenSSL поддерживает оба независимо.
 * Стратегия: разложить KExp15 на составляющие, верифицировать каждый шаг
 * через OpenSSL и собрать обратно.
 *
 * <p>Нюанс IV: KExp15 использует 8-байтный IV (n/2 для Кузнечика),
 * OpenSSL -kuznyechik-ctr ожидает полный 16-байтный начальный счётчик.
 * Расширяем: iv16 = iv8 || 0x0000000000000000.
 */
class OpenSslKexp15CrossValidationTest {

    private static String OPENSSL;
    private static String[] ENGINE_FLAG;

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeKuznyechikCipher();
        OpenSslChecker.assumeCmacKuznyechik();
        OPENSSL = OpenSslChecker.resolveOpenSslBinary();
        ENGINE_FLAG = OpenSslChecker.resolveEngineFlag();
    }

    @Test
    @DisplayName("kExp15: crypto-gost = OpenSSL (CMAC + CTR)")
    void crossValidateKExp15() throws Exception {
        // Тестовые данные (RFC 9189 Appendix A.1.3.2 — KAT)
        byte[] secret = CrossValUtils.fromHex(
                "A5 57 6C E7 92 4A 24 F5 81 13 80 8D BD 9E F8 56" +
                "F5 BD C3 B1 83 CE 5D AD CA 36 A5 3A A0 77 65 1D");
        byte[] kMac = CrossValUtils.fromHex(
                "7D AC 56 E4 8A 4D C1 70 FA A8 FC BA E2 0D B8 45" +
                "45 0C CC C4 C6 32 8B DC 8D 01 15 7C EF A2 A5 F1");
        byte[] kEnc = CrossValUtils.fromHex(
                "1F 1C BA D8 86 61 66 F0 1F FA AB 01 52 E2 4B F4" +
                "60 9D 5F 46 A5 C8 99 C7 87 90 0D 08 B9 FC AD 24");
        byte[] iv8 = CrossValUtils.fromHex("21 4A 6A 29 8E 99 E3 25");
        byte[] expectedSExp = CrossValUtils.fromHex(
                "25 0D 1B 67 A2 70 AB 04 D3 F6 54 18 E1 D3 80 B4" +
                "CB 94 5F 0A 3D CA 51 50 0C F3 A1 BE F3 7F 76 C0" +
                "73 41 A9 83 9C CF 6C BA 71 89 DA 61 EB 67 17 6C");

        TempDirUtils.withTempDir("kexp15-", tmpDir -> {
            // IV для OpenSSL: 16 байт = iv8 || 0x0000000000000000
            byte[] iv16 = Arrays.copyOf(iv8, 16);

            // Шаг 1: CEK_MAC через OpenSSL CMAC
            byte[] ivConcatS = CrossValUtils.concat(iv8, secret);
            byte[] cekMacOssl = opensslCmac(kMac, ivConcatS);

            // Шаг 2: CTR-Encrypt(S || CEK_MAC) через OpenSSL
            byte[] plaintext = CrossValUtils.concat(secret, cekMacOssl);
            byte[] sExpOssl = opensslCtrEncrypt(kEnc, iv16, plaintext);

            // Проверка: crypto-gost == KAT RFC 9189
            byte[] sExpGost = KeyExport.kExp15(secret,
                    new SymmetricKey(kMac), new SymmetricKey(kEnc), iv8);
            assertArrayEquals(expectedSExp, sExpGost,
                    "kExp15 не совпадает с KAT RFC 9189");
            // Проверка: OpenSSL == KAT RFC 9189
            assertArrayEquals(expectedSExp, sExpOssl,
                    "OpenSSL не совпадает с KAT RFC 9189");
            return null;
        });
    }

    @Test
    @DisplayName("kImp15: SExp от OpenSSL импортируется crypto-gost")
    void crossValidateKImp15() throws Exception {
        byte[] secret = new byte[32];
        byte[] kMac = new byte[32];
        byte[] kEnc = new byte[32];
        byte[] iv8 = new byte[8];
        Arrays.fill(secret, (byte) 0xAB);
        Arrays.fill(kMac,   (byte) 0x11);
        Arrays.fill(kEnc,   (byte) 0x22);
        Arrays.fill(iv8,    (byte) 0x55);

        TempDirUtils.withTempDir("kimp15-", tmpDir -> {
            // IV для OpenSSL: 16 байт = iv8 || 0x0000000000000000
            byte[] iv16 = Arrays.copyOf(iv8, 16);

            // Шаг 1: CEK_MAC через OpenSSL
            byte[] ivConcatS = CrossValUtils.concat(iv8, secret);
            byte[] cekMacOssl = opensslCmac(kMac, ivConcatS);

            // Шаг 2: SExp через OpenSSL CTR
            byte[] plaintext = CrossValUtils.concat(secret, cekMacOssl);
            byte[] sExpOssl = opensslCtrEncrypt(kEnc, iv16, plaintext);

            // Шаг 3: импорт SExp через crypto-gost
            byte[] restored = KeyExport.kImp15(sExpOssl,
                    new SymmetricKey(kMac), new SymmetricKey(kEnc), iv8);
            assertArrayEquals(secret, restored,
                    "импорт SExp от OpenSSL не совпадает с оригиналом");
            return null;
        });
    }

    // ========================================================================
    // OpenSSL subprocess helpers
    // ========================================================================

    /** openssl mac -cipher kuznyechik-cbc -macopt hexkey:... CMAC (через stdin). */
    private static byte[] opensslCmac(byte[] key, byte[] data) throws Exception {
        // Флаг -in есть не во всех сборках OpenSSL, поэтому данные подаём
        // через redirectInput, как в OpenSslMacHelper.runMac.
        String[] cmd = fullCmd("mac",
                "-cipher", "kuznyechik-cbc",
                "-macopt", "hexkey:" + CrossValUtils.toHex(key),
                "CMAC");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().write(data);
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException(
                    "openssl mac CMAC failed (exit=" + exitCode + "): " + out);
        }
        return CrossValUtils.fromHex(out);
    }

    /** openssl enc -kuznyechik-ctr -e -K ... -iv ... -nopad -in ... -out ... */
    private static byte[] opensslCtrEncrypt(byte[] key, byte[] iv16,
                                            byte[] plaintext) throws Exception {
        return TempDirUtils.withTempDir("ossl-ctr-", tmpDir -> {
            Path inFile = tmpDir.resolve("in.bin");
            Path outFile = tmpDir.resolve("out.bin");
            Files.write(inFile, plaintext);
            String[] cmd = fullCmd("enc", "-e",
                    "-kuznyechik-ctr",
                    "-K", CrossValUtils.toHex(key),
                    "-iv", CrossValUtils.toHex(iv16),
                    "-nopad",
                    "-in", inFile.toAbsolutePath().toString(),
                    "-out", outFile.toAbsolutePath().toString());
            OpenSslChecker.exec(cmd);
            return Files.readAllBytes(outFile);
        });
    }

    /** Собирает полную команду: openssl subcommand ENGINE_FLAG args... */
    private static String[] fullCmd(String subcommand, String... args) {
        return CrossValUtils.concat(new String[]{OPENSSL, subcommand}, ENGINE_FLAG, args);
    }
}
