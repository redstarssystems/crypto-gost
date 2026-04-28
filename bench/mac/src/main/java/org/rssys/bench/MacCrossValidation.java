package org.rssys.bench;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.rssys.gost.api.CmacApi;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;

import java.util.Arrays;

/**
 * Кросс-валидация: crypto-gost ↔ BouncyCastle 1.83
 *
 * Алгоритмы:
 *   - Streebog-256 (хэш, ГОСТ Р 34.11-2012)
 *   - Streebog-512 (хэш, ГОСТ Р 34.11-2012)
 *   - HMAC-Streebog-256 (RFC 7836)
 *   - HMAC-Streebog-512 (RFC 7836)
 *   - CMAC-Kuznyechik (ГОСТ Р 34.13-2015)
 *
 * Использует api/Digest и api/CmacApi — реальный пользовательский путь.
 */
public class MacCrossValidation {

    private static final int[] ALL_SIZES = {0, 1, 8, 16, 32, 64, 256, 1024, 65535};

    private static int total = 0;
    private static int ok    = 0;
    private static int fail  = 0;

    public static void main(String[] args) throws Exception {
        SymmetricKey gostKey = KeyGenerator.generateSymmetricKey();
        byte[] keyBytes      = gostKey.getKey();

        System.out.println("=".repeat(72));
        System.out.println("  Кросс-валидация: crypto-gost ↔ BouncyCastle 1.83");
        System.out.println("  Алгоритмы: Streebog-256/512, HMAC-256/512, CMAC-Kuznyechik");
        System.out.println("=".repeat(72));
        System.out.println();

        section("Streebog-256 (хэш)",          () -> testDigest256());
        section("Streebog-512 (хэш)",           () -> testDigest512());
        section("HMAC-Streebog-256 (RFC 7836)", () -> testHmac256(keyBytes));
        section("HMAC-Streebog-512 (RFC 7836)", () -> testHmac512(keyBytes));
        section("CMAC-Kuznyechik (ГОСТ Р 34.13-2015)", () -> testCmac(keyBytes));

        System.out.println("=".repeat(72));
        System.out.println("  Сводка:");
        System.out.printf("    Всего проверок:  %d%n", total);
        System.out.printf("    Пройдено:        %d%n", ok);
        System.out.printf("    Ошибок:          %d%n", fail);
        System.out.printf("    Статус:          %s%n", fail == 0 ? "УСПЕХ" : "ПРОВАЛ");
        System.out.println("=".repeat(72));

        System.exit(fail > 0 ? 1 : 0);
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }

    static void section(String name, ThrowingRunnable fn) {
        System.out.printf("  Алгоритм: %s%n", name);
        try {
            fn.run();
        } catch (Exception e) {
            System.out.printf("    Ошибка: %s%n", e.getMessage());
            e.printStackTrace();
        }
        System.out.println();
    }

    // -----------------------------------------------------------------------
    // Streebog-256
    // -----------------------------------------------------------------------

    static void testDigest256() throws Exception {
        for (int sz : ALL_SIZES) {
            byte[] msg   = msg(sz);
            byte[] gHash = Digest.digest256(msg);
            byte[] bHash = bcDigest256(msg);
            chk("gost→BC", "Streebog-256", sz, gHash, bHash);
            chk("BC→gost", "Streebog-256", sz, bHash, gHash);
        }
    }

    static byte[] bcDigest256(byte[] msg) {
        GOST3411_2012_256Digest d = new GOST3411_2012_256Digest();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // Streebog-512
    // -----------------------------------------------------------------------

    static void testDigest512() throws Exception {
        for (int sz : ALL_SIZES) {
            byte[] msg   = msg(sz);
            byte[] gHash = Digest.digest512(msg);
            byte[] bHash = bcDigest512(msg);
            chk("gost→BC", "Streebog-512", sz, gHash, bHash);
            chk("BC→gost", "Streebog-512", sz, bHash, gHash);
        }
    }

    static byte[] bcDigest512(byte[] msg) {
        GOST3411_2012_512Digest d = new GOST3411_2012_512Digest();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // HMAC-Streebog-256
    // -----------------------------------------------------------------------

    static void testHmac256(byte[] keyBytes) throws Exception {
        SymmetricKey key = new SymmetricKey(keyBytes);
        for (int sz : ALL_SIZES) {
            byte[] msg   = msg(sz);
            byte[] gMac  = Digest.hmac256(msg, key);
            byte[] bMac  = bcHmac256(keyBytes, msg);
            chk("gost→BC", "HMAC-Streebog-256", sz, gMac, bMac);
            chk("BC→gost", "HMAC-Streebog-256", sz, bMac, gMac);
        }
    }

    static byte[] bcHmac256(byte[] keyBytes, byte[] msg) {
        org.bouncycastle.crypto.macs.HMac mac =
            new org.bouncycastle.crypto.macs.HMac(new GOST3411_2012_256Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // HMAC-Streebog-512
    // -----------------------------------------------------------------------

    static void testHmac512(byte[] keyBytes) throws Exception {
        SymmetricKey key = new SymmetricKey(keyBytes);
        for (int sz : ALL_SIZES) {
            byte[] msg  = msg(sz);
            byte[] gMac = Digest.hmac512(msg, key);
            byte[] bMac = bcHmac512(keyBytes, msg);
            chk("gost→BC", "HMAC-Streebog-512", sz, gMac, bMac);
            chk("BC→gost", "HMAC-Streebog-512", sz, bMac, gMac);
        }
    }

    static byte[] bcHmac512(byte[] keyBytes, byte[] msg) {
        org.bouncycastle.crypto.macs.HMac mac =
            new org.bouncycastle.crypto.macs.HMac(new GOST3411_2012_512Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // CMAC-Kuznyechik
    // -----------------------------------------------------------------------

    static void testCmac(byte[] keyBytes) throws Exception {
        SymmetricKey key = new SymmetricKey(keyBytes);
        for (int sz : ALL_SIZES) {
            byte[] msg  = msg(sz);
            byte[] gMac = CmacApi.cmac(msg, key);
            byte[] bMac = bcCmac(keyBytes, msg);
            chk("gost→BC", "CMAC-Kuznyechik", sz, gMac, bMac);
            chk("BC→gost", "CMAC-Kuznyechik", sz, bMac, gMac);
        }
    }

    static byte[] bcCmac(byte[] keyBytes, byte[] msg) {
        org.bouncycastle.crypto.macs.CMac mac =
            new org.bouncycastle.crypto.macs.CMac(new GOST3412_2015Engine());
        mac.init(new KeyParameter(keyBytes));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // Утилиты
    // -----------------------------------------------------------------------

    /** Тестовое сообщение: последовательность байт 0x00..0xFF по кругу. */
    static byte[] msg(int sz) {
        byte[] m = new byte[sz];
        for (int i = 0; i < sz; i++) m[i] = (byte) (i & 0xFF);
        return m;
    }

    static void chk(String direction, String algo, int sz,
                    byte[] expected, byte[] actual) {
        total++;
        boolean eq = Arrays.equals(expected, actual);
        if (eq) {
            ok++;
            System.out.printf("    %-8s %-20s размер=%-6d PASS%n",
                direction, algo, sz);
        } else {
            fail++;
            System.out.printf("    %-8s %-20s размер=%-6d FAIL%n",
                direction, algo, sz);
            System.out.printf("      crypto-gost: %s%n", hex(expected));
            System.out.printf("      BC 1.83    : %s%n", hex(actual));
        }
    }

    static String hex(byte[] d) {
        if (d == null)    return "(null)";
        if (d.length == 0) return "(empty)";
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
