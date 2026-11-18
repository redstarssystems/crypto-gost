package org.rssys.gost.pkix.cms;

import java.util.Arrays;
import org.rssys.gost.api.KeyExport;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Реализация {@link CmsKeyWrap} через KExp15/KImp15 (RFC 9189 §8.2.1).
 *
 * <p>Схема: MAC-then-Encrypt на шифре Кузнечик.
 * Экспортные ключи вырабатываются по KEG (R 1323565.1.020-2018 §6.4.5.1):
 * KDF_TREE_256(K_in=VKO, label="kdf tree", seed=UKM[16..24], R=1) -> K_MAC || K_ENC.
 * KExp15: CEK_MAC = CMAC(K_MAC, IV||CEK), wrapped = CTR-Encrypt(K_ENC, IV, CEK||CEK_MAC).
 */
final class Kexp15CmsKeyWrap implements CmsKeyWrap {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.Kexp15CmsKeyWrap");

    // Метка KDF_TREE для KEG — нормативная "kdf tree" (R 1323565.1.020-2018),
    // а не "kexp15": именно её использует КриптоПРО/gost-engine при выводе K_MAC/K_ENC.
    private static final byte[] KDF_TREE_LABEL_BYTES =
            "kdf tree".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    // Смещение и длина seed для KDF_TREE внутри 32-байтового UKM: ukm_source+16, 8 байт.
    private static final int KDF_SEED_OFFSET = 16;
    private static final int KDF_SEED_LENGTH = 8;
    private static final int KEK_LENGTH = 32;

    @Override
    public byte[] wrap(byte[] cek, byte[] kek, byte[] ukm, byte[] iv) {
        LOG.log(Level.DEBUG, "KExp15: wrapping CEK");
        byte[][] keys = deriveKeys(kek, ukm);
        SymmetricKey kMac = null;
        SymmetricKey kEnc = null;
        try {
            kMac = new SymmetricKey(keys[0]);
            kEnc = new SymmetricKey(keys[1]);
            return KeyExport.kExp15(cek, kMac, kEnc, iv);
        } finally {
            wipeDerivedKeys(keys, kMac, kEnc);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedCek, byte[] kek, byte[] ukm, byte[] iv) {
        LOG.log(Level.DEBUG, "KExp15: unwrapping CEK");
        byte[][] keys = deriveKeys(kek, ukm);
        SymmetricKey kMac = null;
        SymmetricKey kEnc = null;
        try {
            kMac = new SymmetricKey(keys[0]);
            kEnc = new SymmetricKey(keys[1]);
            return KeyExport.kImp15(wrappedCek, kMac, kEnc, iv);
        } catch (org.rssys.gost.util.AuthenticationException e) {
            throw new IllegalArgumentException("Invalid MAC during CEK unwrap", e);
        } finally {
            wipeDerivedKeys(keys, kMac, kEnc);
        }
    }

    /**
     * Затирает K_MAC и K_ENC на любом пути выхода. {@link SymmetricKey} копирует переданный
     * массив, поэтому {@code destroy()} стирает только копию, а исходные массивы из
     * {@code deriveKeys} остались бы в памяти и при успехе, и при отказе проверки MAC.
     */
    private static void wipeDerivedKeys(byte[][] keys, SymmetricKey kMac, SymmetricKey kEnc) {
        for (byte[] key : keys) {
            Arrays.fill(key, (byte) 0);
        }
        if (kMac != null) {
            kMac.destroy();
        }
        if (kEnc != null) {
            kEnc.destroy();
        }
    }

    @Override
    public String algorithmOid() {
        return GostOids.WRAP_KUZNYECHIK_KEXP15;
    }

    /**
     * Вычисляет UKM-множитель для VKO по правилу KEG (R 1323565.1.020-2018 §6.4.5.1).
     *
     * <p>В качестве синхропосылки VKO берутся первые 16 байт 32-байтового UKM,
     * развёрнутые в обратном порядке и прочитанные как little-endian — это
     * эквивалентно big-endian представлению первых 16 байт. Если первые 16 байт
     * нулевые, используется значение 2¹²⁰ (единица в старшем октете, как в KEG).
     *
     * @param ukm полный UKM (не менее 16 байт)
     * @return целочисленный множитель для VKO
     */
    static java.math.BigInteger kegVkoUkm(byte[] ukm) {
        byte[] first16 = Arrays.copyOfRange(ukm, 0, 16);
        boolean allZero = true;
        for (byte b : first16) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            return java.math.BigInteger.ONE.shiftLeft(120);
        }
        return new java.math.BigInteger(1, first16);
    }

    private static byte[][] deriveKeys(byte[] kek, byte[] ukm) {
        // 512-бит: VKO_512 сразу даёт 64 байта = K_MAC || K_ENC (без KDF_TREE).
        if (kek.length == KEK_LENGTH * 2) {
            byte[] macKey = Arrays.copyOfRange(kek, 0, KEK_LENGTH);
            byte[] encKey = Arrays.copyOfRange(kek, KEK_LENGTH, KEK_LENGTH * 2);
            return new byte[][] {macKey, encKey};
        }
        // seed KDF_TREE — 8 байт UKM начиная со смещения 16 (KEG §6.4.5.1),
        // а не весь UKM: остальные части UKM идут в VKO (0..16) и IV (24..32).
        byte[] seed = Arrays.copyOfRange(ukm, KDF_SEED_OFFSET, KDF_SEED_OFFSET + KDF_SEED_LENGTH);
        // count=2 (два 32-байтовых блока: K_MAC || K_ENC) безопасно при R=1:
        // счётчик KDF_TREE занимает 1 октет, а i in {1,2} гарантированно в него влезает.
        byte[] allKeys =
                KdfTreeGostR3411_2012_256.generate(kek, KDF_TREE_LABEL_BYTES, seed, 2, KEK_LENGTH);
        byte[] macKey = Arrays.copyOfRange(allKeys, 0, KEK_LENGTH);
        byte[] encKey = Arrays.copyOfRange(allKeys, KEK_LENGTH, KEK_LENGTH * 2);
        Arrays.fill(allKeys, (byte) 0);
        Arrays.fill(seed, (byte) 0);
        return new byte[][] {macKey, encKey};
    }
}
