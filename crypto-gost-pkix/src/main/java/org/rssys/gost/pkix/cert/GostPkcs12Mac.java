package org.rssys.gost.pkix.cert;

import java.security.MessageDigest;
import java.util.Arrays;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.MacData;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Вычисление и проверка MAC целостности PFX (RFC 9548 §7).
 * <p>
 * Алгоритм: PBKDF2(P, salt, iterations, 96) -> K (96 байт); ключ HMAC - последние 32 байта;
 * MAC = HMAC-Streebog-512(содержимое authSafe). В {@code macData.mac.digestAlgorithm} записывается
 * OID хэш-функции {@code id-tc26-gost3411-12-512} (1.2.643.7.1.1.2.3) без параметров; при чтении
 * параметры допускаются либо отсутствующими, либо NULL (так пишет OpenSSL).
 */
public final class GostPkcs12Mac {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.GostPkcs12Mac");

    private static final int DK_LEN = 96;
    private static final int HMAC_KEY_LEN = 32;

    private GostPkcs12Mac() {}

    /**
     * Проверяет MAC целостности PFX.
     *
     * @param macData         MacData из PFX
     * @param password        пароль (UTF-8)
     * @param authSafeContent содержимое AuthSafe (raw bytes под HMAC)
     * @throws IllegalArgumentException если алгоритм не поддерживается, MAC не совпадает
     *                                  или имеет неверную длину
     */
    public static void verify(MacData macData, byte[] password, byte[] authSafeContent) {
        LOG.log(Level.DEBUG, "Verifying PFX MAC (iterations={0})", macData.getIterations());
        // Структура проверяется до PBKDF2: на заведомо некорректном файле не тратим итерации
        requireStandardMac(macData);

        // PBKDF2 с dkLen=96, последние 32 байта - ключ HMAC (RFC 9548 §7)
        byte[] km =
                Pbkdf2Streebog.generate(
                        password, macData.getSalt(), macData.getIterations(), DK_LEN);
        byte[] hmacKey = null;
        Hmac hmac = new Hmac(new Streebog512());
        try {
            hmacKey = new byte[HMAC_KEY_LEN];
            System.arraycopy(km, km.length - HMAC_KEY_LEN, hmacKey, 0, HMAC_KEY_LEN);
            // km больше не нужен - раннее затирание; finally страхует от исключения в arraycopy
            Arrays.fill(km, (byte) 0);

            hmac.init(hmacKey);
            hmac.update(authSafeContent, 0, authSafeContent.length);

            byte[] computed = new byte[GostOids.STREEBOG_512_HASH_LEN];
            hmac.doFinal(computed, 0);

            // MessageDigest.isEqual используется только как сравнение байтов за постоянное время,
            // а не как дайджест из JCA: сам MAC считает наш HMAC-Streebog
            if (!MessageDigest.isEqual(computed, macData.getDigestValue())) {
                throw new IllegalArgumentException(
                        "PFX MAC verification failed: "
                                + "integrity check mismatch (wrong password or corrupted data)");
            }
            LOG.log(Level.DEBUG, "PFX MAC verification passed");
        } finally {
            hmac.destroy();
            if (hmacKey != null) {
                Arrays.fill(hmacKey, (byte) 0);
            }
            Arrays.fill(km, (byte) 0);
        }
    }

    /**
     * Проверяет OID алгоритма и длину значения MAC до любых затратных вычислений.
     * <p>
     * OID HMAC (1.2.643.7.1.1.4.x) и OID хэша Стрибог-256 в MacData писали прежние версии
     * библиотеки; стандарт RFC 9548 §7 их не допускает, поэтому такие файлы отвергаются с
     * подсказкой перевыпустить PFX, а не с общей ошибкой.
     */
    static void requireStandardMac(MacData macData) {
        String digestAlg = macData.getDigestAlgorithm();
        if (GostOids.HMAC_STREEBOG_256.equals(digestAlg)
                || GostOids.HMAC_STREEBOG_512.equals(digestAlg)
                || GostOids.DIGEST_256.equals(digestAlg)) {
            throw new IllegalArgumentException(
                    "Legacy or nonstandard PFX MAC algorithm OID "
                            + digestAlg
                            + ": RFC 9548 section 7 requires "
                            + GostOids.DIGEST_512
                            + "; re-issue the PFX");
        }
        if (!GostOids.DIGEST_512.equals(digestAlg)) {
            throw new IllegalArgumentException("Unsupported MAC digest algorithm: " + digestAlg);
        }
        int macLength = macData.getDigestValue().length;
        if (macLength != GostOids.STREEBOG_512_HASH_LEN) {
            throw new IllegalArgumentException(
                    "PFX MAC length must be "
                            + GostOids.STREEBOG_512_HASH_LEN
                            + " bytes, got "
                            + macLength);
        }
    }

    // ========================================================================
    // Вычисление MAC (направление записи)
    // ========================================================================

    /**
     * Вычисляет MacData для PFX (RFC 9548 §7).
     *
     * @param authSafeContent BER-байты AuthenticatedSafe (raw, на которые считается MAC)
     * @param password        пароль (UTF-8)
     * @param iterations      количество итераций PBKDF2
     * @param salt            соль PBKDF2 (8..32 байта; рекомендуется {@link GostOids#PBKDF2_SALT_LEN})
     * @return DER-байты MacData
     * @throws IllegalArgumentException если длина соли вне диапазона 8..32
     */
    public static byte[] compute(
            byte[] authSafeContent, byte[] password, int iterations, byte[] salt) {
        // Файл с солью вне диапазона RFC другие реализации и наш загрузчик отвергнут,
        // поэтому ошибку лучше выдать при записи, а не при чтении
        if (salt.length < GostOids.MIN_PBKDF2_SALT_LEN
                || salt.length > GostOids.MAX_PBKDF2_SALT_LEN) {
            throw new IllegalArgumentException(
                    "MacData salt length "
                            + salt.length
                            + " is outside "
                            + GostOids.MIN_PBKDF2_SALT_LEN
                            + ".."
                            + GostOids.MAX_PBKDF2_SALT_LEN);
        }
        byte[] km = Pbkdf2Streebog.generate(password, salt, iterations, DK_LEN);
        byte[] hmacKey = null;
        Hmac hmac = new Hmac(new Streebog512());
        try {
            hmacKey = new byte[HMAC_KEY_LEN];
            System.arraycopy(km, km.length - HMAC_KEY_LEN, hmacKey, 0, HMAC_KEY_LEN);
            // km больше не нужен - раннее затирание; finally страхует от исключения в arraycopy
            Arrays.fill(km, (byte) 0);

            hmac.init(hmacKey);
            hmac.update(authSafeContent, 0, authSafeContent.length);

            byte[] digestValue = new byte[hmac.getMacSize()];
            hmac.doFinal(digestValue, 0);

            // DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }; параметры
            // AlgorithmIdentifier опущены (RFC 9548 §7)
            byte[] digestInfo =
                    DerCodec.encodeSequence(
                            DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_512)),
                            DerCodec.encodeOctetString(digestValue));

            // MacData ::= SEQUENCE { DigestInfo, OCTET STRING salt, INTEGER iterations }
            return DerCodec.encodeSequence(
                    digestInfo,
                    DerCodec.encodeOctetString(salt),
                    DerCodec.encodeInteger(iterations));
        } finally {
            hmac.destroy();
            if (hmacKey != null) {
                Arrays.fill(hmacKey, (byte) 0);
            }
            Arrays.fill(km, (byte) 0);
        }
    }
}
