package org.rssys.gost.pkix.cert;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.MessageDigest;
import java.util.Arrays;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.MacData;
import org.rssys.gost.util.DerCodec;

/**
 * Верификация MAC-целостности PFX (RFC 9548 §7).
 * <p>
 * Алгоритм: PBKDF2(P, salt, iterations, 96) -> K(96 байт).
 * Ключ HMAC = последние 32 байта. HMAC-Streebog-512(authSafe.contents).
 */
public final class GostPkcs12Mac {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.GostPkcs12Mac");

    private static final int DK_LEN = 96;
    private static final int HMAC_KEY_LEN = 32;

    private GostPkcs12Mac() {}

    /**
     * Проверяет MAC целостности PFX.
     *
     * @param macData    MacData из PFX
     * @param password   пароль (UTF-8)
     * @param authSafeContent содержимое AuthSafe (raw bytes под HMAC)
     * @throws IllegalArgumentException если MAC не совпадает или алгоритм не поддерживается
     */
    public static void verify(MacData macData, byte[] password, byte[] authSafeContent) {
        LOG.log(Level.DEBUG, "Verifying PFX MAC (iterations={0})", macData.getIterations());
        String digestAlg = macData.getDigestAlgorithm();
        Digest digest;
        if (digestAlg == null || GostOids.HMAC_STREEBOG_512.equals(digestAlg)) {
            digest = new Streebog512();
        } else if (GostOids.HMAC_STREEBOG_256.equals(digestAlg)) {
            digest = new Streebog256();
        } else {
            throw new IllegalArgumentException("Unsupported MAC digest algorithm: " + digestAlg);
        }

        // PBKDF2 с dkLen=96, последние 32 байта — ключ HMAC (RFC 9548 §7)
        byte[] km =
                Pbkdf2Streebog.generate(
                        password, macData.getSalt(), macData.getIterations(), DK_LEN);

        byte[] hmacKey = new byte[HMAC_KEY_LEN];
        System.arraycopy(km, km.length - HMAC_KEY_LEN, hmacKey, 0, HMAC_KEY_LEN);
        Arrays.fill(km, (byte) 0);

        Hmac hmac = new Hmac(digest);
        hmac.init(hmacKey);
        hmac.update(authSafeContent, 0, authSafeContent.length);

        byte[] computed = new byte[digest.getDigestSize()];
        hmac.doFinal(computed, 0);
        hmac.clear();
        Arrays.fill(hmacKey, (byte) 0);

        if (!MessageDigest.isEqual(computed, macData.getDigestValue())) {
            throw new IllegalArgumentException(
                    "PFX MAC verification failed: "
                            + "integrity check mismatch (wrong password or corrupted data)");
        }
        LOG.log(Level.INFO, "PFX MAC verification passed");
    }

    // ========================================================================
    // MAC computation (write direction)
    // ========================================================================

    /**
     * Вычисляет MacData для PFX (RFC 9548 §7).
     *
     * @param authSafeContent BER-байты AuthenticatedSafe (raw, на которые считается MAC)
     * @param password        пароль (UTF-8)
     * @param iterations      кол-во итераций PBKDF2
     * @param salt            соль (16 байт)
     * @return DER-байты MacData
     */
    public static byte[] compute(
            byte[] authSafeContent, byte[] password, int iterations, byte[] salt) {
        return compute(authSafeContent, password, iterations, salt, GostOids.STREEBOG_512_HASH_LEN);
    }

    /**
     * Вычисляет MacData для PFX с выбранным хешем HMAC.
     *
     * @param authSafeContent BER-байты AuthenticatedSafe
     * @param password        пароль (UTF-8)
     * @param iterations      кол-во итераций PBKDF2
     * @param salt            соль (16 байт)
     * @param macHashLen      длина хеша HMAC: 32 (Streebog-256) или 64 (Streebog-512)
     * @return DER-байты MacData
     */
    public static byte[] compute(
            byte[] authSafeContent, byte[] password, int iterations, byte[] salt, int macHashLen) {
        byte[] km = Pbkdf2Streebog.generate(password, salt, iterations, DK_LEN);

        byte[] hmacKey = new byte[HMAC_KEY_LEN];
        System.arraycopy(km, km.length - HMAC_KEY_LEN, hmacKey, 0, HMAC_KEY_LEN);
        Arrays.fill(km, (byte) 0);

        try {
            Digest digest =
                    macHashLen == GostOids.STREEBOG_256_HASH_LEN
                            ? new Streebog256()
                            : new Streebog512();
            Hmac hmac = new Hmac(digest);
            hmac.init(hmacKey);
            hmac.update(authSafeContent, 0, authSafeContent.length);

            byte[] digestValue = new byte[hmac.getMacSize()];
            hmac.doFinal(digestValue, 0);
            hmac.clear();

            String hmacOid =
                    macHashLen == GostOids.STREEBOG_256_HASH_LEN
                            ? GostOids.HMAC_STREEBOG_256
                            : GostOids.HMAC_STREEBOG_512;

            // DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
            byte[] digestInfo =
                    DerCodec.encodeSequence(
                            DerCodec.encodeSequence(DerCodec.encodeOid(hmacOid)),
                            DerCodec.encodeOctetString(digestValue));

            // MacData ::= SEQUENCE { DigestInfo, OCTET STRING salt, INTEGER iterations }
            return DerCodec.encodeSequence(
                    digestInfo,
                    DerCodec.encodeOctetString(salt),
                    DerCodec.encodeInteger(iterations));
        } finally {
            Arrays.fill(hmacKey, (byte) 0);
        }
    }
}
