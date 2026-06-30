package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Arrays;
import org.rssys.gost.api.KeyExport;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.pkix.GostOids;

/**
 * Реализация {@link CmsKeyWrap} через KExp15/KImp15 (RFC 9189 §8.2.1).
 *
 * <p>Схема: MAC-then-Encrypt на шифре Кузнечик.
 * KEK -> KDF_TREE(label="kexp15", seed=UKM, R=2) -> K_MAC, K_ENC.
 * KExp15: CEK_MAC = CMAC(K_MAC, IV||CEK), wrapped = CTR-Encrypt(K_ENC, IV, CEK||CEK_MAC).
 */
public final class Kexp15CmsKeyWrap implements CmsKeyWrap {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cms.Kexp15CmsKeyWrap");

    private static final String KEXP15_LABEL = "kexp15";
    private static final byte[] KEXP15_LABEL_BYTES =
            KEXP15_LABEL.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int KEK_LENGTH = 32;
    private static final int IV_LENGTH = 8;

    public Kexp15CmsKeyWrap() {}

    @Override
    public byte[] wrap(byte[] cek, byte[] kek, byte[] ukm) {
        LOG.log(Level.DEBUG, "KExp15: wrapping CEK");
        byte[][] keys = deriveKeys(kek, ukm);
        SymmetricKey kMac = new SymmetricKey(keys[0]);
        SymmetricKey kEnc = new SymmetricKey(keys[1]);
        byte[] iv = Arrays.copyOf(ukm, IV_LENGTH);
        try {
            return KeyExport.kExp15(cek, kMac, kEnc, iv);
        } finally {
            kMac.destroy();
            kEnc.destroy();
            Arrays.fill(iv, (byte) 0);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedCek, byte[] kek, byte[] ukm) {
        LOG.log(Level.DEBUG, "KExp15: unwrapping CEK");
        byte[][] keys = deriveKeys(kek, ukm);
        SymmetricKey kMac = new SymmetricKey(keys[0]);
        SymmetricKey kEnc = new SymmetricKey(keys[1]);
        byte[] iv = Arrays.copyOf(ukm, IV_LENGTH);
        try {
            return KeyExport.kImp15(wrappedCek, kMac, kEnc, iv);
        } catch (org.rssys.gost.util.AuthenticationException e) {
            throw new IllegalArgumentException("Invalid MAC during CEK unwrap", e);
        } finally {
            kMac.destroy();
            kEnc.destroy();
            Arrays.fill(iv, (byte) 0);
        }
    }

    @Override
    public String algorithmOid() {
        return GostOids.WRAP_KUZNYECHIK_KEXP15;
    }

    private static byte[][] deriveKeys(byte[] kek, byte[] ukm) {
        byte[] allKeys =
                KdfTreeGostR3411_2012_256.generate(kek, KEXP15_LABEL_BYTES, ukm, 2, KEK_LENGTH);
        byte[] macKey = Arrays.copyOfRange(allKeys, 0, KEK_LENGTH);
        byte[] encKey = Arrays.copyOfRange(allKeys, KEK_LENGTH, KEK_LENGTH * 2);
        Arrays.fill(allKeys, (byte) 0);
        return new byte[][] {macKey, encKey};
    }
}
