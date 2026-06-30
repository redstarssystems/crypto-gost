package org.rssys.gost.pkix.cert;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Arrays;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.EncryptedPrivateKeyInfo;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.Pbes2Params;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Расшифровка PKCS8ShroudedKeyBag по PBES2 (RFC 9337 §5, §7).
 * <p>
 * Поддерживает:
 * <ul>
 *   <li>PBES2 с PBKDF2 на HMAC-Streebog-256/512</li>
 *   <li>Шифрование Кузнечиком CTR-ACPKM (с OMAC и без)</li>
 * </ul>
 * <p>
 * Все промежуточные ключи (DK, производные ключи Кузнечика) затираются
 * после использования.
 */
public final class GostPbes2 {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.GostPbes2");

    private GostPbes2() {}

    /**
     * Расшифровывает приватный ключ из EncryptedPrivateKeyInfo по PBES2-GOST.
     *
     * @param epki     разобранный EncryptedPrivateKeyInfo
     * @param password пароль (UTF-8)
     * @return закрытый ключ ГОСТ
     */
    public static PrivateKeyParameters decryptKey(EncryptedPrivateKeyInfo epki, byte[] password) {
        String encOid = epki.getEncryptionAlgorithmOid();
        if (!GostOids.PBES2.equals(encOid)) {
            throw new IllegalArgumentException(
                    "Unsupported PBE algorithm: "
                            + encOid
                            + ". Expected PBES2 ("
                            + GostOids.PBES2
                            + ")");
        }

        Pbes2Params params = GostPkcs12Parser.parsePbes2Params(epki.getEncryptionParams());
        LOG.log(
                Level.DEBUG,
                "Decrypting private key via PBES2 (scheme={0})",
                params.getEncryptionSchemeOid());
        byte[] dk = deriveKey(password, params);
        try {
            byte[] privateKeyInfoDer = decryptKeyData(dk, params, epki.getEncryptedData());
            GostDerCodec.checkNotMasked(privateKeyInfoDer);
            return GostDerCodec.decodePrivateKey(privateKeyInfoDer);
        } finally {
            Arrays.fill(dk, (byte) 0);
        }
    }

    /**
     * Вырабатывает ключ по PBKDF2 с учётом PRF OID из PFX.
     */
    public static byte[] deriveKey(byte[] password, Pbes2Params params) {
        Hmac hmac = createPrf(params.getPrfOid());
        hmac.init(password);
        return Pbkdf2Streebog.generate(hmac, params.getSalt(), params.getIterationCount(), GostOids.KUZNYECHIK_KEY_LEN);
    }

    /**
     * Расшифровывает данные по схеме PBES2.
     */
    public static byte[] decryptKeyData(byte[] dk, Pbes2Params params, byte[] encryptedData) {
        SymmetricKey key = new SymmetricKey(dk);
        String encOid = params.getEncryptionSchemeOid();
        boolean useOmac = GostOids.KUZ_CTR_ACPKM_OMAC.equals(encOid);

        try {
            if (useOmac) {
                return CtrAcpkmMode.decryptWithMac(key, params.getUkm(), encryptedData);
            }
            return CtrAcpkmMode.decryptOnly(key, params.getUkm(), encryptedData);
        } catch (AuthenticationException e) {
            throw new IllegalArgumentException("PBES2 decryption failed: " + e.getMessage(), e);
        } finally {
            key.destroy();
        }
    }

    // ========================================================================
    // Шифрование (write direction)
    // ========================================================================

    /**
     * Шифрует закрытый ключ по PBES2-GOST (RFC 9337 §5, §7).
     *
     * @param privKey       закрытый ключ (будет закодирован в PKCS#8)
     * @param password      пароль (UTF-8)
     * @param encSchemeOid  KUZ_CTR_ACPKM_OMAC или KUZ_CTR_ACPKM
     * @param iterations    кол-во итераций PBKDF2
     * @return DER-байты EncryptedPrivateKeyInfo
     */
    public static byte[] encryptKey(
            PrivateKeyParameters privKey, byte[] password, String encSchemeOid, int iterations) {
        if (!GostOids.KUZ_CTR_ACPKM_OMAC.equals(encSchemeOid)
                && !GostOids.KUZ_CTR_ACPKM.equals(encSchemeOid)) {
            throw new IllegalArgumentException(
                    "Unsupported encryption scheme: "
                            + encSchemeOid
                            + ". Expected "
                            + GostOids.KUZ_CTR_ACPKM_OMAC
                            + " or "
                            + GostOids.KUZ_CTR_ACPKM);
        }

        byte[] privateKeyInfoDer = GostDerCodec.encodePrivateKey(privKey);
        byte[] salt = new byte[GostOids.PBES2_SALT_LEN];
        CryptoRandom.INSTANCE.nextBytes(salt);
        byte[] ukm = new byte[GostOids.PBES2_UKM_LEN];
        CryptoRandom.INSTANCE.nextBytes(ukm);
        byte[] dk = Pbkdf2Streebog.generate(password, salt, iterations, GostOids.KUZNYECHIK_KEY_LEN);

        SymmetricKey symKey = null;
        try {
            symKey = new SymmetricKey(dk);
            byte[] encryptedData;
            if (GostOids.KUZ_CTR_ACPKM_OMAC.equals(encSchemeOid)) {
                encryptedData = CtrAcpkmMode.encryptWithMac(symKey, ukm, privateKeyInfoDer);
            } else {
                encryptedData = CtrAcpkmMode.encryptOnly(symKey, ukm, privateKeyInfoDer);
            }
            String prfOid = GostOids.HMAC_STREEBOG_512;
            byte[] pbes2Params = buildPbes2Params(salt, iterations, ukm, prfOid, encSchemeOid);
            return buildEncryptedPrivateKeyInfo(pbes2Params, encryptedData);
        } finally {
            Arrays.fill(dk, (byte) 0);
            if (symKey != null) {
                symKey.destroy();
            }
        }
    }

    /**
     * Собирает PBES2-params в DER (RFC 9337 §7.2).
     */
    static byte[] buildPbes2Params(
            byte[] salt, int iterations, byte[] ukm, String prfOid, String encOid) {
        byte[] prfAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(prfOid));
        byte[] encParams = DerCodec.encodeSequence(DerCodec.encodeOctetString(ukm));
        byte[] encAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(encOid), encParams);
        byte[] kdfParams =
                DerCodec.encodeSequence(
                        DerCodec.encodeOctetString(salt),
                        DerCodec.encodeInteger(iterations),
                        prfAlgId);
        byte[] kdfAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.PBKDF2), kdfParams);
        return DerCodec.encodeSequence(kdfAlgId, encAlgId);
    }

    /**
     * Собирает EncryptedPrivateKeyInfo в DER (PKCS#8 / RFC 5958).
     */
    static byte[] buildEncryptedPrivateKeyInfo(byte[] pbes2Params, byte[] encryptedData) {
        byte[] algId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.PBES2), pbes2Params);
        return DerCodec.encodeSequence(algId, DerCodec.encodeOctetString(encryptedData));
    }

    // ========================================================================

    private static Hmac createPrf(String prfOid) {
        if (prfOid == null || GostOids.HMAC_STREEBOG_512.equals(prfOid)) {
            return new Hmac(new Streebog512());
        }
        if (GostOids.HMAC_STREEBOG_256.equals(prfOid)) {
            return new Hmac(new Streebog256());
        }
        throw new IllegalArgumentException("Unknown PRF OID: " + prfOid);
    }
}
