package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.MessageDigest;
import java.util.Arrays;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.AcpkmSectionSize;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.DerCodec;

/**
 * CMS-профильный OMAC по Р 1323565.1.025-2019 §8.3.2 (Mac-and-Encrypt).
 *
 * <p>В отличие от inline Encrypt-then-MAC в {@link CtrAcpkmMode#encryptWithMac},
 * профиль CMS требует:
 * <ul>
 *   <li>CMAC вычисляется по <b>открытому</b> тексту содержимого (Mac-and-Encrypt);</li>
 *   <li>зашифрованная имитовставка выносится в {@code unprotectedAttrs}
 *       как атрибут {@code content-mac} ({@link GostOids#ID_CMS_MAC_ATTR}).</li>
 * </ul>
 *
 * <p><b>CTR-поток.</b> Имитовставка шифруется на продолжении того же CTR-потока,
 * что и контент — не с начала IV (gost2015_final_call, gost-engine).
 * <code>CtrAcpkmMode.encryptOnly</code> сбрасывает счётчик при каждом вызове,
 * поэтому здесь используется единый экземпляр режима с одним потоком.
 *
 * <p><b>ACPKM-рекейинг.</b> Секционная смена ключа (ГОСТ Р 34.13-2015 §6.2)
 * выполняется каждые 256 КБ. CMAC считается по открытому тексту отдельным
 * экземпляром Кузнечика (ключ K(2)), а имитовставка шифруется на продолжении
 * того же CTR-потока после контента — при рекейинге имитовставка шифруется
 * на N-й секции ключа. Поведение соответствует gost-engine
 * ({@code gost2015_final_call}).
 */
public final class CmsOmacHelper {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cms.CmsOmacHelper");

    /** Атрибут content-mac для unprotectedAttrs, закодированный в DER. */
    public record ContentMacAttribute(byte[] encodedMac, byte[] derEncoded) {}

    private CmsOmacHelper() {}

    /**
     * Шифрует данные по CMS-профилю OMAC (Р 1323565.1.025-2019 §8.3.2).
     *
     * <p>Последовательность:
     * <ol>
     *   <li>KDF_TREE(CEK, "kdf tree", ukm[8..15]) -> K(1), K(2)</li>
     *   <li>CMAC(K(2), plaintext) -> имитовставка (16 байт)</li>
     *   <li>CTR-шифрование контента K(1), IV=ukm[0..8]</li>
     *   <li>CTR-шифрование имитовставки на продолжении того же потока</li>
     *   <li>Кодирование атрибута content-mac в DER</li>
     * </ol>
     *
     * @param data  открытые данные
     * @param cek   контентный ключ шифрования (32 байта)
     * @param ukm   content-UKM (16 байт: IV[0..8) | kdf_seed[8..16))
     * @return пара {encryptedContent, contentMacAttribute}
     */
    public static EncryptResult encrypt(byte[] data, byte[] cek, byte[] ukm) {
        byte[] kdfSeed = Arrays.copyOfRange(ukm, 8, 16);
        byte[][] keys = CtrAcpkmMode.deriveContentKeys(cek, kdfSeed);
        byte[] encKey = keys[0];
        byte[] macKey = keys[1];

        SymmetricKey k1 = new SymmetricKey(encKey);
        CtrAcpkmMode stream = new CtrAcpkmMode(new Kuznyechik(), false, AcpkmSectionSize.CMS);
        try {
            stream.init(true, new ParametersWithIV(k1, ukm));

            byte[] macTag = CtrAcpkmMode.computeCmac(macKey, data);

            // Единый CTR-поток: контент, затем имитовставка (как gost2015_final_call)
            byte[] encryptedContent = new byte[data.length];
            stream.processBytes(data, 0, data.length, encryptedContent, 0);

            byte[] encryptedMac = new byte[macTag.length];
            stream.processBytes(macTag, 0, macTag.length, encryptedMac, 0);

            byte[] macAttrDer =
                    CmsAttribute.encode(
                            GostOids.ID_CMS_MAC_ATTR, DerCodec.encodeOctetString(encryptedMac));

            ContentMacAttribute macAttr = new ContentMacAttribute(encryptedMac, macAttrDer);
            return new EncryptResult(encryptedContent, macAttr);
        } finally {
            stream.destroy();
            k1.destroy();
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);
        }
    }

    /**
     * Расшифровывает данные с проверкой имитовставки.
     *
     * @param encryptedContent зашифрованные данные (без MAC)
     * @param encryptedMac     зашифрованная имитовставка (16 байт)
     * @param cek              контентный ключ шифрования (32 байта)
     * @param ukm              content-UKM (16 байт)
     * @return расшифрованные данные
     * @throws org.rssys.gost.util.AuthenticationException при несовпадении имитовставки
     */
    public static byte[] decrypt(
            byte[] encryptedContent, byte[] encryptedMac, byte[] cek, byte[] ukm)
            throws AuthenticationException {
        byte[] kdfSeed = Arrays.copyOfRange(ukm, 8, 16);
        byte[][] keys = CtrAcpkmMode.deriveContentKeys(cek, kdfSeed);
        byte[] encKey = keys[0];
        byte[] macKey = keys[1];

        SymmetricKey k1 = new SymmetricKey(encKey);
        CtrAcpkmMode stream = new CtrAcpkmMode(new Kuznyechik(), false, AcpkmSectionSize.CMS);
        try {
            stream.init(false, new ParametersWithIV(k1, ukm));

            // Единый CTR-поток: контент, затем имитовставка (как gost2015_final_call)
            byte[] plaintext = new byte[encryptedContent.length];
            stream.processBytes(encryptedContent, 0, encryptedContent.length, plaintext, 0);

            byte[] macText = new byte[encryptedMac.length];
            stream.processBytes(encryptedMac, 0, encryptedMac.length, macText, 0);

            byte[] macCount = CtrAcpkmMode.computeCmac(macKey, plaintext);

            if (!MessageDigest.isEqual(macText, macCount)) {
                throw new AuthenticationException(
                        "CMS OMAC: content-mac mismatch — content integrity violation");
            }

            LOG.log(Level.DEBUG, "CMS OMAC verification passed");
            return plaintext;
        } finally {
            stream.destroy();
            k1.destroy();
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);
        }
    }

    /**
     * Результат шифрования CMS-OMAC: зашифрованный контент и атрибут content-mac.
     */
    public record EncryptResult(byte[] encryptedContent, ContentMacAttribute macAttribute) {}
}
