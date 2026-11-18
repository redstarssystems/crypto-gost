package org.rssys.gost.pkix.cms;

import java.util.Arrays;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.AcpkmSectionSize;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * CMS-профильный OMAC по Р 1323565.1.025-2019 §8.3.2 (Mac-and-Encrypt).
 *
 * <p>Схема совпадает с PBES2-OMAC (RFC 9337 §5.1.1) и реализована общим режимом
 * {@link CtrAcpkmMode} с OMAC. Отличия профиля CMS:
 * <ul>
 *   <li>размер секции ACPKM - 256 КБ ({@link AcpkmSectionSize#CMS});</li>
 *   <li>зашифрованная имитовставка выносится в {@code unprotectedAttrs}
 *       как атрибут {@code content-mac} ({@link GostOids#ID_CMS_MAC_ATTR}),
 *       а не дописывается к шифртексту.</li>
 * </ul>
 * CMAC вычисляется по <b>открытому</b> тексту содержимого (Mac-and-Encrypt).
 *
 * <p><b>CTR-поток.</b> Имитовставка шифруется на продолжении того же CTR-потока,
 * что и контент — не с начала IV (gost2015_final_call, gost-engine). Поэтому контент
 * и имитовставка обрабатываются одним экземпляром режима: {@code processBytes} для
 * контента, затем {@code finishEncryption} (или {@code verifyEncryptedTag}).
 * Отдельные вызовы статических методов сбрасывали бы счётчик.
 *
 * <p><b>ACPKM-рекейинг.</b> Секционная смена ключа (Р 1323565.1.017-2018, RFC 8645)
 * выполняется каждые 256 КБ. CMAC считается по открытому тексту отдельным
 * экземпляром Кузнечика (ключ K(2)), а имитовставка шифруется на продолжении
 * того же CTR-потока после контента — при рекейинге имитовставка шифруется
 * на N-й секции ключа. Поведение соответствует gost-engine
 * ({@code gost2015_final_call}).
 */
public final class CmsOmacHelper {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.CmsOmacHelper");

    /** Атрибут content-mac для unprotectedAttrs, закодированный в DER. */
    public record ContentMacAttribute(byte[] encodedMac, byte[] derEncoded) {}

    private CmsOmacHelper() {}

    /**
     * Проверяет длину content-UKM. {@code Arrays.copyOfRange} молча дополнил бы короткий UKM
     * нулями в seed KDF_TREE, и при повторе IV ключ K(1) совпал бы.
     */
    private static void requireContentUkm(byte[] ukm) {
        if (ukm == null || ukm.length != GostOids.CMS_CONTENT_UKM_LEN) {
            throw new IllegalArgumentException(
                    "CMS content UKM must be "
                            + GostOids.CMS_CONTENT_UKM_LEN
                            + " bytes, got "
                            + (ukm == null ? "none" : String.valueOf(ukm.length)));
        }
    }

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
        requireContentUkm(ukm);
        SymmetricKey cekKey = new SymmetricKey(cek);
        // Режим с OMAC сам выводит K(1), K(2) = KDF_TREE(CEK, "kdf tree", ukm[8..15]),
        // считает CMAC по открытому тексту и шифрует тег продолжением потока.
        CtrAcpkmMode stream = new CtrAcpkmMode(new Kuznyechik(), true, AcpkmSectionSize.CMS);
        try {
            stream.init(true, new ParametersWithIV(cekKey, ukm));

            byte[] encryptedContent = new byte[data.length];
            stream.processBytes(data, 0, data.length, encryptedContent, 0);
            byte[] encryptedMac = stream.finishEncryption();

            byte[] macAttrDer =
                    CmsAttribute.encode(
                            GostOids.ID_CMS_MAC_ATTR, DerCodec.encodeOctetString(encryptedMac));

            ContentMacAttribute macAttr = new ContentMacAttribute(encryptedMac, macAttrDer);
            return new EncryptResult(encryptedContent, macAttr);
        } finally {
            stream.destroy();
            cekKey.destroy();
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
        requireContentUkm(ukm);
        SymmetricKey cekKey = new SymmetricKey(cek);
        CtrAcpkmMode stream = new CtrAcpkmMode(new Kuznyechik(), true, AcpkmSectionSize.CMS);
        byte[] plaintext = null;
        boolean authenticated = false;
        try {
            stream.init(false, new ParametersWithIV(cekKey, ukm));

            plaintext = new byte[encryptedContent.length];
            stream.processBytes(encryptedContent, 0, encryptedContent.length, plaintext, 0);
            try {
                // Тег неверной длины режим отвергает сам: молча усечённый тег недопустим.
                stream.verifyEncryptedTag(encryptedMac);
            } catch (AuthenticationException e) {
                throw new AuthenticationException(
                        "CMS OMAC: content-mac mismatch — content integrity violation");
            }

            authenticated = true;
            LOG.log(Level.DEBUG, "CMS OMAC verification passed");
            return plaintext;
        } finally {
            // Непроверенный открытый текст не должен остаться в куче.
            if (!authenticated && plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
            stream.destroy();
            cekKey.destroy();
        }
    }

    /**
     * Результат шифрования CMS-OMAC: зашифрованный контент и атрибут content-mac.
     */
    public record EncryptResult(byte[] encryptedContent, ContentMacAttribute macAttribute) {}
}
