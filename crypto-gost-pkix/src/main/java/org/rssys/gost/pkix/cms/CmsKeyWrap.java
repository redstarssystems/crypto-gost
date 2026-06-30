package org.rssys.gost.pkix.cms;

/**
 * Абстракция алгоритма обёртывания ключа для CMS EnvelopedData.
 *
 * <p>Используется в {@link CmsEnvelopedDataBuilder} и
 * {@link CmsEnvelopedDataDecryptor} для обёртывания CEK
 * с помощью KEK, полученного через VKO.
 */
public interface CmsKeyWrap {

    /**
     * Оборачивает ключ содержимого.
     *
     * @param cek ключ содержимого (Content Encryption Key), 32 байта
     * @param kek ключ шифрования ключа (Key Encryption Key), 32 байта
     * @param ukm пользовательский ключевой материал (UserKeyingMaterial), 8 байт
     * @return обёрнутый CEK
     */
    byte[] wrap(byte[] cek, byte[] kek, byte[] ukm);

    /**
     * Разворачивает ключ содержимого.
     *
     * @param wrappedCek обёрнутый CEK
     * @param kek        ключ шифрования ключа (KEK), 32 байта
     * @param ukm        пользовательский ключевой материал, 8 байт
     * @return исходный CEK (32 байта)
     */
    byte[] unwrap(byte[] wrappedCek, byte[] kek, byte[] ukm);

    /** OID алгоритма обёртывания ключа. */
    String algorithmOid();
}
