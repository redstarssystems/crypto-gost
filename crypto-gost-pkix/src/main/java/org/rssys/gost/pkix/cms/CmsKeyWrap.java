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
     * @param ukm пользовательский ключевой материал (UserKeyingMaterial), seed для KDF_TREE
     * @param iv  вектор инициализации для KExp15/KImp15 (8 байт), UKM[24..31] по ТК26
     * @return обёрнутый CEK
     */
    byte[] wrap(byte[] cek, byte[] kek, byte[] ukm, byte[] iv);

    /**
     * Разворачивает ключ содержимого.
     *
     * @param wrappedCek обёрнутый CEK
     * @param kek        ключ шифрования ключа (KEK), 32 байта
     * @param ukm        пользовательский ключевой материал, seed для KDF_TREE
     * @param iv         вектор инициализации для KImp15 (8 байт), UKM[24..31] по ТК26
     * @return исходный CEK (32 байта)
     */
    byte[] unwrap(byte[] wrappedCek, byte[] kek, byte[] ukm, byte[] iv);

    /** OID алгоритма обёртывания ключа. */
    String algorithmOid();
}
