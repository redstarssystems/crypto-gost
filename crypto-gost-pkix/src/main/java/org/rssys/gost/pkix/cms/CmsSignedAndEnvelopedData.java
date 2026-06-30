package org.rssys.gost.pkix.cms;

import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Совмещённая подпись и шифрование CMS через вложение (nesting)
 * одного ContentInfo в другой.
 *
 * <p>Поддерживает два порядка вложенности:
 * <ul>
 *   <li><b>sign-then-encrypt</b> — SignedData внутри EnvelopedData.
 *       Подпись скрыта от внешнего наблюдателя. Получатель сначала
 *       расшифровывает, потом проверяет подпись.</li>
 *   <li><b>encrypt-then-sign</b> — EnvelopedData внутри SignedData.
 *       Подпись доступна для проверки без расшифровки (аудируемость).</li>
 * </ul>
 *
 * <p>Соответствует RFC 5652: вложение нескольких обёрток ContentInfo
 * друг в друга (§1), content-type signed-атрибут совпадает с eContentType (§5.6),
 * версия SignedData — 3 при eContentType != id-data (§5.1).
 *
 * <p>Для детального контроля (выбор алгоритмов дайджеста, key wrap,
 * detached-режим, пользовательские signed-атрибуты) используйте
 * {@link CmsSignedDataBuilder} и {@link CmsEnvelopedDataBuilder} напрямую.
 */
public final class CmsSignedAndEnvelopedData {

    private CmsSignedAndEnvelopedData() {}

    /**
     * Подписать, затем зашифровать для получателей.
     *
     * <p>Порядок: SignedData(данные) -> EnvelopedData(SignedData).
     * Наружу торчит EnvelopedData — подпись не видна без расшифрования.
     *
     * @param data       исходные данные
     * @param signerKey  закрытый ключ подписанта
     * @param signerCert сертификат подписанта
     * @param recipients сертификаты получателей (один и более)
     * @return DER-байты ContentInfo(id-envelopedData), содержащего
     *         зашифрованный ContentInfo(id-signedData)
     */
    public static byte[] signThenEncrypt(
            byte[] data,
            PrivateKeyParameters signerKey,
            GostCertificate signerCert,
            GostCertificate... recipients) {

        // Шаг 1: SignedData
        byte[] signedDer =
                CmsSignedDataBuilder.create().data(data).addSigner(signerKey, signerCert).build();

        // Шаг 2: EnvelopedData(SignedData)
        CmsEnvelopedDataBuilder envBuilder =
                CmsEnvelopedDataBuilder.create()
                        .data(signedDer)
                        .encryptedContentType(GostOids.CMS_SIGNED_DATA);
        for (GostCertificate recipient : recipients) {
            envBuilder.addRecipient(recipient);
        }
        return envBuilder.build();
    }

    /**
     * Зашифровать для получателей, затем подписать.
     *
     * <p>Порядок: EnvelopedData(данные) -> SignedData(EnvelopedData).
     * Наружу торчит SignedData — подпись можно проверить без расшифрования.
     * Используйте, когда нужна аудируемость.
     *
     * @param data       исходные данные
     * @param signerKey  закрытый ключ подписанта
     * @param signerCert сертификат подписанта
     * @param recipients сертификаты получателей (один и более)
     * @return DER-байты ContentInfo(id-signedData), содержащего
     *         ContentInfo(id-envelopedData)
     */
    public static byte[] encryptThenSign(
            byte[] data,
            PrivateKeyParameters signerKey,
            GostCertificate signerCert,
            GostCertificate... recipients) {

        // Шаг 1: EnvelopedData
        CmsEnvelopedDataBuilder envBuilder = CmsEnvelopedDataBuilder.create().data(data);
        for (GostCertificate recipient : recipients) {
            envBuilder.addRecipient(recipient);
        }
        byte[] envelopedDer = envBuilder.build();

        // Шаг 2: SignedData(EnvelopedData)
        return CmsSignedDataBuilder.create()
                .data(envelopedDer)
                .contentType(GostOids.CMS_ENVELOPED_DATA)
                .addSigner(signerKey, signerCert)
                .build();
    }

    /**
     * Расшифровать, затем проверить подпись (обратный порядок к {@link #signThenEncrypt}).
     *
     * <p>Ожидает на входе ContentInfo(id-envelopedData), внутри которого
     * зашифрован ContentInfo(id-signedData).
     *
     * @param combinedDer    DER-байты ContentInfo(id-envelopedData)
     * @param recipientKey   закрытый ключ получателя
     * @param recipientCert  сертификат получателя
     * @param trustedCerts   доверенные сертификаты для проверки подписи
     * @return результат с исходными данными и сертификатом подписанта
     * @throws PkixException если расшифрование или верификация не удались
     */
    public static VerifiedSignedData decryptAndVerify(
            byte[] combinedDer,
            PrivateKeyParameters recipientKey,
            GostCertificate recipientCert,
            GostCertificate... trustedCerts)
            throws PkixException {

        // Шаг 1: расшифровываем EnvelopedData -> получаем SignedData
        byte[] signedDer =
                CmsEnvelopedDataDecryptor.decrypt(
                        combinedDer, recipientKey, recipientCert, new Kexp15CmsKeyWrap());

        // Шаг 2: верифицируем SignedData -> получаем исходные данные
        return CmsSignedDataVerifier.verifyAny(signedDer, trustedCerts);
    }

    /**
     * Проверить подпись, затем расшифровать (обратный порядок к {@link #encryptThenSign}).
     *
     * <p>Ожидает на входе ContentInfo(id-signedData), внутри которого
     * находится ContentInfo(id-envelopedData).
     *
     * @param combinedDer    DER-байты ContentInfo(id-signedData)
     * @param recipientKey   закрытый ключ получателя
     * @param recipientCert  сертификат получателя
     * @param trustedCerts   доверенные сертификаты для проверки подписи
     * @return результат с исходными данными и сертификатом подписанта
     * @throws PkixException если верификация или расшифрование не удались
     */
    public static VerifiedSignedData verifyAndDecrypt(
            byte[] combinedDer,
            PrivateKeyParameters recipientKey,
            GostCertificate recipientCert,
            GostCertificate... trustedCerts)
            throws PkixException {

        // Шаг 1: верифицируем SignedData -> извлекаем EnvelopedData
        VerifiedSignedData verifyResult =
                CmsSignedDataVerifier.verifyAny(combinedDer, trustedCerts);

        byte[] envelopedDer = verifyResult.data();
        if (envelopedDer == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "No enveloped data extracted from SignedData (detached?)");
        }

        // Шаг 2: расшифровываем EnvelopedData -> получаем исходные данные
        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(
                        envelopedDer, recipientKey, recipientCert, new Kexp15CmsKeyWrap());
        return new VerifiedSignedData(
                decrypted, verifyResult.signerCertificate(), verifyResult.unsignedAttributes());
    }
}
