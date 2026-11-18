package org.rssys.gost.pkix.cms;

import java.util.Objects;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
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
 * <p>Шифрование выполняется с имитовставкой (OMAC) по умолчанию. При разборе допускается и
 * контейнер без имитовставки ({@link CmsEnvelopedDataDecryptor#decryptAllowingNoIntegrity}):
 * целостность обеспечивает подпись. При sign-then-encrypt подмена шифртекста или режима даёт
 * содержимое, не проходящее разбор SignedData и проверку подписи; при encrypt-then-sign подпись
 * проверяется над EnvelopedData до расшифрования, поэтому изменить OID шифра или удалить
 * атрибуты, не сломав подпись, нельзя.
 *
 * <p>Для детального контроля (выбор алгоритмов дайджеста,
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
     * @param signer     подписант (может быть HSM-адаптером)
     * @param signerCert сертификат подписанта
     * @param recipients сертификаты получателей (один и более)
     * @return DER-байты ContentInfo(id-envelopedData), содержащего
     *         зашифрованный ContentInfo(id-signedData)
     * @throws NullPointerException если {@code recipients == null}
     * @throws IllegalArgumentException если список получателей пуст или KeyUsage сертификата
     *         получателя не допускает управление ключами, см.
     *         {@link CmsEnvelopedDataBuilder#addRecipient}
     */
    public static byte[] signThenEncrypt(
            byte[] data,
            GostSigner signer,
            GostCertificate signerCert,
            GostCertificate... recipients) {

        // Получателей проверяем до подписи: подпись - обращение к ключу (токен, HSM, PIN,
        // запись в журнале подписей), и отказ из-за плохого получателя не должен её тратить
        CmsEnvelopedDataBuilder envBuilder =
                CmsEnvelopedDataBuilder.create().encryptedContentType(GostOids.CMS_SIGNED_DATA);
        addRecipients(envBuilder, recipients);

        // Шаг 1: SignedData
        byte[] signedDer =
                CmsSignedDataBuilder.create().data(data).addSigner(signer, signerCert).build();

        // Шаг 2: EnvelopedData(SignedData)
        return envBuilder.data(signedDer).build();
    }

    /**
     * Подписать, затем зашифровать для получателей (удобная перегрузка с ключом в памяти).
     *
     * @param data       исходные данные
     * @param signerKey  закрытый ключ подписанта
     * @param signerCert сертификат подписанта
     * @param recipients сертификаты получателей (один и более)
     * @return DER-байты ContentInfo(id-envelopedData)
     * @throws NullPointerException если {@code recipients == null}
     * @throws IllegalArgumentException если список получателей пуст или KeyUsage сертификата
     *         получателя не допускает управление ключами, см.
     *         {@link CmsEnvelopedDataBuilder#addRecipient}
     */
    public static byte[] signThenEncrypt(
            byte[] data,
            PrivateKeyParameters signerKey,
            GostCertificate signerCert,
            GostCertificate... recipients) {
        return signThenEncrypt(data, GostSigner.of(signerKey), signerCert, recipients);
    }

    /**
     * Зашифровать для получателей, затем подписать.
     *
     * <p>Порядок: EnvelopedData(данные) -> SignedData(EnvelopedData).
     * Наружу торчит SignedData — подпись можно проверить без расшифрования.
     * Используйте, когда нужна аудируемость.
     *
     * @param data       исходные данные
     * @param signer     подписант (может быть HSM-адаптером)
     * @param signerCert сертификат подписанта
     * @param recipients сертификаты получателей (один и более)
     * @return DER-байты ContentInfo(id-signedData), содержащего
     *         ContentInfo(id-envelopedData)
     * @throws NullPointerException если {@code recipients == null}
     * @throws IllegalArgumentException если список получателей пуст или KeyUsage сертификата
     *         получателя не допускает управление ключами, см.
     *         {@link CmsEnvelopedDataBuilder#addRecipient}
     */
    public static byte[] encryptThenSign(
            byte[] data,
            GostSigner signer,
            GostCertificate signerCert,
            GostCertificate... recipients) {

        // Шаг 1: EnvelopedData
        CmsEnvelopedDataBuilder envBuilder = CmsEnvelopedDataBuilder.create().data(data);
        addRecipients(envBuilder, recipients);
        byte[] envelopedDer = envBuilder.build();

        // Шаг 2: SignedData(EnvelopedData)
        return CmsSignedDataBuilder.create()
                .data(envelopedDer)
                .contentType(GostOids.CMS_ENVELOPED_DATA)
                .addSigner(signer, signerCert)
                .build();
    }

    /**
     * Зашифровать для получателей, затем подписать (удобная перегрузка с ключом в памяти).
     *
     * @param data       исходные данные
     * @param signerKey  закрытый ключ подписанта
     * @param signerCert сертификат подписанта
     * @param recipients сертификаты получателей (один и более)
     * @return DER-байты ContentInfo(id-signedData)
     * @throws NullPointerException если {@code recipients == null}
     * @throws IllegalArgumentException если список получателей пуст или KeyUsage сертификата
     *         получателя не допускает управление ключами, см.
     *         {@link CmsEnvelopedDataBuilder#addRecipient}
     */
    public static byte[] encryptThenSign(
            byte[] data,
            PrivateKeyParameters signerKey,
            GostCertificate signerCert,
            GostCertificate... recipients) {
        return encryptThenSign(data, GostSigner.of(signerKey), signerCert, recipients);
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

        CmsSignedDataVerifier.requireTrustedCerts(trustedCerts);

        // Шаг 1: расшифровываем EnvelopedData -> получаем SignedData
        byte[] signedDer =
                CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                        combinedDer, recipientKey, recipientCert);

        // Шаг 2: верифицируем SignedData -> получаем исходные данные
        return CmsSignedDataVerifier.verify(signedDer, trustingAny(trustedCerts));
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

        CmsSignedDataVerifier.requireTrustedCerts(trustedCerts);

        // Шаг 1: верифицируем SignedData -> извлекаем EnvelopedData
        VerifiedSignedData verifyResult =
                CmsSignedDataVerifier.verify(combinedDer, trustingAny(trustedCerts));

        byte[] envelopedDer = verifyResult.data();
        if (envelopedDer == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "No enveloped data extracted from SignedData (detached?)");
        }

        // Шаг 2: расшифровываем EnvelopedData -> получаем исходные данные
        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                        envelopedDer, recipientKey, recipientCert);
        return new VerifiedSignedData(
                decrypted, verifyResult.signers(), verifyResult.embeddedCrls());
    }

    /**
     * Добавляет получателей в построитель. Проверка и порядок вызовов здесь общие для обоих
     * методов, чтобы один и тот же неверный аргумент давал одно и то же исключение.
     */
    private static void addRecipients(
            CmsEnvelopedDataBuilder envBuilder, GostCertificate[] recipients) {
        Objects.requireNonNull(recipients, "recipients");
        if (recipients.length == 0) {
            throw new IllegalArgumentException("recipients must not be empty");
        }
        for (GostCertificate recipient : recipients) {
            envBuilder.addRecipient(recipient);
        }
    }

    /** Проверка по доверенным сертификатам, один валидный подписант, без проверки отзыва. */
    private static VerifyOptions trustingAny(GostCertificate[] trustedCerts) {
        return VerifyOptions.trusting(
                TrustAnchors.ofCertificates(trustedCerts), SignerSelection.ANY, Revocation.none());
    }
}
