package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostPemUtils;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Извлечение сертификатов из контейнера PKCS#7/CMS SignedData ({@code .p7b}).
 *
 * <p>Формат {@code .p7b} — распространённый способ обмена сертификатами (и их
 * цепочками) в РФ-PKI: это ContentInfo(id-signedData), у которого поле
 * {@code certificates [0]} заполнено, а {@code signerInfos} обычно пуст. Штатный
 * {@link CmsSignedDataVerifier} для таких контейнеров неприменим — он проверяет
 * подписантов и требует их наличия. Данный класс выполняет только разбор DER и
 * извлечение X.509-сертификатов, без криптографической верификации.</p>
 *
 * <p>Проверка подписи, цепочки, срока действия и отзыва — ответственность
 * вызывающего кода (например, через {@link org.rssys.gost.pkix.cert.ChainValidator}).</p>
 */
public final class GostPkcs7 {

    private GostPkcs7() {}

    /**
     * Строит certs-only PKCS#7/.p7b (SignedData без подписантов) с заданными
     * сертификатами — зеркально {@link #extractCertificates(byte[])}.
     *
     * <p>Результат — {@code ContentInfo(id-signedData)} с заполненным полем
     * {@code certificates [0]} и пустыми {@code signerInfos}; это распространённый
     * формат обмена цепочками сертификатов. Подписи не создаются.</p>
     *
     * <p>Для встраивания CRL в контейнер используйте
     * {@link #buildCertsOnly(List, GostCertificate...)}.</p>
     *
     * @param certs сертификаты для вложения (минимум один)
     * @return DER-байты контейнера {@code .p7b}
     * @throws IllegalArgumentException если сертификаты не переданы либо их число
     *                                  превышает {@link CmsConstants#MAX_P7B_CERTS}
     */
    public static byte[] buildCertsOnly(GostCertificate... certs) {
        return buildCertsOnly(Collections.emptyList(), certs);
    }

    /**
     * Строит certs-only PKCS#7/.p7b с заданными сертификатами и опциональными CRL.
     *
     * <p>Поле {@code crls [1] IMPLICIT SET OF RevocationInfoChoice} (RFC 5652 §5.1)
     * заполняется только если {@code crls} не null и не пуст.</p>
     *
     * @param crls  CRL для встраивания в поле crls [1] (может быть null или пустым)
     * @param certs сертификаты для вложения (минимум один)
     * @return DER-байты контейнера {@code .p7b}
     * @throws IllegalArgumentException если сертификаты не переданы либо их число
     *                                  превышает {@link CmsConstants#MAX_P7B_CERTS}
     */
    public static byte[] buildCertsOnly(List<GostCrl> crls, GostCertificate... certs) {
        if (certs == null || certs.length == 0) {
            throw new IllegalArgumentException("no certificates provided");
        }
        if (certs.length > CmsConstants.MAX_P7B_CERTS) {
            throw new IllegalArgumentException(
                    "certificate count exceeds maximum " + CmsConstants.MAX_P7B_CERTS);
        }
        CmsSignedDataBuilder builder = CmsSignedDataBuilder.create().certsOnly();
        for (GostCertificate cert : certs) {
            builder.addCertificate(cert);
        }
        if (crls != null) {
            for (GostCrl crl : crls) {
                builder.addCrl(crl);
            }
        }
        return builder.build();
    }

    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos }
    // Поле certificates идёт четвёртым, после трёх обязательных полей (RFC 5652 §5.1).
    private static final int CERTIFICATES_FIELD_INDEX = 3;

    /**
     * Извлекает сертификаты из PKCS#7/.p7b с дефолтным потолком
     * {@link CmsConstants#MAX_P7B_CERTS}.
     *
     * @param data байты контейнера в формате DER или PEM ({@code -----BEGIN PKCS7-----})
     * @return список извлечённых сертификатов (возможно пустой)
     * @throws PkixException если вход не является корректным PKCS#7 SignedData
     */
    public static List<GostCertificate> extractCertificates(byte[] data) throws PkixException {
        return extractCertificates(data, CmsConstants.MAX_P7B_CERTS);
    }

    /**
     * Извлекает сертификаты из PKCS#7/.p7b с явным потолком их числа.
     *
     * <p>Автоопределение формата DER/PEM по первому байту (как у
     * {@code fromPemOrDer}-методов). Криптографическая верификация не выполняется.</p>
     *
     * @param data     байты контейнера в формате DER или PEM
     * @param maxCerts потолок числа извлекаемых сертификатов (защита от DoS)
     * @return список извлечённых сертификатов (возможно пустой)
     * @throws PkixException если вход не является корректным PKCS#7 SignedData
     *                       либо число сертификатов превышает {@code maxCerts}
     */
    public static List<GostCertificate> extractCertificates(byte[] data, int maxCerts)
            throws PkixException {
        if (data == null || data.length == 0) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "PKCS#7 data is empty");
        }
        if (data.length > CmsConstants.MAX_P7B_SIZE) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "PKCS#7 data exceeds maximum size " + CmsConstants.MAX_P7B_SIZE);
        }
        if (maxCerts <= 0) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "maxCerts must be positive, got " + maxCerts);
        }

        byte[] der;
        try {
            der = GostPemUtils.isPem(data) ? GostPemUtils.pemToDer(data) : data;

            CmsContentInfo contentInfo = CmsContentInfo.decode(der);
            if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Not a PKCS#7 SignedData: contentType=" + contentInfo.contentType());
            }
            byte[] signedDataBody = contentInfo.content();
            if (signedDataBody == null) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "ContentInfo does not contain SignedData");
            }

            byte[][] parts = DerCodec.parseSequenceContents(signedDataBody, 0);
            // certificates-поле опционально: если после encapContentInfo его нет
            // (сразу crls[1] или signerInfos), сертификатов в контейнере нет.
            if (parts.length <= CERTIFICATES_FIELD_INDEX
                    || !DerCodec.isContextTag(parts[CERTIFICATES_FIELD_INDEX], 0)) {
                return new ArrayList<>();
            }
            return CmsSignedDataVerifier.parseEmbeddedCertificates(
                    parts[CERTIFICATES_FIELD_INDEX], maxCerts);
        } catch (IllegalArgumentException | IllegalStateException e) {
            // DerCodec на битом DER бросает unchecked-исключения; на границе публичного
            // API приводим их к checked PkixException. Настоящие баги (AIOOBE/NPE) не
            // перехватываем — их обязан ловить фаззинг.
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Malformed PKCS#7 SignedData", e);
        }
    }
}
