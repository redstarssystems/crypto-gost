package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CertificateTextFormatter;
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
    //
    // Родственный raw-разбор SignedData есть в SignedDataParts.parse() (CAdESExtender), но здесь
    // разбор проще/частичный и стабилизирован кросс-валидацией — сознательно не унифицирован
    // (см. javadoc SignedDataParts: риск регресса в проверенном коде несоразмерен выгоде).
    private static final int CERTIFICATES_FIELD_INDEX = 3;

    // Контекстный тег поля crls [1] (RFC 5652 §5.1).
    private static final int CRLS_FIELD_TAG = 1;

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

    /**
     * Формирует подробный человекочитаемый отчёт по контейнеру {@code .p7b}.
     *
     * <p>Печатает метаданные контейнера, детальный дамп каждого сертификата
     * (через {@link CertificateTextFormatter}) и метаданные каждого встроенного CRL.
     * Автоопределение DER/PEM, соблюдение DoS-лимитов
     * ({@link CmsConstants#MAX_P7B_CERTS}, {@link CmsConstants#MAX_P7B_SIZE}).</p>
     *
     * <p><b>Отчёт не является результатом криптографической проверки.</b> Как и
     * {@link #extractCertificates(byte[])}, метод выполняет только структурный разбор:
     * показанные DN, сроки и CRL никем не верифицированы в рамках этого вызова.
     * Первая строка вывода несёт явный дисклеймер об этом.</p>
     *
     * @param data байты контейнера в формате DER или PEM
     * @return человекочитаемый многострочный отчёт
     * @throws PkixException если вход не является корректным PKCS#7 SignedData
     *                       либо превышены DoS-лимиты
     */
    public static String formatText(byte[] data) throws PkixException {
        // Явная перегрузка с лимитом — не полагаемся на дефолт extractCertificates(byte[]).
        List<GostCertificate> certs = extractCertificates(data, CmsConstants.MAX_P7B_CERTS);
        List<GostCrl> crls = extractCrls(data);

        StringBuilder sb = new StringBuilder(2048);
        sb.append("=== PKCS#7 / .p7b контейнер (certs-only) ===\n");
        sb.append(
                "ВНИМАНИЕ: данные не верифицированы криптографически — только структурный разбор.\n");
        sb.append("Сертификатов: ")
                .append(certs.size())
                .append(", CRL: ")
                .append(crls.size())
                .append('\n');

        for (int i = 0; i < certs.size(); i++) {
            sb.append("\n--- Сертификат [").append(i).append("] ---\n");
            sb.append(CertificateTextFormatter.format(certs.get(i)));
        }

        for (int i = 0; i < crls.size(); i++) {
            appendCrl(sb, i, crls.get(i));
        }

        return sb.toString();
    }

    private static void appendCrl(StringBuilder sb, int index, GostCrl crl) {
        sb.append("\n--- CRL [").append(index).append("] ---\n");
        sb.append("    Издатель (Issuer): ").append(crl.getIssuerDn()).append('\n');
        sb.append("    This Update: ").append(crl.getThisUpdate()).append('\n');
        sb.append("    Next Update: ").append(crl.getNextUpdate()).append('\n');
        // Список отозванных серийников доступен только после verify() (fail-closed
        // инвариант GostCrl), а formatText() намеренно не верифицирует — поэтому
        // здесь показываем лишь метаданные, честно отмечая это.
        sb.append(
                "    Отозванные сертификаты: доступны после криптографической проверки (verify)\n");
    }

    /**
     * Извлекает встроенные CRL из поля {@code crls [1]} контейнера. Переиспользует
     * DoS-защищённый {@link CmsSignedDataVerifier#parseEmbeddedCrls(byte[])} —
     * без дублирования логики разбора {@code [1] IMPLICIT}.
     */
    private static List<GostCrl> extractCrls(byte[] data) throws PkixException {
        try {
            // Проверяем сырой размер ДО дорогого base64-декодирования PEM — консистентно
            // с extractCertificates и defensive-in-depth на случай отдельного вызова
            // (base64 только уменьшает размер, поэтому сырой data.length — верхняя граница).
            if (data.length > CmsConstants.MAX_P7B_SIZE) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "PKCS#7 data exceeds maximum size " + CmsConstants.MAX_P7B_SIZE);
            }
            byte[] der = GostPemUtils.isPem(data) ? GostPemUtils.pemToDer(data) : data;
            CmsContentInfo contentInfo = CmsContentInfo.decode(der);
            byte[] signedDataBody = contentInfo.content();
            if (signedDataBody == null) {
                return new ArrayList<>();
            }
            byte[][] parts = DerCodec.parseSequenceContents(signedDataBody, 0);
            for (int i = CERTIFICATES_FIELD_INDEX; i < parts.length; i++) {
                if (DerCodec.isContextTag(parts[i], CRLS_FIELD_TAG)) {
                    return CmsSignedDataVerifier.parseEmbeddedCrls(parts[i]);
                }
            }
            return new ArrayList<>();
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Malformed PKCS#7 SignedData", e);
        }
    }
}
