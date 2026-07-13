package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * CAdES-X Long: CertificateValues и RevocationValues (RFC 5126 §6.3).
 *
 * <p>Кодирование/декодирование certificate-values и revocation-values —
 * unsigned-атрибутов, встраиваемых в SignerInfo поверх CAdES-C.
 * Переиспользует типы из {@link CAdESCompleteData} для сверки хэшей.
 */
public final class CAdESXLongData {

    private CAdESXLongData() {}

    /**
     * Результат декодирования RevocationValues.
     */
    public record RevocationValuesDecoded(
            List<GostCrl> crls, List<GostOcspResponse> ocspResponses) {
        public RevocationValuesDecoded {
            Objects.requireNonNull(crls, "crls must not be null");
            Objects.requireNonNull(ocspResponses, "ocspResponses must not be null");
            crls = Collections.unmodifiableList(crls);
            ocspResponses = Collections.unmodifiableList(ocspResponses);
        }

        /** RevocationValues с пустыми списками (нет CRL и нет OCSP). */
        public static final RevocationValuesDecoded EMPTY =
                new RevocationValuesDecoded(List.of(), List.of());
    }

    // ========================================================================
    // Кодирование
    // ========================================================================

    /**
     * Кодирует CertificateValues: SEQUENCE OF Certificate.
     *
     * <p>Результат — DER SEQUENCE, каждый элемент которой — DER-сертификат.
     *
     * @param certs сертификаты цепочки
     * @return DER SEQUENCE OF Certificate
     */
    public static byte[] encodeCertificateValues(List<GostCertificate> certs) throws PkixException {
        Objects.requireNonNull(certs, "certs must not be null");
        if (certs.size() > CmsConstants.MAX_EMBEDDED_CERTS) {
            throw new PkixException(
                    "CertificateValues: "
                            + certs.size()
                            + " certs exceeds limit "
                            + CmsConstants.MAX_EMBEDDED_CERTS);
        }
        byte[][] derCerts = new byte[certs.size()][];
        for (int i = 0; i < certs.size(); i++) {
            derCerts[i] = certs.get(i).getEncoded();
        }
        byte[] seqOf = DerCodec.encodeSequence(derCerts);
        if (seqOf.length > CmsConstants.MAX_CERT_VALUES_SIZE) {
            throw new PkixException(
                    "CertificateValues: "
                            + seqOf.length
                            + " bytes exceeds limit "
                            + CmsConstants.MAX_CERT_VALUES_SIZE);
        }
        return seqOf;
    }

    /**
     * Кодирует RevocationValues: SEQUENCE { crlVals [0], ocspVals [1] }.
     *
     * <p>Пропускает опциональное поле, если соответствующий список пуст.
     *
     * @param crls         CRL для встраивания (может быть null или пуст)
     * @param ocspResponses OCSP-ответы (может быть null или пуст)
     * @return DER RevocationValues
     */
    public static byte[] encodeRevocationValues(
            List<GostCrl> crls, List<GostOcspResponse> ocspResponses) throws PkixException {
        Objects.requireNonNull(crls, "crls must not be null");
        Objects.requireNonNull(ocspResponses, "ocspResponses must not be null");

        if (crls.size() > CmsConstants.MAX_EMBEDDED_CRLS) {
            throw new PkixException(
                    "RevocationValues: "
                            + crls.size()
                            + " CRLs exceeds limit "
                            + CmsConstants.MAX_EMBEDDED_CRLS);
        }
        if (ocspResponses.size() > CmsConstants.MAX_OCSP_VALUES) {
            throw new PkixException(
                    "RevocationValues: "
                            + ocspResponses.size()
                            + " OCSP responses exceeds limit "
                            + CmsConstants.MAX_OCSP_VALUES);
        }

        List<byte[]> parts = new ArrayList<>(2);

        List<GostCrl> nonNullCrls = new ArrayList<>();
        for (GostCrl crl : crls) {
            if (crl != null) {
                nonNullCrls.add(crl);
            }
        }
        if (!nonNullCrls.isEmpty()) {
            byte[][] crlDerList = new byte[nonNullCrls.size()][];
            for (int i = 0; i < nonNullCrls.size(); i++) {
                crlDerList[i] = nonNullCrls.get(i).getEncoded();
            }
            byte[] crlSeqOf = DerCodec.encodeSequence(crlDerList);
            parts.add(DerCodec.encodeContextConstructed(0, crlSeqOf));
        }

        List<GostOcspResponse> nonNullOcsps = new ArrayList<>();
        for (GostOcspResponse ocsp : ocspResponses) {
            if (ocsp != null) {
                nonNullOcsps.add(ocsp);
            }
        }
        if (!nonNullOcsps.isEmpty()) {
            byte[][] ocspDerList = new byte[nonNullOcsps.size()][];
            for (int i = 0; i < nonNullOcsps.size(); i++) {
                ocspDerList[i] = nonNullOcsps.get(i).getEncoded();
            }
            byte[] ocspSeqOf = DerCodec.encodeSequence(ocspDerList);
            parts.add(DerCodec.encodeContextConstructed(1, ocspSeqOf));
        }

        byte[] seqOf = DerCodec.encodeSequence(parts.toArray(new byte[0][]));
        if (seqOf.length > CmsConstants.MAX_REVOC_VALUES_SIZE) {
            throw new PkixException(
                    "RevocationValues: "
                            + seqOf.length
                            + " bytes exceeds limit "
                            + CmsConstants.MAX_REVOC_VALUES_SIZE);
        }
        return seqOf;
    }

    // ========================================================================
    // Декодирование
    // ========================================================================

    /**
     * Декодирует CertificateValues: SEQUENCE OF Certificate.
     *
     * @param der          DER CertificateValues
     * @return список сертификатов
     * @throws PkixException при ошибке DER или превышении лимитов
     */
    public static List<GostCertificate> decodeCertificateValues(byte[] der) throws PkixException {
        if (der == null || der.length == 0) {
            return List.of();
        }
        if (der.length > CmsConstants.MAX_CERT_VALUES_SIZE) {
            throw new PkixException(
                    "CertificateValues: "
                            + der.length
                            + " bytes exceeds limit "
                            + CmsConstants.MAX_CERT_VALUES_SIZE);
        }

        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        if (parts.length > CmsConstants.MAX_EMBEDDED_CERTS) {
            throw new PkixException(
                    "CertificateValues: "
                            + parts.length
                            + " certs exceeds limit "
                            + CmsConstants.MAX_EMBEDDED_CERTS);
        }

        List<GostCertificate> certs = new ArrayList<>(parts.length);
        for (byte[] certDer : parts) {
            certs.add(new GostCertificate(certDer));
        }
        return Collections.unmodifiableList(certs);
    }

    /**
     * Декодирует RevocationValues: SEQUENCE { crlVals [0], ocspVals [1] }.
     *
     * @param der DER RevocationValues
     * @return результат с CRL и OCSP-ответами
     * @throws PkixException при ошибке DER или превышении лимитов
     */
    public static RevocationValuesDecoded decodeRevocationValues(byte[] der) throws PkixException {
        if (der == null || der.length == 0) {
            return RevocationValuesDecoded.EMPTY;
        }
        if (der.length > CmsConstants.MAX_REVOC_VALUES_SIZE) {
            throw new PkixException(
                    "RevocationValues: "
                            + der.length
                            + " bytes exceeds limit "
                            + CmsConstants.MAX_REVOC_VALUES_SIZE);
        }

        byte[][] parts = DerCodec.parseSequenceContents(der, 0);

        List<GostCrl> crls = new ArrayList<>();
        List<GostOcspResponse> ocspResponses = new ArrayList<>();
        boolean crlSeen = false;
        boolean ocspSeen = false;

        for (byte[] part : parts) {
            int tag = part[0] & 0xFF;
            if (tag == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                if (crlSeen) {
                    throw new PkixException("duplicate [0] crlVals in RevocationValues");
                }
                crlSeen = true;
                crls = decodeCrlVals(part);
            } else if (tag == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                if (ocspSeen) {
                    throw new PkixException("duplicate [1] ocspVals in RevocationValues");
                }
                ocspSeen = true;
                ocspResponses = decodeOcspVals(part);
            }
        }

        return new RevocationValuesDecoded(crls, ocspResponses);
    }

    private static List<GostCrl> decodeCrlVals(byte[] der) throws PkixException {
        int[] lenInfo = DerCodec.decodeLength(der, 1);
        int contentOff = 1 + lenInfo[1];
        byte[][] crlParts = DerCodec.parseSequenceContents(der, contentOff);

        if (crlParts.length > CmsConstants.MAX_EMBEDDED_CRLS) {
            throw new PkixException(
                    "RevocationValues crlVals: "
                            + crlParts.length
                            + " CRLs exceeds limit "
                            + CmsConstants.MAX_EMBEDDED_CRLS);
        }

        List<GostCrl> crls = new ArrayList<>(crlParts.length);
        for (byte[] crlDer : crlParts) {
            crls.add(new GostCrl(crlDer));
        }
        return Collections.unmodifiableList(crls);
    }

    private static List<GostOcspResponse> decodeOcspVals(byte[] der) throws PkixException {
        int[] lenInfo = DerCodec.decodeLength(der, 1);
        int contentOff = 1 + lenInfo[1];
        byte[][] ocspParts = DerCodec.parseSequenceContents(der, contentOff);

        if (ocspParts.length > CmsConstants.MAX_OCSP_VALUES) {
            throw new PkixException(
                    "RevocationValues ocspVals: "
                            + ocspParts.length
                            + " OCSP responses exceeds limit "
                            + CmsConstants.MAX_OCSP_VALUES);
        }

        List<GostOcspResponse> responses = new ArrayList<>(ocspParts.length);
        for (byte[] ocspDer : ocspParts) {
            responses.add(new GostOcspResponse(ocspDer));
        }
        return Collections.unmodifiableList(responses);
    }
}
