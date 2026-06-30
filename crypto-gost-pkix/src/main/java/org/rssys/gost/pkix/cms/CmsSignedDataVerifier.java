package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Проверка CMS SignedData.
 *
 * <p>Два режима верификации:
 * <ul>
 *   <li>{@link #verifyAny} — OR-семантика: возвращает первого валидного подписанта.
 *       Полезен для сценариев типа «достаточно подписи любого члена совета директоров».</li>
 *   <li>{@link #verifyAll} — AND-семантика: каждый подписант обязан пройти,
 *       иначе {@link PkixException} с указанием, какой подписант провалился.
 *       Используется {@link CAdESExtender} для multi-signer CAdES-T.</li>
 * </ul>
 *
 * <p>При ошибке оба метода бросают {@link PkixException} (fail-closed).
 */
public final class CmsSignedDataVerifier {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.pkix.cms.CmsSignedDataVerifier");

    private CmsSignedDataVerifier() {}

    // ========================================================================
    // Публичные методы
    // ========================================================================

    /**
     * Верифицирует SignedData DER — хотя бы один подписант должен пройти.
     * OR-семантика: возвращает первого успешно верифицированного подписанта.
     * Остальные подписанты не проверяются до конца — при обнаружении первого
     * валидного метод немедленно возвращает результат.
     *
     * <p>Для сценариев, где важны все подписанты, используйте {@link #verifyAll}.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param trustedCerts  список доверенных сертификатов
     * @return результат с данными и сертификатом первого валидного подписанта
     * @throws PkixException если ни один подписант не прошёл верификацию
     */
    public static VerifiedSignedData verifyAny(
            byte[] signedDataDer, GostCertificate... trustedCerts) throws PkixException {
        return verifyInternal(signedDataDer, trustedCerts, false);
    }

    /**
     * Верифицирует SignedData DER — все подписанты обязаны пройти.
     * AND-семантика: любой провал немедленно прерывает верификацию.
     *
     * <p>В отличие от {@link #verifyAny}, который возвращает первого валидного
     * и игнорирует остальных, этот метод требует успешной верификации каждого
     * подписанта. Используется {@link CAdESExtender} для multi-signer CAdES-T.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param trustedCerts  список доверенных сертификатов
     * @return все успешно верифицированные подписанты
     * @throws PkixException если хотя бы один подписант провалился
     */
    public static MultiSignerVerifiedData verifyAll(
            byte[] signedDataDer, GostCertificate... trustedCerts) throws PkixException {
        return verifyInternal(signedDataDer, trustedCerts, true);
    }

    // ========================================================================
    // Приватная логика
    // ========================================================================

    @SuppressWarnings("unchecked")
    private static <T> T verifyInternal(
            byte[] signedDataDer, GostCertificate[] trustedCerts, boolean strict)
            throws PkixException {
        SignedDataParsed parsed = parseSignedData(signedDataDer);

        int totalSigners = parsed.signerInfos().length;
        if (totalSigners == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "SignedData contains no signerInfos");
        }
        List<SignerResult> results = new ArrayList<>();

        for (int sn = 0; sn < totalSigners; sn++) {
            byte[] signerInfoDer = parsed.signerInfos()[sn];
            LOG.log(Level.DEBUG, "Verifying signer {0}/{1}", sn + 1, totalSigners);
            try {
                SignerResult result =
                        verifyOneSigner(
                                signerInfoDer,
                                parsed.encapData(),
                                parsed.embeddedCerts(),
                                parsed.eContentTypeOid());
                // Проверяем цепочку доверия
                if (trustedCerts.length > 0) {
                    validateCertChain(
                            result.signerCertificate(),
                            parsed.embeddedCerts(),
                            Arrays.asList(trustedCerts));
                }
                LOG.log(
                        Level.INFO,
                        "SignedData verification passed (signer {0}/{1})",
                        sn + 1,
                        totalSigners);

                if (!strict) {
                    // OR-семантика: первый успешный
                    return (T)
                            new VerifiedSignedData(
                                    parsed.encapData(),
                                    result.signerCertificate(),
                                    result.unsignedAttributes());
                }
                results.add(result);
            } catch (PkixException e) {
                if (strict) {
                    // AND-семантика: любой провал немедленно прерывает
                    throw new PkixException(
                            PkixException.Reason.SIGNATURE_INVALID,
                            "Signer "
                                    + (sn + 1)
                                    + "/"
                                    + totalSigners
                                    + " failed verification: "
                                    + e.getMessage(),
                            e);
                }
                LOG.log(Level.DEBUG, "Signer {0} failed: {1}", sn + 1, e.getMessage());
            }
        }

        if (!strict) {
            throw new PkixException(PkixException.Reason.OTHER, "No signer passed verification");
        }
        return (T) new MultiSignerVerifiedData(parsed.encapData(), results);
    }

    private static SignedDataParsed parseSignedData(byte[] signedDataDer) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(signedDataDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Invalid contentType: expected id-signedData");
        }
        if (contentInfo.content() == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "ContentInfo does not contain SignedData");
        }

        byte[] signedDataBody = contentInfo.content();
        byte[][] signedDataParts = DerCodec.parseSequenceContents(signedDataBody, 0);
        if (signedDataParts.length < 3) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData too short: expected at least version, digestAlgorithms, encapContentInfo");
        }

        int partIdx = 0;
        partIdx++; // [0] version
        partIdx++; // [1] digestAlgorithms — пропускаем

        // [2] encapContentInfo
        byte[] encapContentInfo = signedDataParts[partIdx++];
        byte[][] encapParts = DerCodec.parseSequenceContents(encapContentInfo, 0);
        if (encapParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "encapContentInfo has no eContentType");
        }
        byte[] eContentTypeOid = encapParts[0];
        byte[] encapData = null;
        if (encapParts.length > 1) {
            int[] lenInfo = DerCodec.decodeLength(encapParts[1], 1);
            int innerOff = 1 + lenInfo[1];
            int tag = encapParts[1][innerOff] & 0xFF;
            if (tag == DerCodec.TAG_OCTET_STRING_CONSTRUCTED) {
                int[] conLen = DerCodec.decodeLength(encapParts[1], innerOff + 1);
                int inner2 = innerOff + 1 + conLen[1];
                encapData = DerCodec.parseOctetString(encapParts[1], inner2);
            } else if (tag == DerCodec.TAG_OCTET_STRING) {
                encapData = DerCodec.parseOctetString(encapParts[1], innerOff);
            } else {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Unexpected tag in encapContentInfo: 0x" + Integer.toHexString(tag));
            }
        }

        // [3] certificates [0] IMPLICIT OPTIONAL
        List<GostCertificate> embeddedCerts = new ArrayList<>();
        if (partIdx < signedDataParts.length
                && DerCodec.isContextTag(signedDataParts[partIdx], 0)) {
            byte[] certsField = signedDataParts[partIdx++];
            int[] lenInfo = DerCodec.decodeLength(certsField, 1);
            int certsStart = 1 + lenInfo[1];
            int certsEnd = certsField.length;
            int pos = certsStart;
            while (pos < certsEnd) {
                int[] certLen = DerCodec.decodeLength(certsField, pos + 1);
                int certTotal = 1 + certLen[1] + certLen[0];
                byte[] certDer = java.util.Arrays.copyOfRange(certsField, pos, pos + certTotal);
                try {
                    embeddedCerts.add(parseCert(certDer));
                } catch (java.security.cert.CertificateException e) {
                    LOG.log(
                            Level.WARNING,
                            "Corrupted certificate in SignedData certificates field, skipping",
                            e);
                }
                pos += certTotal;
            }
        }

        // [4] crls [1] IMPLICIT OPTIONAL
        if (partIdx < signedDataParts.length
                && DerCodec.isContextTag(signedDataParts[partIdx], 1)) {
            partIdx++;
        }

        // [last] signerInfos
        if (partIdx >= signedDataParts.length) {
            throw new PkixException(PkixException.Reason.OTHER, "No signerInfos in SignedData");
        }
        byte[] signerInfosField = signedDataParts[partIdx];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);

        return new SignedDataParsed(encapData, signerInfos, eContentTypeOid, embeddedCerts);
    }

    private static SignerResult verifyOneSigner(
            byte[] signerInfoDer,
            byte[] encapData,
            List<GostCertificate> embeddedCerts,
            byte[] eContentTypeOid)
            throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length < 6) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignerInfo too short: expected at least version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, signature");
        }
        int idx = 0;

        // [0] version
        idx++;

        // [1] sid
        CmsIssuerAndSerialNumber sid = CmsIssuerAndSerialNumber.decode(siParts[idx++]);

        // [2] digestAlgorithm
        CmsAlgorithmIdentifier digestAlg = CmsAlgorithmIdentifier.decode(siParts[idx++]);
        String digestOid = digestAlg.algorithmOid();

        // [3] signedAttrs [0] IMPLICIT OPTIONAL
        if (idx >= siParts.length || !DerCodec.isContextTag(siParts[idx], 0)) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "SignerInfo does not contain signedAttrs");
        }
        byte[] signedAttrsWrapped = siParts[idx++];
        int[] saLenInfo = DerCodec.decodeLength(signedAttrsWrapped, 1);
        int saStart = 1 + saLenInfo[1];
        byte[] signedAttrsContent =
                java.util.Arrays.copyOfRange(
                        signedAttrsWrapped, saStart, signedAttrsWrapped.length);

        java.util.List<byte[]> attrElems = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < signedAttrsContent.length) {
            int[] attrLen = DerCodec.decodeLength(signedAttrsContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            attrElems.add(java.util.Arrays.copyOfRange(signedAttrsContent, pos, pos + attrTotal));
            pos += attrTotal;
        }

        byte[] signedAttrsForHash = DerCodec.encodeSetOf(attrElems.toArray(new byte[0][]));

        List<CmsAttribute> signedAttributes = new ArrayList<>();
        byte[] expectedDigest = null;
        byte[] signedContentTypeOid = null;
        for (byte[] attrDer : attrElems) {
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            signedAttributes.add(attr);
            if (GostOids.ATTR_MESSAGE_DIGEST.equals(attr.attrType())) {
                byte[][] vals = attr.attrValues();
                if (vals.length > 0) {
                    expectedDigest = DerCodec.parseOctetString(vals[0], 0);
                }
            } else if (GostOids.ATTR_CONTENT_TYPE.equals(attr.attrType())) {
                byte[][] vals = attr.attrValues();
                if (vals.length > 0) {
                    signedContentTypeOid = vals[0];
                }
            }
        }

        if (signedContentTypeOid != null
                && !java.util.Arrays.equals(eContentTypeOid, signedContentTypeOid)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "contentType mismatch: signed-attr does not match eContentType");
        }

        if (encapData != null && expectedDigest != null) {
            byte[] actualDigest = digestFor(encapData, digestOid);
            if (!java.security.MessageDigest.isEqual(expectedDigest, actualDigest)) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Data digest does not match messageDigest attribute");
            }
        }

        // [4] signatureAlgorithm
        idx++;

        // [5] signature
        byte[] sigOctet = siParts[idx];
        byte[] signatureValue = DerCodec.parseOctetString(sigOctet, 0);
        idx++;

        // [6] unsignedAttrs [1] IMPLICIT OPTIONAL
        List<CmsAttribute> unsignedAttributes = new ArrayList<>();
        if (idx < siParts.length && DerCodec.isContextTag(siParts[idx], 1)) {
            byte[] unsignedAttrsWrapped = siParts[idx];
            int[] uaLenInfo = DerCodec.decodeLength(unsignedAttrsWrapped, 1);
            int uaStart = 1 + uaLenInfo[1];
            byte[] unsignedAttrsContent =
                    java.util.Arrays.copyOfRange(
                            unsignedAttrsWrapped, uaStart, unsignedAttrsWrapped.length);

            int uaPos = 0;
            while (uaPos < unsignedAttrsContent.length) {
                int[] attrLen = DerCodec.decodeLength(unsignedAttrsContent, uaPos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                unsignedAttributes.add(
                        CmsAttribute.decode(
                                java.util.Arrays.copyOfRange(
                                        unsignedAttrsContent, uaPos, uaPos + attrTotal)));
                uaPos += attrTotal;
            }
        }

        byte[] signedAttrsHash = digestFor(signedAttrsForHash, digestOid);

        GostCertificate signerCert = findCertByIssuerAndSerial(sid, embeddedCerts);

        PublicKeyParameters pubKey;
        if (signerCert != null) {
            pubKey = signerCert.getPublicKey();
        } else {
            throw new PkixException(PkixException.Reason.OTHER, "Signer certificate not found");
        }

        if (!Signature.verifyHash(signedAttrsHash, signatureValue, pubKey)) {
            throw new PkixException(PkixException.Reason.SIGNATURE_INVALID, "Signature invalid");
        }

        return new SignerResult(signerCert, signatureValue, signedAttributes, unsignedAttributes);
    }

    private static byte[] digestFor(byte[] data, String digestOid) {
        if (GostOids.DIGEST_512.equals(digestOid)) {
            return Digest.digest512(data);
        }
        return Digest.digest256(data);
    }

    private static GostCertificate findCertByIssuerAndSerial(
            CmsIssuerAndSerialNumber sid, List<GostCertificate> certs) {
        for (GostCertificate c : certs) {
            if (!c.getSerialNumberBigInt().equals(sid.serial())) {
                continue;
            }
            if (issuerMatches(c, sid.issuer())) {
                return c;
            }
        }
        return null;
    }

    private static boolean issuerMatches(GostCertificate cert, byte[] issuerDer) {
        return Arrays.equals(cert.getIssuerDnBytes(), issuerDer);
    }

    private static GostCertificate parseCert(byte[] certDer) throws CertificateException {
        try {
            return GostCertificate.fromDer(certDer);
        } catch (Exception e) {
            throw new CertificateException("Failed to parse certificate DER", e);
        }
    }

    private static void validateCertChain(
            GostCertificate signerCert,
            List<GostCertificate> embeddedCerts,
            List<GostCertificate> trustedCerts)
            throws PkixException {
        try {
            List<GostCertificate> chain =
                    CertChainBuilder.buildChain(signerCert, embeddedCerts, trustedCerts);
            List<PublicKeyParameters> caKeys =
                    trustedCerts.stream().map(GostCertificate::getPublicKey).toList();
            ChainValidator.validateChain(chain, caKeys);
        } catch (PkixException e) {
            throw e;
        }
    }

    private record SignedDataParsed(
            byte[] encapData,
            byte[][] signerInfos,
            byte[] eContentTypeOid,
            List<GostCertificate> embeddedCerts) {}
}
