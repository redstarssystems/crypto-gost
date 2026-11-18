package org.rssys.gost.pkix.cms;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * CAdES-C: Complete validation data references (RFC 5126 §6.2).
 *
 * <p>Кодирование/декодирование структур
 * complete-certificate-references / complete-revocation-references
 * и всех вложенных типов ASN.1. Все типы — публичные record-ы,
 * переиспользуемые в CAdES-X Long без дублирования.
 */
public final class CAdESCompleteData {

    private CAdESCompleteData() {}

    // ========================================================================
    // Публичные record-типы
    // ========================================================================

    /**
     * OtherHash (RFC 5126 §5.7.3.3). Для ГОСТ — только вариант otherHash [1].
     */
    public record OtherHash(String hashOid, byte[] hashValue) {
        public OtherHash {
            Objects.requireNonNull(hashOid, "hashOid must not be null");
            Objects.requireNonNull(hashValue, "hashValue must not be null");
        }
    }

    /**
     * IssuerSerial (ESS, RFC 5035).
     */
    public record IssuerSerial(byte[] issuerDer, BigInteger serial) {
        public IssuerSerial {
            Objects.requireNonNull(issuerDer, "issuerDer must not be null");
            Objects.requireNonNull(serial, "serial must not be null");
        }
    }

    /**
     * OtherCertID (RFC 5126 §5.7.3.3).
     */
    public record OtherCertID(OtherHash otherCertHash, IssuerSerial issuerSerial) {
        public OtherCertID {
            Objects.requireNonNull(otherCertHash, "otherCertHash must not be null");
        }
    }

    /**
     * CrlIdentifier (RFC 5126 §6.2.2).
     */
    public record CrlIdentifier(byte[] crlIssuerDer, String crlIssuedTime, BigInteger crlNumber) {
        public CrlIdentifier {
            Objects.requireNonNull(crlIssuerDer, "crlIssuerDer must not be null");
            Objects.requireNonNull(crlIssuedTime, "crlIssuedTime must not be null");
        }
    }

    /**
     * CrlValidatedID (RFC 5126 §6.2.2).
     */
    public record CrlValidatedID(OtherHash crlHash, CrlIdentifier crlIdentifier) {
        public CrlValidatedID {
            Objects.requireNonNull(crlHash, "crlHash must not be null");
            Objects.requireNonNull(crlIdentifier, "crlIdentifier must not be null");
        }
    }

    /**
     * OcspIdentifier (RFC 5126 §6.2.2).
     */
    public record OcspIdentifier(byte[] responderIdDer, String producedAt) {
        public OcspIdentifier {
            Objects.requireNonNull(responderIdDer, "responderIdDer must not be null");
            Objects.requireNonNull(producedAt, "producedAt must not be null");
        }
    }

    /**
     * OcspResponsesID (RFC 5126 §6.2.2).
     */
    public record OcspResponsesID(OcspIdentifier ocspIdentifier, OtherHash ocspRepHash) {
        public OcspResponsesID {
            Objects.requireNonNull(ocspIdentifier, "ocspIdentifier must not be null");
        }
    }

    /**
     * CrlOcspRef (RFC 5126 §6.2.2).
     */
    public record CrlOcspRef(List<CrlValidatedID> crlList, List<OcspResponsesID> ocspList) {
        public CrlOcspRef {
            Objects.requireNonNull(crlList, "crlList must not be null");
            Objects.requireNonNull(ocspList, "ocspList must not be null");
        }
    }

    /**
     * Промежуточный результат построения CAdES-C референсов —
     * вычисленные complete-certificate-refs и complete-revocation-refs.
     */
    record CompleteRefsResult(List<OtherCertID> certRefs, List<CrlOcspRef> revocRefs) {
        CompleteRefsResult {
            Objects.requireNonNull(certRefs, "certRefs must not be null");
            Objects.requireNonNull(revocRefs, "revocRefs must not be null");
        }
    }

    // ========================================================================
    // Кодирование
    // ========================================================================

    /**
     * Кодирует OtherHash как CHOICE {@code otherHash OtherHashAlgAndValue}
     * (RFC 5126 §5.7.3.3 и Annex A.2).
     *
     * <p>Тег {@code [1]} в RFC 5126 отсутствует. Старая форма с {@code [1]}
     * продолжает читаться {@link #decodeOtherHash(byte[])} для совместимости.</p>
     */
    public static byte[] encodeOtherHashStreebog(byte[] hashValue, String hashOid) {
        // КриптоПро в CAdES-C/X Long кодирует AlgorithmIdentifier без параметров
        // (только OID). Наличие NULL ломает сопоставление ссылок и значений
        // доказательств: cryptcp отвечает 0x80070490 «Элемент не найден».
        // Декодер принимает оба варианта, обратная совместимость сохраняется.
        byte[] algId = CmsAlgorithmIdentifier.encodeOnlyOid(hashOid);
        byte[] hashOctet = DerCodec.encodeOctetString(hashValue);
        return DerCodec.encodeSequence(algId, hashOctet);
    }

    /**
     * Кодирует IssuerSerial.
     */
    static byte[] encodeIssuerSerial(byte[] issuerDnDer, BigInteger serial) {
        byte[] generalName = DerCodec.encodeContextConstructed(4, issuerDnDer);
        byte[] generalNames = DerCodec.encodeSequence(generalName);
        byte[] serialInt = DerCodec.encodeInteger(serial);
        return DerCodec.encodeSequence(generalNames, serialInt);
    }

    /**
     * Кодирует OtherCertID.
     */
    public static byte[] encodeOtherCertID(byte[] otherHashDer, byte[] issuerSerialDer) {
        return DerCodec.encodeSequence(otherHashDer, issuerSerialDer);
    }

    /**
     * Кодирует OtherCertID для сертификата (вычисляет хэш, собирает IssuerSerial).
     */
    public static byte[] encodeOtherCertID(GostCertificate cert, String hashOid) {
        byte[] certDer = cert.getEncoded();
        byte[] hash =
                GostSignatureHelper.digestByOid(
                        GostSignatureHelper.keySizeToDigestOid(cert.getKeySize()), certDer);
        byte[] otherHashDer = encodeOtherHashStreebog(hash, hashOid);
        byte[] issuerSerialDer =
                encodeIssuerSerial(cert.getIssuerDnBytes(), cert.getSerialNumberBigInt());
        return encodeOtherCertID(otherHashDer, issuerSerialDer);
    }

    /**
     * Кодирует CrlIdentifier.
     */
    static byte[] encodeCrlIdentifier(
            byte[] crlIssuerDer, String crlIssuedTime, BigInteger crlNumber) {
        byte[] timeDer = DerCodec.encodeTime(crlIssuedTime);
        if (crlNumber != null) {
            return DerCodec.encodeSequence(
                    crlIssuerDer, timeDer, DerCodec.encodeInteger(crlNumber));
        }
        return DerCodec.encodeSequence(crlIssuerDer, timeDer);
    }

    /**
     * Кодирует CrlIdentifier из объекта GostCrl.
     */
    static byte[] encodeCrlIdentifier(GostCrl crl) {
        return encodeCrlIdentifier(
                crl.getIssuerDnBytes(),
                GostSignatureHelper.formatUtcTime(crl.getThisUpdate()),
                crl.getCrlNumber());
    }

    /**
     * Кодирует CrlValidatedID.
     */
    static byte[] encodeCrlValidatedID(GostCrl crl, String hashOid) {
        byte[] crlDer = crl.getEncoded();
        byte[] crlHash = GostSignatureHelper.digestByOid(hashOid, crlDer);
        byte[] otherHashDer = encodeOtherHashStreebog(crlHash, hashOid);
        byte[] crlIdDer = encodeCrlIdentifier(crl);
        return DerCodec.encodeSequence(otherHashDer, crlIdDer);
    }

    /**
     * Кодирует OcspIdentifier.
     */
    static byte[] encodeOcspIdentifier(byte[] responderIdDer, String producedAt) {
        byte[] timeDer = DerCodec.encodeGeneralizedTime(producedAt);
        return DerCodec.encodeSequence(responderIdDer, timeDer);
    }

    /**
     * Кодирует OcspResponsesID.
     */
    static byte[] encodeOcspResponsesID(OcspIdentifier ocspId, OtherHash ocspRepHash) {
        byte[] ocspIdDer = encodeOcspIdentifier(ocspId.responderIdDer(), ocspId.producedAt());
        if (ocspRepHash != null) {
            byte[] repHashDer =
                    encodeOtherHashStreebog(ocspRepHash.hashValue(), ocspRepHash.hashOid());
            return DerCodec.encodeSequence(ocspIdDer, repHashDer);
        }
        return DerCodec.encodeSequence(ocspIdDer);
    }

    /**
     * Кодирует CrlOcspRef из предварительно закодированных списков.
     */
    static byte[] encodeCrlOcspRef(
            List<byte[]> crlValidatedDerList, List<byte[]> ocspResponsesDerList) {
        List<byte[]> parts = new ArrayList<>();
        if (!crlValidatedDerList.isEmpty()) {
            byte[] crlsSeqOf = DerCodec.encodeSequence(crlValidatedDerList.toArray(new byte[0][]));
            byte[] crlListId = DerCodec.encodeSequence(crlsSeqOf);
            parts.add(DerCodec.encodeContextConstructed(0, crlListId));
        }
        if (!ocspResponsesDerList.isEmpty()) {
            byte[] ocspSeqOf = DerCodec.encodeSequence(ocspResponsesDerList.toArray(new byte[0][]));
            byte[] ocspListId = DerCodec.encodeSequence(ocspSeqOf);
            parts.add(DerCodec.encodeContextConstructed(1, ocspListId));
        }
        return DerCodec.encodeSequence(parts.toArray(new byte[0][]));
    }

    /**
     * Кодирует CompleteCertificateRefs: SEQUENCE OF OtherCertID.
     */
    public static byte[] encodeCompleteCertificateRefs(List<byte[]> certRefDerList) {
        return DerCodec.encodeSequence(certRefDerList.toArray(new byte[0][]));
    }

    /**
     * Кодирует CompleteRevocationRefs: SEQUENCE OF CrlOcspRef.
     */
    public static byte[] encodeCompleteRevocationRefs(List<byte[]> revocationRefDerList) {
        return DerCodec.encodeSequence(revocationRefDerList.toArray(new byte[0][]));
    }

    // ========================================================================
    // Декодирование
    // ========================================================================

    /** Декодер одной структуры; нужен, чтобы единообразно перевести сбои разбора в PkixException. */
    @FunctionalInterface
    private interface Decoder<T> {
        T decode(byte[] der) throws PkixException;
    }

    /**
     * Запускает декодер на DER из недоверенной структуры.
     * <p>
     * Публичные методы обещают {@link PkixException}, но {@link DerCodec} на битом DER бросает
     * unchecked-исключения, а пустой массив даёт выход за границы при чтении тега. Эти исключения
     * переводятся здесь один раз, чтобы вызывающий мог ловить только {@code PkixException}.
     */
    private static <T> T decodeGuarded(String structure, byte[] der, Decoder<T> decoder)
            throws PkixException {
        if (der == null || der.length == 0) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, structure + ": empty or null DER");
        }
        try {
            return decoder.decode(der);
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    structure + ": malformed DER: " + e.getMessage(),
                    e);
        }
    }

    /**
     * Декодирует OtherHash из DER.
     *
     * @param der DER-кодировка OtherHash (с обёрткой [1] или без неё)
     * @return разобранный OtherHash
     * @throws PkixException при пустом, повреждённом DER или хэше не из Стрибога-256/512
     */
    public static OtherHash decodeOtherHash(byte[] der) throws PkixException {
        return decodeGuarded("OtherHash", der, CAdESCompleteData::decodeOtherHashImpl);
    }

    /**
     * Декодирует OtherCertID из DER.
     *
     * @param der DER-кодировка OtherCertID
     * @return разобранный OtherCertID
     * @throws PkixException при пустом или повреждённом DER
     */
    public static OtherCertID decodeOtherCertID(byte[] der) throws PkixException {
        return decodeGuarded("OtherCertID", der, CAdESCompleteData::decodeOtherCertIDImpl);
    }

    /**
     * Декодирует CompleteCertificateRefs: SEQUENCE OF OtherCertID.
     *
     * @param der DER-кодировка CompleteCertificateRefs
     * @return список ссылок на сертификаты
     * @throws PkixException при пустом или повреждённом DER
     */
    public static List<OtherCertID> decodeCompleteCertificateRefs(byte[] der) throws PkixException {
        return decodeGuarded(
                "CompleteCertificateRefs",
                der,
                CAdESCompleteData::decodeCompleteCertificateRefsImpl);
    }

    /**
     * Декодирует CompleteRevocationRefs: SEQUENCE OF CrlOcspRef.
     *
     * @param der DER-кодировка CompleteRevocationRefs
     * @return список ссылок на данные отзыва
     * @throws PkixException при пустом или повреждённом DER
     */
    public static List<CrlOcspRef> decodeCompleteRevocationRefs(byte[] der) throws PkixException {
        return decodeGuarded(
                "CompleteRevocationRefs", der, CAdESCompleteData::decodeCompleteRevocationRefsImpl);
    }

    /**
     * Декодирует CrlOcspRef из DER.
     *
     * @param der DER-кодировка CrlOcspRef
     * @return разобранный CrlOcspRef
     * @throws PkixException при пустом или повреждённом DER
     */
    public static CrlOcspRef decodeCrlOcspRef(byte[] der) throws PkixException {
        return decodeGuarded("CrlOcspRef", der, CAdESCompleteData::decodeCrlOcspRefImpl);
    }

    /**
     * Декодирует OtherHash из DER.
     */
    private static OtherHash decodeOtherHashImpl(byte[] der) throws PkixException {
        int tag = der[0] & 0xFF;
        if (tag == DerCodec.TAG_CTX_CONSTRUCTED_1) {
            int[] lenInfo = DerCodec.decodeLength(der, 1);
            int contentOff = 1 + lenInfo[1];
            int contentEnd = contentOff + lenInfo[0];
            if (contentEnd > der.length) {
                throw new PkixException("OtherHash otherHash: content range out of bounds");
            }
            return parseOtherHashAlgAndValue(Arrays.copyOfRange(der, contentOff, contentEnd));
        } else if (tag == DerCodec.TAG_SEQUENCE) {
            // КриптоПро кодирует OtherHash как сам OtherHashAlgAndValue без [1].
            return parseOtherHashAlgAndValue(der);
        } else if (tag == DerCodec.TAG_CTX_PRIMITIVE_0 || tag == DerCodec.TAG_CTX_CONSTRUCTED_0) {
            throw new PkixException("OtherHash sha1Hash [0] not supported for GOST signatures");
        }
        throw new PkixException("OtherHash: unexpected CHOICE tag " + Integer.toHexString(tag));
    }

    private static OtherHash parseOtherHashAlgAndValue(byte[] algAndValContent)
            throws PkixException {
        if (algAndValContent.length < 2 || (algAndValContent[0] & 0xFF) != DerCodec.TAG_SEQUENCE) {
            throw new PkixException("OtherHashAlgAndValue: expected SEQUENCE");
        }

        byte[][] algAndValParts = DerCodec.parseSequenceContents(algAndValContent, 0);
        if (algAndValParts.length < 2) {
            throw new PkixException(
                    "OtherHashAlgAndValue: expected at least 2 elements (algId + hashValue)");
        }

        byte[][] algParts = DerCodec.parseSequenceContents(algAndValParts[0], 0);
        if (algParts.length < 1) {
            throw new PkixException("OtherHashAlgAndValue: expected OID in AlgorithmIdentifier");
        }
        String hashOid = DerCodec.parseOid(algParts[0], 0);
        // Библиотека работает только со Стрибогом: чужой OID отсекаем при разборе, чтобы ни
        // один вызывающий не получил OtherHash, который нельзя пересчитать.
        if (!GostOids.DIGEST_256.equals(hashOid) && !GostOids.DIGEST_512.equals(hashOid)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "OtherHash: unsupported hash algorithm OID "
                            + hashOid
                            + " (only Streebog-256/512 supported)");
        }
        byte[] hashValue = DerCodec.parseOctetString(algAndValParts[1], 0);

        return new OtherHash(hashOid, hashValue);
    }

    /**
     * Декодирует OtherCertID из DER.
     */
    private static OtherCertID decodeOtherCertIDImpl(byte[] der) throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        if (parts.length < 1) {
            throw new PkixException("OtherCertID: expected at least 1 element (otherCertHash)");
        }

        OtherHash certHash = decodeOtherHashImpl(parts[0]);
        IssuerSerial issuerSerial = null;
        if (parts.length >= 2) {
            issuerSerial = decodeIssuerSerial(parts[1]);
        }

        return new OtherCertID(certHash, issuerSerial);
    }

    private static IssuerSerial decodeIssuerSerial(byte[] der) throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        if (parts.length < 2) {
            throw new PkixException(
                    "IssuerSerial: expected at least 2 elements (GeneralNames + serial)");
        }

        // GeneralNames SEQUENCE OF GeneralName → первая GeneralName [4]
        byte[][] gnParts = DerCodec.parseSequenceContents(parts[0], 0);
        if (gnParts.length < 1) {
            throw new PkixException("IssuerSerial: expected at least 1 GeneralName");
        }

        byte[] gnDer = gnParts[0];
        int gnTag = gnDer[0] & 0xFF;
        if (gnTag != 0xA4) {
            throw new PkixException(
                    "IssuerSerial: expected [4] directoryName, got tag "
                            + Integer.toHexString(gnTag));
        }
        int[] gnLen = DerCodec.decodeLength(gnDer, 1);
        int gnContentOff = 1 + gnLen[1];
        int gnContentEnd = gnContentOff + gnLen[0];
        if (gnContentEnd > gnDer.length) {
            throw new PkixException("IssuerSerial: directoryName content out of bounds");
        }
        byte[] issuerDer = Arrays.copyOfRange(gnDer, gnContentOff, gnContentEnd);

        BigInteger serial = DerCodec.parseInteger(parts[1], 0);
        return new IssuerSerial(issuerDer, serial);
    }

    /**
     * Декодирует CompleteCertificateRefs: SEQUENCE OF OtherCertID.
     */
    private static List<OtherCertID> decodeCompleteCertificateRefsImpl(byte[] der)
            throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        List<OtherCertID> refs = new ArrayList<>(parts.length);
        for (byte[] part : parts) {
            refs.add(decodeOtherCertIDImpl(part));
        }
        return refs;
    }

    /**
     * Декодирует CompleteRevocationRefs: SEQUENCE OF CrlOcspRef.
     */
    private static List<CrlOcspRef> decodeCompleteRevocationRefsImpl(byte[] der)
            throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        List<CrlOcspRef> refs = new ArrayList<>(parts.length);
        for (byte[] part : parts) {
            refs.add(decodeCrlOcspRefImpl(part));
        }
        return refs;
    }

    /**
     * Декодирует CrlOcspRef из DER.
     */
    private static CrlOcspRef decodeCrlOcspRefImpl(byte[] der) throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        List<CrlValidatedID> crlList = new ArrayList<>();
        List<OcspResponsesID> ocspList = new ArrayList<>();

        // Флаги, а не проверка пустоты списка: легитимно пустая внутренняя SEQUENCE OF
        // ([0] { CRLListID { crls {} } }) даёт пустой список, неотличимый от «тег не встречался».
        boolean crlSeen = false;
        boolean ocspSeen = false;

        for (byte[] part : parts) {
            int tag = part[0] & 0xFF;
            if (tag == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                if (crlSeen) {
                    throw new PkixException("duplicate [0] crlids in CrlOcspRef");
                }
                crlSeen = true;
                crlList = decodeCrlListId(part);
            } else if (tag == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                if (ocspSeen) {
                    throw new PkixException("duplicate [1] ocspids in CrlOcspRef");
                }
                ocspSeen = true;
                ocspList = decodeOcspListId(part);
            }
        }
        return new CrlOcspRef(crlList, ocspList);
    }

    private static List<CrlValidatedID> decodeCrlListId(byte[] der) throws PkixException {
        // [0] EXPLICIT { CRLListID }
        int[] lenInfo = DerCodec.decodeLength(der, 1);
        int contentOff = 1 + lenInfo[1];

        // CRLListID SEQUENCE { crls SEQUENCE OF CrlValidatedID }
        byte[][] crlListParts = DerCodec.parseSequenceContents(der, contentOff);
        if (crlListParts.length < 1) {
            throw new PkixException("CRLListID: expected crls SEQUENCE");
        }

        byte[][] validatedParts = DerCodec.parseSequenceContents(crlListParts[0], 0);
        List<CrlValidatedID> result = new ArrayList<>(validatedParts.length);
        for (byte[] validatedDer : validatedParts) {
            byte[][] seqParts = DerCodec.parseSequenceContents(validatedDer, 0);
            if (seqParts.length < 1) {
                throw new PkixException("CrlValidatedID: expected at least 1 element (crlHash)");
            }
            OtherHash crlHash = decodeOtherHashImpl(seqParts[0]);
            CrlIdentifier crlId = null;
            if (seqParts.length >= 2) {
                crlId = decodeCrlIdentifier(seqParts[1]);
            }
            result.add(new CrlValidatedID(crlHash, crlId));
        }
        return result;
    }

    private static CrlIdentifier decodeCrlIdentifier(byte[] der) throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        if (parts.length < 2) {
            throw new PkixException(
                    "CrlIdentifier: expected at least 2 elements (issuer + issuedTime)");
        }
        byte[] crlIssuerDer = parts[0];
        String crlIssuedTime = parseTimeString(parts[1]);
        BigInteger crlNumber = null;
        if (parts.length >= 3) {
            crlNumber = DerCodec.parseInteger(parts[2], 0);
        }
        return new CrlIdentifier(crlIssuerDer, crlIssuedTime, crlNumber);
    }

    /**
     * Разбирает UTCTime (tag 0x17) или GeneralizedTime (tag 0x18) в строку.
     */
    private static String parseTimeString(byte[] der) throws PkixException {
        int tag = der[0] & 0xFF;
        int[] lenInfo = DerCodec.decodeLength(der, 1);
        int contentOff = 1 + lenInfo[1];
        int contentLen = lenInfo[0];
        if (contentOff + contentLen > der.length) {
            throw new PkixException("Time: content range out of bounds");
        }
        if (tag == DerCodec.TAG_UTC_TIME || tag == DerCodec.TAG_GENERALIZED_TIME) {
            return new String(der, contentOff, contentLen, StandardCharsets.US_ASCII);
        }
        throw new PkixException(
                "Expected UTCTime or GeneralizedTime, got tag " + Integer.toHexString(tag));
    }

    private static List<OcspResponsesID> decodeOcspListId(byte[] der) throws PkixException {
        // [1] EXPLICIT { OcspListID }
        int[] lenInfo = DerCodec.decodeLength(der, 1);
        int contentOff = 1 + lenInfo[1];

        // OcspListID SEQUENCE { ocspResponses SEQUENCE OF OcspResponsesID }
        byte[][] ocspListParts = DerCodec.parseSequenceContents(der, contentOff);
        if (ocspListParts.length < 1) {
            throw new PkixException("OcspListID: expected ocspResponses SEQUENCE");
        }

        byte[][] respParts = DerCodec.parseSequenceContents(ocspListParts[0], 0);
        List<OcspResponsesID> result = new ArrayList<>(respParts.length);
        for (byte[] respDer : respParts) {
            byte[][] seqParts = DerCodec.parseSequenceContents(respDer, 0);
            if (seqParts.length < 1) {
                throw new PkixException(
                        "OcspResponsesID: expected at least 1 element (ocspIdentifier)");
            }
            byte[][] ocspIdParts = DerCodec.parseSequenceContents(seqParts[0], 0);
            if (ocspIdParts.length < 2) {
                throw new PkixException(
                        "OcspIdentifier: expected at least 2 elements (responderID + producedAt)");
            }
            byte[] responderIdDer = ocspIdParts[0];
            String producedAt = parseTimeString(ocspIdParts[1]);
            OcspIdentifier ocspId = new OcspIdentifier(responderIdDer, producedAt);

            OtherHash ocspHash = null;
            if (seqParts.length >= 2) {
                ocspHash = decodeOtherHashImpl(seqParts[1]);
            }
            result.add(new OcspResponsesID(ocspId, ocspHash));
        }
        return result;
    }

    // ========================================================================
    // Построение референсов
    // ========================================================================

    /**
     * Строит полный набор CAdES-C reference-атрибутов.
     *
     * <p>Принимает цепочку сертификатов (от signer до root) и данные отзыва
     * (CRL и OCSP). Возвращает структурированный результат — переиспользуется
     * в X-Long без перевычисления хэшей.
     *
     * <p>Списки {@code crlsForChain} и {@code ocspForChain} обязаны иметь ту же длину,
     * что и {@code chain} (по одному элементу на сертификат, {@code null} если данных
     * нет). Для подписанта и промежуточных УЦ нужен CRL или OCSP, для последнего звена
     * (доверенного корня) допустима пустая запись. Сертификаты делегированных
     * OCSP-ответчиков передаются перегрузкой с {@code additionalCerts}: они идут после
     * цепочки, доказательства отзыва для них не нужны, запись для каждого пустая.</p>
     */
    public static CompleteRefsResult buildCompleteRefsResult(
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain)
            throws PkixException {
        return buildCompleteRefsResult(chain, crlsForChain, ocspForChain, List.of());
    }

    /**
     * Строит ссылки CAdES-C с дополнительными сертификатами, использованными при
     * проверке (делегированные OCSP-ответчики).
     *
     * <p>КриптоПро требует, чтобы сертификат, которым подписан OCSP-ответ, был указан в
     * CompleteCertificateRefs и лежал в certificate-values. Такие сертификаты идут после
     * цепочки, а для каждого в CompleteRevocationRefs добавляется пустая запись:
     * отзыв ответчика не проверяется (id-pkix-ocsp-nocheck).</p>
     *
     * <p>Размеры {@code crlsForChain} и {@code ocspForChain} должны совпадать с размером
     * {@code chain}; для {@code additionalCerts} отдельных списков нет, и CRL/OCSP для них
     * не требуются. Пустая {@code CrlOcspRef} допустима для доверенного корня и для
     * каждого дополнительного сертификата.</p>
     *
     * @param additionalCerts сертификаты вне цепочки подписанта; дубликаты по DER и
     *                        совпадающие с цепочкой схлопываются, лимит ссылок проверяется
     *                        после дедупликации; якорями доверия не становятся, лишь
     *                        указываются в ссылках
     */
    public static CompleteRefsResult buildCompleteRefsResult(
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            List<GostCertificate> additionalCerts)
            throws PkixException {
        Objects.requireNonNull(additionalCerts, "additionalCerts must not be null");

        Objects.requireNonNull(chain, "chain must not be null");
        Objects.requireNonNull(crlsForChain, "crlsForChain must not be null");
        Objects.requireNonNull(ocspForChain, "ocspForChain must not be null");

        if (crlsForChain.size() != chain.size()) {
            throw new PkixException(
                    "crlsForChain size " + crlsForChain.size() + " != chain size " + chain.size());
        }
        if (ocspForChain.size() != chain.size()) {
            throw new PkixException(
                    "ocspForChain size " + ocspForChain.size() + " != chain size " + chain.size());
        }

        // Ответ службы без responseBytes (tryLater и т.п.) не имеет времени выдачи: без этой
        // проверки ниже был бы NullPointerException вместо PkixException
        for (GostOcspResponse ocsp : ocspForChain) {
            CAdESSupport.requireSuccessfulOcsp(ocsp);
        }

        GostCertificate signerCert = chain.get(0);
        int keySize = signerCert.getKeySize();
        String hashOid = GostSignatureHelper.keySizeToDigestOid(keySize);

        // CompleteCertificateRefs: все сертификаты цепочки после подписанта, включая
        // доверенный корень (RFC 5126 §6.2.1 не исключает якорь, а КриптоПро без
        // ссылки на корень не строит цепочку подписанта до доверенного корня).
        // chain = [signer, CA1, CA2, ..., trustedRoot]
        // certRefs = [CA1, CA2, ..., trustedRoot]
        List<OtherCertID> certRefs = new ArrayList<>();
        for (int i = 1; i < chain.size(); i++) {
            GostCertificate ca = chain.get(i);
            byte[] certDer = ca.getEncoded();
            byte[] hash = GostSignatureHelper.digestByOid(hashOid, certDer);
            OtherHash otherHash = new OtherHash(hashOid, hash);
            IssuerSerial issuerSerial =
                    new IssuerSerial(ca.getIssuerDnBytes(), ca.getSerialNumberBigInt());
            certRefs.add(new OtherCertID(otherHash, issuerSerial));
        }

        // Дубликаты по DER (и совпадающие с цепочкой) схлопываются: ссылка на сертификат
        // уже есть, повторная дала бы лишние OtherCertID и пустые CrlOcspRef.
        List<GostCertificate> uniqueAdditional = new ArrayList<>();
        for (GostCertificate extra : additionalCerts) {
            if (!containsDer(chain, extra) && !containsDer(uniqueAdditional, extra)) {
                uniqueAdditional.add(extra);
            }
        }
        if (Math.max(0, chain.size() - 1) + uniqueAdditional.size() > CmsConstants.MAX_CERT_REFS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-C: too many certificate references: "
                            + (Math.max(0, chain.size() - 1) + uniqueAdditional.size()));
        }
        for (GostCertificate extra : uniqueAdditional) {
            byte[] hash = GostSignatureHelper.digestByOid(hashOid, extra.getEncoded());
            certRefs.add(
                    new OtherCertID(
                            new OtherHash(hashOid, hash),
                            new IssuerSerial(
                                    extra.getIssuerDnBytes(), extra.getSerialNumberBigInt())));
        }

        // CompleteRevocationRefs: CrlOcspRef[0] для signer, далее по одной записи
        // на каждую ссылку CertificateRefs в том же порядке. Для доверенного корня
        // доказательство не обязательно: пустая запись допустима, а переданные
        // CRL/OCSP корня включаются. Для подписанта и промежуточных CA оно обязательно.
        int lastIndex = chain.size() - 1;
        List<CrlOcspRef> revocRefs = new ArrayList<>();
        for (int i = 0; i < chain.size(); i++) {
            GostCrl crl = crlsForChain.get(i);
            GostOcspResponse ocsp = ocspForChain.get(i);

            List<CrlValidatedID> crlList = new ArrayList<>();
            List<OcspResponsesID> ocspList = new ArrayList<>();

            if (crl != null) {
                byte[] crlDer = crl.getEncoded();
                byte[] crlVal = GostSignatureHelper.digestByOid(hashOid, crlDer);
                crlList.add(
                        new CrlValidatedID(
                                new OtherHash(hashOid, crlVal),
                                new CrlIdentifier(
                                        crl.getIssuerDnBytes(),
                                        GostSignatureHelper.formatUtcTime(crl.getThisUpdate()),
                                        crl.getCrlNumber())));
            }

            if (ocsp != null) {
                // Хэш ссылки и значение в revocation-values должны быть одним и тем
                // же DER. RevocationValues несёт BasicOCSPResponse, поэтому hash
                // считается по getRevocationValueDer(), а не по полной обёртке.
                byte[] respDer = ocsp.getRevocationValueDer();
                byte[] ocspVal = GostSignatureHelper.digestByOid(hashOid, respDer);
                ocspList.add(
                        new OcspResponsesID(
                                new OcspIdentifier(
                                        ocsp.getResponderIdDer(),
                                        GostSignatureHelper.formatGeneralizedTime(
                                                ocsp.getProducedAt())),
                                new OtherHash(hashOid, ocspVal)));
            }

            boolean trustedRootEntry = i == lastIndex && i > 0;
            if (crlList.isEmpty() && ocspList.isEmpty() && !trustedRootEntry) {
                throw new PkixException(
                        "Certificate " + i + " in chain has neither CRL nor OCSP data");
            }

            revocRefs.add(new CrlOcspRef(crlList, ocspList));
        }

        // Дополнительные сертификаты (OCSP-ответчики): отзыв не проверяется, запись пустая.
        for (int i = 0; i < uniqueAdditional.size(); i++) {
            revocRefs.add(new CrlOcspRef(List.of(), List.of()));
        }

        return new CompleteRefsResult(certRefs, revocRefs);
    }

    private static boolean containsDer(List<GostCertificate> certs, GostCertificate cert) {
        byte[] encoded = cert.getEncoded();
        for (GostCertificate c : certs) {
            if (java.util.Arrays.equals(encoded, c.getEncoded())) {
                return true;
            }
        }
        return false;
    }
}
