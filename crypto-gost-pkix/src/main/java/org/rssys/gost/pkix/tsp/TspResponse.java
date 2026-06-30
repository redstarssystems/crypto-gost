package org.rssys.gost.pkix.tsp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
import org.rssys.gost.pkix.cms.MultiSignerVerifiedData;
import org.rssys.gost.pkix.cms.SignerResult;
import org.rssys.gost.util.DerCodec;

/**
 * Разбор и валидация TimeStampResp (RFC 3161 §2.4.2).
 *
 * <p>По образцу {@link org.rssys.gost.pkix.cert.GostOcspResponse}:
 * конструктор парсит DER, метод {@link #verify(byte[], String, GostCertificate...)}
 * выполняет криптографическую проверку и устанавливает флаг {@code signatureVerified}.
 */
public final class TspResponse {



    private final int status;
    private final String statusString;
    private final byte[] timeStampTokenDer;
    private final TstInfo tstInfo;
    private final int failInfo;
    private volatile boolean signatureVerified;

    private TspResponse(
            int status, String statusString, byte[] timeStampTokenDer,
            TstInfo tstInfo, int failInfo) {
        this.status = status;
        this.statusString = statusString;
        this.timeStampTokenDer = timeStampTokenDer != null ? timeStampTokenDer.clone() : null;
        this.tstInfo = tstInfo;
        this.failInfo = failInfo;
    }

    public int status() {
        return status;
    }

    public String statusString() {
        return statusString;
    }

    public byte[] timeStampTokenDer() {
        return timeStampTokenDer != null ? timeStampTokenDer.clone() : null;
    }

    public TstInfo tstInfo() {
        return tstInfo;
    }

    public boolean isSignatureVerified() {
        return signatureVerified;
    }

    // ========================================================================
    // Парсинг
    // ========================================================================

    /**
     * Разбирает TimeStampToken (CMS SignedData c TSTInfo) напрямую — без обёртки TimeStampResp.
     * Используется при верификации CAdES-T, где метка уже встроена в unsignedAttrs.
     */
    public static TspResponse parseTimeStampToken(byte[] timeStampTokenDer) throws PkixException {
        TstInfo tstInfo = parseTstInfo(timeStampTokenDer);
        return new TspResponse(GostOids.PKI_STATUS_GRANTED, null, timeStampTokenDer, tstInfo, 0);
    }

    /**
     * Создаёт TspResponse из DER-байтов TimeStampResp (RFC 3161 §2.4.2).
     *
     * @param tspResponseDer DER-байты TimeStampResp
     * @return распарсенный ответ (status, TSTInfo)
     * @throws PkixException при ошибке разбора
     */
    public static TspResponse fromDer(byte[] tspResponseDer) throws PkixException {
        Objects.requireNonNull(tspResponseDer, "tspResponseDer must not be null");

        // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL
        // }
        byte[][] parts = DerCodec.parseSequenceContents(tspResponseDer, 0);
        if (parts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "TimeStampResp has no PKIStatusInfo");
        }

        // PKIStatusInfo: SEQUENCE { status INTEGER, statusString UTF8String OPTIONAL, failInfo BIT
        // STRING OPTIONAL }
        byte[][] statusParts = DerCodec.parseSequenceContents(parts[0], 0);
        if (statusParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "PKIStatusInfo has no status");
        }
        int status = DerCodec.parseInteger(statusParts[0], 0).intValue();
        String statusString = null;
        int idx = 1;
        // statusString: RFC 4210 определяет PKIFreeText как SEQUENCE OF UTF8String,
        // но некоторые TSA присылают bare UTF8String. Принимаем оба формата.
        if (idx < statusParts.length && statusParts[idx].length > 0) {
            int tag = statusParts[idx][0] & 0xFF;
            if (tag == DerCodec.TAG_UTF8_STRING) {
                statusString = DerCodec.parseUTF8String(statusParts[idx], 0);
                idx++;
            } else if (tag == DerCodec.TAG_SEQUENCE) {
                // PKIFreeText: SEQUENCE SIZE (1..MAX) OF UTF8String — берём первый элемент
                byte[][] freeTextParts = DerCodec.parseSequenceContents(statusParts[idx], 0);
                if (freeTextParts.length > 0) {
                    statusString = DerCodec.parseUTF8String(freeTextParts[0], 0);
                }
                idx++;
            }
        }
        // failInfo — BIT STRING, опционально
        int failInfo = 0;
        if (idx < statusParts.length
                && statusParts[idx].length > 0
                && (statusParts[idx][0] & 0xFF) == DerCodec.TAG_BIT_STRING) {
            byte[] bitContent = DerCodec.parseBitString(statusParts[idx], 0);
            if (bitContent.length > 0) {
                failInfo = decodeFailInfo(bitContent);
            }
            idx++;
        }

        if (status == GostOids.PKI_STATUS_REJECTED) {
            String msg = "TSP status: rejection";
            if (statusString != null) {
                msg += " (" + statusString + ")";
            }
            throw new PkixException(PkixException.Reason.OTHER, msg, failInfo);
        }
        if (status != GostOids.PKI_STATUS_GRANTED
                && status != GostOids.PKI_STATUS_GRANTED_WITH_MODS) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "TSP status: unknown status " + status);
        }

        // timeStampToken: ContentInfo (CMS SignedData)
        if (parts.length < 2) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TSP status granted but no TimeStampToken in response");
        }
        byte[] timeStampTokenDer = parts[1];

        // Разбираем TimeStampToken = ContentInfo(id-signedData) -> SignedData -> TSTInfo
        TstInfo tstInfo = parseTstInfo(timeStampTokenDer);

        return new TspResponse(status, statusString, timeStampTokenDer, tstInfo, failInfo);
    }

    /**
     * Извлекает TSTInfo из TimeStampToken (CMS SignedData с eContent id-ct-TSTInfo).
     */
    private static TstInfo parseTstInfo(byte[] timeStampTokenDer) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(timeStampTokenDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TimeStampToken is not SignedData, contentType=" + contentInfo.contentType());
        }
        if (contentInfo.content() == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "TimeStampToken has no SignedData content");
        }

        byte[] signedDataBody = contentInfo.content();
        byte[][] signedDataParts = DerCodec.parseSequenceContents(signedDataBody, 0);
        // signedDataParts: [0]=version, [1]=digestAlgorithms, [2]=encapContentInfo, [3]=certs?,
        // [4]=crls?, [5]=signerInfos
        if (signedDataParts.length < 3) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "SignedData in TimeStampToken too short");
        }

        // encapContentInfo: SEQUENCE { eContentType OID, [0] EXPLICIT eContent }
        byte[] encapContentInfo = signedDataParts[2];
        byte[][] encapParts = DerCodec.parseSequenceContents(encapContentInfo, 0);
        if (encapParts.length < 2) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "TimeStampToken encapContentInfo missing eContent");
        }

        // eContent: [0] EXPLICIT с OCTET STRING внутри
        byte[] eContentField = encapParts[1];
        // Снимаем обёртку [0] EXPLICIT
        int[] outerLen = DerCodec.decodeLength(eContentField, 1);
        int innerOff = 1 + outerLen[1];
        byte[] octetField =
                java.util.Arrays.copyOfRange(eContentField, innerOff, eContentField.length);
        // Снимаем обёртку OCTET STRING (примитивная 0x04 или BER-constructed 0x24)
        int octetTag = octetField[0] & 0xFF;
        byte[] tstInfoDer;
        if (octetTag == DerCodec.TAG_OCTET_STRING_CONSTRUCTED) {
            int[] conLen = DerCodec.decodeLength(octetField, 1);
            int innerOff2 = 1 + conLen[1];
            tstInfoDer = DerCodec.parseOctetString(octetField, innerOff2);
        } else if (octetTag == DerCodec.TAG_OCTET_STRING) {
            tstInfoDer = DerCodec.parseOctetString(octetField, 0);
        } else {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Unexpected tag in eContent: 0x" + Integer.toHexString(octetTag));
        }

        // Парсим TSTInfo
        return parseTstInfoBody(tstInfoDer);
    }

    /**
     * Разбирает TSTInfo SEQUENCE (RFC 3161 §2.4.2).
     */
    private static TstInfo parseTstInfoBody(byte[] tstInfoDer) throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(tstInfoDer, 0);
        if (parts.length < 5) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "TSTInfo too short: expected at least version, policy, messageImprint, serialNumber, genTime");
        }
        int idx = 0;

        // [0] version
        DerCodec.parseInteger(parts[idx++], 0); // пропускаем

        // [1] policy OID
        String policyOid = DerCodec.parseOid(parts[idx++], 0);

        // [2] messageImprint: SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET
        // STRING }
        byte[][] miParts = DerCodec.parseSequenceContents(parts[idx++], 0);
        if (miParts.length < 2) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "messageImprint too short: expected hashAlgorithm and hashedMessage");
        }
        // hashAlgorithm = SEQUENCE { OID, NULL }
        byte[][] hashAlgParts = DerCodec.parseSequenceContents(miParts[0], 0);
        if (hashAlgParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "messageImprint hashAlgorithm has no OID");
        }
        String hashAlgOid = DerCodec.parseOid(hashAlgParts[0], 0);
        byte[] hashedMessage = DerCodec.parseOctetString(miParts[1], 0);

        // [3] serialNumber
        BigInteger serialNumber = DerCodec.parseInteger(parts[idx++], 0);

        // [4] genTime — GeneralizedTime
        String genTime = DerCodec.parseGeneralizedTime(parts[idx++], 0);

        // [5] accuracy OPTIONAL
        Integer accuracySec = null;
        Integer accuracyMillis = null;
        if (idx < parts.length
                && parts[idx].length > 0
                && (parts[idx][0] & 0xFF) == DerCodec.TAG_SEQUENCE) {
            byte[][] accParts = DerCodec.parseSequenceContents(parts[idx], 0);
            int aIdx = 0;
            // seconds: INTEGER — первый элемент, если не контекстный тег
            if (aIdx < accParts.length
                    && accParts[aIdx].length > 0
                    && (accParts[aIdx][0] & 0xFF) == DerCodec.TAG_INTEGER) {
                accuracySec = DerCodec.parseInteger(accParts[aIdx], 0).intValue();
                aIdx++;
            }
            // millis: [0] IMPLICIT INTEGER (примитивный контекстный тег 0x80)
            if (aIdx < accParts.length
                    && accParts[aIdx].length > 0
                    && (accParts[aIdx][0] & 0xFF) == DerCodec.TAG_CTX_PRIMITIVE_0) {
                int[] millisLen = DerCodec.decodeLength(accParts[aIdx], 1);
                int millisOff = 1 + millisLen[1];
                byte[] millisVal =
                        java.util.Arrays.copyOfRange(
                                accParts[aIdx], millisOff, millisOff + millisLen[0]);
                accuracyMillis = new BigInteger(millisVal).intValue();
                aIdx++;
            }
            // micros: [1] IMPLICIT INTEGER — игнорируем
            idx++;
        }

        // [6] ordering BOOLEAN DEFAULT FALSE
        boolean ordering = false;
        if (idx < parts.length
                && parts[idx].length > 0
                && (parts[idx][0] & 0xFF) == DerCodec.TAG_BOOLEAN) {
            ordering = DerCodec.parseBoolean(parts[idx], 0);
            idx++;
        }

        // [7] nonce INTEGER OPTIONAL
        BigInteger nonce = null;
        if (idx < parts.length
                && parts[idx].length > 0
                && (parts[idx][0] & 0xFF) == DerCodec.TAG_INTEGER) {
            nonce = DerCodec.parseInteger(parts[idx], 0);
            // idx++; // дальше могут быть extensions [1]
        }

        return new TstInfo(
                policyOid,
                hashedMessage,
                hashAlgOid,
                serialNumber,
                genTime,
                accuracySec,
                accuracyMillis,
                ordering,
                nonce);
    }

    /**
     * Декодирует байтовый массив ASN.1 BIT STRING в failInfo-маску.
     *
     * <p>ASN.1-бит N отображается как {@code content[N/8] & (0x80 >> (N%8))}.
     * Это прямое побитовое декодирование, а не big-endian число
     * — в отличие от {@link BigInteger#BigInteger(int, byte[])}.
     *
     * @param bitStringContent байтовый массив из BIT STRING (без ведущего unused-bits октета)
     * @return битовая маска PKIFailureInfo
     */
    private static int decodeFailInfo(byte[] bitStringContent) {
        int failInfo = 0;
        for (int n = 0; n < bitStringContent.length * 8; n++) {
            if ((bitStringContent[n / 8] & (byte) (0x80 >> (n % 8))) != 0) {
                failInfo |= (1 << n);
            }
        }
        return failInfo;
    }

    // ========================================================================
    // Верификация
    // ========================================================================

    /**
     * Верифицирует TimeStampToken.
     *
     * <p>Проверяет:
     * <ul>
     *   <li>Соответствие messageImprint ожидаемому хэшу</li>
     *   <li>Совпадение nonce (если передан — не null)</li>
     *   <li>genTime — не в будущем с учётом CLOCK_SKEW 5 минут</li>
     *   <li>Подпись TSA на TimeStampToken</li>
     *   <li>Цепочку сертификатов TSA</li>
     * </ul>
     *
     * @param expectedHash       ожидаемый хэш (для сверки с messageImprint)
     * @param expectedHashAlgOid OID алгоритма хэширования
     * @param expectedNonce      ожидаемый nonce (null — не проверять)
     * @param tsaTrustedCerts    доверенные корневые сертификаты TSA
     * @throws PkixException при любой ошибке верификации
     */
    public void verify(
            byte[] expectedHash,
            String expectedHashAlgOid,
            BigInteger expectedNonce,
            GostCertificate... tsaTrustedCerts)
            throws PkixException {
        Objects.requireNonNull(expectedHash, "expectedHash must not be null");
        Objects.requireNonNull(expectedHashAlgOid, "expectedHashAlgOid must not be null");

        // 1. Сверка messageImprint
        if (!MessageDigest.isEqual(tstInfo.messageImprintHash(), expectedHash)) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "TSP messageImprint does not match expected hash");
        }

        // 2. Сверка алгоритма хэширования
        if (!expectedHashAlgOid.equals(tstInfo.messageImprintAlgOid())) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TSP messageImprint hashAlgorithm mismatch: expected "
                            + expectedHashAlgOid
                            + ", got "
                            + tstInfo.messageImprintAlgOid());
        }

        // 3. Проверка genTime
        long genTimeMs = parseGeneralizedTimeToMs(tstInfo.genTime());
        long nowMs = System.currentTimeMillis();
        if (genTimeMs > nowMs + GostOids.CLOCK_SKEW_MS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TSP genTime is in the future: " + tstInfo.genTime());
        }

        // 4. Проверка nonce (если передан)
        // Nonce в TSP передаётся открыто, его цель — replay-protection, не confidentiality.
        // Диагностическая ценность (клиент видит что именно не совпало) важнее сокрытия.
        if (expectedNonce != null) {
            if (tstInfo.nonce() == null) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "TSP response missing nonce, but nonce was expected: " + expectedNonce);
            }
            if (!expectedNonce.equals(tstInfo.nonce())) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "TSP nonce mismatch: expected "
                                + expectedNonce
                                + ", got "
                                + tstInfo.nonce());
            }
        }

        // 5. Проверка подписи TimeStampToken (CMS SignedData)
        if (timeStampTokenDer == null) {
            throw new PkixException(PkixException.Reason.OTHER, "No TimeStampToken to verify");
        }
        List<GostCertificate> trustedList = List.of(tsaTrustedCerts);
        List<GostCertificate> flattenedTrustedList = new ArrayList<>(trustedList);
        MultiSignerVerifiedData tsResult =
                CmsSignedDataVerifier.verifyAll(
                        timeStampTokenDer, flattenedTrustedList.toArray(new GostCertificate[0]));

        // Проверяем EKU id-kp-timeStamping у каждого подписанта TimeStampToken
        for (SignerResult sr : tsResult.signers()) {
            if (!sr.signerCertificate().isTimeStamping()) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "TSA certificate does not have id-kp-timeStamping EKU");
            }
        }

        signatureVerified = true;
    }

    /**
     * Преобразует GeneralizedTime строку (YYYMMDDHHMMSSZ) в миллисекунды Unix epoch.
     */
    public static long parseGeneralizedTimeToMs(String genTime) throws PkixException {
        // RFC 3161: genTime is YYYYMMDDHHMMSS.SSSZ или YYYYMMDDHHMMSSZ
        try {
            // Убираем дробные секунды если есть (substring вместо regex)
            int dotIdx = genTime.indexOf('.');
            String cleaned = dotIdx >= 0 ? genTime.substring(0, dotIdx) + "Z" : genTime;
            DateTimeFormatter fmt =
                    DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
            return Instant.from(fmt.parse(cleaned)).toEpochMilli();
        } catch (DateTimeParseException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Cannot parse genTime: " + genTime, e);
        }
    }
}
