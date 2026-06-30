package org.rssys.gost.pkix.tsp;

import java.math.BigInteger;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsAlgorithmIdentifier;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель TSP-ответов (TimeStampResp) — серверная сторона протокола TSP (RFC 3161).
 *
 * <p>Принимает {@link TspRequest} (распарсенный TimeStampReq), настраивается через fluent API
 * и генерирует DER-кодированный TimeStampResp с подписанным TimeStampToken.
 *
 * <p>Типовой сценарий для сервера:
 * <pre>
 * TspRequest request = TspRequest.fromDer(httpRequestBody);
 * // проверка политики, алгоритма...
 * byte[] responseDer = TspResponseBuilder.create(request)
 *     .signer(tsaPrivateKey, tsaCert)
 *     .policyOid("1.3.6.1.4.1.4146.1.2.1")
 *     .serialNumber(nextSerial())
 *     .accuracy(1)
 *     .buildGranted();
 * </pre>
 *
 * <p>Отклонение:
 * <pre>
 * byte[] rejectionDer = TspResponseBuilder.buildRejected("Unsupported algorithm");
 * </pre>
 *
 * <p>Алгоритм дайджеста для подписи TimeStampToken определяется автоматически
 * по размеру ключа (hlen=32 -> Streebog-256, hlen=64 -> Streebog-512).
 *
 * <p>Сертификат TSA всегда включается в SignedData.certificates.
 *
 * <p>{@link #buildGranted()} / {@link #buildGrantedWithMods()} / {@link #buildRejected}
 * возвращают wire-формат DER-байтов для передачи по сети.
 * Для инспекции и проверки — consumer-класс {@link TspResponse}:
 * {@code TspResponse.fromDer(bytes).verify(...)}. Разделение producer
 * (TSA строит ответ) и consumer (клиент проверяет) осмысленно:
 * TSP-ответ — fail-closed объект, подпись и nonce не проверены до вызова
 * {@link TspResponse#verify verify()}. {@link #buildRejected} — исключение
 * из fluent-паттерна (статический метод без состояния builder'а), но
 * возвращает wire-формат как и экземплярные {@code buildGranted()}.
 */
public final class TspResponseBuilder {

    private final byte[] messageImprintHash;
    private final String messageImprintAlgOid;
    private final BigInteger requestNonce;

    private PrivateKeyParameters privateKey;
    private GostCertificate tsaCert;
    private String policyOid;
    private BigInteger serialNumber;
    private Integer accuracySeconds;
    private Integer accuracyMillis;
    private boolean ordering;
    private boolean cadesAttributes;
    private String digestOid;
    private final List<GostCertificate> chainCerts = new ArrayList<>();

    private TspResponseBuilder(TspRequest request) {
        this.messageImprintHash = request.messageImprintHash();
        this.messageImprintAlgOid = request.messageImprintAlgOid();
        this.requestNonce = request.nonce();
    }

    /**
     * Создаёт построитель из распарсенного запроса.
     *
     * @param request распарсенный TimeStampReq
     */
    public static TspResponseBuilder create(TspRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        return new TspResponseBuilder(request);
    }

    /**
     * Создаёт построитель из DER-байтов TimeStampReq (convenience overload).
     *
     * @param tspRequestDer DER-байты TimeStampReq
     * @throws PkixException при ошибке разбора
     */
    public static TspResponseBuilder create(byte[] tspRequestDer) throws PkixException {
        return create(TspRequest.fromDer(tspRequestDer));
    }

    /**
     * Устанавливает ключ и сертификат подписанта TSA.
     *
     * <p>Автоматически определяет алгоритм дайджеста по размеру ключа:
     * hlen=32 -> Streebog-256, hlen=64 -> Streebog-512.
     */
    public TspResponseBuilder signer(PrivateKeyParameters privateKey, GostCertificate cert) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
        this.tsaCert = Objects.requireNonNull(cert, "cert must not be null");
        int hlen = privateKey.getParams().hlen;
        this.digestOid =
                (hlen == GostOids.STREEBOG_512_HASH_LEN) ? GostOids.DIGEST_512 : GostOids.DIGEST_256;
        return this;
    }

    /** OID политики TSA (обязательное). */
    public TspResponseBuilder policyOid(String oid) {
        this.policyOid = Objects.requireNonNull(oid, "policyOid must not be null");
        return this;
    }

    /**
     * Серийный номер штампа (обязательное).
     *
     * <p>RFC 3161 §2.4.2 требует глобальной уникальности.
     * Вызывающий сам обеспечивает уникальность (например, через БД или AtomicLong).
     */
    public TspResponseBuilder serialNumber(BigInteger serialNumber) {
        this.serialNumber = Objects.requireNonNull(serialNumber, "serialNumber must not be null");
        return this;
    }

    /** Точность — только секунды. */
    public TspResponseBuilder accuracy(int seconds) {
        this.accuracySeconds = seconds;
        this.accuracyMillis = null;
        return this;
    }

    /** Точность — секунды + миллисекунды. */
    public TspResponseBuilder accuracy(int seconds, int millis) {
        this.accuracySeconds = seconds;
        this.accuracyMillis = millis;
        return this;
    }

    /**
     * Флаг упорядоченности штампов (RFC 3161 §2.4.2, DEFAULT FALSE).
     * Если true, TSA гарантирует что штампы с одним policyOid упорядочены по genTime.
     */
    public TspResponseBuilder ordering(boolean ordering) {
        this.ordering = ordering;
        return this;
    }

    /**
     * Включает автоматическое добавление CAdES signed-атрибутов
     * ({@code signingCertificateV2}) в TimeStampToken.
     * По умолчанию атрибуты не добавляются — соответствует RFC 3161.
     */
    public TspResponseBuilder withCAdES() {
        this.cadesAttributes = true;
        return this;
    }

    /** Добавляет дополнительный сертификат цепочки TSA в SignedData. */
    public TspResponseBuilder addChainCert(GostCertificate cert) {
        this.chainCerts.add(Objects.requireNonNull(cert, "cert must not be null"));
        return this;
    }

    /**
     * Собирает granted-ответ (PKIStatus=0).
     *
     * @return DER-байты TimeStampResp
     * @throws IllegalStateException если не заданы signer, policyOid или serialNumber
     */
    public byte[] buildGranted() {
        validateRequired();
        byte[] tstInfoDer = encodeTstInfo();
        byte[] timeStampTokenDer = buildTimeStampToken(tstInfoDer);
        return wrapResponse(GostOids.PKI_STATUS_GRANTED, null, timeStampTokenDer);
    }

    /**
     * Собирает grantedWithMods-ответ (PKIStatus=1).
     *
     * <p>Поля TSTInfo формируются так же как в {@link #buildGranted()}.
     * Механизм указания конкретных модификаций не реализован —
     * при необходимости вызывающий должен строить ответ вручную.
     *
     * @return DER-байты TimeStampResp
     * @throws IllegalStateException если не заданы signer, policyOid или serialNumber
     */
    public byte[] buildGrantedWithMods() {
        validateRequired();
        byte[] tstInfoDer = encodeTstInfo();
        byte[] timeStampTokenDer = buildTimeStampToken(tstInfoDer);
        return wrapResponse(GostOids.PKI_STATUS_GRANTED_WITH_MODS, null, timeStampTokenDer);
    }

    /**
     * Собирает rejection-ответ (PKIStatus=2) без текстового описания.
     *
     * <p>Используется когда причина отклонения не раскрывается (RFC 3161
     * допускает отсутствие statusString в PKIStatusInfo).
     *
     * @return DER-байты TimeStampResp (только PKIStatusInfo, без TimeStampToken)
     */
    public static byte[] buildRejected() {
        return buildRejected(0);
    }

    /**
     * Собирает rejection-ответ (PKIStatus=2) с текстовым сообщением.
     *
     * <p>statusString кодируется как SEQUENCE OF UTF8String (PKIFreeText, RFC 4210).
     *
     * @param statusString сообщение с причиной отклонения (не null)
     * @return DER-байты TimeStampResp (только PKIStatusInfo, без TimeStampToken)
     */
    public static byte[] buildRejected(String statusString) {
        return buildRejected(statusString, 0);
    }

    /**
     * Собирает rejection-ответ (PKIStatus=2) с failInfo, без сообщения.
     *
     * <p>failInfo — битовая маска PKIFailureInfo (RFC 4210 §D.2).
     * Константы — {@link GostOids#PKI_FAIL_BAD_ALG} и т.д.
     * Допускается комбинация через {@code |}: {@code PKI_FAIL_BAD_ALG | PKI_FAIL_UNACCEPTED_POLICY}.
     *
     * @param failInfo битовая маска причин отказа (0 — failInfo не добавляется)
     * @return DER-байты TimeStampResp
     */
    public static byte[] buildRejected(int failInfo) {
        if (failInfo < 0) {
            throw new IllegalArgumentException("failInfo must be non-negative");
        }
        return wrapResponse(GostOids.PKI_STATUS_REJECTED, null, null, failInfo);
    }

    /**
     * Собирает rejection-ответ (PKIStatus=2) с сообщением и failInfo.
     *
     * @param statusString сообщение с причиной отклонения (не null)
     * @param failInfo битовая маска причин отказа
     * @return DER-байты TimeStampResp
     */
    public static byte[] buildRejected(String statusString, int failInfo) {
        Objects.requireNonNull(statusString, "statusString must not be null");
        if (failInfo < 0) {
            throw new IllegalArgumentException("failInfo must be non-negative");
        }
        return wrapResponse(GostOids.PKI_STATUS_REJECTED, statusString, null, failInfo);
    }

    // ========================================================================
    // Приватные методы
    // ========================================================================

    private static final DateTimeFormatter GEN_TIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private void validateRequired() {
        if (privateKey == null) {
            throw new IllegalStateException("signer not set");
        }
        if (policyOid == null) {
            throw new IllegalStateException("policyOid not set");
        }
        if (serialNumber == null) {
            throw new IllegalStateException("serialNumber not set");
        }
    }

    private byte[] encodeTstInfo() {
        String genTime = ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME_FMT);

        // version INTEGER v1(1)
        byte[] version = DerCodec.encodeInteger(1);

        // policy OID
        byte[] policy = DerCodec.encodeOid(policyOid);

        // messageImprint: SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
        byte[] hashAlgId = CmsAlgorithmIdentifier.encode(messageImprintAlgOid);
        byte[] hashedMessage = DerCodec.encodeOctetString(messageImprintHash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlgId, hashedMessage);

        // serialNumber
        byte[] serial = DerCodec.encodeInteger(serialNumber);

        // genTime — всегда GeneralizedTime (RFC 3161)
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);

        List<byte[]> tstElements = new ArrayList<>();
        tstElements.add(version);
        tstElements.add(policy);
        tstElements.add(messageImprint);
        tstElements.add(serial);
        tstElements.add(genTimeDer);

        // accuracy OPTIONAL
        if (accuracySeconds != null) {
            List<byte[]> accParts = new ArrayList<>();
            accParts.add(DerCodec.encodeInteger(BigInteger.valueOf(accuracySeconds)));
            if (accuracyMillis != null) {
                byte[] millisContent = BigInteger.valueOf(accuracyMillis).toByteArray();
                accParts.add(DerCodec.encodeContextPrimitive(0, millisContent));
            }
            tstElements.add(DerCodec.encodeSequence(accParts.toArray(new byte[0][])));
        }

        // ordering BOOLEAN DEFAULT FALSE — кодируем только при true (DER X.690 §11.5)
        if (ordering) {
            tstElements.add(DerCodec.encodeBoolean(true));
        }

        // nonce INTEGER OPTIONAL — echo из запроса
        if (requestNonce != null) {
            tstElements.add(DerCodec.encodeInteger(requestNonce));
        }

        return DerCodec.encodeSequence(tstElements.toArray(new byte[0][]));
    }

    private byte[] buildTimeStampToken(byte[] tstInfoDer) {
        CmsSignedDataBuilder builder =
                CmsSignedDataBuilder.create()
                        .data(tstInfoDer)
                        .contentType(GostOids.TST_INFO)
                        .digestAlgorithm(digestOid)
                        .addSigner(privateKey, tsaCert);

        if (cadesAttributes) {
            builder.withCAdES();
        }
        for (GostCertificate chainCert : chainCerts) {
            builder.addCertificate(chainCert);
        }

        return builder.build();
    }

    /**
     * Кодирует failInfo-маску в байтовый массив для ASN.1 BIT STRING.
     *
     * <p>ASN.1-бит N отображается в {@code content[N/8] |= 0x80 >> (N%8)}.
     * Это прямое побитовое отображение, а не big-endian число
     * — в отличие от {@link BigInteger#toByteArray()}.
     *
     * @param failInfo битовая маска PKIFailureInfo
     * @return байтовый массив без ведущего unused-bits октета
     */
    private static byte[] encodeFailInfo(int failInfo) {
        int maxBit = 0;
        for (int n = 0; n < 32; n++) {
            if ((failInfo & (1 << n)) != 0) {
                maxBit = n;
            }
        }
        int byteLen = (maxBit / 8) + 1;
        byte[] content = new byte[byteLen];
        for (int n = 0; n <= maxBit; n++) {
            if ((failInfo & (1 << n)) != 0) {
                content[n / 8] |= (byte) (0x80 >> (n % 8));
            }
        }
        return content;
    }

    private static byte[] wrapResponse(int status, String statusString, byte[] timeStampTokenDer) {
        return wrapResponse(status, statusString, timeStampTokenDer, 0);
    }

    private static byte[] wrapResponse(int status, String statusString,
            byte[] timeStampTokenDer, int failInfo) {
        List<byte[]> pkiParts = new ArrayList<>();
        pkiParts.add(DerCodec.encodeInteger(BigInteger.valueOf(status)));
        if (statusString != null) {
            // PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String (RFC 4210)
            byte[] freeText = DerCodec.encodeSequence(
                    DerCodec.encodeUTF8String(statusString));
            pkiParts.add(freeText);
        }
        if (failInfo != 0) {
            pkiParts.add(DerCodec.encodeBitString(encodeFailInfo(failInfo)));
        }
        byte[] pkiStatus = DerCodec.encodeSequence(pkiParts.toArray(new byte[0][]));

        if (timeStampTokenDer != null) {
            return DerCodec.encodeSequence(pkiStatus, timeStampTokenDer);
        } else {
            return DerCodec.encodeSequence(pkiStatus);
        }
    }
}
