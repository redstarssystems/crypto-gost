package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель OCSP-ответа (RFC 6960).
 *
 * <p>Fluent API:
 * <pre>
 * byte[] ocsp = GostOcspResponseBuilder.create(serialNumber)
 *     .issuerDn(caSubjectDer)
 *     .nextUpdate("20260101000000Z")
 *     .sign(signer);
 * </pre>
 *
 * <p>С делегированными сертификатами:
 * <pre>
 * byte[] ocsp = GostOcspResponseBuilder.create(serialNumber)
 *     .caPublicKey(caPub)
 *     .issuerDn(caSubjectDer)
 *     .withDelegatedCerts(cert1Der, cert2Der)
 *     .sign(responderSigner);
 * </pre>
 *
 * <p>Подписант передаётся в терминальный {@link #sign(GostSigner)} — единообразно с
 * {@link GostCertificateBuilder}, {@link GostCrlBuilder}, {@link GostCsrBuilder}.
 * Открытый ключ подписанта выводится из {@link GostSigner#getPublicKey()}; отдельно
 * задавать его не нужно, что исключает риск несогласованной пары priv/pub.</p>
 *
 * <p>{@link #sign(GostSigner)} возвращает wire-формат DER-байтов для передачи по сети.
 * Для инспекции и проверки — consumer-класс {@link GostOcspResponse}:
 * {@code new GostOcspResponse(bytes).verify(caPub)}. Разделение producer
 * (OCSP-responder строит ответ) и consumer (клиент проверяет) осмысленно:
 * OCSP-ответ — fail-closed объект, подпись не проверена до вызова
 * {@link GostOcspResponse#verify verify()}.</p>
 */
public final class GostOcspResponseBuilder {

    private final byte[] serialNumber;
    private PublicKeyParameters caPub;
    private byte[] caSubjectDer;
    private String nextUpdate;
    private boolean omitNextUpdate;
    private String producedAt;
    private String thisUpdate;
    private byte[][] delegatedCertsDer;
    private byte[] certStatusDer; // null = good по умолчанию
    private byte[] nonce;
    private boolean useByKey;
    private int responderKeyHashLen = GostOids.STREEBOG_256_HASH_LEN;
    // 0 = длина хэша CertID по ключу CA (поведение по умолчанию)
    private int certIdHashLen;

    private GostOcspResponseBuilder(byte[] serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * Создаёт построитель OCSP-ответа.
     *
     * @param serialNumber серийный номер проверяемого сертификата
     */
    public static GostOcspResponseBuilder create(byte[] serialNumber) {
        return new GostOcspResponseBuilder(serialNumber);
    }

    /** Публичный ключ CA для CertID issuerKeyHash. По умолчанию = открытый ключ подписанта. */
    public GostOcspResponseBuilder caPublicKey(PublicKeyParameters pub) {
        this.caPub = pub;
        return this;
    }

    /**
     * Явно задаёт длину хэша CertID, не привязывая её к ключу CA.
     *
     * <p>По умолчанию длина берётся из ключа CA. Явный выбор нужен для ответов,
     * где хэш CertID не совпадает с размером ключа УЦ — например, УЦ с ключом
     * 512 бит и запрос на Стрибоге-256 (Р 1323565.1.059-2024, п. 7.2.2.2).</p>
     *
     * @param hlen длина хэша: 32 (Стрибог-256) или 64 (Стрибог-512)
     * @throws IllegalArgumentException если длина не равна 32 или 64
     */
    public GostOcspResponseBuilder certIdHashLen(int hlen) {
        if (hlen != GostOids.STREEBOG_256_HASH_LEN && hlen != GostOids.STREEBOG_512_HASH_LEN) {
            throw new IllegalArgumentException("CertID hash length must be 32 or 64, got: " + hlen);
        }
        this.certIdHashLen = hlen;
        return this;
    }

    /** DER-кодированный subject DN CA для CertID issuerNameHash. */
    public GostOcspResponseBuilder issuerDn(byte[] subjectDer) {
        this.caSubjectDer = subjectDer;
        return this;
    }

    /**
     * Удобная перегрузка: DN из строки "CN=..., O=...".
     *
     * <p>Для OCSP-ответа по уже существующему УЦ передавайте DER через
     * {@link #issuerDn(byte[])} (например, {@code caCert.getSubjectDnBytes()}):
     * строковая перегрузка кодирует DN заново и может не совпасть с issuer
     * DN старых сертификатов.</p>
     */
    public GostOcspResponseBuilder issuerDn(String dn) {
        this.caSubjectDer = GostDnParser.encodeDn(dn);
        return this;
    }

    /** @param time nextUpdate в формате GeneralizedTime (YYYYMMDDHHMMSSZ, UTC), опционально — по умолчанию now + 3 года. */
    public GostOcspResponseBuilder nextUpdate(String time) {
        this.nextUpdate = time;
        return this;
    }

    /** @param time nextUpdate как Instant (UTC) */
    public GostOcspResponseBuilder nextUpdate(Instant time) {
        this.nextUpdate = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    /**
     * Не включать поле nextUpdate в SingleResponse (RFC 6960 §2.4 — опционально).
     * В этом режиме relying party применяет локальную политику свежести
     * (см. {@code maxOcspAgeMs} в {@link OcspVerifier}).
     */
    public GostOcspResponseBuilder noNextUpdate() {
        this.omitNextUpdate = true;
        return this;
    }

    /** @param time producedAt в формате GeneralizedTime (YYYYMMDDHHMMSSZ, UTC), опционально — по умолчанию сейчас. */
    public GostOcspResponseBuilder producedAt(String time) {
        this.producedAt = time;
        return this;
    }

    /** @param time producedAt как Instant (UTC) */
    public GostOcspResponseBuilder producedAt(Instant time) {
        this.producedAt = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    /** @param time thisUpdate в формате GeneralizedTime (YYYYMMDDHHMMSSZ, UTC), опционально — по умолчанию сейчас. */
    public GostOcspResponseBuilder thisUpdate(String time) {
        this.thisUpdate = time;
        return this;
    }

    /** @param time thisUpdate как Instant (UTC) */
    public GostOcspResponseBuilder thisUpdate(Instant time) {
        this.thisUpdate = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    /** Добавляет делегированные сертификаты responder'а в BasicOCSPResponse.certs. */
    public GostOcspResponseBuilder withDelegatedCerts(byte[]... certsDer) {
        this.delegatedCertsDer = certsDer;
        return this;
    }

    /**
     * Статус сертификата — good (по умолчанию).
     * Явный вызов для читаемости, можно не вызывать.
     */
    public GostOcspResponseBuilder good() {
        this.certStatusDer = DerCodec.encodeTlv(0x80, new byte[0]);
        return this;
    }

    /**
     * Статус сертификата — revoked без указания причины.
     *
     * @param revocationTime GeneralizedTime отзыва ("20260101000000Z")
     */
    public GostOcspResponseBuilder revoked(String revocationTime) {
        return revoked(revocationTime, ReasonCode.UNSPECIFIED);
    }

    /**
     * Статус сертификата — revoked с указанием причины.
     *
     * @param revocationTime GeneralizedTime отзыва ("20260101000000Z")
     * @param reasonCode код причины из {@link ReasonCode} ({@code ReasonCode.UNSPECIFIED} — без добавления поля причины в DER)
     */
    public GostOcspResponseBuilder revoked(String revocationTime, ReasonCode reasonCode) {
        // RFC 6960 §2.4: revocationTime — GeneralizedTime независимо от года.
        byte[] revTime = DerCodec.encodeGeneralizedTime(revocationTime);
        java.io.ByteArrayOutputStream rvContent = new java.io.ByteArrayOutputStream();
        try {
            rvContent.write(revTime);
            if (reasonCode != ReasonCode.UNSPECIFIED) {
                byte[] reasonEnc = DerCodec.encodeTlv(0x0A, new byte[] {(byte) reasonCode.value()});
                byte[] reasonExp = DerCodec.encodeTlv(0xA0, reasonEnc);
                rvContent.write(reasonExp);
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException", e);
        }
        this.certStatusDer = DerCodec.encodeTlv(0xA1, rvContent.toByteArray());
        return this;
    }

    /** Статус сертификата — unknown. */
    public GostOcspResponseBuilder unknown() {
        this.certStatusDer = DerCodec.encodeTlv(0x82, new byte[0]);
        return this;
    }

    /**
     * Nonce для эхо-возврата из запроса (RFC 8954).
     *
     * <p>Принимает сырые байты значения {@code Nonce} (как их возвращает
     * {@link GostOcspRequest#getNonce()}); обёртки OCTET STRING добавляются при построении.
     *
     * @param nonce значение nonce из OCSP-запроса длиной 1..32 байта или {@code null} —
     *              расширение не добавляется
     * @throws IllegalArgumentException если длина nonce вне диапазона 1..32
     */
    public GostOcspResponseBuilder nonce(byte[] nonce) {
        if (nonce == null) {
            this.nonce = null;
            return this;
        }
        OcspNonceCodec.requireValidLength(nonce);
        this.nonce = nonce.clone();
        return this;
    }

    /**
     * Использовать byKey responder ID — хэш Streebog-256 от публичного ключа
     * подписанта (ГОСТ-конвенция). По умолчанию — byName (обратная совместимость).
     *
     * <p>RFC 5019bis рекомендует byKey для высоконагруженных сред — компактнее
     * byName. Хэш вычисляется через Streebog, поэтому распознаётся только
     * ГОСТ-клиентами; для универсальной совместимости используйте byName.</p>
     *
     * <p><b>Отступление от нормы:</b> Р 1323565.1.059-2024 (п. 7.3.3.3) требует для byKey
     * хэш SHA-1 (20 байт). Построитель SHA-1 не вычисляет, поэтому ответ не будет
     * распознан сторонними клиентами, ожидающими SHA-1. Проверяющая сторона библиотеки
     * принимает чужие ответы с 20-байтным byKey без сверки хэша.</p>
     */
    public GostOcspResponseBuilder withResponderByKey() {
        return withResponderByKey(GostOids.STREEBOG_256_HASH_LEN);
    }

    /**
     * byKey responder ID с выбором длины хэша.
     *
     * @param hlen длина хэша: 32 (Streebog-256) или 64 (Streebog-512)
     */
    public GostOcspResponseBuilder withResponderByKey(int hlen) {
        if (hlen != GostOids.STREEBOG_256_HASH_LEN && hlen != GostOids.STREEBOG_512_HASH_LEN) {
            throw new IllegalArgumentException(
                    "responderKeyHash length must be 32 or 64, got: " + hlen);
        }
        this.useByKey = true;
        this.responderKeyHashLen = hlen;
        return this;
    }

    /**
     * Собирает и подписывает OCSP-ответ подписантом (может быть HSM-адаптером).
     * Открытый ключ подписанта выводится из {@link GostSigner#getPublicKey()}.
     *
     * <p>Параметры кривой (hlen) для хэширования TBS берутся из открытого ключа подписанта;
     * длина хэша CertID — заданная явно ({@link #certIdHashLen(int)}), иначе длина хэша ключа CA
     * ({@link #caPublicKey}), а если CA не задан — ключа подписанта.</p>
     *
     * @param signer подписант OCSP-ответа
     * @return DER-кодированный OCSPResponse
     * @throws IllegalStateException если issuerDn не задан
     */
    public byte[] sign(GostSigner signer) {
        Objects.requireNonNull(signer, "signer must not be null");
        PublicKeyParameters signerPub = signer.getPublicKey();
        if (caSubjectDer == null) {
            throw new IllegalStateException("issuerDn must be set");
        }
        PublicKeyParameters caKey = caPub != null ? caPub : signerPub;
        String pa = producedAt != null ? producedAt : GostSignatureHelper.nowGeneralizedTime();
        String tu = thisUpdate != null ? thisUpdate : GostSignatureHelper.nowGeneralizedTime();
        String nu =
                omitNextUpdate
                        ? null
                        : (nextUpdate != null ? nextUpdate : GostSignatureHelper.nowPlusYears(3));

        byte[] statusDer =
                certStatusDer != null ? certStatusDer : DerCodec.encodeTlv(0x80, new byte[0]);
        byte[] responderId = buildResponderId(caSubjectDer, delegatedCertsDer, signerPub);
        byte[] tbs =
                buildTbsResponseData(
                        serialNumber,
                        caKey,
                        certIdHashLen != 0 ? certIdHashLen : caKey.getParams().hlen,
                        caSubjectDer,
                        nu,
                        pa,
                        tu,
                        delegatedCertsDer,
                        statusDer,
                        nonce,
                        responderId);
        int hlen = signerPub.getParams().hlen;
        byte[] hash = GostSignatureHelper.doHash(tbs, hlen);
        byte[] sig = GostSignatureHelper.signHashChecked(hash, signer);
        byte[] sigAlg = GostSignatureHelper.buildAlgId(signerPub.getParams());

        byte[] basicOcsp;
        if (delegatedCertsDer != null && delegatedCertsDer.length > 0) {
            byte[] certsSeq = DerCodec.encodeSequence(delegatedCertsDer);
            byte[] certsTagged = DerCodec.encodeTlv(0xA0, certsSeq);
            basicOcsp =
                    DerCodec.encodeSequence(
                            tbs, sigAlg, DerCodec.encodeBitString(sig), certsTagged);
        } else {
            basicOcsp = DerCodec.encodeSequence(tbs, sigAlg, DerCodec.encodeBitString(sig));
        }
        return wrapOcspResponse(basicOcsp);
    }

    /**
     * Собирает и подписывает OCSP-ответ закрытым ключом в памяти.
     * Удобная обёртка через {@link GostSigner#of(PrivateKeyParameters)}.
     *
     * @param signerPriv ключ, подписывающий OCSP-ответ
     * @return DER-кодированный OCSPResponse
     */
    public byte[] sign(PrivateKeyParameters signerPriv) {
        return sign(GostSigner.of(signerPriv));
    }

    private static byte[] wrapOcspResponse(byte[] basicOcsp) {
        byte[] basicOctet = DerCodec.encodeOctetString(basicOcsp);
        byte[] responseBytesContent =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = DerCodec.encodeTlv(0xA0, responseBytesContent);
        byte[] status = new byte[] {0x0A, 0x01, 0x00};
        return DerCodec.encodeSequence(status, responseBytes);
    }

    private byte[] buildResponderId(
            byte[] caSubjectDer, byte[][] delegatedCertsDer, PublicKeyParameters signerPub) {
        if (useByKey) {
            byte[] keyValue = GostDerCodec.encodeSpkiKeyBits(signerPub);
            byte[] keyHash = GostSignatureHelper.doHash(keyValue, responderKeyHashLen);
            return DerCodec.encodeTlv(
                    DerCodec.TAG_CTX_CONSTRUCTED_2, DerCodec.encodeOctetString(keyHash));
        }
        // byName — subject DN подписанта (RFC 6960 §4.2.1)
        byte[] responderSubjectDer;
        if (delegatedCertsDer != null && delegatedCertsDer.length > 0) {
            responderSubjectDer = new GostCertificate(delegatedCertsDer[0]).getSubjectDnBytes();
        } else {
            responderSubjectDer = caSubjectDer;
        }
        return DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, responderSubjectDer);
    }

    private static byte[] buildTbsResponseData(
            byte[] serialNumber,
            PublicKeyParameters caPub,
            int hlenCertId,
            byte[] caSubjectDer,
            String nextUpdateGeneralizedTime,
            String producedAtGeneralizedTime,
            String thisUpdateGeneralizedTime,
            byte[][] delegatedCertsDer,
            byte[] certStatusDer,
            byte[] nonce,
            byte[] responderId) {
        byte[] issuerNameHash = GostSignatureHelper.doHash(caSubjectDer, hlenCertId);
        byte[] issuerKeyHash =
                GostSignatureHelper.doHash(GostDerCodec.encodeSpkiKeyBits(caPub), hlenCertId);
        String digestOid =
                hlenCertId == GostOids.STREEBOG_512_HASH_LEN
                        ? GostOids.DIGEST_512
                        : GostOids.DIGEST_256;
        byte[] hashAlg = DerCodec.encodeSequence(DerCodec.encodeOid(digestOid));
        byte[] certId =
                DerCodec.encodeSequence(
                        hashAlg,
                        DerCodec.encodeOctetString(issuerNameHash),
                        DerCodec.encodeOctetString(issuerKeyHash),
                        DerCodec.encodeTlv(0x02, serialNumber));
        // RFC 6960 §2.4: thisUpdate — GeneralizedTime независимо от года.
        byte[] thisUpdate = DerCodec.encodeGeneralizedTime(thisUpdateGeneralizedTime);
        ByteArrayOutputStream srOut = new ByteArrayOutputStream();
        try {
            srOut.write(certId);
            srOut.write(certStatusDer);
            srOut.write(thisUpdate);
            if (nextUpdateGeneralizedTime != null) {
                byte[] nu =
                        DerCodec.encodeTlv(
                                0xA0,
                                DerCodec.encodeTlv(
                                        0x18,
                                        nextUpdateGeneralizedTime.getBytes(
                                                StandardCharsets.US_ASCII)));
                srOut.write(nu);
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        byte[] singleResponse = DerCodec.encodeSequence(srOut.toByteArray());
        byte[] producedAt =
                DerCodec.encodeTlv(
                        0x18, producedAtGeneralizedTime.getBytes(StandardCharsets.US_ASCII));
        byte[] responses = DerCodec.encodeSequence(singleResponse);

        // version имеет DEFAULT v1: по DER (X.690 §11.5) значение по умолчанию не
        // кодируется. Явный [0] v1 нормализуют при пересохранении (КриптоПро в
        // revocation-values X-Long), и подпись над исходным TBS перестаёт сходиться.
        byte[] baseContent = DerCodec.concat(responderId, producedAt, responses);
        if (nonce != null) {
            byte[] nonceExt = OcspNonceCodec.encodeExtension(nonce);
            byte[] nonceExtSeq = DerCodec.encodeSequence(nonceExt);
            byte[] responseExtensions = DerCodec.encodeTlv(0xA1, nonceExtSeq);
            return DerCodec.encodeSequence(DerCodec.concat(baseContent, responseExtensions));
        }
        return DerCodec.encodeSequence(baseContent);
    }
}
