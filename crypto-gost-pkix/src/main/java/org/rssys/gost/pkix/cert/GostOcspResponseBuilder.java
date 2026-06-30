package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.rssys.gost.api.Signature;
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
 *     .signer(signerPriv, signerPub)
 *     .issuerDn(caSubjectDer)
 *     .nextUpdate("20260101000000Z")
 *     .build();
 * </pre>
 *
 * <p>С делегированными сертификатами:
 * <pre>
 * byte[] ocsp = GostOcspResponseBuilder.create(serialNumber)
 *     .signer(responderPriv, responderPub)
 *     .caPublicKey(caPub)
 *     .issuerDn(caSubjectDer)
 *     .withDelegatedCerts(cert1Der, cert2Der)
 *     .build();
 * </pre>
 *
 * <p>{@link #build()} возвращает wire-формат DER-байтов для передачи по сети.
 * Для инспекции и проверки — consumer-класс {@link GostOcspResponse}:
 * {@code new GostOcspResponse(bytes).verify(caPub)}. Разделение producer
 * (OCSP-responder строит ответ) и consumer (клиент проверяет) осмысленно:
 * OCSP-ответ — fail-closed объект, подпись не проверена до вызова
 * {@link GostOcspResponse#verify verify()}.</p>
 */
public final class GostOcspResponseBuilder {

    private final byte[] serialNumber;
    private PrivateKeyParameters signerPriv;
    private PublicKeyParameters signerPub;
    private PublicKeyParameters caPub;
    private byte[] caSubjectDer;
    private String nextUpdate;
    private String producedAt;
    private String thisUpdate;
    private byte[][] delegatedCertsDer;
    private byte[] certStatusDer; // null = good по умолчанию
    private byte[] nonce;

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

    /** Ключ, подписывающий OCSP-ответ. */
    public GostOcspResponseBuilder signer(PrivateKeyParameters priv, PublicKeyParameters pub) {
        this.signerPriv = priv;
        this.signerPub = pub;
        return this;
    }

    /** Публичный ключ CA для CertID issuerKeyHash. По умолчанию = signerPub. */
    public GostOcspResponseBuilder caPublicKey(PublicKeyParameters pub) {
        this.caPub = pub;
        return this;
    }

    /** DER-кодированный subject DN CA для CertID issuerNameHash. */
    public GostOcspResponseBuilder issuerDn(byte[] subjectDer) {
        this.caSubjectDer = subjectDer;
        return this;
    }

    /** Удобная перегрузка: DN из строки "CN=..., O=..." */
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
        byte[] revTime = DerCodec.encodeTime(revocationTime);
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
     * @param nonce значение nonce из OCSP-запроса (16 байт) или null — не добавлять
     */
    public GostOcspResponseBuilder nonce(byte[] nonce) {
        this.nonce = nonce;
        return this;
    }

    /** Собирает и подписывает OCSP-ответ. */
    public byte[] build() {
        if (signerPriv == null || signerPub == null) {
            throw new IllegalStateException("signer key must be set");
        }
        if (caSubjectDer == null) {
            throw new IllegalStateException("issuerDn must be set");
        }
        PublicKeyParameters caKey = caPub != null ? caPub : signerPub;
        String pa = producedAt != null ? producedAt : GostSignatureHelper.nowGeneralizedTime();
        String tu = thisUpdate != null ? thisUpdate : GostSignatureHelper.nowGeneralizedTime();
        String nu = nextUpdate != null ? nextUpdate : GostSignatureHelper.nowPlusYears(3);

        byte[] statusDer =
                certStatusDer != null ? certStatusDer : DerCodec.encodeTlv(0x80, new byte[0]);
        byte[] tbs =
                buildTbsResponseData(
                        serialNumber,
                        caKey,
                        caSubjectDer,
                        nu,
                        pa,
                        tu,
                        delegatedCertsDer,
                        statusDer,
                        nonce);
        int hlen = signerPub.getParams().hlen;
        byte[] hash = GostSignatureHelper.doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, signerPriv);
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

    private static byte[] wrapOcspResponse(byte[] basicOcsp) {
        byte[] basicOctet = DerCodec.encodeOctetString(basicOcsp);
        byte[] responseBytesContent =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = DerCodec.encodeTlv(0xA0, responseBytesContent);
        byte[] status = new byte[] {0x0A, 0x01, 0x00};
        return DerCodec.encodeSequence(status, responseBytes);
    }

    private static byte[] buildTbsResponseData(
            byte[] serialNumber,
            PublicKeyParameters caPub,
            byte[] caSubjectDer,
            String nextUpdateGeneralizedTime,
            String producedAtGeneralizedTime,
            String thisUpdateGeneralizedTime,
            byte[][] delegatedCertsDer,
            byte[] certStatusDer,
            byte[] nonce) {
        int hlenCa = caPub.getParams().hlen;
        byte[] issuerNameHash = GostSignatureHelper.doHash(caSubjectDer, hlenCa);
        byte[] caSpkiDer = GostDerCodec.encodePublicKey(caPub);
        int[] spkiSeq = GostDerParser.parseSequence(caSpkiDer, 0);
        int spkiPos = spkiSeq[0];
        int[] algTlv = GostDerParser.readTlv(caSpkiDer, spkiPos);
        spkiPos = algTlv[1];
        int[] bsTlv = GostDerParser.readTlv(caSpkiDer, spkiPos);
        byte[] bitStringValue = java.util.Arrays.copyOfRange(caSpkiDer, bsTlv[0], bsTlv[1]);
        byte[] issuerKeyHash = GostSignatureHelper.doHash(bitStringValue, hlenCa);
        String digestOid =
                hlenCa == GostOids.STREEBOG_512_HASH_LEN
                        ? GostOids.DIGEST_512
                        : GostOids.DIGEST_256;
        byte[] hashAlg = DerCodec.encodeSequence(DerCodec.encodeOid(digestOid));
        byte[] certId =
                DerCodec.encodeSequence(
                        hashAlg,
                        DerCodec.encodeOctetString(issuerNameHash),
                        DerCodec.encodeOctetString(issuerKeyHash),
                        DerCodec.encodeTlv(0x02, serialNumber));
        byte[] thisUpdate = DerCodec.encodeTime(thisUpdateGeneralizedTime);
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
        byte[] version = DerCodec.encodeTlv(0xA0, new byte[] {0x02, 0x01, 0x00});
        // byName [1] — subject DN подписанта (RFC 6960 §4.2.1)
        byte[] responderSubjectDer;
        if (delegatedCertsDer != null && delegatedCertsDer.length > 0) {
            responderSubjectDer = new GostCertificate(delegatedCertsDer[0]).getSubjectDnBytes();
        } else {
            // Неделегированный режим: подписант = CA
            responderSubjectDer = caSubjectDer;
        }
        byte[] responderId = DerCodec.encodeTlv(0xA1, responderSubjectDer);
        byte[] producedAt =
                DerCodec.encodeTlv(
                        0x18, producedAtGeneralizedTime.getBytes(StandardCharsets.US_ASCII));
        byte[] responses = DerCodec.encodeSequence(singleResponse);

        byte[] baseContent = DerCodec.concat(version, responderId, producedAt, responses);
        if (nonce != null) {
            byte[] nonceOid = DerCodec.encodeOid(GostOids.OCSP_NONCE);
            byte[] nonceValue = DerCodec.encodeOctetString(nonce);
            byte[] nonceExt = DerCodec.encodeSequence(nonceOid, nonceValue);
            byte[] nonceExtSeq = DerCodec.encodeSequence(nonceExt);
            byte[] responseExtensions = DerCodec.encodeTlv(0xA1, nonceExtSeq);
            return DerCodec.encodeSequence(DerCodec.concat(baseContent, responseExtensions));
        }
        return DerCodec.encodeSequence(baseContent);
    }
}
