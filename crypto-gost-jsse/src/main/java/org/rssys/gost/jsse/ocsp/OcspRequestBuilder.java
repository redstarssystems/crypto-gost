package org.rssys.gost.jsse.ocsp;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.OcspCertIdHasher;
import org.rssys.gost.tls13.cert.TlsDerParser;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель DER-закодированного OCSPRequest (RFC 6960 §4.1) с поддержкой nonce (RFC 8954).
 * <p>
 * Использует Streebog256 для хеширования issuerNameHash и issuerKeyHash и
 * всегда добавляет nonce-расширение (16 байт, SecureRandom) в requestExtensions.
 */
public final class OcspRequestBuilder {

    /** [2] EXPLICIT constructed context tag для requestExtensions */
    private static final int TAG_CONTEXT_2 = 0xA2;

    private OcspRequestBuilder() { }

    /**
     * Строит DER-encoded OCSPRequest без nonce.
     *
     * @param certDer   DER-encoded проверяемый сертификат
     * @param issuerDer DER-encoded сертификат издателя
     * @return DER-encoded OCSPRequest
     * @deprecated используйте {@link #buildWithNonce(byte[], byte[])} для nonce-защиты
     */
    @Deprecated
    public static byte[] build(byte[] certDer, byte[] issuerDer) {
        return buildWithNonce(certDer, issuerDer).der();
    }

    /**
     * Строит подписанный OCSPRequest (RFC 6960 §4.1.1) с nonce (RFC 8954).
     * <p>
     * Добавляет optionalSignature: подпись GOST R 34.10-2012 над TBSRequest.
     * Большинство OCSP-responder'ов не проверяют подпись запроса, поэтому
     * {@link #buildWithNonce(byte[], byte[])} без подписи — достаточен для
     * большинства случаев.
     *
     * @param certDer   DER-encoded проверяемый сертификат
     * @param issuerDer DER-encoded сертификат издателя
     * @param signKey   закрытый ключ для подписи запроса (если null — без подписи)
     * @param params    параметры кривой для подписи (только если signKey не null)
     * @return OcspRequest с DER и nonce
     */
    public static OcspRequest buildSigned(byte[] certDer, byte[] issuerDer,
                                          PrivateKeyParameters signKey, ECParameters params) {
        if (signKey == null) return buildWithNonce(certDer, issuerDer);
        try {
            OcspRequest base = buildWithNonce(certDer, issuerDer);
            byte[] der = base.der();
            int hlen = params.hlen;

            byte[] hash;
            String sigOid;
            if (hlen == TlsConstants.STREEBOG_256_HASH_LEN) {
                hash      = Digest.digest256(der);
                sigOid    = GostOids.SIGN_ALG_256;
            } else {
                hash      = Digest.digest512(der);
                sigOid    = GostOids.SIGN_ALG_512;
            }
            byte[] sig = Signature.signHash(hash, signKey);

            // AlgorithmIdentifier для GOST R 34.10-2012 — signwithdigest OID без параметров (RFC 9215 §4.2)
            byte[] sigAlg = DerCodec.encodeSequence(DerCodec.encodeOid(sigOid));

            // Signature ::= SEQUENCE { signatureAlgorithm, signature, certs OPTIONAL }
            byte[] signature = DerCodec.encodeSequence(sigAlg, DerCodec.encodeBitString(sig));

            // [0] EXPLICIT
            byte[] optSig = DerCodec.encodeContextConstructed(0, signature);

            // OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature }
            byte[] requestDer = DerCodec.encodeSequence(der, optSig);
            return new OcspRequest(requestDer, base.nonce());
        } catch (Exception e) {
            throw new RuntimeException("Failed to build signed OCSPRequest", e);
        }
    }

    /**
     * Строит DER-encoded OCSPRequest с nonce (RFC 8954).
     * <p>
     * Nonce (16 байт, SecureRandom) добавляется в
     * {@code TBSRequest.requestExtensions} как id-pkix-ocsp-nonce.
     *
     * @param certDer   DER-encoded проверяемый сертификат
     * @param issuerDer DER-encoded сертификат издателя
     * @return OcspRequest с DER и nonce
     */
    public static OcspRequest buildWithNonce(byte[] certDer, byte[] issuerDer) {
        try {
            byte[] nonce = new byte[16];
            CryptoRandom.INSTANCE.nextBytes(nonce);

            byte[] certId = buildCertId(certDer, issuerDer);
            byte[] request = DerCodec.encodeSequence(certId);
            byte[] requestList = DerCodec.encodeSequence(request);
            byte[] nonceExt = buildNonceExtension(nonce);
            byte[] extensions = DerCodec.encodeSequence(nonceExt);
            byte[] requestExtensions = DerCodec.encodeContextConstructed(2, extensions);

            byte[] tbsRequestContent = DerCodec.concat(requestList, requestExtensions);
            byte[] tbsRequest = DerCodec.encodeSequence(tbsRequestContent);
            byte[] der = DerCodec.encodeSequence(tbsRequest);
            return new OcspRequest(der, nonce);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build OCSPRequest with nonce", e);
        }
    }

    /**
     * Строит Extension с id-pkix-ocsp-nonce.
     * Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }
     */
    private static byte[] buildNonceExtension(byte[] nonce) {
        byte[] oid = new byte[]{
                0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
        };
        byte[] value = DerCodec.encodeOctetString(nonce);
        return DerCodec.encodeSequence(oid, value);
    }

    /**
     * CertID ::= SEQUENCE {
     *   hashAlgorithm   AlgorithmIdentifier,
     *   issuerNameHash  OCTET STRING,
     *   issuerKeyHash   OCTET STRING,
     *   serialNumber    CertificateSerialNumber }
     */
    private static byte[] buildCertId(byte[] certDer, byte[] issuerDer) {
        byte[] issuerNameHash = OcspCertIdHasher.hashIssuerName(issuerDer);
        byte[] issuerKeyHash = OcspCertIdHasher.hashIssuerPublicKey(issuerDer);

        byte[] hashAlg = buildStreebog256AlgorithmId();
        byte[] nameHash = DerCodec.encodeOctetString(issuerNameHash);
        byte[] keyHash = DerCodec.encodeOctetString(issuerKeyHash);
        // serial: TLV as-is (bit-exact, RFC 6960 §4.1.1)
        // serial: копируем TLV как есть (bit-exact), чтобы не изменить семантику серийного номера — RFC 6960 §4.1.1
        byte[] serial = extractSerialTlv(certDer);

        return DerCodec.encodeSequence(hashAlg, nameHash, keyHash, serial);
    }

    /**
     * Извлекает полный TLV serialNumber (включая 02 LL) для bit-exact копирования.
     */
    private static byte[] extractSerialTlv(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = TlsDerParser.readTlv(der, pos)[1];
        int tlvStart = pos;
        int[] serialTlv = TlsDerParser.readTlv(der, pos);
        return java.util.Arrays.copyOfRange(der, tlvStart, serialTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = TlsDerParser.readTlv(der, 0);
        int[] tbsTlv = TlsDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }

    /**
     * AlgorithmIdentifier для Streebog256:
     * SEQUENCE { OID(1.2.643.7.1.1.2.2), NULL }
     */
    private static byte[] buildStreebog256AlgorithmId() {
        byte[] oidContent = new byte[]{
                0x06, 0x08, 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02,
                0x05, 0x00
        };
        return DerCodec.encodeSequence(oidContent);
    }
}
