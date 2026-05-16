package org.rssys.gost.jsse.ocsp;

import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.OcspCertIdHasher;
import org.rssys.gost.tls13.cert.TlsDerParser;

import java.security.SecureRandom;

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

            Digest d = hlen == 64 ? new Streebog512() : new Streebog256();
            d.update(der, 0, der.length);
            byte[] hash = new byte[hlen];
            d.doFinal(hash, 0);
            byte[] sig = Signature.signHash(hash, signKey);
            String sigOid = hlen == 32
                    ? GostOids.SIGN_ALG_256 : GostOids.SIGN_ALG_512;
            String digestOid = hlen == 32
                    ? GostOids.DIGEST_256 : GostOids.DIGEST_512;
            String curveOid = GostOids.CURVE_256A;

            // AlgorithmIdentifier для GOST R 34.10-2012
            byte[] sigAlgOid = encodeOid(sigOid);
            byte[] paramsSeq = encodeTag(0x30, concat(encodeOid(curveOid), encodeOid(digestOid)));
            byte[] sigAlg = encodeTag(0x30, concat(sigAlgOid, paramsSeq));

            // BIT STRING подписи
            byte[] sigWithPad = new byte[sig.length + 1];
            System.arraycopy(sig, 0, sigWithPad, 1, sig.length);
            byte[] sigBs = encodeTag(0x03, sigWithPad);

            // Signature ::= SEQUENCE { signatureAlgorithm, signature, certs OPTIONAL }
            byte[] signature = encodeTag(0x30, concat(sigAlg, sigBs));

            // [0] EXPLICIT
            byte[] optSig = encodeTag(0xA0, signature);

            // OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature }
            byte[] requestDer = encodeTag(0x30, concat(der, optSig));
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
            SecureRandom random = new SecureRandom();
            byte[] nonce = new byte[16];
            random.nextBytes(nonce);

            byte[] certId = buildCertId(certDer, issuerDer);
            byte[] request = encodeTag(0x30, certId);
            byte[] requestList = encodeTag(0x30, request);
            byte[] nonceExt = buildNonceExtension(nonce);
            byte[] extensions = encodeTag(0x30, nonceExt);
            byte[] requestExtensions = encodeTag(TAG_CONTEXT_2, extensions);

            byte[] tbsRequestContent = concat(requestList, requestExtensions);
            byte[] tbsRequest = encodeTag(0x30, tbsRequestContent);
            byte[] der = encodeTag(0x30, tbsRequest);
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
        byte[] value = encodeTag(0x04, nonce);
        return encodeTag(0x30, concat(oid, value));
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
        byte[] nameHash = encodeTag(0x04, issuerNameHash);
        byte[] keyHash = encodeTag(0x04, issuerKeyHash);
        // serial: TLV as-is (bit-exact, RFC 6960 §4.1.1)
        // serial: копируем TLV как есть (bit-exact), чтобы не изменить семантику серийного номера — RFC 6960 §4.1.1
        byte[] serial = extractSerialTlv(certDer);

        return encodeTag(0x30, concat(hashAlg, nameHash, keyHash, serial));
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
        return encodeTag(0x30, oidContent);
    }

    private static byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");
        int[] vals = new int[parts.length];
        for (int i = 0; i < parts.length; i++) vals[i] = Integer.parseInt(parts[i]);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(40 * vals[0] + vals[1]);
        for (int i = 2; i < vals.length; i++) {
            int v = vals[i];
            if (v < 0x80) { out.write(v); continue; }
            int bits = 32 - Integer.numberOfLeadingZeros(v);
            int bytes = (bits + 6) / 7;
            for (int j = bytes - 1; j >= 0; j--) {
                int b = (v >>> (j * 7)) & 0x7F;
                if (j > 0) b |= 0x80;
                out.write(b);
            }
        }
        byte[] oidBytes = out.toByteArray();
        byte[] len = encodeLength(oidBytes.length);
        byte[] result = new byte[1 + len.length + oidBytes.length];
        result[0] = 0x06;
        System.arraycopy(len, 0, result, 1, len.length);
        System.arraycopy(oidBytes, 0, result, 1 + len.length, oidBytes.length);
        return result;
    }

    private static byte[] encodeTag(int tag, byte[] content) {
        byte[] len = encodeLength(content.length);
        byte[] result = new byte[1 + len.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(len, 0, result, 1, len.length);
        System.arraycopy(content, 0, result, 1 + len.length, content.length);
        return result;
    }

    private static byte[] encodeLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        }
        int numBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
        byte[] result = new byte[1 + numBytes];
        result[0] = (byte) (0x80 | numBytes);
        for (int i = numBytes; i >= 1; i--) {
            result[i] = (byte) (length & 0xFF);
            length >>= 8;
        }
        return result;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] result = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, result, off, p.length);
            off += p.length;
        }
        return result;
    }
}
