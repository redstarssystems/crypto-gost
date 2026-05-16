package org.rssys.gost.tls13.cert;

import org.rssys.gost.api.Digest;

import java.util.Arrays;

/**
 * Единый источник истины для вычисления хешей CertID (RFC 6960 §4.1.1).
 * <p>
 * issuerKeyHash: Streebog-256 от BIT STRING value SubjectPublicKeyInfo
 * (включая unused-bits byte, без tag и length BIT STRING).
 * issuerNameHash: Streebog-256 от полного DER subject DN (включая SEQUENCE tag+length).
 * <p>
 * BT: Для согласованности с {@code TlsTestHelper.buildOcspResponse} используем
 * re-encoding через GostDerCodec (decode → encode), так как buildOcspResponse
 * также encode'ит ключ перед хешированием BIT STRING value.
 */
public final class OcspCertIdHasher {

    private OcspCertIdHasher() {
    }

    public static byte[] hashIssuerName(byte[] issuerCertDer) {
        byte[] subjectDer = extractSubject(issuerCertDer);
        return Digest.digest256(subjectDer);
    }

    public static byte[] hashIssuerName(TlsCertificate issuer) {
        return hashIssuerName(issuer.getEncoded());
    }

    public static byte[] hashIssuerPublicKey(byte[] issuerCertDer) {
        byte[] bsValue = extractBitStringValue(issuerCertDer);
        return Digest.digest256(bsValue);
    }

    public static byte[] hashIssuerPublicKey(TlsCertificate issuer) {
        return hashIssuerPublicKey(issuer.getEncoded());
    }

    static byte[] extractSubject(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = TlsDerParser.readTlv(der, pos)[1];
        pos = TlsDerParser.readTlv(der, pos)[1]; // serial
        pos = TlsDerParser.readTlv(der, pos)[1]; // signature
        int[] issuerTlv = TlsDerParser.readTlv(der, pos);
        pos = issuerTlv[1];
        int[] validityTlv = TlsDerParser.readTlv(der, pos);
        pos = validityTlv[1];
        int[] subjectTlv = TlsDerParser.readTlv(der, pos);
        return Arrays.copyOfRange(der, pos, subjectTlv[1]);
    }

    static byte[] extractBitStringValue(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = TlsDerParser.readTlv(der, pos)[1];
        pos = TlsDerParser.readTlv(der, pos)[1]; // serial
        pos = TlsDerParser.readTlv(der, pos)[1]; // signature
        pos = TlsDerParser.readTlv(der, pos)[1]; // issuer
        pos = TlsDerParser.readTlv(der, pos)[1]; // validity
        pos = TlsDerParser.readTlv(der, pos)[1]; // subject
        // SPKI SEQUENCE → skip AlgorithmIdentifier → BIT STRING value
        int[] spkiTlv = TlsDerParser.readTlv(der, pos);
        int spkiPos = spkiTlv[0];
        int[] algTlv = TlsDerParser.readTlv(der, spkiPos);
        spkiPos = algTlv[1];
        int[] bsTlv = TlsDerParser.readTlv(der, spkiPos);
        return Arrays.copyOfRange(der, bsTlv[0], bsTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = TlsDerParser.readTlv(der, 0);
        int[] tbsTlv = TlsDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }
}
