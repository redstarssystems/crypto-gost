package org.rssys.gost.pkix.cert;

import java.util.Arrays;
import org.rssys.gost.pkix.GostOids;

/**
 * Единый источник истины для вычисления хешей CertID (RFC 6960 §4.1.1).
 * <p>
 * hashAlgorithm в CertID — свободный AlgorithmIdentifier.
 * Размер хэша (32 или 64 байта) определяется параметром {@code hlen} —
 * политика данной реализации: hlen = {@link GostOids#STREEBOG_512_HASH_LEN} -> Streebog-512, иначе Streebog-256.
 * <p>
 * issuerKeyHash: хэш от битов subjectPublicKey (RFC 6960 §4.1.1): значение BIT STRING
 * SubjectPublicKeyInfo без tag, length и октета unused-bits.
 * issuerNameHash: хэш от полного DER subject DN (включая SEQUENCE tag+length).
 */
public final class CertIdHasher {

    private CertIdHasher() {}

    /** Streebog-256, делегат к {@link #hashIssuerName(byte[], int)} с hlen=32. */
    public static byte[] hashIssuerName(byte[] issuerCertDer) {
        return hashIssuerName(issuerCertDer, GostOids.STREEBOG_256_HASH_LEN);
    }

    public static byte[] hashIssuerName(byte[] issuerCertDer, int hlen) {
        try {
            byte[] subjectDer = extractSubject(issuerCertDer);
            return GostSignatureHelper.doHash(subjectDer, hlen);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Failed to extract issuerNameHash from cert DER", e);
        }
    }

    /**
     * Вычисляет issuerNameHash из готового subject DN сертификата эмитента,
     * избегая полного перепарсинга DER (getEncoded() + extractSubject).
     * Делегат к {@link #hashIssuerName(GostCertificate, int)} с hlen = {@link GostOids#STREEBOG_256_HASH_LEN}.
     */
    public static byte[] hashIssuerName(GostCertificate issuer) {
        return hashIssuerName(issuer, GostOids.STREEBOG_256_HASH_LEN);
    }

    public static byte[] hashIssuerName(GostCertificate issuer, int hlen) {
        return GostSignatureHelper.doHash(issuer.getSubjectDnBytes(), hlen);
    }

    /** Streebog-256, делегат к {@link #hashIssuerPublicKey(byte[], int)} с hlen = {@link GostOids#STREEBOG_256_HASH_LEN}. */
    public static byte[] hashIssuerPublicKey(byte[] issuerCertDer) {
        return hashIssuerPublicKey(issuerCertDer, GostOids.STREEBOG_256_HASH_LEN);
    }

    public static byte[] hashIssuerPublicKey(byte[] issuerCertDer, int hlen) {
        try {
            byte[] bsValue = extractKeyBits(issuerCertDer);
            return GostSignatureHelper.doHash(bsValue, hlen);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Failed to extract issuerKeyHash from cert DER", e);
        }
    }

    /** Streebog-256, делегат к {@link #hashIssuerPublicKey(GostCertificate, int)} с hlen = {@link GostOids#STREEBOG_256_HASH_LEN}. */
    public static byte[] hashIssuerPublicKey(GostCertificate issuer) {
        return hashIssuerPublicKey(issuer, GostOids.STREEBOG_256_HASH_LEN);
    }

    public static byte[] hashIssuerPublicKey(GostCertificate issuer, int hlen) {
        return GostSignatureHelper.doHash(issuer.getSpkiKeyBits(), hlen);
    }

    static byte[] extractSubject(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1]; // version [0]
        checkTag(der, pos, GostDerParser.TAG_INTEGER, "serialNumber");
        pos = GostDerParser.readTlv(der, pos)[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "signature");
        pos = GostDerParser.readTlv(der, pos)[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "issuer");
        int[] issuerTlv = GostDerParser.readTlv(der, pos);
        pos = issuerTlv[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "validity");
        int[] validityTlv = GostDerParser.readTlv(der, pos);
        pos = validityTlv[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "subject");
        int[] subjectTlv = GostDerParser.readTlv(der, pos);
        return Arrays.copyOfRange(der, pos, subjectTlv[1]);
    }

    static byte[] extractKeyBits(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1]; // version [0]
        checkTag(der, pos, GostDerParser.TAG_INTEGER, "serialNumber");
        pos = GostDerParser.readTlv(der, pos)[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "signature");
        pos = GostDerParser.readTlv(der, pos)[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "issuer");
        pos = GostDerParser.readTlv(der, pos)[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "validity");
        pos = GostDerParser.readTlv(der, pos)[1];
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "subject");
        pos = GostDerParser.readTlv(der, pos)[1];
        // SPKI SEQUENCE -> skip AlgorithmIdentifier -> BIT STRING value
        checkTag(der, pos, GostDerParser.TAG_SEQUENCE, "subjectPublicKeyInfo");
        int[] spkiTlv = GostDerParser.readTlv(der, pos);
        int spkiPos = spkiTlv[0];
        int[] algTlv = GostDerParser.readTlv(der, spkiPos); // AlgorithmIdentifier
        spkiPos = algTlv[1];
        checkTag(der, spkiPos, GostDerParser.TAG_BIT_STRING, "subjectPublicKey");
        int[] bsTlv = GostDerParser.readTlv(der, spkiPos);
        // Первый октет значения - число неиспользуемых бит; для ГОСТ-ключа он обязан быть 0.
        if (bsTlv[1] - bsTlv[0] < 2 || der[bsTlv[0]] != 0) {
            throw new IllegalArgumentException(
                    "SubjectPublicKey BIT STRING has non-zero unused bits");
        }
        return Arrays.copyOfRange(der, bsTlv[0] + 1, bsTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = GostDerParser.readTlv(der, 0);
        int[] tbsTlv = GostDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }

    private static void checkTag(byte[] der, int pos, int expectedTag, String fieldName) {
        if (pos >= der.length) {
            throw new IllegalArgumentException(
                    "TBSCertificate: unexpected end of DER, expected "
                            + fieldName
                            + " at offset "
                            + pos);
        }
        if ((der[pos] & 0xFF) != expectedTag) {
            throw new IllegalArgumentException(
                    "TBSCertificate: expected tag 0x"
                            + Integer.toHexString(expectedTag)
                            + " for "
                            + fieldName
                            + " at offset "
                            + pos
                            + ", got 0x"
                            + Integer.toHexString(der[pos] & 0xFF));
        }
    }
}
