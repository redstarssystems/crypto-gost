package org.rssys.gost.tls13;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.RevokedEntry;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Вспомогательные методы для тестов TLS 1.3 — DER-построители и сертификаты.
 *
 * <p>После плана 084: все методы — тонкие делегаты в builder'ы pkix.
 * Единственное исключение — {@link #createCertWithForcedIssuer} (тестовый хак,
 * issuer != signer). DER-обёртки оставлены для обратной совместимости.</p>
 */
public class TlsTestHelper {

    private static final DateTimeFormatter GEN_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");

    public static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        int len = clean.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(clean.charAt(i), 16) << 4)
                                    | Character.digit(clean.charAt(i + 1), 16));
        }
        return data;
    }

    public static String hexStr(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    private static int certCounter = 0;

    /** Результат создания сертификата — сам сертификат, ключи и subject DN. */
    public static class CertBundle {
        public final GostCertificate cert;
        public final PrivateKeyParameters priv;
        public final byte[] subjectDn;

        public CertBundle(GostCertificate cert, PrivateKeyParameters priv, byte[] subjectDn) {
            this.cert = cert;
            this.priv = priv;
            this.subjectDn = subjectDn;
        }
    }

    // ========================================================================
    // Сертификаты (keygen здесь -> builder'ы в pkix для сборки)
    // ========================================================================

    /**
     * Создаёт самоподписанный сертификат и возвращает его с ключом.
     * Генерация ключей — в TlsTestHelper (тестовый скоуп), сборка — в GostCertificateBuilder.
     */
    public static CertBundle createCertWithKey(ECParameters params) {
        return createCertWithKey(params, "20250101000000Z", "21010101000000Z", null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params, String notBefore, String notAfter) {
        return createCertWithKey(params, notBefore, notAfter, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params, String notBefore, String notAfter, String[] sanDnsNames) {
        return createCertWithKey(params, notBefore, notAfter, sanDnsNames, null, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids) {
        return createCertWithKey(
                params, notBefore, notAfter, sanDnsNames, kuFlags, ekuOids, null, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids,
            String[] sanIps) {
        return createCertWithKey(
                params, notBefore, notAfter, sanDnsNames, kuFlags, ekuOids, sanIps, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids,
            String[] sanIps,
            String[] policyOids) {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        byte[] additionalExt = buildAdditionalExtensions(kuFlags, ekuOids, policyOids);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .sanDns(sanDnsNames)
                        .sanIp(sanIps)
                        .additionalExtensions(additionalExt)
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, priv, params);
        return new CertBundle(cert, priv, subjectDn);
    }

    /** Создаёт корневой CA (самоподписанный, BC: cA=TRUE, KU: keyCertSign). */
    public static CertBundle createRootCA(ECParameters params) throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Root CA " + (++certCounter));
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.keyUsageFlags(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN));
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, priv, params);
        return new CertBundle(cert, priv, subjectDn);
    }

    /** Создаёт сертификат, подписанный issuerPriv.
     *  Issuer DN берётся из parentSubjectDn.
     *  Возвращает CertBundle с сгенерированным privKey подписанного сертификата. */
    public static CertBundle createCertSignedBy(
            ECParameters params,
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            byte[] parentSubjectDn,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids,
            boolean isCA,
            Integer pathLen)
            throws Exception {
        return createCertSignedBy(
                params,
                issuerPriv,
                issuerPub,
                parentSubjectDn,
                notBefore,
                notAfter,
                sanDnsNames,
                null,
                kuFlags,
                ekuOids,
                isCA,
                pathLen);
    }

    public static CertBundle createCertSignedBy(
            ECParameters params,
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            byte[] parentSubjectDn,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            String[] sanIps,
            byte[] kuFlags,
            String[] ekuOids,
            boolean isCA,
            Integer pathLen)
            throws Exception {
        return createCertSignedBy(
                params,
                issuerPriv,
                issuerPub,
                parentSubjectDn,
                notBefore,
                notAfter,
                sanDnsNames,
                sanIps,
                kuFlags,
                ekuOids,
                isCA,
                pathLen,
                null,
                null);
    }

    public static CertBundle createCertSignedBy(
            ECParameters params,
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            byte[] parentSubjectDn,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            String[] sanIps,
            byte[] kuFlags,
            String[] ekuOids,
            boolean isCA,
            Integer pathLen,
            byte[] extraExtensions)
            throws Exception {
        return createCertSignedBy(
                params,
                issuerPriv,
                issuerPub,
                parentSubjectDn,
                notBefore,
                notAfter,
                sanDnsNames,
                sanIps,
                kuFlags,
                ekuOids,
                isCA,
                pathLen,
                extraExtensions,
                null);
    }

    public static CertBundle createCertSignedBy(
            ECParameters params,
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            byte[] parentSubjectDn,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            String[] sanIps,
            byte[] kuFlags,
            String[] ekuOids,
            boolean isCA,
            Integer pathLen,
            byte[] extraExtensions,
            String[] policyOids)
            throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters leafPriv = kp.getPrivate();
        PublicKeyParameters leafPub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        if (isCA || pathLen != null) {
            extBuf.write(GostCertificateBuilder.buildBasicConstraintsExtension(isCA, pathLen));
        }
        if (kuFlags != null) {
            extBuf.write(GostCertificateBuilder.buildKeyUsageExtension(kuFlags));
        }
        if (ekuOids != null) {
            extBuf.write(GostCertificateBuilder.buildEkuExtension(ekuOids));
        }
        if (policyOids != null) {
            extBuf.write(GostCertificateBuilder.buildCertificatePoliciesExtension(policyOids));
        }
        if (extraExtensions != null) {
            extBuf.write(extraExtensions);
        }
        byte[] additionalExt = extBuf.size() == 0 ? null : extBuf.toByteArray();
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(leafPub)
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .sanDns(sanDnsNames)
                        .sanIp(sanIps)
                        .additionalExtensions(additionalExt)
                        .issuerDn(parentSubjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, issuerPriv, params);
        return new CertBundle(cert, leafPriv, subjectDn);
    }

    /** Тестовый хак: issuer != signer. Не переносится в GostCertificateBuilder. */
    public static CertBundle createCertWithForcedIssuer(
            ECParameters params,
            PrivateKeyParameters signerPriv,
            byte[] issuerDn,
            String subjectCN,
            String notBefore,
            String notAfter)
            throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters leafPriv = kp.getPrivate();
        PublicKeyParameters leafPub = kp.getPublic();
        int hlen = params.hlen;
        byte[] subjectDn = buildDN(subjectCN);
        byte[] tbs =
                buildTbs(
                        leafPub, params, notBefore, notAfter, null, null, null, issuerDn,
                        subjectDn);
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, signerPriv);
        byte[] algId = buildAlgId(params);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new CertBundle(new GostCertificate(certDer), leafPriv, subjectDn);
    }

    // ========================================================================
    // Расширения X.509 (делегаты)
    // ========================================================================

    public static byte[] buildAiaOcspExtension(String ocspUri) {
        return GostCertificateBuilder.buildAiaOcspExtension(ocspUri);
    }

    public static byte[] buildCdpExtension(String... crlUris) {
        return GostCertificateBuilder.buildCdpExtension(crlUris);
    }

    public static byte[] buildTbs(
            PublicKeyParameters pub,
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            String[] sanIps,
            byte[] additionalExtensions,
            byte[] issuerDn,
            byte[] subjectDn) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(params, subjectDn).publicKey(pub);
        if (notBefore != null) {
            builder.notBefore(notBefore);
        }
        if (notAfter != null) {
            builder.notAfter(notAfter);
        }
        if (sanDnsNames != null) {
            builder.sanDns(sanDnsNames);
        }
        if (sanIps != null) {
            builder.sanIp(sanIps);
        }
        if (additionalExtensions != null) {
            builder.additionalExtensions(additionalExtensions);
        }
        if (issuerDn != null) {
            builder.issuerDn(issuerDn);
        }
        return builder.buildTbs();
    }

    // ========================================================================
    // CRL (делегаты -> GostCrlBuilder)
    // ========================================================================

    /**
     * Convenience-перегрузка для обратной совместимости.
     * Оборачивает {@code byte[][] serialNumbers} в {@link RevokedEntry}[] с null-полями.
     * RevocationDate = текущее время.
     */
    public static byte[] buildCrl(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            boolean withIdpExtension)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        GostCrlBuilder builder = GostCrlBuilder.create(caPriv, issuerDnDer);
        if (nextUpdateGeneralizedTime != null) {
            builder = builder.nextUpdate(nextUpdateGeneralizedTime);
        }
        if (withIdpExtension) {
            builder = builder.withIdpExtension();
        }
        if (entries != null) {
            builder = builder.addRevoked(Arrays.asList(entries));
        }
        return builder.build();
    }

    public static byte[] buildCrlLegacyVersion(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            boolean withIdpExtension)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        return GostCrlBuilder.assembleCrl(
                entries, caPriv, issuerDnDer,
                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME),
                nextUpdateGeneralizedTime, true, null, null, null, withIdpExtension);
    }

    /**
     * Собирает CRL с cRLNumber.
     */
    public static byte[] buildCrlWithCrlNumber(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            int crlNumber)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        GostCrlBuilder builder =
                GostCrlBuilder.create(caPriv, issuerDnDer)
                        .withCrlNumber(crlNumber);
        if (nextUpdateGeneralizedTime != null) {
            builder = builder.nextUpdate(nextUpdateGeneralizedTime);
        }
        if (entries != null) {
            builder = builder.addRevoked(Arrays.asList(entries));
        }
        return builder.build();
    }

    /**
     * Собирает Delta CRL (cRLNumber + deltaCRLIndicator).
     */
    public static byte[] buildDeltaCrl(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            int crlNumber,
            int baseCrlNumber)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        GostCrlBuilder builder =
                GostCrlBuilder.create(caPriv, issuerDnDer)
                        .withCrlNumber(crlNumber)
                        .withDeltaCrlIndicator(baseCrlNumber);
        if (entries != null) {
            builder = builder.addRevoked(Arrays.asList(entries));
        }
        return builder.build();
    }

    /**
     * Собирает base CRL с freshestCRL.
     */
    public static byte[] buildCrlWithFreshestCrl(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            int crlNumber,
            String... freshestUris)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        GostCrlBuilder builder =
                GostCrlBuilder.create(caPriv, issuerDnDer)
                        .withCrlNumber(crlNumber)
                        .withFreshestCrl(freshestUris);
        if (nextUpdateGeneralizedTime != null) {
            builder = builder.nextUpdate(nextUpdateGeneralizedTime);
        }
        if (entries != null) {
            builder = builder.addRevoked(Arrays.asList(entries));
        }
        return builder.build();
    }

    // ========================================================================
    // OCSP (делегаты -> GostOcspResponseBuilder)
    // ========================================================================

    public static byte[] buildOcspResponse(
            byte[] serialNumber,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] caSubjectDer)
            throws Exception {
        return GostOcspResponseBuilder.create(serialNumber)
                .signer(caPriv, caPub)
                .issuerDn(caSubjectDer)
                .build();
    }

    public static byte[] buildOcspResponse(
            byte[] serialNumber,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] caSubjectDer,
            String nextUpdateGeneralizedTime)
            throws Exception {
        GostOcspResponseBuilder builder =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(caPriv, caPub)
                        .issuerDn(caSubjectDer);
        if (nextUpdateGeneralizedTime != null) {
            builder.nextUpdate(nextUpdateGeneralizedTime);
        }
        return builder.build();
    }

    public static byte[] buildOcspResponseWithDelegatedCerts(
            byte[] serialNumber,
            PrivateKeyParameters signerPriv,
            PublicKeyParameters signerPub,
            PublicKeyParameters caPub,
            byte[] caSubjectDer,
            String nextUpdateGeneralizedTime,
            byte[][] delegatedCertsDer)
            throws Exception {
        return GostOcspResponseBuilder.create(serialNumber)
                .signer(signerPriv, signerPub)
                .caPublicKey(caPub)
                .issuerDn(caSubjectDer)
                .nextUpdate(nextUpdateGeneralizedTime)
                .withDelegatedCerts(delegatedCertsDer)
                .build();
    }

    public static byte[] buildDummyOcspResponse() throws Exception {
        byte[] tbs = new byte[] {0x30, 0x03, 0x02, 0x01, 0x00};
        byte[] sigAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.SIGN_ALG_256));
        byte[] sig = DerCodec.encodeBitString(new byte[64]);
        byte[] basicOcsp = DerCodec.encodeSequence(tbs, sigAlg, sig);
        // wrapOcspResponse
        byte[] basicOctet = DerCodec.encodeOctetString(basicOcsp);
        byte[] responseBytesContent =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = DerCodec.encodeTlv(0xA0, responseBytesContent);
        byte[] status = new byte[] {0x0A, 0x01, 0x00};
        return DerCodec.encodeSequence(status, responseBytes);
    }

    // ========================================================================
    // Хелперы (оставлены для createCertWithForcedIssuer и обратной совместимости)
    // ========================================================================

    public static byte[] doHash(byte[] data, int hlen) {
        if (hlen == GostOids.STREEBOG_512_HASH_LEN) return Digest.digest512(data);
        return Digest.digest256(data);
    }

    public static byte[] buildAlgId(ECParameters params) {
        int hlen = params.hlen;
        String signOid =
                (hlen == GostOids.STREEBOG_512_HASH_LEN)
                        ? GostOids.SIGN_ALG_512
                        : GostOids.SIGN_ALG_256;
        return derSequence(derOid(signOid));
    }

    public static byte[] buildDN(String cn) {
        return GostDnParser.encodeDn("CN=" + cn);
    }

    // ========================================================================
    // DER-обёртки (обратная совместимость)
    // ========================================================================

    public static byte[] derSequence(byte[]... elements) {
        return DerCodec.encodeSequence(elements);
    }

    public static byte[] derBitString(byte[] content) {
        return DerCodec.encodeBitString(content);
    }

    public static byte[] derOctetString(byte[] data) {
        return DerCodec.encodeOctetString(data);
    }

    public static byte[] derOid(String oidStr) {
        return DerCodec.encodeOid(oidStr);
    }

    public static byte[] derTime(String time) {
        return DerCodec.encodeTime(time);
    }

    public static byte[] derTlv(int tag, byte[] content) {
        return DerCodec.encodeTlv(tag, content);
    }

    public static byte[] encodeSet(byte[] content) {
        return DerCodec.encodeSet(content);
    }

    // ========================================================================
    // Приватные
    // ========================================================================

    private static byte[] buildAdditionalExtensions(
            byte[] kuFlags, String[] ekuOids, String[] policyOids) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            if (kuFlags != null) {
                out.write(GostCertificateBuilder.buildKeyUsageExtension(kuFlags));
            }
            if (ekuOids != null) {
                out.write(GostCertificateBuilder.buildEkuExtension(ekuOids));
            }
            if (policyOids != null) {
                out.write(GostCertificateBuilder.buildCertificatePoliciesExtension(policyOids));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] data = out.toByteArray();
        return data.length == 0 ? null : data;
    }

    // ========================================================================
    // Multi-SingleResponse OCSP (для тестов TlsOcspVerifierTest)
    // ========================================================================

    /**
     * Строит OCSP-ответ с двумя SingleResponse и валидной подписью.
     * Логика парсинга/пересборки идентична приватному методу в
     * {@code TlsOcspVerifierTest.buildMultiResponseOcsp()}, но здесь
     * TBS переподписывается переданным ключом — подпись валидна.
     */
    public static byte[] buildMultiResponseOcsp(
            byte[] baseOcsp, byte[] sr1, byte[] sr2,
            PrivateKeyParameters signKey) {
        byte[][] outer = DerCodec.parseSequenceContents(baseOcsp, 0);
        byte[] rb = outer[1];
        int[] rbLen = DerCodec.decodeLength(rb, 1);
        byte[][] rbContent = DerCodec.parseSequenceContents(rb, 1 + rbLen[1]);
        byte[] basicDer = DerCodec.parseOctetString(rbContent[1], 0);
        byte[][] basicParts = DerCodec.parseSequenceContents(basicDer, 0);
        byte[] tbs = basicParts[0];
        byte[][] tbsParts = DerCodec.parseSequenceContents(tbs, 0);

        byte[] newResponses = DerCodec.encodeSequence(sr1, sr2);

        byte[][] newTbsParts = new byte[tbsParts.length][];
        System.arraycopy(tbsParts, 0, newTbsParts, 0, tbsParts.length);
        newTbsParts[3] = newResponses;
        byte[] newTbs = DerCodec.encodeSequence(newTbsParts);

        // Переподписываем TBS
        int hlen = signKey.getParams().hlen;
        byte[] hash = doHash(newTbs, hlen);
        byte[] sig = Signature.signHash(hash, signKey);
        byte[] sigBs = DerCodec.encodeBitString(sig);

        byte[] newBasic = DerCodec.encodeSequence(newTbs, basicParts[1], sigBs);
        byte[] newBasicOctet = DerCodec.encodeOctetString(newBasic);
        byte[] newRbContent = DerCodec.encodeSequence(rbContent[0], newBasicOctet);
        byte[] newRb = DerCodec.encodeContextConstructed(0, newRbContent);
        return DerCodec.encodeSequence(outer[0], newRb);
    }
}
