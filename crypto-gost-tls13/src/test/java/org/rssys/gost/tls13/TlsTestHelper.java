package org.rssys.gost.tls13;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsDerParser;
import org.rssys.gost.util.DerCodec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Вспомогательные методы для тестов TLS 1.3 — DER-построители и сертификаты.
 */
public class TlsTestHelper {

    // Контекстно-зависимые теги (X.509 SAN, CTX) — нет в DerCodec
    public static final int TAG_CTX_0         = 0xA0;
    public static final int TAG_CTX_3         = 0xA3;
    public static final int TAG_DNS_NAME      = 0x82;
    public static final int TAG_IP_ADDRESS    = 0x87;

    public static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        int len = clean.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(clean.charAt(i), 16) << 4)
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
        public final TlsCertificate cert;
        public final PrivateKeyParameters priv;
        public final byte[] subjectDn;
        public CertBundle(TlsCertificate cert, PrivateKeyParameters priv, byte[] subjectDn) {
            this.cert = cert; this.priv = priv; this.subjectDn = subjectDn;
        }
    }

    /** Создаёт самоподписанный сертификат и возвращает его с ключом. */
    public static CertBundle createCertWithKey(ECParameters params) {
        return createCertWithKey(params, "20240501120000Z", "21060101120000Z", null);
    }

    public static CertBundle createCertWithKey(ECParameters params, String notBefore, String notAfter) {
        return createCertWithKey(params, notBefore, notAfter, null);
    }

    public static CertBundle createCertWithKey(ECParameters params, String notBefore,
                                         String notAfter, String[] sanDnsNames) {
        return createCertWithKey(params, notBefore, notAfter, sanDnsNames, null, null);
    }

    public static CertBundle createCertWithKey(ECParameters params, String notBefore,
                                         String notAfter, String[] sanDnsNames,
                                         byte[] kuFlags, String[] ekuOids) {
        return createCertWithKey(params, notBefore, notAfter, sanDnsNames, kuFlags, ekuOids, null);
    }

    public static CertBundle createCertWithKey(ECParameters params, String notBefore,
                                         String notAfter, String[] sanDnsNames,
                                         byte[] kuFlags, String[] ekuOids,
                                         String[] sanIps) {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();
        int hlen = params.hlen;

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        byte[] additionalExt = buildAdditionalExtensions(kuFlags, ekuOids);
        byte[] tbs = buildTbs(pub, params, notBefore, notAfter, sanDnsNames, sanIps,
                additionalExt, subjectDn, subjectDn);
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, priv);

        byte[] algId = buildAlgId(params);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new CertBundle(new TlsCertificate(certDer), priv, subjectDn);
    }

    private static byte[] buildAdditionalExtensions(byte[] kuFlags, String[] ekuOids) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            if (kuFlags != null) {
                out.write(buildKeyUsageExtension(kuFlags));
            }
            if (ekuOids != null) {
                out.write(buildEkuExtension(ekuOids));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] data = out.toByteArray();
        return data.length == 0 ? null : data;
    }

    private static byte[] buildKeyUsageExtension(byte[] kuFlags) {
        byte[] extValue = derOctetString(derBitString(kuFlags));
        return derSequence(derOid("2.5.29.15"), extValue);
    }

    private static byte[] buildEkuExtension(String[] oids) {
        ByteArrayOutputStream ekuSeq = new ByteArrayOutputStream();
        for (String oid : oids) {
            try {
                ekuSeq.write(derOid(oid));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return derSequence(derOid("2.5.29.37"),
                derOctetString(derSequence(ekuSeq.toByteArray())));
    }

    /** Строит AIA extension с OCSP URI (id-ad-ocsp). */
    public static byte[] buildAiaOcspExtensionBytes(String ocspUri) {
        byte[] uriBytes = ocspUri.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] accessDesc = derSequence(derOid(GostOids.OCSP_AD), derTlv(0x86, uriBytes));
        byte[] aiaSeq = derSequence(accessDesc);
        byte[] extValue = derOctetString(aiaSeq);
        return derSequence(derOid(GostOids.EXT_AIA), extValue);
    }

    /** Строит SubjectAltName расширение для DNS и IP. */
    private static byte[] buildSanExtensionBytes(String[] dnsNames, String[] ipAddresses) {
        ByteArrayOutputStream gn = new ByteArrayOutputStream();
        if (dnsNames != null) {
            for (String name : dnsNames) {
                byte[] nameBytes = name.getBytes(StandardCharsets.US_ASCII);
                byte[] dnsEntry = derTlv(TAG_DNS_NAME, nameBytes);
                gn.write(dnsEntry, 0, dnsEntry.length);
            }
        }
        if (ipAddresses != null) {
            for (String ip : ipAddresses) {
                byte[] ipBytes;
                try {
                    ipBytes = java.net.InetAddress.getByName(ip).getAddress();
                } catch (java.net.UnknownHostException e) {
                    throw new RuntimeException("Invalid IP: " + ip, e);
                }
                byte[] ipEntry = derTlv(TAG_IP_ADDRESS, ipBytes);
                gn.write(ipEntry, 0, ipEntry.length);
            }
        }
        byte[] gnSeq = derSequence(gn.toByteArray());
        byte[] oid = derOid("2.5.29.17");
        byte[] extValue = derOctetString(gnSeq);
        return derSequence(oid, extValue);
    }

    /** Строит TBSCertificate — минимальный дайджест-контейнер. */
    public static byte[] buildTbs(PublicKeyParameters pub, ECParameters params,
                                    String notBefore, String notAfter,
                                    String[] sanDnsNames, String[] sanIps,
                                    byte[] additionalExtensions,
                                    byte[] issuerDn, byte[] subjectDn) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(TAG_CTX_0);
            out.write(0x03);
            out.write(0x02);
            out.write(0x01);
            out.write(0x02);
            out.write(derTlv(0x02, new byte[]{0x01}));
            out.write(buildAlgId(params));
            out.write(issuerDn != null ? issuerDn : derSequence(new byte[0]));
            out.write(derSequence(derTime(notBefore), derTime(notAfter)));
            out.write(subjectDn != null ? subjectDn : derSequence(new byte[0]));
            byte[] spki = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(pub);
            out.write(spki, 0, spki.length);
            ByteArrayOutputStream extBytes = new ByteArrayOutputStream();
            if ((sanDnsNames != null && sanDnsNames.length > 0)
                    || (sanIps != null && sanIps.length > 0)) {
                extBytes.write(buildSanExtensionBytes(sanDnsNames, sanIps));
            }
            if (additionalExtensions != null) {
                extBytes.write(additionalExtensions);
            }
            if (extBytes.size() > 0) {
                byte[] extensionsSeq = derSequence(extBytes.toByteArray());
                out.write(derTlv(TAG_CTX_3, extensionsSeq));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return derSequence(out.toByteArray());
    }

    public static byte[] doHash(byte[] data, int hlen) {
        if (hlen == TlsConstants.STREEBOG_256_HASH_LEN) return Digest.digest256(data);
        if (hlen == TlsConstants.STREEBOG_512_HASH_LEN) return Digest.digest512(data);
        throw new IllegalArgumentException("Unsupported hash length: " + hlen);
    }

    // ========================================================================
    // Chain-building helpers
    // ========================================================================

    /** Создаёт корневой CA (самоподписанный, BC: cA=TRUE, KU: keyCertSign). */
    public static CertBundle createRootCA(ECParameters params) throws Exception {
        org.rssys.gost.api.KeyPair kp = org.rssys.gost.api.KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();
        int hlen = params.hlen;

        byte[] subjectDn = buildDN("Test Root CA " + (++certCounter));
        byte[] bcExt = buildBasicConstraintsExtension(true, null);
        byte[] kuExt = buildKeyUsageExtension(new byte[]{(byte) 0x04});
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        byte[] tbs = buildTbs(pub, params, "20240501120000Z", "21060101120000Z",
                null, null, extBuf.toByteArray(), subjectDn, subjectDn);

        byte[] hash = doHash(tbs, hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, priv);
        byte[] algId = buildAlgId(params);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new CertBundle(new TlsCertificate(certDer), priv, subjectDn);
    }

    /** Создаёт сертификат, подписанный issuerPriv.
     *  Issuer DN берётся из parentSubjectDn.
     *  Возвращает CertBundle с сгенерированным privKey подписанного сертификата. */
    public static CertBundle createCertSignedBy(ECParameters params,
                                          PrivateKeyParameters issuerPriv,
                                          PublicKeyParameters issuerPub,
                                          byte[] parentSubjectDn,
                                          String notBefore, String notAfter,
                                          String[] sanDnsNames,
                                          byte[] kuFlags, String[] ekuOids,
                                          boolean isCA, Integer pathLen) throws Exception {
        return createCertSignedBy(params, issuerPriv, issuerPub, parentSubjectDn,
                notBefore, notAfter, sanDnsNames, null,
                kuFlags, ekuOids, isCA, pathLen);
    }

    public static CertBundle createCertSignedBy(ECParameters params,
                                          PrivateKeyParameters issuerPriv,
                                          PublicKeyParameters issuerPub,
                                          byte[] parentSubjectDn,
                                          String notBefore, String notAfter,
                                          String[] sanDnsNames, String[] sanIps,
                                          byte[] kuFlags, String[] ekuOids,
                                          boolean isCA, Integer pathLen) throws Exception {
        return createCertSignedBy(params, issuerPriv, issuerPub, parentSubjectDn,
                notBefore, notAfter, sanDnsNames, sanIps,
                kuFlags, ekuOids, isCA, pathLen, null);
    }

    public static CertBundle createCertSignedBy(ECParameters params,
                                          PrivateKeyParameters issuerPriv,
                                          PublicKeyParameters issuerPub,
                                          byte[] parentSubjectDn,
                                          String notBefore, String notAfter,
                                          String[] sanDnsNames, String[] sanIps,
                                          byte[] kuFlags, String[] ekuOids,
                                          boolean isCA, Integer pathLen,
                                          byte[] extraExtensions) throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters leafPriv = kp.getPrivate();
        PublicKeyParameters leafPub = kp.getPublic();
        int hlen = params.hlen;

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        if (isCA || pathLen != null) {
            extBuf.write(buildBasicConstraintsExtension(isCA, pathLen));
        }
        if (kuFlags != null) {
            extBuf.write(buildKeyUsageExtension(kuFlags));
        }
        if (ekuOids != null) {
            extBuf.write(buildEkuExtension(ekuOids));
        }
        if (extraExtensions != null) {
            extBuf.write(extraExtensions);
        }
        byte[] additionalExt = extBuf.size() == 0 ? null : extBuf.toByteArray();
        byte[] tbs = buildTbs(leafPub, params, notBefore, notAfter, sanDnsNames, sanIps,
                additionalExt, parentSubjectDn, subjectDn);
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, issuerPriv);
        byte[] algId = buildAlgId(params);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new CertBundle(new TlsCertificate(certDer), leafPriv, subjectDn);
    }

    /** Создаёт сертификат с явно заданным issuer DN (для тестов DN mismatch). */
    public static CertBundle createCertWithForcedIssuer(ECParameters params,
                                                   PrivateKeyParameters signerPriv,
                                                   byte[] issuerDn,
                                                   String subjectCN,
                                                   String notBefore, String notAfter) throws Exception {
        org.rssys.gost.api.KeyPair kp = org.rssys.gost.api.KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters leafPriv = kp.getPrivate();
        PublicKeyParameters leafPub = kp.getPublic();
        int hlen = params.hlen;
        byte[] subjectDn = buildDN(subjectCN);
        byte[] tbs = buildTbs(leafPub, params, notBefore, notAfter, null, null,
                null, issuerDn, subjectDn);
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, signerPriv);
        byte[] algId = buildAlgId(params);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new CertBundle(new TlsCertificate(certDer), leafPriv, subjectDn);
    }

    private static byte[] buildBasicConstraintsExtension(boolean isCA, Integer pathLen) throws IOException {
        ByteArrayOutputStream bcSeq = new ByteArrayOutputStream();
        if (isCA) {
            bcSeq.write(new byte[]{0x01, 0x01, (byte) 0xFF});  // BOOLEAN TRUE
        }
        if (pathLen != null) {
            bcSeq.write(new byte[]{0x02, 0x01, pathLen.byteValue()});  // INTEGER
        }
        byte[] bcContent = derSequence(bcSeq.toByteArray());
        byte[] extValue = derOctetString(bcContent);
        return derSequence(derOid("2.5.29.19"), extValue);
    }

    public static byte[] buildAlgId(ECParameters params) {
        String signOid = (params.hlen == TlsConstants.STREEBOG_256_HASH_LEN)
                ? GostOids.SIG_WITH_DIGEST_256
                : GostOids.SIG_WITH_DIGEST_512;
        String curveOid = curveOidOf(params);
        String digestOid = (params.hlen == TlsConstants.STREEBOG_256_HASH_LEN)
                ? GostOids.DIGEST_256
                : GostOids.DIGEST_512;
        byte[] paramsSeq = derSequence(derOid(curveOid), derOid(digestOid));
        return derSequence(derOid(signOid), paramsSeq);
    }

    // ---- DER ----

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

    /**
     * Кодирует Time в DER: 13 символов (YYMMDDHHmmssZ) → UTCTime,
     * 15 символов (YYYYMMDDHHmmssZ) → GeneralizedTime.
     */
    public static byte[] derTime(String time) {
        int tag = time.length() == 13 ? DerCodec.TAG_UTC_TIME : DerCodec.TAG_GENERALIZED_TIME;
        return DerCodec.encodeTlv(tag, time.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] derTlv(int tag, byte[] content) {
        return DerCodec.encodeTlv(tag, content);
    }

    public static byte[] Set(byte[] content) {
        return DerCodec.encodeSet(content);
    }

    public static byte[] buildDN(String cn) {
        // RDN = SET { SEQUENCE { OID (CN=2.5.4.3), UTF8String cn } }
        byte[] attr = derSequence(derOid("2.5.4.3"), derTlv(DerCodec.TAG_UTF8_STRING,
                cn.getBytes(StandardCharsets.UTF_8)));
        return derSequence(derSet(attr));
    }

    private static byte[] derSet(byte[] item) {
        return DerCodec.encodeSet(item);
    }

    private static String curveOidOf(ECParameters params) {
        if (params == ECParameters.tc26a256()) return GostOids.CURVE_256A;
        if (params == ECParameters.cryptoProA()) return GostOids.CURVE_CP_A;
        if (params == ECParameters.cryptoProB()) return GostOids.CURVE_CP_B;
        if (params == ECParameters.tc26a512()) return GostOids.CURVE_512A;
        if (params == ECParameters.tc26b512()) return GostOids.CURVE_512B;
        if (params == ECParameters.tc26c512()) return GostOids.CURVE_512C;
        throw new IllegalArgumentException("Unknown EC parameters");
    }

    // ========================================================================
    // OCSP-стэпплинг (RFC 6960)
    // ========================================================================

    /**
     * Строит OCSPResponse DER для тестов с реальной подписью CA.
     * Использует CA-ключ для подписи tbsResponseData.
     */
    public static byte[] buildOcspResponse(byte[] serialNumber,
                                     PrivateKeyParameters caPriv,
                                     PublicKeyParameters caPub,
                                     byte[] caSubjectDer) throws Exception {
        return buildOcspResponse(serialNumber, caPriv, caPub, caSubjectDer, "20300101120000Z");
    }

    public static byte[] buildOcspResponse(byte[] serialNumber,
                                     PrivateKeyParameters caPriv,
                                     PublicKeyParameters caPub,
                                     byte[] caSubjectDer,
                                     String nextUpdateGeneralizedTime) throws Exception {
        byte[] tbs = buildOcspTbs(serialNumber, caPub, caSubjectDer, nextUpdateGeneralizedTime);
        int hlen = caPub.getParams().hlen;
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, caPriv);
        byte[] sigAlg = buildAlgId(caPub.getParams());
        byte[] basicOcsp = derSequence(tbs, sigAlg, derBitString(sig));
        byte[] basicOctet = derOctetString(basicOcsp);
        byte[] responseBytesContent = derSequence(derOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = derTlv(0xA0, responseBytesContent);
        byte[] status = new byte[]{0x0A, 0x01, 0x00};
        return derSequence(status, responseBytes);
    }

    /**
     * Строит OCSPResponse с делегированными responder-сертификатами (RFC 6960 §4.2.2.1).
     * <p>
     * OCSP подписывается ключом signerPriv (обычно ключ делегированного сертификата).
     * CertID строится по caPub/caSubjectDer для корректной привязки к проверяемому
     * сертификату. Параметры signer и ca разделены, чтобы симулировать реальную
     * delegated-схему, где подпись OCSP ставит delegated responder, а не CA.
     *
     * @param serialNumber            серийный номер проверяемого сертификата
     * @param signerPriv              ключ, подписывающий OCSP-ответ
     * @param signerPub               публичный ключ подписанта (для AlgorithmIdentifier)
     * @param caPub                   публичный ключ CA (для CertID issuerKeyHash)
     * @param caSubjectDer            DER subject DN CA (для CertID issuerNameHash)
     * @param nextUpdateGeneralizedTime nextUpdate или null
     * @param delegatedCertsDer       DER-encoded сертификаты для поля certs
     * @return DER-encoded OCSPResponse
     */
    public static byte[] buildOcspResponseWithDelegatedCerts(byte[] serialNumber,
                                                      PrivateKeyParameters signerPriv,
                                                      PublicKeyParameters signerPub,
                                                      PublicKeyParameters caPub,
                                                      byte[] caSubjectDer,
                                                      String nextUpdateGeneralizedTime,
                                                      byte[][] delegatedCertsDer) throws Exception {
        byte[] tbs = buildOcspTbs(serialNumber, caPub, caSubjectDer, nextUpdateGeneralizedTime);
        int hlen = signerPub.getParams().hlen;
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, signerPriv);
        byte[] sigAlg = buildAlgId(signerPub.getParams());
        byte[] certsSeq = derSequence(delegatedCertsDer);
        byte[] certsTagged = derTlv(0xA0, certsSeq);
        byte[] basicOcsp = derSequence(tbs, sigAlg, derBitString(sig), certsTagged);
        byte[] basicOctet = derOctetString(basicOcsp);
        byte[] responseBytesContent = derSequence(derOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = derTlv(0xA0, responseBytesContent);
        byte[] status = new byte[]{0x0A, 0x01, 0x00};
        return derSequence(status, responseBytes);
    }

    /** Строит tbsResponseData для OCSP-ответа (общий для всех перегрузок). */
    private static byte[] buildOcspTbs(byte[] serialNumber,
                                PublicKeyParameters caPub,
                                byte[] caSubjectDer,
                                String nextUpdateGeneralizedTime) throws Exception {
        byte[] issuerNameHash = doHash(caSubjectDer, 32);
        byte[] caSpkiDer = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(caPub);
        int[] spkiSeq = TlsDerParser.parseSequence(caSpkiDer, 0);
        int spkiPos = spkiSeq[0];
        int[] algTlv = TlsDerParser.readTlv(caSpkiDer, spkiPos);
        spkiPos = algTlv[1];
        int[] bsTlv = TlsDerParser.readTlv(caSpkiDer, spkiPos);
        byte[] bitStringValue = java.util.Arrays.copyOfRange(caSpkiDer, bsTlv[0], bsTlv[1]);
        byte[] issuerKeyHash = doHash(bitStringValue, 32);
        byte[] hashAlg = derSequence(derOid(GostOids.DIGEST_256));
        byte[] certId = derSequence(hashAlg, derOctetString(issuerNameHash),
                derOctetString(issuerKeyHash), derTlv(0x02, serialNumber));
        byte[] goodStatus = derTlv(0xA0, derTlv(0x05, new byte[0]));
        byte[] thisUpdate = derTime("20250501120001Z");
        ByteArrayOutputStream srOut = new ByteArrayOutputStream();
        srOut.write(certId);
        srOut.write(goodStatus);
        srOut.write(thisUpdate);
        if (nextUpdateGeneralizedTime != null) {
            byte[] nu = derTlv(0xA0, derTlv(0x18,
                    nextUpdateGeneralizedTime.getBytes(StandardCharsets.US_ASCII)));
            srOut.write(nu);
        }
        byte[] singleResponse = derSequence(srOut.toByteArray());
        byte[] version = derTlv(0xA0, new byte[]{0x02, 0x01, 0x00});
        byte[] responderId = derTlv(0xA0, new byte[]{0x30, 0x00});
        byte[] producedAt = derTlv(0x18, "20250501120000Z".getBytes(StandardCharsets.US_ASCII));
        byte[] responses = derSequence(singleResponse);
        return derSequence(version, responderId, producedAt, responses);
    }

    /**
     * Строит CDP extension (CRLDistributionPoints, 2.5.29.31) для тестов.
     *
     * @param crlUris URI точек распространения CRL (один или несколько mirror'ов)
     * @return DER-encoded Extension (SEQUENCE { OID, OCTET STRING })
     */
    public static byte[] buildCdpExtension(String... crlUris) throws Exception {
        ByteArrayOutputStream dps = new ByteArrayOutputStream();
        for (String crlUri : crlUris) {
            byte[] uriBytes = crlUri.getBytes(StandardCharsets.US_ASCII);
            byte[] gnUri = derTlv(0x86, uriBytes);                              // [6] URI
            byte[] generalNames = derSequence(gnUri);                           // GeneralNames
            byte[] fullName = derTlv(0xA0, generalNames);                       // [0] fullName
            byte[] distPointContent = derTlv(0xA0, fullName);                   // [0] distributionPoint
            byte[] distPointSeq = derSequence(distPointContent);                // DistributionPoint SEQUENCE
            dps.write(distPointSeq);
        }
        byte[] distributionPoints = derSequence(dps.toByteArray());             // CRLDistributionPoints SEQUENCE OF
        byte[] extValue = derOctetString(distributionPoints);
        return derSequence(derOid("2.5.29.31"), extValue);
    }

    /**
     * Строит dummy-OCSPResponse (без подписи) для presence-тестов.
     */
    public static byte[] buildDummyOcspResponse() throws Exception {
        byte[] tbs = new byte[]{0x30, 0x03, 0x02, 0x01, 0x00}; // SEQUENCE { INTEGER(0) }
        byte[] sigAlg = derSequence(derOid(GostOids.SIGN_ALG_256));
        byte[] sig = derBitString(new byte[64]);
        byte[] basicOcsp = derSequence(tbs, sigAlg, sig);
        byte[] basicOctet = derOctetString(basicOcsp);
        byte[] responseBytesContent = derSequence(derOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = derTlv(0xA0, responseBytesContent);
        byte[] status = new byte[]{0x0A, 0x01, 0x00}; // ENUMERATED(0) — без [0]
        return derSequence(status, responseBytes);
    }

    // ========================================================================
    // CRL построитель (для тестов TlsCrlVerifier)
    // ========================================================================

    /**
     * Строит подписанный CRL (CertificateList, RFC 5280 §5.1) для тестов.
     * <p>
     * Предполагается direct CRL (issuer CRL == issuer сертификата).
     * Версия: v2 (содержит extensions для issuingDistributionPoint если нужно).
     *
     * @param serialNumbers          серийные номера отозванных сертификатов
     *                               (raw DER INTEGER value), может быть null/empty
     * @param caPriv                 закрытый ключ CA для подписи CRL
     * @param caPub                  открытый ключ CA (для AlgorithmIdentifier)
     * @param issuerDnDer            DER issuer Name (из сертификата CA)
     * @param nextUpdateGeneralizedTime nextUpdate (null = без nextUpdate)
     * @param withIdpExtension       true = добавить issuingDistributionPoint extension
     * @return DER-encoded CertificateList
     */
    public static byte[] buildCrl(byte[][] serialNumbers,
                                  PrivateKeyParameters caPriv,
                                  PublicKeyParameters caPub,
                                  byte[] issuerDnDer,
                                  String nextUpdateGeneralizedTime,
                                  boolean withIdpExtension) throws Exception {
        return buildCrlImpl(serialNumbers, caPriv, caPub, issuerDnDer,
                nextUpdateGeneralizedTime, withIdpExtension, false);
    }

    /**
     * Создаёт CRL с version в формате [0] EXPLICIT INTEGER (нестандартный —
     * ошибочное кодирование как в TBSCertificate, RFC 5280 §4.1.2.1).
     * Используется только в тестах для проверки fallback-ветки
     * {@link org.rssys.gost.tls13.cert.TlsCrlVerifier}.
     */
    public static byte[] buildCrlLegacyVersion(byte[][] serialNumbers,
                                                PrivateKeyParameters caPriv,
                                                PublicKeyParameters caPub,
                                                byte[] issuerDnDer,
                                                String nextUpdateGeneralizedTime,
                                                boolean withIdpExtension) throws Exception {
        return buildCrlImpl(serialNumbers, caPriv, caPub, issuerDnDer,
                nextUpdateGeneralizedTime, withIdpExtension, true);
    }

    private static byte[] buildCrlImpl(byte[][] serialNumbers,
                                       PrivateKeyParameters caPriv,
                                       PublicKeyParameters caPub,
                                       byte[] issuerDnDer,
                                       String nextUpdateGeneralizedTime,
                                       boolean withIdpExtension,
                                       boolean legacyVersion) throws Exception {
        ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
        if (legacyVersion) {
            // version [0] EXPLICIT INTEGER (v2 = 1) — нестандартный формат
            tbsOut.write(derTlv(0xA0, new byte[]{0x02, 0x01, 0x01}));
        } else {
            // version INTEGER (v2 = 1) — RFC 5280 §5.1.2.1
            tbsOut.write(derTlv(0x02, new byte[]{0x01}));
        }
        // signature AlgorithmIdentifier
        tbsOut.write(buildAlgId(caPub.getParams()));
        // issuer Name
        tbsOut.write(derSequence(issuerDnDer));
        // thisUpdate
        tbsOut.write(derTime("20250501120000Z"));
        // nextUpdate (optional) — используем GeneralizedTime для дат > 2049
        if (nextUpdateGeneralizedTime != null) {
            tbsOut.write(derTime(nextUpdateGeneralizedTime));
        }
        // revokedCertificates (optional)
        if (serialNumbers != null && serialNumbers.length > 0) {
            ByteArrayOutputStream rvOut = new ByteArrayOutputStream();
            for (byte[] serial : serialNumbers) {
                byte[] revokedEntry = derSequence(
                        derTlv(0x02, serial),               // serialNumber INTEGER
                        derTime("20250601120000Z"));        // revocationDate
                rvOut.write(revokedEntry);
            }
            tbsOut.write(derSequence(rvOut.toByteArray()));
        }
        // crlExtensions [0] (optional)
        if (withIdpExtension) {
            byte[] idpOid = derOid("2.5.29.28");
            byte[] idpExt = derSequence(idpOid, derTlv(0x04, new byte[]{0x30, 0x00}));
            byte[] extSeq = derSequence(idpExt);
            tbsOut.write(derTlv(0xA0, extSeq));
        }

        byte[] tbsCertList = derSequence(tbsOut.toByteArray());
        int hlen = caPub.getParams().hlen;
        byte[] hash = doHash(tbsCertList, hlen);
        byte[] sig = Signature.signHash(hash, caPriv);
        byte[] sigAlg = buildAlgId(caPub.getParams());
        return derSequence(tbsCertList, sigAlg, derBitString(sig));
    }
}
