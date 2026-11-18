package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.tsp.TspRequest;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESXLongFuzz: fuzz-тесты verifyXLong")
class CAdESXLongFuzzTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;
    private static GostCrl signerCrl;
    private static GostOcspResponse signerOcsp;

    @BeforeAll
    static void setUp() throws Exception {
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signerKp.getPrivate(),
                        signerKp.getPublic(),
                        BigInteger.valueOf(1),
                        "FuzzSigner");

        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert = CmsTestUtils.createTsaCert(tsaKp.getPrivate(), tsaKp.getPublic());

        byte[] crlDer =
                GostCrlBuilder.create(signerCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(signerKp.getPrivate());
        signerCrl = new GostCrl(crlDer);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(signerCert.getSerialNumber())
                        .issuerDn(signerCert.getSubjectDnBytes())
                        .sign(signerKp.getPrivate());
        signerOcsp = new GostOcspResponse(ocspDer);
    }

    @Test
    @DisplayName("Валидный CAdES-X Long DER проходит верификацию (регрессия)")
    void validXLongPassesVerification() throws Exception {
        byte[] cadesXLong = buildValidXLong();
        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Валидный X-Long DER должен проходить верификацию");
    }

    @Test
    @DisplayName("Мутация certificate-values (переворот случайного байта) вызывает PkixException")
    void mutateCertificateValuesThrowsPkixException() throws Exception {
        byte[] cadesXLong = buildValidXLong();
        Mutation mutation = mutateAttributeValue(cadesXLong, GostOids.CERTIFICATE_VALUES);

        assertThrows(
                Exception.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                mutation.data(), TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Испорченный certificate-values должен вызывать исключение"
                        + " (byte offset "
                        + mutation.offset()
                        + ")");
    }

    @Test
    @DisplayName("Мутация revocation-values (переворот случайного байта) вызывает PkixException")
    void mutateRevocationValuesThrowsPkixException() throws Exception {
        byte[] cadesXLong = buildValidXLong();
        Mutation mutation = mutateAttributeValue(cadesXLong, GostOids.REVOCATION_VALUES);

        assertThrows(
                Exception.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                mutation.data(), TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Испорченный revocation-values должен вызывать исключение"
                        + " (byte offset "
                        + mutation.offset()
                        + ")");
    }

    @Test
    @DisplayName("Усечённый DER вызывает исключение")
    void truncatedDerThrowsException() throws Exception {
        byte[] cadesXLong = buildValidXLong();
        byte[] truncated = Arrays.copyOf(cadesXLong, cadesXLong.length / 2);

        assertThrows(
                Exception.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                truncated, TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Усечённый DER должен вызывать исключение");
    }

    @Test
    @DisplayName("certificate-values с цепочкой из нескольких сертификатов проходит верификацию")
    void severalCertsWithinLimitPasses() throws Exception {
        KeyPair issuerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate issuerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        issuerKp.getPrivate(),
                        issuerKp.getPublic(),
                        BigInteger.valueOf(300),
                        "ManyCertsCA");

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDnDer = CmsTestUtils.buildDn("ManyCertsLeaf");
        GostCertificate leafCert =
                GostCertificateBuilder.create(PARAMS, leafDnDer)
                        .issuerDn(issuerCert.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sign(issuerKp.getPrivate());

        byte[] crlDer =
                GostCrlBuilder.create(issuerCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(issuerKp.getPrivate());
        GostCrl crl = new GostCrl(crlDer);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(leafCert.getSerialNumber())
                        .issuerDn(issuerCert.getSubjectDnBytes())
                        .sign(issuerKp.getPrivate());
        GostOcspResponse ocsp = new GostOcspResponse(ocspDer);

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("many chain test".getBytes())
                        .addSigner(leafKp.getPrivate(), leafCert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = List.of(leafCert, issuerCert);
        List<GostCrl> crls = Arrays.asList(crl, null);
        List<GostOcspResponse> ocspList = Arrays.asList(ocsp, null);

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(
                        cadesBes,
                        chain,
                        crls,
                        ocspList,
                        "http://local.tsa",
                        dynamicTsTransport(),
                        tsaCert);

        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLong, TrustAnchors.ofCertificates(issuerCert, tsaCert)),
                "Цепочка из двух сертификатов должна проходить верификацию");
    }

    @Test
    @DisplayName("certificate-values с превышением лимита размера вызывает исключение")
    void oversizedCertificateValuesThrowsException() throws Exception {
        byte[] bigContent = new byte[CmsConstants.MAX_CERT_VALUES_SIZE + 1024];
        CryptoRandom.INSTANCE.nextBytes(bigContent);
        byte[] certValuesAttr = CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, bigContent);

        byte[] cadesXLong = buildXLongWithCustomCertValuesAttr(certValuesAttr);

        assertThrows(
                Exception.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Превышение лимита размера certificate-values должно вызывать исключение");
    }

    // ========================================================================
    // Построители DER
    // ========================================================================

    private byte[] buildValidXLong() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("fuzz test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        return CAdESExtender.embedXLongType1(
                cadesBes, chain, crls, ocspList, "http://local.tsa", dynamicTsTransport(), tsaCert);
    }

    private byte[] buildXLongWithCustomCertValues(List<GostCertificate> certValues)
            throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("many certs".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesT =
                CAdESExtender.addTimestamp(cadesBes, "http://local.tsa", mockTransport, tsaCert);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        // Включаем дополнительные сертификаты в cert-values, но C-refs остаются от chain
        List<GostCertificate> allCertValues = new ArrayList<>();
        allCertValues.add(signerCert);
        allCertValues.addAll(certValues);

        byte[] certValuesDer = CAdESXLongData.encodeCertificateValues(allCertValues);
        byte[] certValuesAttr = CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, certValuesDer);

        byte[] revocValuesDer = CAdESXLongData.encodeRevocationValues(crls, ocspList);
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        byte[] signedDataBody = CmsContentInfo.decode(cadesC).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDer(signerInfos[0], certValuesAttr);
        modifiedSi = injectUnsignedAttrDer(modifiedSi, revocValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newCerts = mergeChainIntoField(sd.certs(), allCertValues);
        byte[] newSignedData = sd.rebuild(newCerts, newSignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private byte[] buildXLongWithCustomCertValuesAttr(byte[] customCertValuesAttr)
            throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("oversized".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesT =
                CAdESExtender.addTimestamp(cadesBes, "http://local.tsa", mockTransport, tsaCert);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);
        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] revocValuesDer = CAdESXLongData.encodeRevocationValues(crls, ocspList);
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        byte[] signedDataBody = CmsContentInfo.decode(cadesC).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDer(signerInfos[0], customCertValuesAttr);
        modifiedSi = injectUnsignedAttrDer(modifiedSi, revocValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private record Mutation(byte[] data, int offset) {}

    private Mutation mutateAttributeValue(byte[] xLongDer, String attrOid) throws Exception {
        byte[] oidDer = DerCodec.encodeOid(attrOid);
        byte[] mutated = xLongDer.clone();

        int oidPos = indexOf(mutated, oidDer, 0);
        if (oidPos < 0) {
            throw new IllegalArgumentException("OID not found in DER: " + attrOid);
        }

        int searchPos = oidPos + oidDer.length;
        int octetStringPos = -1;
        while (searchPos < mutated.length - 2) {
            if ((mutated[searchPos] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                octetStringPos = searchPos;
                break;
            }
            searchPos++;
        }
        if (octetStringPos < 0) {
            throw new IllegalArgumentException("OCTET STRING not found after OID: " + attrOid);
        }

        int[] lenInfo = DerCodec.decodeLength(mutated, octetStringPos + 1);
        int contentOff = octetStringPos + 1 + lenInfo[1];
        int contentLen = lenInfo[0];

        int offset = contentOff + CryptoRandom.INSTANCE.nextInt(contentLen);
        mutated[offset] ^= 0xFF;

        return new Mutation(mutated, offset);
    }

    private static int indexOf(byte[] data, byte[] pattern, int fromIndex) {
        outer:
        for (int i = fromIndex; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static byte[] injectUnsignedAttrDer(byte[] signerInfoDer, byte[] attrDer)
            throws Exception {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length == 0) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "SignerInfo is empty");
        }

        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }

        byte[] newUnsignedAttrs;
        if (unsignedIdx >= 0) {
            byte[] existingField = siParts[unsignedIdx];
            int[] lenInfo = DerCodec.decodeLength(existingField, 1);
            int contentOff = 1 + lenInfo[1];
            byte[] existingContent =
                    Arrays.copyOfRange(existingField, contentOff, existingField.length);

            List<byte[]> attrs = new ArrayList<>();
            int pos = 0;
            while (pos < existingContent.length) {
                int[] attrLen = DerCodec.decodeLength(existingContent, pos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                attrs.add(Arrays.copyOfRange(existingContent, pos, pos + attrTotal));
                pos += attrTotal;
            }
            attrs.add(attrDer);
            byte[][] sorted = attrs.toArray(new byte[0][]);
            DerCodec.sortDer(sorted);
            byte[] expandedContent = DerCodec.concat(sorted);
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, expandedContent);
            siParts[unsignedIdx] = newUnsignedAttrs;
        } else {
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, attrDer);
            byte[][] newParts = Arrays.copyOf(siParts, siParts.length + 1);
            newParts[newParts.length - 1] = newUnsignedAttrs;
            siParts = newParts;
        }

        return DerCodec.encodeSequence(siParts);
    }

    private static byte[] mergeChainIntoField(
            byte[] existingCertsField, List<GostCertificate> chain) throws Exception {
        List<byte[]> derList = new ArrayList<>();
        if (existingCertsField != null) {
            int[] lenInfo = DerCodec.decodeLength(existingCertsField, 1);
            int contentOff = 1 + lenInfo[1];
            int pos = contentOff;
            int end = existingCertsField.length;
            while (pos < end) {
                int[] certLen = DerCodec.decodeLength(existingCertsField, pos + 1);
                int certTotal = 1 + certLen[1] + certLen[0];
                derList.add(Arrays.copyOfRange(existingCertsField, pos, pos + certTotal));
                pos += certTotal;
            }
        }
        for (GostCertificate cert : chain) {
            boolean dup = false;
            byte[] certDer = cert.getEncoded();
            for (byte[] existing : derList) {
                if (Arrays.equals(existing, certDer)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                derList.add(certDer);
            }
        }
        if (derList.isEmpty()) {
            return null;
        }
        byte[][] sorted = derList.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(sorted));
    }

    // ========================================================================
    // TSP helpers
    // ========================================================================

    private byte[] extractAndHashSignature(byte[] signedDataDer) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);
        byte[] sigOctet = null;
        for (int i = siParts.length - 1; i >= 0; i--) {
            if ((siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                sigOctet = siParts[i];
                break;
            }
        }
        byte[] sig = DerCodec.parseOctetString(sigOctet, 0);
        int hlen = (sig.length == 64) ? 32 : 64;
        return hlen == 32
                ? org.rssys.gost.api.Digest.digest256(sig)
                : org.rssys.gost.api.Digest.digest512(sig);
    }

    private byte[] buildTimeStampToken(byte[] sigHash, BigInteger nonce) throws Exception {
        byte[] tstInfo = buildTstInfo(sigHash, nonce);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaKp.getPrivate(), tsaCert)
                .build();
    }

    private byte[] buildTspResponse(byte[] sigHash, byte[] timeStampToken, BigInteger nonce) {
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        return DerCodec.encodeSequence(pkiStatus, timeStampToken);
    }

    private byte[] buildTstInfo(byte[] hash, BigInteger nonce) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1");
        byte[] hashAlg = CmsAlgorithmIdentifier.encode(GostOids.DIGEST_256);
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(nonce);
        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
    }

    private TspTransport dynamicTsTransport() {
        return (req, url) -> {
            try {
                TspRequest request = TspRequest.fromDer(req);
                byte[] hash = request.messageImprintHash();
                BigInteger nonce = parseNonceFromRequest(req);
                byte[] token = buildTimeStampToken(hash, nonce);
                return buildTspResponse(hash, token, nonce);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private static BigInteger parseNonceFromRequest(byte[] tspReqDer) {
        try {
            byte[][] parts = DerCodec.parseSequenceContents(tspReqDer, 0);
            if (parts.length < 3) return BigInteger.ZERO;
            for (int i = 2; i < parts.length; i++) {
                if (parts[i].length > 0 && (parts[i][0] & 0xFF) == DerCodec.TAG_INTEGER) {
                    return DerCodec.parseInteger(parts[i], 0);
                }
            }
            return BigInteger.ZERO;
        } catch (Exception e) {
            return BigInteger.ZERO;
        }
    }
}
