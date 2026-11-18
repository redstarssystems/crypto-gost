package org.rssys.gost.crossval.cadesc;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CmsAlgorithmIdentifier;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Генерация тестовых ключей, сертификатов, CRL, OCSP и CAdES-C для кросс-валидации.
 */
final class TestData {

    static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    static final ECParameters PARAMS_512 = ECParameters.tc26a512();

    static final String ROOT_DN = "CN=Root CA,O=Test,C=RU";
    static final String INT_DN = "CN=Intermediate CA,O=Test,C=RU";
    static final String LEAF_DN = "CN=Leaf,O=Test,C=RU";

    static final String NOT_BEFORE = "20250101000000Z";
    static final String NOT_AFTER_CA = "21250101000000Z";
    static final String NOT_AFTER_LEAF = "20300101000000Z";

    private static final KeyPair TSA_KP;
    private static final GostCertificate TSA_CERT;

    static {
        try {
            TSA_KP = KeyGenerator.generateKeyPair(PARAMS_256);
            TSA_CERT = CmsTestUtils.createTsaCert(TSA_KP.getPrivate(), TSA_KP.getPublic());
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private TestData() {}

    static GostCertificate tsaCert() {
        return TSA_CERT;
    }

    // ========================================================================
    // Трёхуровневая цепочка: [leaf, intermediateCA, rootCA]
    // ========================================================================

    /**
     * Генерирует трёхуровневую цепочку [leaf, intermediateCA, rootCA].
     * rootCA — самоподписанный (trusted root).
     * intermediateCA — подписан rootCA.
     * leaf — подписан intermediateCA.
     * Для signer'а и intermediateCA генерируются CRL.
     */
    static ThreeLevelChain generateThreeLevelChain(ECParameters params) throws Exception {
        byte[] rootDn = GostDnParser.encodeDn(ROOT_DN);
        byte[] intDn = GostDnParser.encodeDn(INT_DN);
        byte[] leafDn = GostDnParser.encodeDn(LEAF_DN);

        KeyPair rootKp = KeyGenerator.generateKeyPair(params);
        GostCertificate rootCert =
                GostCertificateBuilder.create(params, rootDn)
                        .publicKey(rootKp.getPublic())
                        .notBefore(NOT_BEFORE)
                        .notAfter(NOT_AFTER_CA)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .basicConstraints(true, null)
                        .serial(BigInteger.valueOf(1))
                        .sign(rootKp.getPrivate());

        KeyPair intKp = KeyGenerator.generateKeyPair(params);
        GostCertificate intCert =
                GostCertificateBuilder.create(params, intDn)
                        .publicKey(intKp.getPublic())
                        .issuerDn(rootDn)
                        .notBefore(NOT_BEFORE)
                        .notAfter(NOT_AFTER_CA)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .basicConstraints(true, null)
                        .serial(BigInteger.valueOf(2))
                        .sign(rootKp.getPrivate());

        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        GostCertificate leafCert =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .issuerDn(intDn)
                        .notBefore(NOT_BEFORE)
                        .notAfter(NOT_AFTER_LEAF)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .serial(BigInteger.valueOf(3))
                        .sign(intKp.getPrivate());

        GostCrl intermediateCrl =
                buildCrl(intCert.getSubjectDnBytes(), NOT_BEFORE, intKp.getPrivate(), 1);
        GostCrl leafCrl = buildCrl(leafCert.getSubjectDnBytes(), NOT_BEFORE, intKp.getPrivate(), 2);

        return new ThreeLevelChain(
                rootCert,
                rootKp.getPrivate(),
                intCert,
                intKp.getPrivate(),
                intermediateCrl,
                leafCert,
                leafKp.getPrivate(),
                leafKp.getPublic(),
                leafCrl);
    }

    /**
     * Генерирует самоподписанную CA + leaf-сертификат + CRL для CA.
     * Для тестов, где certRefs пуст (chain.size()=2).
     */
    static CertChainData generateCaAndLeaf(ECParameters params) throws Exception {
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA,O=Test Org,C=RU");
        byte[] leafDn = GostDnParser.encodeDn("CN=Test Leaf,O=Test Org,C=RU");

        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        GostCertificate caCert =
                GostCertificateBuilder.create(params, caDn)
                        .publicKey(caKp.getPublic())
                        .notBefore(NOT_BEFORE)
                        .notAfter(NOT_AFTER_CA)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .basicConstraints(true, null)
                        .serial(BigInteger.valueOf(1))
                        .sign(caKp.getPrivate());

        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        GostCertificate leafCert =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .issuerDn(caDn)
                        .notBefore(NOT_BEFORE)
                        .notAfter(NOT_AFTER_LEAF)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .serial(BigInteger.valueOf(2))
                        .sign(caKp.getPrivate());

        GostCrl caCrl = buildCrl(caDn, NOT_BEFORE, caKp.getPrivate(), 1);

        return new CertChainData(caCert, leafKp.getPrivate(), leafKp.getPublic(), leafCert, caCrl);
    }

    // ========================================================================
    // CAdES-C построение
    // ========================================================================

    /**
     * Строит CAdES-C: CAdES-BES + embedCompleteRefs.
     * chain = [leaf, ca], crlsForChain = [caCrl, null], ocspForChain = [null, null].
     */
    static byte[] buildCAdESC(CertChainData cd, byte[] data) throws PkixException, IOException {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(cd.leafKey(), cd.leafCert())
                        .withCAdES()
                        .build();

        return CAdESExtender.embedCompleteRefs(
                addTimestamp(cadesBes),
                Arrays.asList(cd.leafCert(), cd.caCert()),
                Arrays.asList(cd.caCrl(), null),
                Arrays.asList((GostOcspResponse) null, null));
    }

    /**
     * Строит CAdES-C из трёхуровневой цепочки с опциональными OCSP-ответами.
     */
    static byte[] buildCAdESCFromThreeLevel(
            ThreeLevelChain tc, List<GostOcspResponse> ocspForChain, byte[] data)
            throws PkixException, IOException {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(tc.leafKey(), tc.leafCert())
                        .withCAdES()
                        .build();

        List<GostCrl> crlsForChain = Arrays.asList(tc.leafCrl(), tc.intermediateCrl(), null);
        return CAdESExtender.embedCompleteRefs(
                addTimestamp(cadesBes),
                Arrays.asList(tc.leafCert(), tc.intermediateCert(), tc.rootCert()),
                crlsForChain,
                ocspForChain);
    }

    /**
     * Строит CAdES-C с самоподписанным сертификатом.
     * chain = [signer], crlsForChain = [signerCrl], ocspForChain = [null].
     */
    static byte[] buildCAdESCSelfSigned(
            PrivateKeyParameters signerKey,
            GostCertificate signerCert,
            GostCrl signerCrl,
            byte[] data)
            throws PkixException, IOException {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKey, signerCert)
                        .withCAdES()
                        .build();

        return CAdESExtender.embedCompleteRefs(
                addTimestamp(cadesBes),
                Arrays.asList(signerCert),
                Arrays.asList(signerCrl),
                Arrays.asList((GostOcspResponse) null));
    }

    // ========================================================================
    // OCSP
    // ========================================================================

    static GostOcspResponse buildOcspResponse(
            PrivateKeyParameters responderKey, GostCertificate targetCert) throws PkixException {
        byte[] ocspDer =
                GostOcspResponseBuilder.create(targetCert.getSerialNumber())
                        .issuerDn(targetCert.getIssuerDnBytes())
                        .sign(responderKey);
        return new GostOcspResponse(ocspDer);
    }

    // ========================================================================
    // CRL
    // ========================================================================

    private static GostCrl buildCrl(
            byte[] issuerDn, String thisUpdate, PrivateKeyParameters issuerKey, int crlNumber)
            throws PkixException {
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdate(thisUpdate)
                        .nextUpdateDays(30)
                        .withCrlNumber(crlNumber)
                        .addRevoked(
                                BigInteger.valueOf(99), GostSignatureHelper.nowGeneralizedTime())
                        .sign(issuerKey);
        return new GostCrl(crlDer);
    }

    // ========================================================================
    // Подписи и signedAttrs
    // ========================================================================

    /**
     * Извлекает raw signature из SignedData (contents octets, без TLV).
     */
    static byte[] extractSignature(byte[] signedDataDer) throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);
        byte[] sigOctet = null;
        for (int i = siParts.length - 1; i >= 0; i--) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                sigOctet = siParts[i];
                break;
            }
        }
        if (sigOctet == null) {
            throw new PkixException("Signature OCTET STRING not found");
        }
        return DerCodec.parseOctetString(sigOctet, 0);
    }

    /**
     * Извлекает signedAttrs, перекодированные как SET (для хэширования).
     */
    static byte[] extractSignedAttrsAsSet(byte[] signedDataDer) throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);

        int signedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == 0xA0) {
                signedIdx = i;
                break;
            }
        }
        if (signedIdx < 0) {
            throw new PkixException("signedAttrs [0] not found");
        }
        byte[] signedField = siParts[signedIdx];
        int[] lenInfo = DerCodec.decodeLength(signedField, 1);
        int contentOff = 1 + lenInfo[1];
        byte[] signedAttrsContent = Arrays.copyOfRange(signedField, contentOff, signedField.length);

        java.util.List<byte[]> attrElems = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < signedAttrsContent.length) {
            int[] attrLen = DerCodec.decodeLength(signedAttrsContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            attrElems.add(Arrays.copyOfRange(signedAttrsContent, pos, pos + attrTotal));
            pos += attrTotal;
        }
        return DerCodec.encodeSetOf(attrElems.toArray(new byte[0][]));
    }

    // ========================================================================
    // Локальный TSA для CAdES-T
    // ========================================================================

    static byte[] addTimestamp(byte[] cadesBesDer) throws PkixException, IOException {
        byte[] sigHash = extractAndHashSignature(cadesBesDer);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger nonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, nonce);
                        byte[] pkiStatus =
                                DerCodec.encodeSequence(
                                        DerCodec.encodeInteger(
                                                BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
                        return DerCodec.encodeSequence(pkiStatus, token);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        return CAdESExtender.addTimestamp(cadesBesDer, "http://local.tsa", mockTransport, TSA_CERT);
    }

    private static byte[] extractAndHashSignature(byte[] signedDataDer) throws PkixException {
        byte[] sig = extractSignature(signedDataDer);
        return sig.length == 64 ? Digest.digest256(sig) : Digest.digest512(sig);
    }

    private static byte[] buildTimeStampToken(byte[] sigHash, BigInteger nonce)
            throws PkixException {
        byte[] tstInfo = buildTstInfo(sigHash, nonce);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(TSA_KP.getPrivate(), TSA_CERT)
                .build();
    }

    private static byte[] buildTstInfo(byte[] hash, BigInteger nonce) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1");
        byte[] hashAlg =
                CmsAlgorithmIdentifier.encode(
                        hash.length == 32 ? GostOids.DIGEST_256 : GostOids.DIGEST_512);
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(nonce);
        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
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

    // ========================================================================
    // Файловые утилиты
    // ========================================================================

    static Path writeDer(Path dir, String name, byte[] der) throws IOException {
        Path path = dir.resolve(name);
        Files.write(path, der);
        return path;
    }

    // ========================================================================
    // Типы данных
    // ========================================================================

    record ThreeLevelChain(
            GostCertificate rootCert,
            PrivateKeyParameters rootKey,
            GostCertificate intermediateCert,
            PrivateKeyParameters intermediateKey,
            GostCrl intermediateCrl,
            GostCertificate leafCert,
            PrivateKeyParameters leafKey,
            PublicKeyParameters leafPub,
            GostCrl leafCrl) {}

    record CertChainData(
            GostCertificate caCert,
            PrivateKeyParameters leafKey,
            PublicKeyParameters leafPub,
            GostCertificate leafCert,
            GostCrl caCrl) {}
}
