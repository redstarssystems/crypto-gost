package org.rssys.gost.crossval.cadest;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CmsAlgorithmIdentifier;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Генерация тестовых ключей, сертификатов и mock-TSP для кросс-валидации CAdES.
 */
final class TestData {

    static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    static final ECParameters PARAMS_512 = ECParameters.tc26a512();

    static final String DN_STR = "CN=Test CA,O=Test Org,C=RU";
    static final String LEAF_DN_STR = "CN=Test Leaf,O=Test Org,C=RU";

    static final String NOT_BEFORE = "20250101000000Z";
    static final String NOT_AFTER_CA = "21250101000000Z";
    static final String NOT_AFTER_LEAF = "20300101000000Z";
    static final String NOT_AFTER_EXPIRED = "20200101000000Z";

    /** Тестовый OID политики TSA — заглушка для TSTInfo. */
    static final String DUMMY_TSA_POLICY_OID = "1.3.6.1.4.1.4146.1.2.1";

    private TestData() {}

    // ========================================================================
    // Ключи и сертификаты
    // ========================================================================

    static CertPair generateCaAndLeaf(ECParameters params) throws Exception {
        byte[] caDn = GostDnParser.encodeDn(DN_STR);
        byte[] leafDn = GostDnParser.encodeDn(LEAF_DN_STR);

        var caKp = KeyGenerator.generateKeyPair(params);
        GostCertificate caCert = GostCertificateBuilder.create(params, caDn)
                .publicKey(caKp.getPublic())
                .notBefore(NOT_BEFORE)
                .notAfter(NOT_AFTER_CA)
                .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .basicConstraints(true, null)
                .assembleCert(caKp.getPrivate());

        var leafKp = KeyGenerator.generateKeyPair(params);
        GostCertificate leafCert = GostCertificateBuilder.create(params, leafDn)
                .publicKey(leafKp.getPublic())
                .issuerDn(caDn)
                .notBefore(NOT_BEFORE)
                .notAfter(NOT_AFTER_LEAF)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .assembleCert(caKp.getPrivate());

        return new CertPair(caCert, leafKp.getPrivate(), leafKp.getPublic(), leafCert);
    }

    /** Сертификат, истёкший задним числом (для negative-тестов). */
    static GostCertificate makeExpiredCa(ECParameters params) throws Exception {
        byte[] caDn = GostDnParser.encodeDn("CN=Expired CA,O=Test,C=RU");
        var caKp = KeyGenerator.generateKeyPair(params);
        return GostCertificateBuilder.create(params, caDn)
                .publicKey(caKp.getPublic())
                .notBefore(NOT_BEFORE)
                .notAfter(NOT_AFTER_EXPIRED)
                .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .basicConstraints(true, null)
                .assembleCert(caKp.getPrivate());
    }

    // ========================================================================
    // CAdES построение
    // ========================================================================

    static byte[] buildCAdESBES(byte[] data, PrivateKeyParameters key, GostCertificate cert) {
        return CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(key, cert)
                .withCAdES()
                .build();
    }

    static byte[] buildCAdESBESdetached(byte[] data, PrivateKeyParameters key,
                                        GostCertificate cert) {
        return CmsSignedDataBuilder.create()
                .data(data)
                .detached(true)
                .addSigner(key, cert)
                .withCAdES()
                .build();
    }

    /** CAdES-BES без signingCertificateV2 (без withCAdES()). */
    static byte[] buildCAdESBESNoAttr(byte[] data, PrivateKeyParameters key,
                                      GostCertificate cert) {
        return CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(key, cert)
                .build();
    }

    /**
     * Строит CAdES-T: CAdES-BES + встроенный TimeStampToken.
     */
    static byte[] buildCAdEST(byte[] cadesBes, byte[] timeStampTokenDer) throws PkixException {
        return CAdESExtender.embedTimestamp(cadesBes, timeStampTokenDer);
    }

    // ========================================================================
    // TSP mock
    // ========================================================================

    static byte[] buildTspRequest(byte[] dataHash, String hashOid) {
        return TspRequestBuilder.create()
                .messageImprint(dataHash, hashOid)
                .certReq(true)
                .build();
    }

    /**
     * Строит TimeStampToken — CMS SignedData, содержащий TSTInfo.
     * Используется withCAdES() для signingCertificateV2, т.к. BC TimeStampToken требует этот атрибут.
     */
    static byte[] buildTimeStampToken(byte[] hash, String hashOid,
                                      PrivateKeyParameters tsaKey, GostCertificate tsaCert) {
        byte[] tstInfo = buildTstInfoDer(hash, hashOid);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaKey, tsaCert)
                .withCAdES()
                .build();
    }

    /**
     * Строит TimeStampResp DER = SEQUENCE { PKIStatusInfo, TimeStampToken }.
     */
    static byte[] buildTspResponse(byte[] timeStampTokenDer) {
        byte[] pkiStatus = DerCodec.encodeSequence(
                DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        return DerCodec.encodeSequence(pkiStatus, timeStampTokenDer);
    }

    /**
     * Строит TSTInfo DER для вложения в CMS SignedData.
     */
    static byte[] buildTstInfoDer(byte[] hash, String hashOid) {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")
                .withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());

        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid(DUMMY_TSA_POLICY_OID);
        byte[] hashAlg = CmsAlgorithmIdentifier.encode(hashOid);
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(BigInteger.valueOf(42));

        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
    }

    /**
     * Извлекает signature первого подписанта из SignedData
     * и вычисляет Стрибог-хэш подписи (для TSP messageImprint).
     */
    static byte[] hashFirstSignature(byte[] signedDataDer) throws PkixException {
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
        return hlen == 32 ? Digest.digest256(sig) : Digest.digest512(sig);
    }

    static String hashOidForSigLength(byte[] sig) {
        // sig — сырые октеты подписи (r||s), не хэш
        return sig.length == 64 ? GostOids.DIGEST_256 : GostOids.DIGEST_512;
    }

    static String hashOidForParams(ECParameters params) {
        return params.hlen == 32 ? GostOids.DIGEST_256 : GostOids.DIGEST_512;
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

    record CertPair(GostCertificate caCert, PrivateKeyParameters leafKey,
                    PublicKeyParameters leafPub, GostCertificate leafCert) {
    }

    record SignerEntry(PrivateKeyParameters key, GostCertificate cert) {
    }
}
