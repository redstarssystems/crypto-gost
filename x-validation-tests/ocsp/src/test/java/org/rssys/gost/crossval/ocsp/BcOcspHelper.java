package org.rssys.gost.crossval.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.*;

import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Stateless хелпер для OCSP-операций с BouncyCastle.
 */
final class BcOcspHelper {

    private BcOcspHelper() {}

    // ========================================================================
    // Ключи и сертификаты BC
    // ========================================================================

    static KeyPair generateBcKeyPair(ECParameters params) throws Exception {
        String curveName = params.hlen == 32
                ? "Tc26-Gost-3410-12-256-paramSetA"
                : "Tc26-Gost-3410-12-512-paramSetA";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        kpg.initialize(new ECNamedCurveGenParameterSpec(curveName), new SecureRandom());
        return kpg.generateKeyPair();
    }

    static X509Certificate buildBcSelfSignedCert(KeyPair kp, String dnStr,
                                                  ECParameters params) throws Exception {
        X500Name issuer = new X500Name(dnStr);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86400000L);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, kp.getPublic());

        String sigAlg = params.hlen == 32
                ? "GOST3411-2012-256WITHECGOST3410-2012-256"
                : "GOST3411-2012-512WITHECGOST3410-2012-512";
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    static X509Certificate gostCertToBcX509Cert(GostCertificate gostCert) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(gostCert.getEncoded()));
    }

    /**
     * Извлекает GOST PublicKeyParameters из BC X509Certificate.
     */
    static PublicKeyParameters extractGostPubKey(X509Certificate cert) throws Exception {
        GostCertificate gc = new GostCertificate(cert.getEncoded());
        return gc.getPublicKey();
    }

    // ========================================================================
    // OCSP: BC -> GOST (build with BC, parse with GOST)
    // ========================================================================

    /**
     * Строит OCSP-ответ через BC BasicOCSPRespBuilder, подписанный BC-ключом.
     */
    static byte[] buildBcOcspResponse(byte[] leafCertDer, byte[] caCertDer,
                                       KeyPair signerKp, X509Certificate signerCert,
                                       String status) throws Exception {
        return buildBcOcspResponse(leafCertDer, caCertDer, signerKp, signerCert,
                status, null, false, null, null);
    }

    static byte[] buildBcOcspResponse(byte[] leafCertDer, byte[] caCertDer,
                                       KeyPair signerKp, X509Certificate signerCert,
                                       String status, byte[] nonce) throws Exception {
        return buildBcOcspResponse(leafCertDer, caCertDer, signerKp, signerCert,
                status, nonce, false, null, null);
    }

    static byte[] buildBcOcspResponseDelegated(byte[] leafCertDer, byte[] caCertDer,
                                                KeyPair signerKp, X509Certificate signerCert,
                                                KeyPair responderKp, X509Certificate responderCert)
            throws Exception {
        return buildBcOcspResponse(leafCertDer, caCertDer, signerKp, signerCert,
                "good", null, true, responderKp, responderCert);
    }

    private static byte[] buildBcOcspResponse(byte[] leafCertDer, byte[] caCertDer,
                                               KeyPair signerKp, X509Certificate signerCert,
                                               String status, byte[] nonce,
                                               boolean delegated,
                                               KeyPair responderKp,
                                               X509Certificate responderCert) throws Exception {
        GostCertificate leafGc = new GostCertificate(leafCertDer);
        BigInteger serial = new BigInteger(1, leafGc.getSerialNumber());

        X509Certificate caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(caCertDer));
        X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(caCert);

        // Стрибог — для вычисления CertID (RFC 6960 §4.1.1)
        DigestCalculator stbDigestCalc = createStreebog256DigestCalculator();
        CertificateID certId = new CertificateID(stbDigestCalc, issuerHolder, serial);

        X509CertificateHolder signerHolder = new JcaX509CertificateHolder(signerCert);

        // RespID byName (тег 0xA1) — совместим с GostOcspResponse парсером
        RespID respId = new RespID(signerHolder.getSubject());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respId);

        Extensions responseExts = null;
        if (nonce != null) {
            responseExts = new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce));
        }
        if (responseExts != null) {
            builder.setResponseExtensions(responseExts);
        }

        Date thisUpdate = new Date();
        Date nextUpdate = new Date(System.currentTimeMillis() + 86400000L * 7);

        CertificateStatus certStatus;
        switch (status) {
            case "revoked":
                certStatus = new RevokedStatus(thisUpdate, 1);
                break;
            case "unknown":
                certStatus = new UnknownStatus();
                break;
            default:
                certStatus = CertificateStatus.GOOD;
                break;
        }

        builder.addResponse(certId, certStatus, thisUpdate, nextUpdate);

        String sigAlg = "GOST3411-2012-256WITHECGOST3410-2012-256";
        ContentSigner cs = new JcaContentSignerBuilder(sigAlg)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signerKp.getPrivate());

        X509CertificateHolder[] certChain;
        if (delegated && responderCert != null) {
            certChain = new X509CertificateHolder[]{
                    new JcaX509CertificateHolder(responderCert)};
        } else {
            certChain = new X509CertificateHolder[]{signerHolder};
        }

        BasicOCSPResp basic = builder.build(cs, certChain, thisUpdate);

        org.bouncycastle.cert.ocsp.OCSPRespBuilder respBuilder =
                new org.bouncycastle.cert.ocsp.OCSPRespBuilder();
        OCSPResp ocspResp = respBuilder.build(
                org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL, basic);
        return ocspResp.getEncoded();
    }

    /**
     * Строит OCSP-запрос через BC OCSPReqBuilder.
     */
    static byte[] buildBcOcspRequest(byte[] leafCertDer, byte[] caCertDer) throws Exception {
        return buildBcOcspRequestImpl(leafCertDer, caCertDer,
                createStreebog256DigestCalculator(), true);
    }

    static byte[] buildBcOcspRequestSha256(byte[] leafCertDer, byte[] caCertDer) throws Exception {
        return buildBcOcspRequestImpl(leafCertDer, caCertDer,
                createSha256DigestCalculator(), false);
    }

    private static byte[] buildBcOcspRequestImpl(byte[] leafCertDer, byte[] caCertDer,
                                                  DigestCalculator digestCalc,
                                                  boolean includeNonce) throws Exception {
        GostCertificate leafGc = new GostCertificate(leafCertDer);
        BigInteger serial = new BigInteger(1, leafGc.getSerialNumber());

        X509Certificate caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(caCertDer));
        X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(caCert);

        CertificateID certId = new CertificateID(digestCalc, issuerHolder, serial);

        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);

        if (includeNonce) {
            byte[] nonceVal = new byte[16];
            new SecureRandom().nextBytes(nonceVal);
            Extensions exts = new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonceVal));
            builder.setRequestExtensions(exts);
        }

        return builder.build().getEncoded();
    }

    // ========================================================================
    // DigestCalculator
    // ========================================================================

    static DigestCalculator createStreebog256DigestCalculator() throws Exception {
        JcaDigestCalculatorProviderBuilder providerBuilder =
                new JcaDigestCalculatorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return providerBuilder.build().get(
                new AlgorithmIdentifier(
                        org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256));
    }

    static DigestCalculator createSha256DigestCalculator() throws Exception {
        JcaDigestCalculatorProviderBuilder providerBuilder =
                new JcaDigestCalculatorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return providerBuilder.build().get(
                new AlgorithmIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256));
    }

    static DigestCalculator createSha1DigestCalculator() {
        // BC RespID требует точного совпадения AlgorithmIdentifier (включая params=DERNull).
        // JcaDigestCalculatorProvider может вернуть params=null — кастомный враппер гарантирует совпадение.
        return new DigestCalculator() {
            private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return RespID.HASH_SHA1;
            }
            @Override
            public OutputStream getOutputStream() {
                return buf;
            }
            @Override
            public byte[] getDigest() {
                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-1");
                    return md.digest(buf.toByteArray());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
