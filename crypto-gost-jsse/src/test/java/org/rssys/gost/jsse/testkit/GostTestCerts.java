package org.rssys.gost.jsse.testkit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.util.DerCodec;

/**
 * Генерация тестовых сертификатов с ГОСТ-ключами (CA + серверный).
 * <p>
 * DER-кодирование вручную (RFC 5280) — через {@link TlsTestHelper} и {@link DerCodec}.
 * Вся криптография через crypto-gost-core (KeyGenerator, Signature).
 */
public final class GostTestCerts {

    private static int certSerial;

    private GostTestCerts() {}

    /**
     * Результат создания сертификата: цепочка TLS-сертификатов,
     * приватный ключ сервера, публичный ключ CA.
     */
    public record CertChain(
            List<GostCertificate> chain, PrivateKeyParameters key, PublicKeyParameters caKey) {

        /**
         * Конвертирует GostCertificate[] -> X509Certificate[] через
         * {@code CertificateBridge}. Нужен для {@code GostX509KeyManager.addKeyEntry()},
         * который принимает JCA-совместимые сертификаты.
         */
        public X509Certificate[] toJca() throws CertificateException {
            List<X509Certificate> result = new ArrayList<>(chain.size());
            for (GostCertificate c : chain) {
                result.add(org.rssys.gost.jsse.bridge.CertificateBridge.toJca(c));
            }
            return result.toArray(new X509Certificate[0]);
        }
    }

    /**
     * Создаёт самоподписанный CA + подписанный им серверный сертификат с SAN localhost.
     * <p>
     * Двухуровневая цепочка (CA -> server) минимально достаточна для
     * тестов TLS: клиент доверяет CA, сервер предъявляет подписанный сертификат.
     * SAN localhost обязателен — без него hostname verification (RFC 2818 §3.1)
     * отклоняет localhost-подключения.
     */
    public static CertChain createServerCert() throws Exception {
        return createServerCert(ECParameters.tc26a256());
    }

    public static CertChain createServerCert(ECParameters params) throws Exception {
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters caPriv = caKp.getPrivate();
        PublicKeyParameters caPub = caKp.getPublic();

        byte[] caName = TlsTestHelper.buildDN("JsseTestRootCA " + (++certSerial));
        byte[] bcExt = buildBasicConstraintsExt(true);
        GostCertificate caCert = createCert(caPriv, caPub, caPub, params, caName, caName, bcExt);

        KeyPair serverKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        PublicKeyParameters serverPub = serverKp.getPublic();

        byte[] serverName = TlsTestHelper.buildDN("JsseTestServer " + (++certSerial));
        byte[] sanExt = buildSanExt("localhost");
        byte[] kuExt = buildKeyUsageExt(new byte[] {(byte) 0x80});
        GostCertificate serverCert =
                createCert(
                        caPriv,
                        caPub,
                        serverPub,
                        params,
                        caName,
                        serverName,
                        TlsTestHelper.derSequence(sanExt, kuExt));

        List<GostCertificate> chain = new ArrayList<>();
        chain.add(serverCert);
        return new CertChain(chain, serverPriv, caCert.getPublicKey());
    }

    // ========================================================================
    // DER-кодирование вручную (RFC 5280)
    // ========================================================================

    private static final int TAG_CTX_0 = 0xA0;
    private static final int TAG_CTX_3 = 0xA3;

    // AlgorithmIdentifier для ГОСТ: SEQUENCE { signOid, SEQUENCE { curveOid, digestOid } }
    private static byte[] buildAlgId(ECParameters params) {
        String signOid = GostOids.SIG_WITH_DIGEST_256;
        String curveOid = GostOids.CURVE_256A;
        String digestOid = GostOids.DIGEST_256;
        return TlsTestHelper.derSequence(
                TlsTestHelper.derOid(signOid),
                TlsTestHelper.derSequence(
                        TlsTestHelper.derOid(curveOid), TlsTestHelper.derOid(digestOid)));
    }

    // TBSCertificate (RFC 5280 §4.1.2): version [0], serial, sigAlg,
    // issuer, validity, subject, SPKI, extensions [3]
    private static byte[] buildTbs(
            PublicKeyParameters pub,
            ECParameters params,
            byte[] issuerDn,
            byte[] subjectDn,
            byte[] additionalExtensions)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TAG_CTX_0);
        out.write(0x03);
        out.write(0x02);
        out.write(0x01);
        out.write(0x02);
        out.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
        out.write(buildAlgId(params));
        out.write(issuerDn);
        out.write(
                TlsTestHelper.derSequence(
                        TlsTestHelper.derTime("20250101120000Z"),
                        TlsTestHelper.derTime("21060101120000Z")));
        out.write(subjectDn);
        byte[] spki = GostDerCodec.encodePublicKey(pub);
        out.write(spki, 0, spki.length);
        if (additionalExtensions != null) {
            out.write(DerCodec.encodeTlv(TAG_CTX_3, additionalExtensions));
        }
        return TlsTestHelper.derSequence(out.toByteArray());
    }

    // Certificate = SEQUENCE { tbs, signatureAlgId, signature }
    // Подпись по схеме signHash: хэш -> подпись через ключ issuer-а.
    private static GostCertificate createCert(
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            PublicKeyParameters subjectPub,
            ECParameters params,
            byte[] issuerDn,
            byte[] subjectDn,
            byte[] exts)
            throws Exception {
        byte[] tbs = buildTbs(subjectPub, params, issuerDn, subjectDn, exts);
        byte[] hash = TlsTestHelper.doHash(tbs, 32);
        byte[] sig = Signature.signHash(hash, issuerPriv);
        byte[] certDer =
                TlsTestHelper.derSequence(tbs, buildAlgId(params), TlsTestHelper.derBitString(sig));
        return new GostCertificate(certDer);
    }

    // BasicConstraints (2.5.29.19): cA=TRUE для CA, cA=FALSE для остальных
    private static byte[] buildBasicConstraintsExt(boolean isCA) throws IOException {
        byte[] bc = isCA ? DerCodec.encodeTlv(0x01, new byte[] {(byte) 0xFF}) : new byte[0];
        byte[] extValue = DerCodec.encodeOctetString(TlsTestHelper.derSequence(bc));
        return TlsTestHelper.derSequence(
                TlsTestHelper.derOid(GostOids.EXT_BC),
                isCA ? DerCodec.encodeTlv(0x01, new byte[] {(byte) 0xFF}) : new byte[0],
                extValue);
    }

    // KeyUsage (2.5.29.15): битовая маска с critical-флагом
    private static byte[] buildKeyUsageExt(byte[] kuBits) {
        byte[] extValue = DerCodec.encodeOctetString(TlsTestHelper.derBitString(kuBits));
        return TlsTestHelper.derSequence(
                TlsTestHelper.derOid(GostOids.EXT_KU),
                DerCodec.encodeTlv(0x01, new byte[] {(byte) 0xFF}),
                extValue);
    }

    // SubjectAltName (2.5.29.17): dNSName (0x82) для hostname-верификации
    private static byte[] buildSanExt(String... dnsNames) throws IOException {
        ByteArrayOutputStream gn = new ByteArrayOutputStream();
        for (String name : dnsNames) {
            gn.write(DerCodec.encodeTlv(0x82, name.getBytes(StandardCharsets.US_ASCII)));
        }
        byte[] extValue = DerCodec.encodeOctetString(TlsTestHelper.derSequence(gn.toByteArray()));
        return TlsTestHelper.derSequence(TlsTestHelper.derOid(GostOids.EXT_SAN), extValue);
    }
}
