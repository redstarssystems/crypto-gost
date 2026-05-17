package org.rssys.gost.jsse.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.cert.TlsCertificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Демонстрационный хелпер для примеров JSSE: генерирует CA + серверный
 * сертификат для localhost и собирает SSLContext с ГОСТ TLS 1.3.
 * <p>
 * Использует только production API: KeyGenerator, Signature, TlsCertificate.
 * Не предназначен для production-использования — только для примеров и тестов.
 */
public final class ExamplesCertHelper {

    private final CertChain certs;
    private final SSLContext sslContext;

    public ExamplesCertHelper() throws Exception {
        this.certs = createServerCert();
        Security.addProvider(new RssysGostJsseProvider());
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", certs.toJca(), certs.key());
        GostX509TrustManager tm = new GostX509TrustManager(certs.caKey(), false);
        SSLContext ctx = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        ctx.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);
        this.sslContext = ctx;
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public GostX509KeyManager createKeyManager() {
        GostX509KeyManager km = new GostX509KeyManager();
        try {
            km.addKeyEntry("default", certs.toJca(), certs.key());
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        return km;
    }

    public GostX509TrustManager createTrustManager() {
        return new GostX509TrustManager(certs.caKey(), false);
    }

    /** DER серверного сертификата. */
    public byte[] getCertDer() {
        return certs.chain().get(0).getEncoded();
    }

    /** DER закрытого ключа (PKCS#8 PrivateKeyInfo). */
    public byte[] getKeyDer() {
        return GostDerCodec.encodePrivateKey(certs.key());
    }

    /** DER CA-сертификата. */
    public byte[] getCaCertDer() {
        return certs.caCert().getEncoded();
    }

    // ========================================================================
    // Генерация сертификатов
    // ========================================================================

    private static CertChain createServerCert() throws Exception {
        return createServerCert(ECParameters.tc26a256());
    }

    private static CertChain createServerCert(ECParameters params) throws Exception {
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters caPriv = caKp.getPrivate();
        PublicKeyParameters caPub = caKp.getPublic();

        byte[] caName = buildDN("CN=GOST Example CA");
        byte[] bcExt = buildBasicConstraintsExt(true);
        TlsCertificate caCert = createCert(caPriv, caPub, caPub, params, caName, caName, bcExt);

        KeyPair serverKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        PublicKeyParameters serverPub = serverKp.getPublic();

        byte[] serverName = buildDN("CN=GOST Example Server");
        byte[] sanExt = buildSanExt("localhost");
        byte[] kuExt = buildKeyUsageExt(new byte[]{(byte) 0x80});
        TlsCertificate serverCert = createCert(caPriv, caPub, serverPub, params, caName, serverName,
                derSequence(sanExt, kuExt));

        List<TlsCertificate> chain = new ArrayList<>();
        chain.add(serverCert);
        return new CertChain(chain, serverPriv, caCert.getPublicKey(), caCert);
    }

    // ========================================================================
    // DER-кодирование (RFC 5280)
    // ========================================================================

    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_SET = 0x31;
    private static final int TAG_OID = 0x06;
    private static final int TAG_UTF8_STRING = 0x0C;
    private static final int TAG_BIT_STRING = 0x03;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_CTX_0 = 0xA0;
    private static final int TAG_CTX_3 = 0xA3;

    private static byte[] derTlv(int tag, byte[] content) {
        byte[] lenBytes = buildLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    private static byte[] buildLength(int len) {
        if (len < 0x80) return new byte[]{(byte) len};
        if (len < 0x100) return new byte[]{(byte) 0x81, (byte) len};
        return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
    }

    private static byte[] derSequence(byte[]... elements) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] el : elements) out.write(el, 0, el.length);
        return derTlv(TAG_SEQUENCE, out.toByteArray());
    }

    private static byte[] derBitString(byte[] content) {
        byte[] withUnused = new byte[content.length + 1];
        withUnused[0] = 0;
        System.arraycopy(content, 0, withUnused, 1, content.length);
        return derTlv(TAG_BIT_STRING, withUnused);
    }

    private static byte[] derOctetString(byte[] data) {
        return derTlv(TAG_OCTET_STRING, data);
    }

    private static byte[] derOid(String oidStr) {
        String[] parts = oidStr.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] arcs = new int[parts.length];
        for (int i = 0; i < parts.length; i++) arcs[i] = Integer.parseInt(parts[i]);
        out.write(40 * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            if (arcs[i] < 128) {
                out.write(arcs[i]);
            } else {
                out.write(0x80 | (arcs[i] >>> 7));
                out.write(arcs[i] & 0x7F);
            }
        }
        return derTlv(TAG_OID, out.toByteArray());
    }

    private static byte[] buildDN(String cn) {
        byte[] attr = derSequence(derOid(GostOids.ATTR_CN),
                derTlv(TAG_UTF8_STRING, cn.getBytes(StandardCharsets.UTF_8)));
        return derSequence(derTlv(TAG_SET, attr));
    }

    private static byte[] doHash(byte[] data) {
        Streebog256 d = new Streebog256();
        d.update(data, 0, data.length);
        byte[] h = new byte[32];
        d.doFinal(h, 0);
        return h;
    }

    private static byte[] buildAlgId(ECParameters params) {
        return derSequence(derOid(GostOids.SIG_WITH_DIGEST_256),
                derSequence(derOid(GostOids.CURVE_256A), derOid(GostOids.DIGEST_256)));
    }

    private static byte[] buildTbs(PublicKeyParameters pub, ECParameters params,
                                    byte[] issuerDn, byte[] subjectDn,
                                    byte[] additionalExtensions) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TAG_CTX_0);
        out.write(0x03);
        out.write(0x02);
        out.write(0x01);
        out.write(0x02);
        out.write(derTlv(0x02, new byte[]{0x01}));
        out.write(buildAlgId(params));
        out.write(issuerDn);
        out.write(derSequence(derTlv(0x17, "250101120000Z".getBytes(StandardCharsets.US_ASCII)),
                derTlv(0x17, "360101120000Z".getBytes(StandardCharsets.US_ASCII))));
        out.write(subjectDn);
        byte[] spki = GostDerCodec.encodePublicKey(pub);
        out.write(spki, 0, spki.length);
        if (additionalExtensions != null) {
            out.write(derTlv(TAG_CTX_3, additionalExtensions));
        }
        return derSequence(out.toByteArray());
    }

    private static TlsCertificate createCert(PrivateKeyParameters issuerPriv,
                                              PublicKeyParameters issuerPub,
                                              PublicKeyParameters subjectPub,
                                              ECParameters params,
                                              byte[] issuerDn, byte[] subjectDn,
                                              byte[] exts) throws Exception {
        byte[] tbs = buildTbs(subjectPub, params, issuerDn, subjectDn, exts);
        byte[] hash = doHash(tbs);
        byte[] sig = Signature.signHash(hash, issuerPriv);
        byte[] certDer = derSequence(tbs, buildAlgId(params), derBitString(sig));
        return new TlsCertificate(certDer);
    }

    private static byte[] buildBasicConstraintsExt(boolean isCA) throws IOException {
        byte[] bc = isCA ? derTlv(0x01, new byte[]{(byte) 0xFF}) : new byte[0];
        byte[] extValue = derOctetString(derSequence(bc));
        return derSequence(derOid(GostOids.EXT_BC),
                isCA ? derTlv(0x01, new byte[]{(byte) 0xFF}) : new byte[0], extValue);
    }

    private static byte[] buildKeyUsageExt(byte[] kuBits) {
        byte[] extValue = derOctetString(derBitString(kuBits));
        return derSequence(derOid(GostOids.EXT_KU), derTlv(0x01, new byte[]{(byte) 0xFF}), extValue);
    }

    private static byte[] buildSanExt(String... dnsNames) throws IOException {
        ByteArrayOutputStream gn = new ByteArrayOutputStream();
        for (String name : dnsNames) {
            gn.write(derTlv(0x82, name.getBytes(StandardCharsets.US_ASCII)));
        }
        byte[] extValue = derOctetString(derSequence(gn.toByteArray()));
        return derSequence(derOid(GostOids.EXT_SAN), extValue);
    }

    // ========================================================================
    // Внутреннее представление цепочки сертификатов
    // ========================================================================

    public record CertChain(
            List<TlsCertificate> chain,
            PrivateKeyParameters key,
            PublicKeyParameters caKey,
            TlsCertificate caCert
    ) {
        public X509Certificate[] toJca() throws CertificateException {
            List<X509Certificate> result = new ArrayList<>(chain.size());
            for (TlsCertificate c : chain) {
                result.add(CertificateBridge.toJca(c));
            }
            return result.toArray(new X509Certificate[0]);
        }
    }
}
