package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Вспомогательные методы для примеров (построение сертификатов, DER). */
public final class ExampleUtils {

    private static int certCounter;

    private ExampleUtils() {}

    // ---- DER ----
    static final int TAG_SEQUENCE = 0x30;
    static final int TAG_SET = 0x31;
    static final int TAG_OID = 0x06;
    static final int TAG_UTF8_STRING = 0x0C;
    static final int TAG_BIT_STRING = 0x03;
    static final int TAG_OCTET_STRING = 0x04;
    static final int TAG_CTX_0 = 0xA0;
    static final int TAG_CTX_3 = 0xA3;

    static byte[] derTlv(int tag, byte[] content) {
        byte[] lenBytes = buildLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    static byte[] buildLength(int len) {
        if (len < 0x80) return new byte[]{(byte) len};
        if (len < 0x100) return new byte[]{(byte) 0x81, (byte) len};
        return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
    }

    static byte[] derSequence(byte[]... elements) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] el : elements) out.write(el, 0, el.length);
        return derTlv(TAG_SEQUENCE, out.toByteArray());
    }

    static byte[] derOid(String oidStr) {
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

    static byte[] derBitString(byte[] content) {
        byte[] withUnused = new byte[content.length + 1];
        withUnused[0] = 0;
        System.arraycopy(content, 0, withUnused, 1, content.length);
        return derTlv(TAG_BIT_STRING, withUnused);
    }

    static byte[] derUtcTime(String time) {
        return derTlv(0x17, time.getBytes(StandardCharsets.US_ASCII));
    }

    // ---- DN ----
    static byte[] buildDN(String cn) {
        byte[] attr = derSequence(derOid("2.5.4.3"),
                derTlv(TAG_UTF8_STRING, cn.getBytes(StandardCharsets.UTF_8)));
        return derSequence(derTlv(TAG_SET, attr));
    }

    // ---- Подпись ----
    static byte[] doHash(byte[] data, int hlen) {
        if (hlen == 32) {
            Streebog256 d = new Streebog256();
            d.update(data, 0, data.length);
            byte[] h = new byte[32];
            d.doFinal(h, 0);
            return h;
        }
        Streebog512 d = new Streebog512();
        d.update(data, 0, data.length);
        byte[] h = new byte[64];
        d.doFinal(h, 0);
        return h;
    }

    static byte[] buildAlgId(ECParameters params) {
        String signOid = params.hlen == 32 ? "1.2.643.7.1.1.1.1" : "1.2.643.7.1.1.1.2";
        String curveOid = curveOidOf(params);
        String digestOid = params.hlen == 32 ? "1.2.643.7.1.1.2.2" : "1.2.643.7.1.1.2.3";
        return derSequence(derOid(signOid), derSequence(derOid(curveOid), derOid(digestOid)));
    }

    static String curveOidOf(ECParameters params) {
        if (params == ECParameters.tc26a256()) return "1.2.643.7.1.1.2.1";
        if (params == ECParameters.cryptoProA()) return "1.2.643.2.2.35.1";
        if (params == ECParameters.tc26a512()) return "1.2.643.7.1.1.2.2";
        return "1.2.643.7.1.1.2.1";
    }

    // ---- Сертификаты ----
    static byte[] buildAlgIdSHA256() {
        return derSequence(derOid("1.2.643.7.1.1.1.1"),
                derSequence(derOid("1.2.643.7.1.1.2.1"), derOid("1.2.643.7.1.1.2.2")));
    }

    static byte[] buildTbs(PublicKeyParameters pub, ECParameters params,
                           byte[] issuerDn, byte[] subjectDn,
                           byte[] additionalExtensions) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TAG_CTX_0);
        out.write(0x03);
        out.write(0x02);
        out.write(0x01);
        out.write(0x02);
        out.write(derTlv(0x02, new byte[]{0x01}));  // serial = 1
        out.write(buildAlgId(params));
        out.write(issuerDn);
        out.write(derSequence(derUtcTime("250101120000Z"), derUtcTime("360101120000Z")));
        out.write(subjectDn);
        byte[] spki = GostDerCodec.encodePublicKey(pub);
        out.write(spki, 0, spki.length);
        if (additionalExtensions != null) {
            byte[] extensionsSeq = derSequence(additionalExtensions);
            out.write(derTlv(TAG_CTX_3, extensionsSeq));
        }
        return derSequence(out.toByteArray());
    }

    static TlsCertificate createCert(PrivateKeyParameters issuerPriv,
                                     PublicKeyParameters issuerPub,
                                     PublicKeyParameters subjectPub,
                                     ECParameters params,
                                     byte[] issuerDn, byte[] subjectDn,
                                     byte[] exts) throws Exception {
        byte[] tbs = buildTbs(subjectPub, params, issuerDn, subjectDn, exts);
        int hlen = params.hlen;
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, issuerPriv);
        byte[] certDer = derSequence(tbs, buildAlgId(params), derBitString(sig));
        return new TlsCertificate(certDer);
    }

    public static TlsCertificate createRootCA() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = buildDN("Example Root CA " + (++certCounter));
        byte[] bcExt = buildBasicConstraintsExt(true, null);
        return createCert(kp.getPrivate(), kp.getPublic(), kp.getPublic(),
                params, dn, dn, bcExt);
    }

    public static TlsCertificate createServerCert(TlsCertificate ca, PrivateKeyParameters caPriv,
                                                   PublicKeyParameters caPub) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = buildDN("Example Server " + (++certCounter));
        byte[] sanExt = buildSanExt(new String[]{"localhost"}, null);
        byte[] kuExt = buildKeyUsageExt(new byte[]{(byte) 0x80}); // digitalSignature
        byte[] combined = derSequence(sanExt, kuExt);
        return createCert(caPriv, caPub, kp.getPublic(), params,
                ca.getSubjectDnBytes(), subjectDn, combined);
    }

    public static TlsCertificate createClientCert(TlsCertificate ca, PrivateKeyParameters caPriv,
                                                   PublicKeyParameters caPub) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = buildDN("Example Client " + (++certCounter));
        byte[] kuExt = buildKeyUsageExt(new byte[]{(byte) 0x80});
        byte[] ekuExt = buildEkuExt("1.3.6.1.5.5.7.3.2"); // clientAuth
        byte[] combined = derSequence(kuExt, ekuExt);
        return createCert(caPriv, caPub, kp.getPublic(), params,
                ca.getSubjectDnBytes(), subjectDn, combined);
    }

    // ---- Расширения ----
    static byte[] buildBasicConstraintsExt(boolean isCA, Integer pathLen) throws IOException {
        ByteArrayOutputStream bc = new ByteArrayOutputStream();
        if (isCA) bc.write(derTlv(0x01, new byte[]{(byte) 0xFF})); // BOOLEAN TRUE
        if (pathLen != null) bc.write(derTlv(0x02, new byte[]{pathLen.byteValue()}));
        byte[] extValue = derOctetString(derSequence(bc.toByteArray()));
        return derSequence(derOid("2.5.29.19"), isCA ? derTlv(0x01, new byte[]{(byte) 0xFF}) : new byte[0], extValue);
    }

    static byte[] buildKeyUsageExt(byte[] kuBits) {
        byte[] extValue = derOctetString(derBitString(kuBits));
        return derSequence(derOid("2.5.29.15"), derTlv(0x01, new byte[]{(byte) 0xFF}), extValue);
    }

    static byte[] buildEkuExt(String... oids) throws IOException {
        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        for (String oid : oids) seq.write(derOid(oid));
        byte[] extValue = derOctetString(derSequence(seq.toByteArray()));
        return derSequence(derOid("2.5.29.37"), extValue);
    }

    static byte[] buildSanExt(String[] dnsNames, String[] ipAddresses) throws IOException {
        ByteArrayOutputStream gn = new ByteArrayOutputStream();
        if (dnsNames != null) {
            for (String name : dnsNames) {
                gn.write(derTlv(0x82, name.getBytes(StandardCharsets.US_ASCII)));
            }
        }
        if (ipAddresses != null) {
            for (String ip : ipAddresses) {
                gn.write(derTlv(0x87, java.net.InetAddress.getByName(ip).getAddress()));
            }
        }
        byte[] extValue = derOctetString(derSequence(gn.toByteArray()));
        return derSequence(derOid("2.5.29.17"), extValue);
    }

    static byte[] derOctetString(byte[] data) {
        return derTlv(TAG_OCTET_STRING, data);
    }

    static byte[] buildOcspExt() throws IOException {
        return derSequence(derOid("1.3.6.1.5.5.7.1.1"), derOid("1.3.6.1.5.5.7.48.1"));
    }
}
