package org.rssys.bench;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.Pack;

import org.rssys.gost.jca.RssysGostProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;

class BenchHelper {
    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    static final byte TAG_SEQUENCE = 0x30;
    static final byte TAG_INTEGER = 0x02;
    static final byte TAG_OID = 0x06;
    static final byte TAG_BIT_STRING = 0x03;
    static final byte TAG_OCTET_STRING = 0x04;
    static final byte TAG_UTC_TIME = 0x17;
    static final byte TAG_CTX_0 = (byte) 0xA0;

    static class Bundle {
        final TlsCertificate cert;
        final PrivateKeyParameters priv;
        byte[] keyShareEntry;

        Bundle(TlsCertificate cert, PrivateKeyParameters priv) {
            this.cert = cert;
            this.priv = priv;
        }
    }

    static TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    static Bundle createBundle() throws IOException {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PublicKeyParameters pub = kp.getPublic();
        PrivateKeyParameters priv = kp.getPrivate();
        int hlen = pub.getParams().hlen;

        byte[] subjectDn = buildDn("CN=Bench CA");
        byte[] tbs = buildTbs(pub, subjectDn, hlen);
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, priv);

        byte[] algId = buildSigAlg(hlen);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new Bundle(new TlsCertificate(certDer), priv);
    }

    static byte[] buildTbs(PublicKeyParameters pub, byte[] subjectDn, int hlen) throws IOException {
        return derSequence(
            derExpl(0, derSequence(derInteger(new byte[]{2}))),       // version [0] v3
            derInteger(randomBytes(8)),                              // serial
            buildSigAlg(hlen),                                       // signature algorithm
            subjectDn,                                               // issuer
            derSequence(                                             // validity
                derUtcTime(fmtDate(new Date(System.currentTimeMillis() - 86400000L))),
                derUtcTime(fmtDate(new Date(System.currentTimeMillis() + 86400000L * 365)))),
            subjectDn,                                               // subject
            GostDerCodec.encodePublicKey(pub));                      // SPKI
    }

    /** Строит AlgorithmIdentifier для подписи (SEQUENCE { signOID, params }). */
    static byte[] buildSigAlg(int hlen) throws IOException {
        String signOid = hlen == 32 ? "1.2.643.7.1.1.1.1" : "1.2.643.7.1.1.1.2";
        String curveOid = "1.2.643.7.1.2.1.2.1";
        String digestOid = hlen == 32 ? "1.2.643.7.1.1.2.2" : "1.2.643.7.1.1.2.3";
        byte[] paramsSeq = derSequence(derOid(curveOid), derOid(digestOid));
        return derSequence(derOid(signOid), paramsSeq);
    }

    static byte[] buildKeyShareEntry() throws IOException {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] point = encodePoint(kp.getPublic());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x00); out.write(0x22); // GRP_GC256A
        out.write((byte) (point.length >>> 8)); out.write((byte) point.length);
        out.write(point);
        return out.toByteArray();
    }

    /** Кодирует публичный ключ в TLS wire format: X||Y, обе LE. */
    static byte[] encodePoint(PublicKeyParameters pub) {
        ECPoint q = pub.getQ().normalize();
        byte[] x = Pack.reverseBytes(toFixedLengthBytes(q.getX(), pub.getParams().hlen));
        byte[] y = Pack.reverseBytes(toFixedLengthBytes(q.getY(), pub.getParams().hlen));
        byte[] result = new byte[x.length + y.length];
        System.arraycopy(x, 0, result, 0, x.length);
        System.arraycopy(y, 0, result, x.length, y.length);
        return result;
    }

    static byte[] toFixedLengthBytes(BigInteger value, int len) {
        byte[] raw = value.toByteArray();
        if (raw.length == len) return raw;
        byte[] result = new byte[len];
        if (raw.length < len) {
            System.arraycopy(raw, 0, result, len - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - len, result, 0, len);
        }
        return result;
    }

    static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        byte[] data = new byte[clean.length() / 2];
        for (int i = 0; i < clean.length(); i += 2)
            data[i / 2] = (byte) ((Character.digit(clean.charAt(i), 16) << 4)
                    | Character.digit(clean.charAt(i + 1), 16));
        return data;
    }

    static byte[] doHash(byte[] data, int hlen) {
        org.rssys.gost.digest.Digest d = hlen == 64
                ? new org.rssys.gost.digest.Streebog512()
                : new org.rssys.gost.digest.Streebog256();
        d.update(data, 0, data.length);
        byte[] hash = new byte[hlen];
        d.doFinal(hash, 0);
        return hash;
    }

    static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    static String fmtDate(Date d) {
        return new java.text.SimpleDateFormat("yyMMddHHmmss'Z'").format(d);
    }

    static byte[] derSequence(byte[]... items) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] b : items) out.write(b);
        return derTlv(TAG_SEQUENCE, out.toByteArray());
    }

    static byte[] derInteger(byte[] val) throws IOException {
        return derTlv(TAG_INTEGER, val);
    }

    static byte[] derBitString(byte[] val) throws IOException {
        byte[] withPad = new byte[val.length + 1];
        System.arraycopy(val, 0, withPad, 1, val.length);
        return derTlv(TAG_BIT_STRING, withPad);
    }

    static byte[] derOid(String oid) throws IOException {
        return derTlv(TAG_OID, oidToBytes(oid));
    }

    static byte[] derOid(byte[] oidBytes) throws IOException {
        return derTlv(TAG_OID, oidBytes);
    }

    static byte[] derUtcTime(String s) throws IOException {
        return derTlv(TAG_UTC_TIME, s.getBytes(StandardCharsets.US_ASCII));
    }

    static byte[] derExpl(int tagNum, byte[] content) throws IOException {
        return derTlv((byte) (0xA0 | tagNum), content);
    }

    static byte[] derTlv(byte tag, byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        out.write(content);
        return out.toByteArray();
    }

    static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len <= 0xFF) {
            out.write(0x81); out.write(len);
        } else if (len <= 0xFFFF) {
            out.write(0x82); out.write(len >>> 8); out.write(len);
        } else {
            throw new IllegalArgumentException("Length too large: " + len);
        }
    }

    static byte[] oidToBytes(String oid) {
        String[] parts = oid.split("\\.");
        int[] vals = new int[parts.length];
        for (int i = 0; i < parts.length; i++) vals[i] = Integer.parseInt(parts[i]);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(40 * vals[0] + vals[1]);
        for (int i = 2; i < vals.length; i++) {
            int v = vals[i];
            if (v < 0x80) { out.write(v); continue; }
            int bits = 32 - Integer.numberOfLeadingZeros(v);
            int bytes = (bits + 6) / 7;
            for (int j = bytes - 1; j >= 0; j--) {
                int b = (v >>> (j * 7)) & 0x7F;
                if (j > 0) b |= 0x80;
                out.write(b);
            }
        }
        return out.toByteArray();
    }

    static byte[] buildDn(String name) throws IOException {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] oid = hex("55 04 03");
        byte[] attr = derSequence(derOid(oid), derTlv((byte) 0x0C, nameBytes));
        return derSequence(derSet(attr));
    }

    static byte[] derSet(byte[] item) throws IOException {
        return derTlv((byte) 0x31, item);
    }
}
