package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.GostOids;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Генерирует PKCS#10 CSR (Certificate Signing Request) для ГОСТ Р 34.10-2012.
 * <p>
 * Результат — PEM-файл с запросом на подпись сертификата, готовый для отправки
 * в Удостоверяющий Центр (например, CryptoPro TestCA). Атрибуты пустые ({@code [0] SET}),
 * что допускается спецификацией RFC 2986 §4.1 и принимается тестовым УЦ.
 * <p>
 * Запуск:
 * {@snippet :
 * mvn exec:java -pl examples/tls \
 *   -Dexec.mainClass=org.rssys.gost.tls13.examples.GenerateCsr \
 *   -Dexec.args="CN=ТестовыйСертификат"
 * }
 */
public final class GenerateCsr {

    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_SET = 0x31;
    private static final int TAG_BIT_STRING = 0x03;
    private static final int TAG_OID = 0x06;
    private static final int TAG_UTF8_STRING = 0x0C;
    private static final int TAG_INTEGER = 0x02;
    private static final int TAG_CTX_0 = (byte) 0xA0;

    private GenerateCsr() {}

    public static void main(String[] args) throws Exception {
        String subjectDn = args.length > 0 ? args[0] : "CN=GOST Test Certificate";
        int hlen = args.length > 1 ? Integer.parseInt(args[1]) : 256;

        ECParameters params = hlen == 512 ? ECParameters.tc26a512() : ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters privKey = kp.getPrivate();
        PublicKeyParameters pubKey = kp.getPublic();

        byte[] tbs = buildTbsCertRequest(subjectDn, pubKey, params);
        byte[] sigValue = Signature.sign(tbs, privKey);

        // В signatureAlgorithm используем OID подписи с хэшем (1.2.643.7.1.1.3.2),
        // а не OID алгоритма ключа (1.2.643.7.1.1.1.1). CryptoPro-совместимость.
        byte[] csrDer = derSequence(
                tbs,
                buildSignatureAlgId(params),
                derBitString(sigValue));

        String pem = toPem(csrDer);
        System.out.println(pem);
    }

    /**
     * Строит TBSCertificationRequest (RFC 2986 §4.1):
     * <pre>
     *   version [0] INTEGER 0
     *   subject Name
     *   subjectPKInfo SubjectPublicKeyInfo
     *   attributes [0] IMPLICIT SET (пустой)
     * </pre>
     */
    private static byte[] buildTbsCertRequest(String subjectDn,
                                               PublicKeyParameters pub,
                                               ECParameters params) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] spki = GostDerCodec.encodePublicKey(pub);

        // version INTEGER { v1(0) } — RFC 2986 §4.1, просто INTEGER
        out.write(derTlv(TAG_INTEGER, new byte[]{0x00}));

        // subject
        out.write(buildDn(subjectDn));

        // subjectPKInfo — полный SubjectPublicKeyInfo (алгоритм + ключ)
        out.write(spki);

        // attributes [0] IMPLICIT SET — пустой, RFC 2986 §4.1 разрешает
        out.write(new byte[]{TAG_CTX_0, 0x00});

        return derSequence(out.toByteArray());
    }

    private static byte[] buildDn(String dn) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String part : dn.split(",")) {
            part = part.trim();
            String[] kv = part.split("=", 2);
            String key = kv[0].trim();
            String value = kv.length > 1 ? kv[1].trim() : "";
            String oid;
            switch (key.toUpperCase()) {
                case "CN": oid = GostOids.ATTR_CN; break;
                case "O":  oid = "2.5.4.10"; break;
                case "OU": oid = "2.5.4.11"; break;
                case "L":  oid = "2.5.4.7"; break;
                case "ST": oid = "2.5.4.8"; break;
                case "C":  oid = "2.5.4.6"; break;
                default:   oid = GostOids.ATTR_CN;
            }
            byte[] attr = derSequence(
                    derOid(oid),
                    derTlv(TAG_UTF8_STRING, value.getBytes(StandardCharsets.UTF_8)));
            out.write(derTlv(TAG_SET, attr));
        }
        return derSequence(out.toByteArray());
    }

    /**
     * AlgorithmIdentifier для PKCS#10 signatureAlgorithm.
     * Использует OID id_tc26_gost3410_2012_256 (1.2.643.7.1.1.3.2) —
     * этот OID обозначает подпись ГОСТ Р 34.10-2012 вместе со хэшем Стрибог-256.
     * В SubjectPublicKeyInfo применяется другой OID (1.2.643.7.1.1.1.1),
     * поэтому {@code ExampleUtils.buildAlgId()} не подходит — используем этот метод.
     */
    private static byte[] buildSignatureAlgId(ECParameters params) throws Exception {
        String signOid = params.hlen == 32
                ? GostOids.SIGN_ALG_256
                : GostOids.SIGN_ALG_512;
        String curveOid = curveOidOf(params);
        String digestOid = params.hlen == 32
                ? GostOids.DIGEST_256
                : GostOids.DIGEST_512;
        return derSequence(
                derOid(signOid),
                derSequence(derOid(curveOid), derOid(digestOid)));
    }

    private static String curveOidOf(ECParameters params) {
        if (params == ECParameters.tc26a256()) return GostOids.CURVE_256A;
        if (params == ECParameters.cryptoProA()) return GostOids.CURVE_CP_A;
        if (params == ECParameters.tc26a512()) return GostOids.CURVE_512A;
        return GostOids.CURVE_256A;
    }

    private static String toPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    // ---- DER ----

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

    private static byte[] derSequence(byte[]... elements) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] el : elements) out.write(el);
        return derTlv(TAG_SEQUENCE, out.toByteArray());
    }

    private static byte[] derBitString(byte[] content) {
        byte[] withUnused = new byte[content.length + 1];
        withUnused[0] = 0;
        System.arraycopy(content, 0, withUnused, 1, content.length);
        return derTlv(TAG_BIT_STRING, withUnused);
    }

    private static byte[] derOid(String oidStr) throws Exception {
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
}
