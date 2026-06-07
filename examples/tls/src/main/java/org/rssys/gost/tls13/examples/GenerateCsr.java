package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsConstants;

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
        byte[] csrDer = DerCodec.encodeSequence(
                tbs,
                buildSignatureAlgId(params),
                DerCodec.encodeBitString(sigValue));

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
        out.write(DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[]{0x00}));

        // subject
        out.write(buildDn(subjectDn));

        // subjectPKInfo — полный SubjectPublicKeyInfo (алгоритм + ключ)
        out.write(spki);

        // attributes [0] IMPLICIT SET — пустой, RFC 2986 §4.1 разрешает
        out.write(DerCodec.encodeContextConstructed(0, new byte[0]));

        return DerCodec.encodeSequence(out.toByteArray());
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
            byte[] attr = DerCodec.encodeSequence(
                    DerCodec.encodeOid(oid),
                    DerCodec.encodeTlv(DerCodec.TAG_UTF8_STRING, value.getBytes(StandardCharsets.UTF_8)));
            out.write(DerCodec.encodeTlv(DerCodec.TAG_SET, attr));
        }
        return DerCodec.encodeSequence(out.toByteArray());
    }

    /**
     * AlgorithmIdentifier для PKCS#10 signatureAlgorithm.
     * Использует OID id_tc26_gost3410_2012_256 (1.2.643.7.1.1.3.2) —
     * составной OID подписи и хэша, parameters отсутствуют (RFC 9215 §4.2).
     * В SubjectPublicKeyInfo применяется другой OID (1.2.643.7.1.1.1.1)
     * с обязательными параметрами — там этот метод не подходит.
     */
    private static byte[] buildSignatureAlgId(ECParameters params) {
        String signOid = params.hlen == TlsConstants.STREEBOG_256_HASH_LEN
                ? GostOids.SIGN_ALG_256
                : GostOids.SIGN_ALG_512;
        return DerCodec.encodeSequence(DerCodec.encodeOid(signOid));
    }

    private static String toPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

}
