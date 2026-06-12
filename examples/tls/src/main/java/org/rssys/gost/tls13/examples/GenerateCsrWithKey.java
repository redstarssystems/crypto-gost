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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public final class GenerateCsrWithKey {

    private GenerateCsrWithKey() {}

    public static void main(String[] args) throws Exception {
        String subjectDn = args.length > 0 ? args[0] : "CN=TestCert";
        int hlen = args.length > 1 ? Integer.parseInt(args[1]) : 256;
        Path outDir = args.length > 2 ? Path.of(args[2]) : Path.of(".");

        ECParameters params = hlen == 512 ? ECParameters.tc26a512() : ECParameters.tc26a256();
        String curveLabel = hlen == 512 ? "gost512" : "gost256";

        KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters privKey = kp.getPrivate();
        PublicKeyParameters pubKey = kp.getPublic();

        // сохраняем приватный ключ в PEM
        byte[] privDer = GostDerCodec.encodePrivateKey(privKey);
        String privPem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privDer)
                + "\n-----END PRIVATE KEY-----\n";
        Path privFile = outDir.resolve("key-" + curveLabel + ".pem");
        Files.writeString(privFile, privPem);
        System.out.println("Private key: " + privFile.toAbsolutePath().normalize());

        // строим CSR
        byte[] tbs = buildTbsCertRequest(subjectDn, pubKey, params);
        byte[] sigValue = Signature.sign(tbs, privKey);

        byte[] csrDer = DerCodec.encodeSequence(
                tbs,
                buildSignatureAlgId(params),
                DerCodec.encodeBitString(sigValue));

        String csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(csrDer)
                + "\n-----END CERTIFICATE REQUEST-----\n";
        Path csrFile = outDir.resolve("csr-" + curveLabel + ".pem");
        Files.writeString(csrFile, csrPem);
        System.out.println("CSR:         " + csrFile.toAbsolutePath().normalize());

        privKey.destroy();
    }

    private static byte[] buildTbsCertRequest(String subjectDn,
                                               PublicKeyParameters pub,
                                               ECParameters params) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] spki = GostDerCodec.encodePublicKey(pub);
        out.write(DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[]{0x00}));
        out.write(buildDn(subjectDn));
        out.write(spki);
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

    private static byte[] buildSignatureAlgId(ECParameters params) {
        String signOid = params.hlen == TlsConstants.STREEBOG_256_HASH_LEN
                ? GostOids.SIGN_ALG_256
                : GostOids.SIGN_ALG_512;
        return DerCodec.encodeSequence(DerCodec.encodeOid(signOid));
    }
}
