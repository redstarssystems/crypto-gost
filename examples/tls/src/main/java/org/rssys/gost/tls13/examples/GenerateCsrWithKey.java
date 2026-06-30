package org.rssys.gost.tls13.examples;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.GostCsrBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

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

        byte[] privDer = GostDerCodec.encodePrivateKey(privKey);
        String privPem =
                "-----BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(privDer)
                        + "\n-----END PRIVATE KEY-----\n";
        Path privFile = outDir.resolve("key-" + curveLabel + ".pem");
        Files.writeString(privFile, privPem);
        System.out.println("Private key: " + privFile.toAbsolutePath().normalize());

        byte[] csrDer = GostCsrBuilder.buildCsr(privKey, pubKey, subjectDn);

        String csrPem =
                "-----BEGIN CERTIFICATE REQUEST-----\n"
                        + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(csrDer)
                        + "\n-----END CERTIFICATE REQUEST-----\n";
        Path csrFile = outDir.resolve("csr-" + curveLabel + ".pem");
        Files.writeString(csrFile, csrPem);
        System.out.println("CSR:         " + csrFile.toAbsolutePath().normalize());

        privKey.destroy();
    }
}
