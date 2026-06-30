package org.rssys.gost.tls13.examples;

import java.util.Base64;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCsrBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Генерирует PKCS#10 CSR (Certificate Signing Request) для ГОСТ Р 34.10-2012.
 * <p>
 * Использует {@link GostCsrBuilder} для сборки CSR.
 * Результат — PEM-файл с запросом на подпись сертификата, готовый для отправки
 * в Удостоверяющий Центр.
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

        byte[] csrDer = GostCsrBuilder.buildCsr(privKey, pubKey, subjectDn);

        String pem = toPem(csrDer);
        System.out.println(pem);
    }

    private static String toPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }
}
