package org.rssys.gost.pkix.examples;

import java.nio.file.Files;
import java.nio.file.Path;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.pkix.cert.GostPemUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Подписывает сертификат для контейнера CryptoPro CSP от существующего ЦА.
 *
 * <p>Сценарий использования:
 * <ol>
 *   <li>{@code csptest -keyset -makecert -cont <container> -password <pin>}</li>
 *   <li>{@code csptest -keyset -expcert /tmp/container-cert.cer -cont <container> -password <pin>}</li>
 *   <li>{@code java org.rssys.gost.pkix.examples.SignContainerCert ...}</li>
 *   <li>{@code csptest -keyset -impcert /tmp/client-signed.cer -cont <container> -password <pin>}</li>
 * </ol>
 */
public final class SignContainerCert {

    private SignContainerCert() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 6) {
            System.err.println(
                    """
                    Usage:
                      SignContainerCert \\
                        --container-cert <file> \\
                        --ca-key <file> \\
                        --ca-cert <file> \\
                        --out <file>
                    """);
            System.exit(1);
        }

        Path containerCertPath = null;
        Path caKeyPath = null;
        Path caCertPath = null;
        Path outPath = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--container-cert" -> containerCertPath = Path.of(args[++i]);
                case "--ca-key" -> caKeyPath = Path.of(args[++i]);
                case "--ca-cert" -> caCertPath = Path.of(args[++i]);
                case "--out" -> outPath = Path.of(args[++i]);
            }
        }

        // Читаем self-signed сертификат из контейнера CryptoPro CSP
        GostCertificate containerCert =
                GostCertificate.fromPemOrDer(Files.readAllBytes(containerCertPath));

        ECParameters params = containerCert.getPublicKey().getParams();

        // Читаем CA ключ (PKCS#8 PEM)
        byte[] caKeyDer = GostPemUtils.pemToDer(Files.readAllBytes(caKeyPath));
        PrivateKeyParameters caPriv = GostDerCodec.decodePrivateKey(caKeyDer);

        // Читаем CA сертификат
        GostCertificate caCert = GostCertificate.fromPemOrDer(Files.readAllBytes(caCertPath));

        // Выпускаем новый сертификат с тем же ключом и subject, подписанный CA
        GostCertificate signedCert =
                GostCertificateBuilder.fromCertificate(containerCert, params)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_CLIENT_AUTH)
                        .randomSerial()
                        .sign(caPriv);

        // Сохраняем как DER
        byte[] certPem = signedCert.toPem().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Files.write(outPath, GostPemUtils.pemToDer(certPem));
        System.out.println("Signed cert (DER): " + outPath.toAbsolutePath());

        caPriv.destroy();
    }
}
