package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.GostPkcs12Builder;
import org.rssys.gost.tls13.cert.GostPkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Создание PFX-контейнера с ГОСТ-сертификатом и ключом.
 * <p>
 * Генерирует CA и серверный ключ/сертификат, собирает PFX через
 * {@link GostPkcs12Builder}, сохраняет в файл и верифицирует загрузку.
 * <p>
 * Пример запуска:
 * {@snippet :
 * java org.rssys.gost.tls13.examples.PfxExportExample \
 *     --output /tmp/gost-cert.p12 --password changeit \
 *     --friendly-name "GOST Server"
 * }
 */
public final class PfxExportExample {

    private PfxExportExample() {}

    public static void main(String[] args) throws Exception {
        String outputPath = "./gost-cert.p12";
        String password = "changeit";
        String friendlyName = null;
        int iterations = 2000;
        String curveName = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--output":
                    outputPath = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--friendly-name":
                    friendlyName = args[++i];
                    break;
                case "--iterations":
                    iterations = Integer.parseInt(args[++i]);
                    break;
                case "--curve":
                    curveName = args[++i];
                    break;
                default:
                    System.err.println("Unknown flag: " + args[i]);
                    System.exit(1);
            }
        }

        ECParameters params = curveName != null
                ? mapCurve(curveName.toUpperCase())
                : ECParameters.tc26a256();
        // 1. Генерируем CA
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters caPriv = caKp.getPrivate();
        PublicKeyParameters caPub = caKp.getPublic();
        byte[] caDn = ExampleUtils.buildDN("PfxExport CA");
        byte[] bcExt = ExampleUtils.buildBasicConstraintsExt(true, null);
        TlsCertificate caCert = ExampleUtils.createCert(
                caPriv, caPub, caPub, params, caDn, caDn, bcExt);

        // 2. Генерируем серверный ключ и сертификат
        KeyPair serverKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        PublicKeyParameters serverPub = serverKp.getPublic();
        byte[] serverDn = ExampleUtils.buildDN("PfxExport Server");
        byte[] sanExt = ExampleUtils.buildSanExt(new String[]{"localhost"}, null);
        byte[] kuExt = ExampleUtils.buildKeyUsageExt(new byte[]{(byte) 0x80});
        // buildTbs уже оборачивает в SEQUENCE — передаём сырые extension-байты
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(sanExt);
        extBuf.write(kuExt);
        TlsCertificate serverCert = ExampleUtils.createCert(
                caPriv, caPub, serverPub, params, caDn, serverDn, extBuf.toByteArray());

        // 3. Собираем PFX
        byte[] pfx = GostPkcs12Builder.newBuilder()
                .key(serverPriv)
                .certificate(serverCert)
                .caCertificate(caCert)
                .password(password.toCharArray())
                .friendlyName(friendlyName)
                .iterations(iterations)
                .build();

        Path outFile = Path.of(outputPath);
        Files.write(outFile, pfx);
        System.out.println("PFX saved to " + outFile.toAbsolutePath());

        // 4. Верифицируем: загружаем PFX обратно
        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, password.toCharArray());
        PrivateKeyParameters loadedKey = result.getPrivateKey();
        List<TlsCertificate> chain = result.getCertificateChain();

        if (loadedKey == null) {
            System.err.println("ERROR: private key is null");
            System.exit(1);
        }
        System.out.println("Private key: loaded OK");

        if (chain == null || chain.isEmpty()) {
            System.err.println("ERROR: certificate chain is empty");
            System.exit(1);
        }
        System.out.println("Certificate chain: " + chain.size() + " cert(s)");
        for (int i = 0; i < chain.size(); i++) {
            System.out.println("  [" + i + "] isCA=" + chain.get(i).isCA());
        }

        // 5. Подпись/проверка
        byte[] msg = "PfxExportExample verification".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Signature.sign(msg, loadedKey);
        boolean verified = Signature.verify(msg, sig, chain.get(0).getPublicKey());
        if (!verified) {
            System.err.println("ERROR: sign/verify failed");
            System.exit(1);
        }
        System.out.println("Sign/verify: OK");
        System.out.println("SUCCESS");
    }

    private static ECParameters mapCurve(String name) {
        return switch (name) {
            case "GC256A" -> ECParameters.tc26a256();
            case "GC256B" -> ECParameters.cryptoProA();
            case "GC256C" -> ECParameters.cryptoProB();
            case "GC256D" -> ECParameters.cryptoProC();
            case "GC512A" -> ECParameters.tc26a512();
            case "GC512B" -> ECParameters.tc26b512();
            case "GC512C" -> ECParameters.tc26c512();
            default -> throw new IllegalArgumentException("Unknown curve: " + name);
        };
    }
}
