package org.rssys.gost.pkix.examples;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder;
import org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * CLI-утилита шифрования и расшифрования файлов через CMS EnvelopedData.
 *
 * <h2>Примеры использования</h2>
 *
 * <pre>
 * 1. Сгенерировать тестовый сертификат и ключ (одноразово):
 *   java CmsEnvelopeTool gen --key key.der --cert cert.der
 *
 * 2. Зашифровать файл с помощью crypto-gost:
 *   java CmsEnvelopeTool encrypt --in secret.txt --cert cert.der
 *
 * 3. Расшифровать файл с помощью crypto-gost:
 *   java CmsEnvelopeTool decrypt --in secret.txt.p7e --key key.der --cert cert.der
 *
 * 4. Зашифровать без имитовставки (по умолчанию применяется OMAC; режим без неё — только явный выбор):
 *   java CmsEnvelopeTool encrypt --in secret.txt --cert cert.der --no-integrity
 *   java CmsEnvelopeTool decrypt --in secret.txt.p7e --key key.der --cert cert.der --no-integrity
 *
 * 5. Зашифровать в формате KeyAgreeRecipientInfo (kari):
 *   java CmsEnvelopeTool encrypt --in secret.txt --cert cert.der --kari
 *
 * 6. Зашифровать, явно указав KeyTransRecipientInfo (ktri, по умолчанию):
 *   java CmsEnvelopeTool encrypt --in secret.txt --cert cert.der --ktri
 *
 * 7. Зашифровать с помощью КриптоПРО (если установлен):
 *   java CmsEnvelopeTool encrypt-cp --in secret.txt --cert cert.der
 *
 * 8. Расшифровать с помощью КриптоПРО:
 *   java CmsEnvelopeTool decrypt-cp --in secret.txt.p7e --container MyContainer
 * </pre>
 */
public final class CmsEnvelopeTool {
    // Флаг отказа от имитовставки: при шифровании — без OMAC, при расшифровании — принять контейнер
    // без OMAC
    private static final String FLAG_NO_INTEGRITY = "--no-integrity";

    static {
        Security.insertProviderAt(new RssysGostProvider(), 1);
    }

    private CmsEnvelopeTool() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printHelp();
            return;
        }

        String command = args[0];
        switch (command) {
            case "gen" -> cmdGen(shift(args));
            case "encrypt" -> cmdEncrypt(shift(args), false);
            case "decrypt" -> cmdDecrypt(shift(args), false);
            case "encrypt-cp" -> cmdEncryptCp(shift(args));
            case "decrypt-cp" -> cmdDecryptCp(shift(args));
            default -> {
                System.err.println("Неизвестная команда: " + command);
                printHelp();
            }
        }
    }

    // ================================================================================
    // Команды crypto-gost
    // ================================================================================

    /**
     * Генерация тестового сертификата и ключа (self-signed GOST).
     */
    static void cmdGen(String[] args) throws Exception {
        String keyFile = getArg(args, "--key");
        String certFile = getArg(args, "--cert");
        if (keyFile == null || certFile == null) {
            System.err.println("--key и --cert обязательны");
            return;
        }

        var params = org.rssys.gost.signature.ECParameters.tc26a256();
        var kp = org.rssys.gost.api.KeyGenerator.generateKeyPair(params);

        byte[] keyDer = GostDerCodec.encodePrivateKey(kp.getPrivate());
        Files.write(Path.of(keyFile), keyDer);
        System.out.println("Ключ записан: " + keyFile);

        GostCertificate cert =
                GostCertificateBuilder.create(params, "CN=TestCert,O=crypto-gost,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sign(kp.getPrivate());
        byte[] certDer = cert.getEncoded();
        Files.write(Path.of(certFile), certDer);
        System.out.println("Сертификат записан: " + certFile);

        kp.getPrivate().destroy();
        System.out.println("Готово. Используйте --key " + keyFile + " --cert " + certFile);
    }

    private static void cmdEncrypt(String[] args, boolean cryptopro) throws Exception {
        String inFile = getArg(args, "--in");
        String certFile = getArg(args, "--cert");
        boolean noIntegrity = hasFlag(args, FLAG_NO_INTEGRITY);
        boolean kari = hasFlag(args, "--kari");

        if (inFile == null || certFile == null) {
            System.err.println("--in и --cert обязательны");
            return;
        }

        byte[] data = Files.readAllBytes(Path.of(inFile));
        byte[] certDer = Files.readAllBytes(Path.of(certFile));
        GostCertificate cert = GostCertificate.fromDer(certDer);

        System.out.println(
                "Шифрую "
                        + data.length
                        + " байт для получателя: "
                        + cert.getSubjectDn().toString());

        var builder =
                (kari ? CmsEnvelopedDataBuilder.createKari() : CmsEnvelopedDataBuilder.create())
                        .data(data)
                        .addRecipient(cert);
        if (noIntegrity) builder = builder.withoutIntegrity();

        String mode = (kari ? "kari" : "ktri") + (noIntegrity ? ", без имитовставки" : "+omac");
        System.out.println("Режим: " + mode);

        byte[] enveloped = builder.build();
        String outFile = getArg(args, "--out");
        if (outFile == null) outFile = inFile + ".p7e";
        Files.write(Path.of(outFile), enveloped);
        System.out.println("Зашифровано: " + outFile + " (" + enveloped.length + " байт)");
    }

    private static void cmdDecrypt(String[] args, boolean cryptopro) throws Exception {
        String inFile = getArg(args, "--in");
        String keyFile = getArg(args, "--key");
        String certFile = getArg(args, "--cert");

        if (inFile == null || keyFile == null || certFile == null) {
            System.err.println("--in, --key и --cert обязательны");
            return;
        }

        byte[] p7e = Files.readAllBytes(Path.of(inFile));
        byte[] keyDer = Files.readAllBytes(Path.of(keyFile));
        byte[] certDer = Files.readAllBytes(Path.of(certFile));

        PrivateKeyParameters key = GostDerCodec.decodePrivateKey(keyDer);
        GostCertificate cert = GostCertificate.fromDer(certDer);

        try {
            // Контейнер без имитовставки принимается только по явному флагу
            byte[] dec =
                    hasFlag(args, FLAG_NO_INTEGRITY)
                            ? CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(p7e, key, cert)
                            : CmsEnvelopedDataDecryptor.decrypt(p7e, key, cert);
            String outFile = getArg(args, "--out");
            if (outFile == null) outFile = inFile.replace(".p7e", "");
            Files.write(Path.of(outFile), dec);
            System.out.println("Расшифровано: " + outFile + " (" + dec.length + " байт)");
        } catch (PkixException e) {
            System.err.println("Ошибка расшифрования: " + e.getMessage());
        } finally {
            key.destroy();
        }
    }

    // ================================================================================
    // Команды КриптоПРО
    // ================================================================================

    private static void cmdEncryptCp(String[] args) throws Exception {
        String inFile = getArg(args, "--in");
        String certFile = getArg(args, "--cert");

        if (inFile == null || certFile == null) {
            System.err.println("--in и --cert обязательны");
            return;
        }

        String cryptcp = findCryptcp();
        if (cryptcp == null) {
            System.err.println("КриптоПРО cryptcp не найден");
            return;
        }

        System.out.println("Шифрую " + inFile + " через КриптоПРО...");
        Process p = new ProcessBuilder(cryptcp, "-encrf", inFile, "-recip", certFile).start();
        int exit = p.waitFor();
        if (exit == 0) {
            System.out.println("Зашифровано: " + inFile + ".p7e");
        } else {
            System.err.println("Ошибка cryptcp, exit=" + exit);
            new String(p.getErrorStream().readAllBytes())
                    .lines()
                    .filter(l -> !l.isBlank())
                    .forEach(System.err::println);
        }
    }

    private static void cmdDecryptCp(String[] args) throws Exception {
        String inFile = getArg(args, "--in");
        String container = getArg(args, "--container");

        if (inFile == null || container == null) {
            System.err.println("--in и --container обязательны");
            return;
        }

        String cryptcp = findCryptcp();
        if (cryptcp == null) {
            System.err.println("КриптоПРО cryptcp не найден");
            return;
        }

        System.out.println(
                "Расшифровываю " + inFile + " через КриптоПРО (контейнер: " + container + ")...");
        Process p = new ProcessBuilder(cryptcp, "-decrf", inFile, "-container", container).start();
        int exit = p.waitFor();
        if (exit == 0) {
            String outFile = inFile.replace(".p7e", "");
            System.out.println("Расшифровано: " + outFile);
        } else {
            System.err.println("Ошибка cryptcp, exit=" + exit);
            new String(p.getErrorStream().readAllBytes())
                    .lines()
                    .filter(l -> !l.isBlank())
                    .forEach(System.err::println);
        }
    }

    // ================================================================================
    // Утилиты
    // ================================================================================

    private static String findCryptcp() {
        for (String path :
                new String[] {"/opt/cprocsp/bin/amd64/cryptcp", "/opt/cprocsp/bin/cryptcp"}) {
            if (new java.io.File(path).canExecute()) return path;
        }
        return null;
    }

    private static String getArg(String[] args, String name) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals(name)) return args[i + 1];
        }
        return null;
    }

    private static boolean hasFlag(String[] args, String name) {
        for (String a : args) if (a.equals(name)) return true;
        return false;
    }

    private static String[] shift(String[] a) {
        return Arrays.copyOfRange(a, 1, a.length);
    }

    private static void printHelp() {
        System.out.println(
                """
                CmsEnvelopeTool — утилита шифрования/расшифрования файлов (CMS EnvelopedData)

                Команды:

                  gen         Сгенерировать тестовый сертификат и ключ
                             --key KEY.der  --cert CERT.der

                  encrypt     Зашифровать файл (crypto-gost, ktri по умолчанию)
                             --in FILE  --cert CERT.der [--out OUT.p7e] [--no-integrity] [--kari] [--ktri]

                  decrypt     Расшифровать файл (crypto-gost, авто ktri/kari)
                             --in FILE.p7e  --key KEY.der  --cert CERT.der [--out FILE] [--no-integrity]

                  encrypt-cp  Зашифровать файл (КриптоПРО cryptcp)
                             --in FILE  --cert CERT.der

                  decrypt-cp  Расшифровать файл (КриптоПРО cryptcp)
                             --in FILE.p7e  --container NAME

                Режимы:
                  --no-integrity  Без имитовставки (по умолчанию OMAC, ТК26 §8.3.1);
                                  при расшифровании — принять контейнер без OMAC
                  --kari      Формат KeyAgreeRecipientInfo
                  --ktri      Формат KeyTransRecipientInfo (используется по умолчанию)

                Примеры:
                  java CmsEnvelopeTool gen --key mykey.der --cert mycert.cer
                  java CmsEnvelopeTool encrypt --in secret.txt --cert mycert.cer
                  java CmsEnvelopeTool decrypt --in secret.txt.p7e --key mykey.der --cert mycert.cer
                  java CmsEnvelopeTool encrypt --in secret.txt --cert mycert.cer --no-integrity
                  java CmsEnvelopeTool encrypt --in secret.txt --cert mycert.cer --ktri
                  java CmsEnvelopeTool encrypt --in secret.txt --cert mycert.cer --kari
                  java CmsEnvelopeTool encrypt-cp --in secret.txt --cert mycert.cer
                  java CmsEnvelopeTool decrypt-cp --in secret.txt.p7e --container MyContainer
                """);
    }
}
