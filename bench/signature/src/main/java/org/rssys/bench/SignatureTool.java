package org.rssys.bench;

import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * CLI-мост для кросс-валидации подписи crypto-gost ↔ OpenSSL.
 *
 * <p>Режимы:
 * <pre>
 *   sign   &lt;curve&gt; &lt;privkey-hex&gt; &lt;msg-file&gt; &lt;sig-file&gt;
 *       Подписывает сообщение из msg-file, записывает подпись (s||r, big-endian, X.509-формат) в sig-file.
 *
 *   pubkey &lt;curve&gt; &lt;privkey-hex&gt; &lt;out-file&gt;
 *       Выводит публичный ключ в формате DER SubjectPublicKeyInfo в out-file.
 *       Формат совместим с OpenSSL: openssl dgst -verify pub.der ...
 * </pre>
 *
 * <p>Поддерживаемые кривые (совместимые с OpenSSL gostprov):
 * <ul>
 *   <li>{@code cryptopro-A} — CryptoPro-A, OID 1.2.643.2.2.35.1, OpenSSL paramset A</li>
 *   <li>{@code cryptopro-B} — CryptoPro-B, OID 1.2.643.2.2.35.2, OpenSSL paramset B</li>
 *   <li>{@code cryptopro-C} — CryptoPro-C, OID 1.2.643.2.2.35.3, OpenSSL paramset C</li>
 * </ul>
 */
public class SignatureTool {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            printUsage();
            System.exit(1);
        }

        String mode = args[0].toLowerCase();
        switch (mode) {
            case "sign":
                if (args.length < 5) { printUsage(); System.exit(1); }
                doSign(args[1], args[2], args[3], args[4]);
                break;
            case "pubkey":
                if (args.length < 4) { printUsage(); System.exit(1); }
                doPubkey(args[1], args[2], args[3]);
                break;
            default:
                System.err.println("Unknown mode: " + mode);
                printUsage();
                System.exit(1);
        }
    }

    /**
     * Подписывает сообщение из {@code msgFile} закрытым ключом {@code privHex}
     * на кривой {@code curve} и записывает подпись в {@code sigFile}.
     * Формат подписи: s || r, big-endian, каждая компонента rolen байт (X.509-формат).
     */
    static void doSign(String curve, String privHex, String msgFile, String sigFile)
            throws Exception {
        ECParameters params = resolveCurve(curve);
        // Редуцируем d по модулю n: скрипт передаёт openssl rand -hex 32 который
        // может быть >= n для кривых с n < 2^256 (CryptoPro-B, CryptoPro-C).
        BigInteger d = new BigInteger(privHex, 16).mod(params.n);
        if (d.signum() == 0) d = BigInteger.ONE;
        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);

        byte[] message = Files.readAllBytes(Paths.get(msgFile));
        byte[] sig = Signature.sign(message, priv);

        priv.destroy();
        Files.write(Paths.get(sigFile), sig);
    }

    /**
     * Вычисляет публичный ключ Q = d·G и записывает его в {@code outFile}
     * в формате DER SubjectPublicKeyInfo, совместимом с OpenSSL:
     * {@code openssl dgst -verify pub.der -signature sig.bin msg.bin}
     */
    static void doPubkey(String curve, String privHex, String outFile)
            throws Exception {
        ECParameters params = resolveCurve(curve);
        BigInteger d = new BigInteger(privHex, 16).mod(params.n);
        if (d.signum() == 0) d = BigInteger.ONE;
        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);

        // Q = d·G через высокоуровневый API
        PublicKeyParameters pub = Signature.derivePublicKey(priv);
        priv.destroy();

        byte[] derBytes = GostDerCodec.encodePublicKey(pub);
        Files.write(Paths.get(outFile), derBytes);
    }

    /**
     * Резолвит имя кривой в ECParameters.
     * Только кривые с OID совместимыми с OpenSSL gostprov.
     */
    static ECParameters resolveCurve(String curve) {
        // Используем реестр GostCurves для унификации
        ECParameters params = GostCurves.byName(curve);
        if (params == null) {
            System.err.println("Unknown curve: " + curve);
            System.err.println("Supported: cryptopro-A, cryptopro-B, cryptopro-C");
            System.exit(1);
        }
        return params;
    }

    static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  SignatureTool sign   <curve> <privkey-hex> <msg-file> <sig-file>");
        System.err.println("  SignatureTool pubkey <curve> <privkey-hex> <out-file>");
        System.err.println("");
        System.err.println("Curves (OpenSSL-compatible, 256-bit only):");
        System.err.println("  cryptopro-A  (OID 1.2.643.2.2.35.1, OpenSSL paramset A)");
        System.err.println("  cryptopro-B  (OID 1.2.643.2.2.35.2, OpenSSL paramset B)");
        System.err.println("  cryptopro-C  (OID 1.2.643.2.2.35.3, OpenSSL paramset C)");
    }
}
