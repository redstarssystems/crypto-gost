package org.rssys.gost.crossval.kuznyechik;

import org.rssys.gost.api.Cipher;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Вспомогательный класс для кросс-валидации с OpenSSL.
 * Работа с предыдущей версией crypto-gost вынесена в {@link OldVersionWorker}.
 */
public final class CompatHelper {

    private static String OPENSSL_BIN;
    private static String[] ENGINE_FLAG;

    private static void ensureInit() {
        if (OPENSSL_BIN == null) {
            OPENSSL_BIN = OpenSslChecker.resolveOpenSslBinary();
            ENGINE_FLAG = OpenSslChecker.resolveEngineFlag();
        }
    }

    private CompatHelper() {}

    /**
     * Выполняет операцию шифрования/расшифрования через {@code openssl enc}.
     */
    public static byte[] opensslOp(
            Cipher.Mode mode, String op,
            byte[] key, byte[] iv, byte[] input, boolean nopad) throws Exception {
        ensureInit();

        String osslMode = mode.name().toLowerCase();
        String keyHex = CrossValUtils.toHex(key);
        String ivHex = CrossValUtils.toHex(iv);

        return TempDirUtils.withTempDir("ossl-", tmpDir -> {
            Path inFile = tmpDir.resolve("in.bin");
            Path outFile = tmpDir.resolve("out.bin");
            Files.write(inFile, input);
            List<String> args = new ArrayList<>();
            args.add(OPENSSL_BIN);
            args.add("enc");
            args.addAll(List.of(ENGINE_FLAG));
            args.add(op);
            args.add("-kuznyechik-" + osslMode);
            args.add("-K");
            args.add(keyHex);
            args.add("-iv");
            args.add(ivHex);
            if (nopad) {
                args.add("-nopad");
            }
            args.add("-in");
            args.add(inFile.toAbsolutePath().toString());
            args.add("-out");
            args.add(outFile.toAbsolutePath().toString());
            ProcessBuilder processBuilder = new ProcessBuilder(args);
            processBuilder.redirectErrorStream(true);
            processBuilder.environment().putAll(OpenSslChecker.getOpenSslEnv());
            Process process = processBuilder.start();
            byte[] outputBytes = process.getInputStream().readAllBytes();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                String cmdLine = String.join(" ", args);
                throw new RuntimeException("openssl failed (exit=" + exitCode + ")\n  command: " + cmdLine + "\n  output: " + new String(outputBytes));
            }
            return Files.readAllBytes(outFile);
        });
    }

    /**
     * Выполняет операцию шифрования/расшифрования через {@code openssl enc}.
     * Без отключения паддинга (для режимов с PKCS7).
     */
    public static byte[] opensslOp(
            Cipher.Mode mode, String op,
            byte[] key, byte[] iv, byte[] input) throws Exception {
        return opensslOp(mode, op, key, iv, input, false);
    }
}
