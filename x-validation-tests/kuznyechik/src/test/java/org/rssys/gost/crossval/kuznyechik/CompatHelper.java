package org.rssys.gost.crossval.kuznyechik;

import org.rssys.gost.api.Cipher;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Вспомогательный класс для кросс-версионных тестов и кросс-валидации с OpenSSL.
 * Содержит общие для тестов методы: запуск subprocess со старой версией,
 * работа с OpenSSL через subprocess.
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
     * Запускает {@code CrossVersionTool} на старой версии JAR как subprocess.
     * Через файлы на диске передаёт ключ, IV, входные данные и читает результат.
     */
    public static byte[] runSubprocess(
            String oldJar, String compatClasses,
            Cipher.Mode mode, String op,
            byte[] key, byte[] iv, byte[] input) throws Exception {

        return TempDirUtils.withTempDir("cv-", tmpDir -> {
            Path inFile = tmpDir.resolve("in.bin");
            Path outFile = tmpDir.resolve("out.bin");
            Files.write(inFile, input);
            String modeStr = mode.name().toLowerCase();
            String keyHex = CrossValUtils.toHex(key);
            byte[] iv16 = new byte[16];
            System.arraycopy(iv, 0, iv16, 0, Math.min(iv.length, 16));
            String ivHex = CrossValUtils.toHex(iv16);
            String javaExecutable = System.getProperty("java.home")
                    + File.separator + "bin" + File.separator + "java";
            String classpath = oldJar + File.pathSeparator + compatClasses;

            ProcessBuilder processBuilder = new ProcessBuilder(
                    javaExecutable,
                    "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                    "--add-opens", "java.base/java.util=ALL-UNNAMED",
                    "--add-opens", "java.base/java.io=ALL-UNNAMED",
                    "--add-opens", "java.base/java.text=ALL-UNNAMED",
                    "--add-opens", "java.base/jdk.internal.misc=ALL-UNNAMED",
                    "-cp", classpath,
                    CrossVersionTool.class.getName(),
                    modeStr, op, keyHex, ivHex,
                    inFile.toAbsolutePath().toString(),
                    outFile.toAbsolutePath().toString()
            );
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            byte[] outputBytes = process.getInputStream().readAllBytes();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("Subprocess failed (exit=" + exitCode + "): " + new String(outputBytes));
            }
            return Files.readAllBytes(outFile);
        });
    }

    /**
     * Запускает MGM-операцию на старой версии JAR crypto-gost как subprocess.
     */
    public static byte[] runMgmSubprocess(
            String oldJar, String compatClasses,
            String op, byte[] key, byte[] icn, byte[] input) throws Exception {

        return TempDirUtils.withTempDir("mgm-", tmpDir -> {
            Path inFile = tmpDir.resolve("in.bin");
            Path outFile = tmpDir.resolve("out.bin");
            Files.write(inFile, input);
            String keyHex = CrossValUtils.toHex(key);
            String icnHex = CrossValUtils.toHex(icn);
            String javaExecutable = System.getProperty("java.home")
                    + File.separator + "bin" + File.separator + "java";
            String classpath = oldJar + File.pathSeparator + compatClasses;

            ProcessBuilder processBuilder = new ProcessBuilder(
                    javaExecutable,
                    "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                    "--add-opens", "java.base/java.util=ALL-UNNAMED",
                    "--add-opens", "java.base/java.io=ALL-UNNAMED",
                    "--add-opens", "java.base/java.text=ALL-UNNAMED",
                    "--add-opens", "java.base/jdk.internal.misc=ALL-UNNAMED",
                    "-cp", classpath,
                    CrossVersionTool.class.getName(),
                    "mgm", op, keyHex, icnHex,
                    inFile.toAbsolutePath().toString(),
                    outFile.toAbsolutePath().toString()
            );
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            byte[] outputBytes = process.getInputStream().readAllBytes();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("Subprocess mgm failed (exit=" + exitCode + "): " + new String(outputBytes));
            }
            return Files.readAllBytes(outFile);
        });
    }

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
