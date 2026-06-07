package org.rssys.gost.crossval.digestmac;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Subprocess openssl для кросс-валидации MAC/хэшей.
 *
 * Флаг -in у openssl mac есть не во всех сборках, поэтому данные
 * подаются через redirectInput. Временные файлы зачищаются в finally.
 */
public final class OpenSslMacHelper {

    private static String OPENSSL_BIN;
    private static String[] ENGINE_FLAG;

    private OpenSslMacHelper() {}

    private static void ensureInit() {
        if (OPENSSL_BIN == null) {
            OPENSSL_BIN = OpenSslChecker.resolveOpenSslBinary();
            ENGINE_FLAG = OpenSslChecker.resolveEngineFlag();
        }
    }

    public static byte[] opensslDgst256(byte[] data) throws Exception {
        return runDgst("md_gost12_256", data);
    }

    public static byte[] opensslDgst512(byte[] data) throws Exception {
        return runDgst("md_gost12_512", data);
    }

    public static byte[] opensslHmac256(byte[] key, byte[] data) throws Exception {
        return runMac("md_gost12_256", null, key, data);
    }

    public static byte[] opensslHmac512(byte[] key, byte[] data) throws Exception {
        return runMac("md_gost12_512", null, key, data);
    }

    public static byte[] opensslCmac(byte[] key, byte[] data) throws Exception {
        return runMac(null, "kuznyechik-cbc", key, data);
    }

    private static byte[] runDgst(String algo, byte[] data) throws Exception {
        ensureInit();
        return TempDirUtils.withTempFile("ossl-dgst-in-", ".bin", inFile -> {
            Files.write(inFile, data);
            String[] cmd = CrossValUtils.concat(
                    new String[]{OPENSSL_BIN, "dgst", "-" + algo, "-r"},
                    ENGINE_FLAG,
                    new String[]{inFile.toAbsolutePath().toString()});
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            int exitCode = p.waitFor();
            if (exitCode != 0) {
                throw new IOException("openssl dgst -" + algo
                        + " завершился ошибкой (exit=" + exitCode + "): " + out);
            }
            return CrossValUtils.fromHex(out.split("\\s+")[0]);
        });
    }

    private static byte[] runMac(String digest, String cipher, byte[] key, byte[] data) throws Exception {
        ensureInit();
        List<String> cmd = new ArrayList<>();
        cmd.add(OPENSSL_BIN);
        cmd.add("mac");
        cmd.addAll(List.of(ENGINE_FLAG));
        if (digest != null) {
            cmd.add("-digest");
            cmd.add(digest);
        }
        if (cipher != null) {
            cmd.add("-cipher");
            cmd.add(cipher);
        }
        cmd.add("-macopt");
        cmd.add("hexkey:" + CrossValUtils.toHex(key));
        cmd.add(digest != null ? "HMAC" : "CMAC");

        return TempDirUtils.withTempFile("ossl-mac-in-", ".bin", inFile -> {
            Files.write(inFile, data);
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
            pb.redirectInput(ProcessBuilder.Redirect.from(inFile.toFile()));
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            int exitCode = p.waitFor();
            if (exitCode != 0) {
                throw new IOException("openssl mac завершился ошибкой (exit="
                        + exitCode + "): " + out);
            }
            return CrossValUtils.fromHex(out);
        });
    }


}
