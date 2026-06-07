package org.rssys.gost.crossval.kuznyechik;

import org.rssys.gost.api.Cipher;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.SymmetricKey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Утилита для кросс-версионной проверки совместимности между разными версиями crypto-gost.
 * Запускается как subprocess с JAR предыдущей версии на classpath.
 * Читает данные из файла, пишет результат в файл — не через аргументы,
 * чтобы избежать ограничения длины командной строки.
 *
 * <pre>
 * CrossVersionTool &lt;ctr|cbc|cfb|ofb&gt; &lt;encrypt|decrypt&gt;
 *     &lt;keyHex&gt; &lt;ivHex&gt; &lt;inFile&gt; &lt;outFile&gt;
 * </pre>
 *
 * IV для CTR: используются первые 8 байт, остальные игнорируются.
 * Padding для CBC: PKCS7 (по умолчанию Cipher).
 */
public class CrossVersionTool {

    public static void main(String[] args) throws Exception {
        if (args.length < 6) {
            System.err.println("Использование:");
            System.err.println("  CrossVersionTool <ctr|cbc|cfb|ofb> <encrypt|decrypt>");
            System.err.println("                  <keyHex> <ivHex> <inFile> <outFile>");
            System.err.println("  CrossVersionTool mgm <seal|open>");
            System.err.println("                  <keyHex> <icnHex> <inFile> <outFile>");
            System.exit(1);
        }

        String mode = args[0].toLowerCase();

        if ("mgm".equals(mode)) {
            handleMgm(args);
            return;
        }

        boolean encrypt = args[1].equalsIgnoreCase("encrypt");
        byte[] keyBytes = hex(args[2]);
        byte[] iv = hex(args[3]);
        Path inFile = Paths.get(args[4]);
        Path outFile = Paths.get(args[5]);

        byte[] data = Files.readAllBytes(inFile);
        SymmetricKey key = new SymmetricKey(keyBytes);

        Cipher.Mode cipherMode;
        switch (mode) {
            case "ctr":
                cipherMode = Cipher.Mode.CTR;
                if (iv.length > 8) {
                    byte[] truncatedIv = new byte[8];
                    System.arraycopy(iv, 0, truncatedIv, 0, 8);
                    iv = truncatedIv;
                }
                break;
            case "cbc":
                cipherMode = Cipher.Mode.CBC;
                break;
            case "cfb":
                cipherMode = Cipher.Mode.CFB;
                break;
            case "ofb":
                cipherMode = Cipher.Mode.OFB;
                break;
            default:
                System.err.println("Неизвестный режим: " + mode);
                System.exit(1);
                return;
        }

        byte[] result;
        if (encrypt) {
            result = Cipher.encrypt(data, key, iv, cipherMode);
        } else {
            result = Cipher.decrypt(data, key, iv, cipherMode);
        }

        Files.write(outFile, result);
    }

    /**
     * Обработка MGM subcommand.
     * args: mgm <seal|open> <keyHex> <icnHex> <inFile> <outFile>
     *
     * ICN генерируется случайно на каждый тестовый случай (в CrossVersionTest),
     * не фиксирован — каждый вызов seal с новым ICN, повтора ICN при одном ключе не происходит.
     * AAD пустой — тест проверяет совместимость ядра MGM, не AAD-обработку.
     */
    private static void handleMgm(String[] args) throws Exception {
        boolean seal = args[1].equalsIgnoreCase("seal");
        byte[] keyBytes = hex(args[2]);
        byte[] icn = hex(args[3]);
        Path inFile = Paths.get(args[4]);
        Path outFile = Paths.get(args[5]);

        SymmetricKey key = new SymmetricKey(keyBytes);
        byte[] data = Files.readAllBytes(inFile);

        byte[] result;
        if (seal) {
            result = MgmCipher.sealWithIcn(data, key, icn, new byte[0]);
        } else {
            result = MgmCipher.open(data, key, new byte[0]);
        }
        Files.write(outFile, result);
    }

    /** Парсит hex-строку в массив байт. */
    static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }
}
