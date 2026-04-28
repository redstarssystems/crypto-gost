package org.rssys.bench;

import org.rssys.gost.api.CmacApi;
import org.rssys.gost.api.Digest;
import org.rssys.gost.cipher.SymmetricKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * CLI-утилита для кросс-валидации MAC/хэш с OpenSSL.
 *
 * Использование:
 *   MacTool streebog256 <infile>          — вычислить Streebog-256
 *   MacTool streebog512 <infile>          — вычислить Streebog-512
 *   MacTool hmac256 <keyhex> <infile>     — вычислить HMAC-Streebog-256
 *   MacTool hmac512 <keyhex> <infile>     — вычислить HMAC-Streebog-512
 *   MacTool cmac    <keyhex> <infile>     — вычислить CMAC-Kuznyechik
 *
 * Вывод: hex в нижнем регистре без разделителей (совместимо с openssl dgst -r).
 * Завершается с кодом 1 при ошибке.
 */
public class MacTool {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            System.exit(1);
        }

        String algo = args[0].toLowerCase();

        try {
            switch (algo) {
                case "streebog256": {
                    requireArgs(args, 2, "streebog256 <infile>");
                    byte[] data = readFile(args[1]);
                    System.out.println(hex(Digest.digest256(data)));
                    break;
                }
                case "streebog512": {
                    requireArgs(args, 2, "streebog512 <infile>");
                    byte[] data = readFile(args[1]);
                    System.out.println(hex(Digest.digest512(data)));
                    break;
                }
                case "hmac256": {
                    requireArgs(args, 3, "hmac256 <keyhex> <infile>");
                    SymmetricKey key = keyFromHex(args[1]);
                    byte[] data = readFile(args[2]);
                    System.out.println(hex(Digest.hmac256(data, key)));
                    break;
                }
                case "hmac512": {
                    requireArgs(args, 3, "hmac512 <keyhex> <infile>");
                    SymmetricKey key = keyFromHex(args[1]);
                    byte[] data = readFile(args[2]);
                    System.out.println(hex(Digest.hmac512(data, key)));
                    break;
                }
                case "cmac": {
                    requireArgs(args, 3, "cmac <keyhex> <infile>");
                    SymmetricKey key = keyFromHex(args[1]);
                    byte[] data = readFile(args[2]);
                    System.out.println(hex(CmacApi.cmac(data, key)));
                    break;
                }
                default:
                    System.err.println("Неизвестный алгоритм: " + algo);
                    usage();
                    System.exit(1);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Ошибка: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Ошибка чтения файла: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void requireArgs(String[] args, int required, String usage) {
        if (args.length < required) {
            throw new IllegalArgumentException("Недостаточно аргументов. Использование: MacTool " + usage);
        }
    }

    private static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    private static SymmetricKey keyFromHex(String hexKey) {
        byte[] keyBytes = fromHex(hexKey);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException(
                "Ключ должен быть 32 байта (64 hex-символа), получено: " + keyBytes.length);
        }
        return new SymmetricKey(keyBytes);
    }

    private static byte[] fromHex(String hex) {
        hex = hex.trim();
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Нечётная длина hex-строки: " + hex.length());
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2),     16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Некорректный hex-символ в позиции " + (i * 2));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    static String hex(byte[] d) {
        if (d == null || d.length == 0) return "";
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static void usage() {
        System.err.println("Использование:");
        System.err.println("  MacTool streebog256 <infile>");
        System.err.println("  MacTool streebog512 <infile>");
        System.err.println("  MacTool hmac256 <keyhex> <infile>");
        System.err.println("  MacTool hmac512 <keyhex> <infile>");
        System.err.println("  MacTool cmac    <keyhex> <infile>");
    }
}
