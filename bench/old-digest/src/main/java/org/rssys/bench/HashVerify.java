package org.rssys.bench;

import org.rssys.gost.digest.Streebog256;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class HashVerify {

    static final String[] SIZES = {"1k", "10k", "100k", "1m", "10m"};

    static final long[] BYTES = {1024, 10240, 102400, 1048576, 10485760};

    public static void main(String[] args) throws Exception {
        boolean allMatch = true;

        System.out.println();
        System.out.println("  === Verification: crypto-gost vs BouncyCastle 1.83 ===");
        System.out.println();

        for (int i = 0; i < SIZES.length; i++) {
            String size = SIZES[i];
            long byteCount = BYTES[i];

            Path path = Paths.get("data", "data-" + size + ".bin");
            if (!Files.exists(path)) {
                System.out.printf("  %-30s — файл не найден, пропускаю\n", path);
                allMatch = false;
                continue;
            }

            byte[] data = Files.readAllBytes(path);

            byte[] gostHash = hashGost(data);
            byte[] bcHash = hashBc(data);

            boolean match = Arrays.equals(gostHash, bcHash);
            if (!match) allMatch = false;

            System.out.printf("  data-%s.bin (%d b):\n", size, byteCount);
            System.out.printf("    crypto-gost : %s\n", toHex(gostHash));
            System.out.printf("    BouncyCastle: %s\n", toHex(bcHash));
            System.out.printf("    %s\n\n", match ? "\u2713 MATCH" : "\u2717 MISMATCH");
        }

        if (allMatch) {
            System.out.println("  === Result: ALL HASHES MATCH \u2713 ===");
        } else {
            System.out.println("  === Result: MISMATCHES FOUND \u2717 ===");
        }
        System.out.println();

        System.exit(allMatch ? 0 : 1);
    }

    static byte[] hashGost(byte[] data) {
        Streebog256 d = new Streebog256();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    static byte[] hashBc(byte[] data) {
        GOST3411_2012_256Digest d = new GOST3411_2012_256Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
