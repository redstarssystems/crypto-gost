package org.rssys.bench;

import org.rssys.gost.api.Cipher;
import org.rssys.gost.cipher.SymmetricKey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class KuznyechikTool {

  public static void main(String[] args) throws Exception {
    if (args.length < 6) {
      System.err.println("Usage:");
      System.err.println("  KuznyechikTool <ctr|cbc|cbc-nopad|cfb|ofb> <encrypt|decrypt>");
      System.err.println("            <keyhex> <ivhex> <infile> <outfile>");
      System.exit(1);
    }

    String mode = args[0].toLowerCase();
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
          byte[] tmp = new byte[8];
          System.arraycopy(iv, 0, tmp, 0, 8);
          iv = tmp;
        }
        break;
      case "cbc":
        cipherMode = Cipher.Mode.CBC;
        break;
      case "cbc-nopad":
        cipherMode = Cipher.Mode.CBC;
        break;
      case "cfb":
        cipherMode = Cipher.Mode.CFB;
        break;
      case "ofb":
        cipherMode = Cipher.Mode.OFB;
        break;
      default:
        System.err.println("Unknown mode: " + mode);
        System.exit(1);
        return;
    }

    Cipher.Padding padding = Cipher.Padding.PKCS7;
    if (mode.equals("cbc-nopad")) {
      padding = Cipher.Padding.NONE;
    }

    byte[] result;
    if (encrypt) {
      result = Cipher.encrypt(data, key, iv, cipherMode, padding);
    } else {
      result = Cipher.decrypt(data, key, iv, cipherMode, padding);
    }

    Files.write(outFile, result);
  }

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
