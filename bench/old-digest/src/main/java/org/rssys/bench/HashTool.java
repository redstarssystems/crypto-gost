package org.rssys.bench;

import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HashTool {

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println("Usage: HashTool <streebog256|streebog512> <infile>");
      System.exit(1);
    }

    byte[] data = Files.readAllBytes(Paths.get(args[1]));

    switch (args[0].toLowerCase()) {
      case "streebog256": {
        Streebog256 d = new Streebog256();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        System.out.println(hex(out));
        break;
      }
      case "streebog512": {
        Streebog512 d = new Streebog512();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        System.out.println(hex(out));
        break;
      }
      default:
        System.err.println("Unknown algorithm: " + args[0]);
        System.exit(1);
    }
  }

  static String hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
