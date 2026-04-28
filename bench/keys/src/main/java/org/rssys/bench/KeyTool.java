package org.rssys.bench;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class KeyTool {

  public static void main(String[] args) throws Exception {
    if (args.length < 4 || !"genkey".equals(args[0])) {
      System.err.println("Usage:");
      System.err.println("  KeyTool genkey <curve> <pub-out.der> <priv-out.der>");
      System.err.println();
      System.err.println("Curves: cryptopro-A, cryptopro-B, cryptopro-C,");
      System.err.println("        tc26-gost-A-256, tc26-gost-A-512,");
      System.err.println("        tc26-gost-B-512, tc26-gost-C-512");
      System.exit(1);
    }

    String curveName = args[1];
    Path pubOut = Paths.get(args[2]);
    Path privOut = Paths.get(args[3]);

    ECParameters params = GostCurves.byName(curveName);
    KeyPair pair = KeyGenerator.generateKeyPair(params);

    byte[] pubDer = GostDerCodec.encodePublicKey(pair.getPublic());
    byte[] privDer = GostDerCodec.encodePrivateKey(pair.getPrivate());

    Files.write(pubOut, pubDer);
    Files.write(privOut, privDer);

    System.out.println("PUB_DER:  " + pubOut.toAbsolutePath() + " (" + pubDer.length + " bytes)");
    System.out.println("PRIV_DER: " + privOut.toAbsolutePath() + " (" + privDer.length + " bytes)");
    System.out.println("CURVE: " + curveName);
    System.out.println("OID: " + GostCurves.oidOf(params));
  }
}
