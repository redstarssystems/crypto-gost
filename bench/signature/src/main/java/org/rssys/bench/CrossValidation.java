package org.rssys.bench;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class CrossValidation {

  // 100 сообщений на кривую — достаточно для проверки корректности,
  // не слишком долго для медленных 512-бит кривых (~40 ops/s).
  private static final int NUM_MESSAGES = 100;
  private static final int MSG_SIZE = 1024;

  private static int totalTests = 0;
  private static int totalFails = 0;

  record CurveSpec(String name, String bits, Supplier<ECParameters> paramsFn, int rolen) {}

  static final CurveSpec[] CURVES = {
      new CurveSpec("TC26-A-256",  "256-bit", ECParameters::tc26a256,   32),
      new CurveSpec("CryptoPro-A", "256-bit", ECParameters::cryptoProA, 32),
      new CurveSpec("CryptoPro-B", "256-bit", ECParameters::cryptoProB, 32),
      new CurveSpec("CryptoPro-C", "256-bit", ECParameters::cryptoProC, 32),
      new CurveSpec("TC26-A-512",  "512-bit", ECParameters::tc26a512,  64),
      new CurveSpec("TC26-B-512",  "512-bit", ECParameters::tc26b512,  64),
      new CurveSpec("TC26-C-512",  "512-bit", ECParameters::tc26c512,  64),
  };

  public static void main(String[] args) {
    int filterBits = 0;
    for (int i = 0; i < args.length; i++) {
      if ("--bits".equals(args[i]) && i + 1 < args.length) {
        filterBits = Integer.parseInt(args[i + 1]);
        i++;
      }
    }

    String bitLabel;
    if (filterBits == 256) {
      bitLabel = "256-";
    } else if (filterBits == 512) {
      bitLabel = "512-";
    } else {
      bitLabel = "";
    }

    System.out.println("=".repeat(68));
    System.out.println("  \u041A\u0440\u043E\u0441\u0441-\u0432\u0430\u043B\u0438\u0434\u0430\u0446\u0438\u044F: crypto-gost \u2194 BouncyCastle 1.83");
    System.out.println("  \u041F\u043E\u0434\u043F\u0438\u0441\u044C: \u0413\u041E\u0421\u0422 \u0420 34.10-2012 (" + bitLabel + "\u0432\u0441\u0435 \u043A\u0440\u0438\u0432\u044B\u0435)");
    System.out.println("=".repeat(68));
    System.out.println();

    SecureRandom rnd = new SecureRandom();
    byte[][] messages = new byte[NUM_MESSAGES][MSG_SIZE];
    for (int i = 0; i < NUM_MESSAGES; i++) {
      rnd.nextBytes(messages[i]);
    }

    for (CurveSpec spec : CURVES) {
      if (filterBits == 256 && spec.rolen() != 32) continue;
      if (filterBits == 512 && spec.rolen() != 64) continue;
      testCurve(spec, messages);
    }

    System.out.println("=".repeat(68));
    if (totalFails == 0) {
      System.out.println("  All " + totalTests + " cross-validation checks PASSED. \u2713");
    } else {
      System.out.println("  FAILED! " + totalFails + " / " + totalTests + " checks failed.");
    }
    System.out.println("=".repeat(68));

    System.exit(totalFails > 0 ? 1 : 0);
  }

  static void testCurve(CurveSpec spec, byte[][] messages) {
    System.out.println("--- " + spec.name() + " (" + spec.bits() + ") ---");

    ECParameters params = spec.paramsFn().get();
    KeyPair pair = KeyGenerator.generateKeyPair(params);
    PrivateKeyParameters gostPriv = pair.getPrivate();
    PublicKeyParameters gostPub = pair.getPublic();

    BigInteger d = gostPriv.getD();
    BigInteger qx = gostPub.getQ().normalize().getX();
    BigInteger qy = gostPub.getQ().normalize().getY();

    ECCurve curve = new ECCurve.Fp(params.p, params.a, params.b);
    org.bouncycastle.math.ec.ECPoint g = curve.createPoint(params.gx, params.gy);
    ECDomainParameters bcDomain = new ECDomainParameters(curve, g, params.n);
    org.bouncycastle.math.ec.ECPoint bcQ = curve.createPoint(qx, qy);

    ECPrivateKeyParameters bcPriv = new ECPrivateKeyParameters(d, bcDomain);
    ECPublicKeyParameters bcPub = new ECPublicKeyParameters(bcQ, bcDomain);

    int dir1Fails  = testDir1(spec, messages, gostPriv, bcPub);
    int dir2Fails  = testDir2(spec, messages, gostPub, bcPriv);
    int tamperFails = testTamper(spec, messages, gostPriv, gostPub, bcPriv, bcPub);

    totalTests += 2 * NUM_MESSAGES + 2 * NUM_MESSAGES;
    totalFails += dir1Fails + dir2Fails + tamperFails;

    System.out.println();
  }

  static int testDir1(CurveSpec spec, byte[][] messages,
                       PrivateKeyParameters gostPriv,
                       ECPublicKeyParameters bcPub) {
    int fails = 0;
    for (int i = 0; i < NUM_MESSAGES; i++) {
      byte[] gostSig = Signature.sign(messages[i], gostPriv);

      BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(gostSig, 0, spec.rolen()));
      BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(gostSig, spec.rolen(), 2 * spec.rolen()));

      Digest bcDigest = newDigest(spec);
      byte[] hash = new byte[bcDigest.getDigestSize()];
      bcDigest.update(messages[i], 0, messages[i].length);
      bcDigest.doFinal(hash, 0);

      ECGOST3410_2012Signer bcSigner = new ECGOST3410_2012Signer();
      bcSigner.init(false, bcPub);
      if (!bcSigner.verifySignature(hash, r, s)) {
        fails++;
      }
    }
    String s = fails == 0 ? "PASSED" : "FAILED";
    System.out.printf("  %-18s gost\u2192bc  %d/%d %s%n", spec.name(), NUM_MESSAGES - fails, NUM_MESSAGES, s);
    return fails;
  }

  static int testDir2(CurveSpec spec, byte[][] messages,
                       PublicKeyParameters gostPub,
                       ECPrivateKeyParameters bcPriv) {
    int fails = 0;
    for (int i = 0; i < NUM_MESSAGES; i++) {
      Digest bcDigest = newDigest(spec);
      byte[] hash = new byte[bcDigest.getDigestSize()];
      bcDigest.update(messages[i], 0, messages[i].length);
      bcDigest.doFinal(hash, 0);

      ECGOST3410_2012Signer bcSigner = new ECGOST3410_2012Signer();
      bcSigner.init(true, bcPriv);
      BigInteger[] bcSig = bcSigner.generateSignature(hash);

      byte[] encoded = encodeSig(bcSig[0], bcSig[1], spec.rolen());
      if (!Signature.verify(messages[i], encoded, gostPub)) {
        fails++;
      }
    }
    String s = fails == 0 ? "PASSED" : "FAILED";
    System.out.printf("  %-18s bc\u2192gost  %d/%d %s%n", spec.name(), NUM_MESSAGES - fails, NUM_MESSAGES, s);
    return fails;
  }

  /**
   * Tamper-тест: испорченная подпись должна быть отклонена обеими библиотеками.
   * <p>
   * Доказывает что верификация реально проверяет подпись, а не возвращает {@code true} всегда.
   * Портится копия подписи (XOR первого байта r-компоненты) — оригинал не изменяется.
   * <p>
   * Проверяет два направления:
   * <ul>
   *   <li>crypto-gost-подпись испорчена → BC должен отклонить</li>
   *   <li>bc-подпись испорчена → crypto-gost должен отклонить</li>
   * </ul>
   */
  static int testTamper(CurveSpec spec, byte[][] messages,
                        PrivateKeyParameters gostPriv, PublicKeyParameters gostPub,
                        ECPrivateKeyParameters bcPriv, ECPublicKeyParameters bcPub) {
    int fails = 0;

    // Direction 1: gost подписывает, портим, BC должен отклонить
    for (int i = 0; i < NUM_MESSAGES; i++) {
      byte[] gostSig = Signature.sign(messages[i], gostPriv);
      // Портим копию — XOR первого байта r-компоненты
      byte[] tampered = gostSig.clone();
      tampered[0] ^= 0x01;

      BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(tampered, 0, spec.rolen()));
      BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(tampered, spec.rolen(), 2 * spec.rolen()));

      Digest bcDigest = newDigest(spec);
      byte[] hash = new byte[bcDigest.getDigestSize()];
      bcDigest.update(messages[i], 0, messages[i].length);
      bcDigest.doFinal(hash, 0);

      ECGOST3410_2012Signer bcSigner = new ECGOST3410_2012Signer();
      bcSigner.init(false, bcPub);
      // Испорченная подпись ДОЛЖНА быть отклонена — verifySignature должен вернуть false
      if (bcSigner.verifySignature(hash, r, s)) {
        fails++;
      }
    }
    String s1 = fails == 0 ? "PASSED" : "FAILED";
    System.out.printf("  %-18s tamper gost\u2192bc  %d/%d %s%n",
        spec.name(), NUM_MESSAGES - fails, NUM_MESSAGES, s1);

    int tamperBcFails = 0;

    // Direction 2: BC подписывает, портим, crypto-gost должен отклонить
    for (int i = 0; i < NUM_MESSAGES; i++) {
      Digest bcDigest = newDigest(spec);
      byte[] hash = new byte[bcDigest.getDigestSize()];
      bcDigest.update(messages[i], 0, messages[i].length);
      bcDigest.doFinal(hash, 0);

      ECGOST3410_2012Signer bcSigner = new ECGOST3410_2012Signer();
      bcSigner.init(true, bcPriv);
      BigInteger[] bcSig = bcSigner.generateSignature(hash);

      byte[] encoded = encodeSig(bcSig[0], bcSig[1], spec.rolen());
      // Портим копию — XOR первого байта r-компоненты
      byte[] tampered = encoded.clone();
      tampered[0] ^= 0x01;

      // Испорченная подпись ДОЛЖНА быть отклонена — verify должен вернуть false
      if (Signature.verify(messages[i], tampered, gostPub)) {
        tamperBcFails++;
      }
    }
    String s2 = tamperBcFails == 0 ? "PASSED" : "FAILED";
    System.out.printf("  %-18s tamper bc\u2192gost  %d/%d %s%n",
        spec.name(), NUM_MESSAGES - tamperBcFails, NUM_MESSAGES, s2);

    return fails + tamperBcFails;
  }

  static Digest newDigest(CurveSpec spec) {
    if (spec.rolen() == 32) {
      return new org.bouncycastle.crypto.digests.GOST3411_2012_256Digest();
    } else {
      return new org.bouncycastle.crypto.digests.GOST3411_2012_512Digest();
    }
  }

  static byte[] encodeSig(BigInteger r, BigInteger s, int rolen) {
    byte[] result = new byte[2 * rolen];
    byte[] rBytes = r.toByteArray();
    byte[] sBytes = s.toByteArray();
    // BigInteger.toByteArray() добавляет ведущий 0x00 если старший бит установлен — пропускаем его.
    int rStart = (rBytes[0] == 0) ? 1 : 0;
    int sStart = (sBytes[0] == 0) ? 1 : 0;
    int rLen = rBytes.length - rStart;
    int sLen = sBytes.length - sStart;
    // Для валидных ГОСТ-подписей r, s < n, поэтому rLen/sLen <= rolen.
    // Если это не так — данные некорректны; бросаем исключение вместо молчаливой порчи.
    if (rLen > rolen || sLen > rolen) {
      throw new IllegalStateException(
          "r or s exceeds rolen: rLen=" + rLen + " sLen=" + sLen + " rolen=" + rolen);
    }
    System.arraycopy(rBytes, rStart, result, rolen - rLen, rLen);
    System.arraycopy(sBytes, sStart, result, 2 * rolen - sLen, sLen);
    return result;
  }
}
