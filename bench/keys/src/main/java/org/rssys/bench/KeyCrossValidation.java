package org.rssys.bench;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

public class KeyCrossValidation {

  private static final SecureRandom RND = new SecureRandom();

  record CurveSpec(String name, String bits, Supplier<ECParameters> paramsFn) {}

  static final CurveSpec[] CURVES = {
      new CurveSpec("TC26-A-256",  "256-bit", ECParameters::tc26a256),
      new CurveSpec("CryptoPro-A", "256-bit", ECParameters::cryptoProA),
      new CurveSpec("CryptoPro-B", "256-bit", ECParameters::cryptoProB),
      new CurveSpec("CryptoPro-C", "256-bit", ECParameters::cryptoProC),
      new CurveSpec("TC26-A-512",  "512-bit", ECParameters::tc26a512),
      new CurveSpec("TC26-B-512",  "512-bit", ECParameters::tc26b512),
      new CurveSpec("TC26-C-512",  "512-bit", ECParameters::tc26c512),
  };

  private static int total = 0;
  private static int ok = 0;
  private static int fail = 0;

  public static void main(String[] args) {
    System.out.println("=".repeat(72));
    System.out.println("  Cross-validation: crypto-gost <-> BouncyCastle 1.83");
    System.out.println("  Keys: GOST R 34.10-2012 (all 7 curves)");
    System.out.println("=".repeat(72));
    System.out.println();

    for (CurveSpec spec : CURVES) {
      testCurve(spec);
    }

    System.out.println("=".repeat(72));
    System.out.printf("  Summary:%n");
    System.out.printf("    Total checks:  %d%n", total);
    System.out.printf("    Passed:        %d%n", ok);
    System.out.printf("    Failed:        %d%n", fail);
    System.out.printf("    Status:        %s%n", fail == 0 ? "SUCCESS" : "FAILED");
    System.out.println("=".repeat(72));

    System.exit(fail > 0 ? 1 : 0);
  }

  static void testCurve(CurveSpec spec) {
    System.out.println("--- " + spec.name() + " (" + spec.bits() + ") ---");

    ECParameters params = spec.paramsFn().get();
    testGostRoundtrip(spec, params);
    testGostToBc(spec, params);
    testBcToGost(spec, params);
    testDerStructure(spec, params);

    System.out.println();
  }

  // ==========================================================
  // 1. crypto-gost DER roundtrip
  // ==========================================================

  static void testGostRoundtrip(CurveSpec spec, ECParameters params) {
    KeyPair pair = KeyGenerator.generateKeyPair(params);
    PublicKeyParameters pub = pair.getPublic();
    PrivateKeyParameters priv = pair.getPrivate();

    ECPoint q = pub.getQ().normalize();
    BigInteger qx = q.getX();
    BigInteger qy = q.getY();
    BigInteger d = priv.getD();

    byte[] pubDer = GostDerCodec.encodePublicKey(pub);
    byte[] privDer = GostDerCodec.encodePrivateKey(priv);

    PublicKeyParameters pubDecoded = GostDerCodec.decodePublicKey(pubDer);
    PrivateKeyParameters privDecoded = GostDerCodec.decodePrivateKey(privDer);

    ECPoint qRestored = pubDecoded.getQ().normalize();
    boolean pubOk = qRestored.getX().equals(qx) && qRestored.getY().equals(qy);
    boolean privOk = privDecoded.getD().equals(d);

    recordResult(spec, "roundtrip DER", pubOk && privOk);
  }

  // ==========================================================
  // 2. crypto-gost -> BC param conversion
  // ==========================================================

  static void testGostToBc(CurveSpec spec, ECParameters params) {
    KeyPair pair = KeyGenerator.generateKeyPair(params);
    PublicKeyParameters gostPub = pair.getPublic();
    PrivateKeyParameters gostPriv = pair.getPrivate();

    ECPoint q = gostPub.getQ().normalize();
    BigInteger qx = q.getX();
    BigInteger qy = q.getY();
    BigInteger d = gostPriv.getD();

    ECCurve bcCurve = new ECCurve.Fp(params.p, params.a, params.b);
    org.bouncycastle.math.ec.ECPoint bcG = bcCurve.createPoint(params.gx, params.gy);
    ECDomainParameters bcDomain = new ECDomainParameters(bcCurve, bcG, params.n);
    org.bouncycastle.math.ec.ECPoint bcQ = bcCurve.createPoint(qx, qy);

    ECPrivateKeyParameters bcPriv = new ECPrivateKeyParameters(d, bcDomain);
    ECPublicKeyParameters bcPub = new ECPublicKeyParameters(bcQ, bcDomain);

    boolean dOk = bcPriv.getD().equals(d);
    boolean qOk = bcPub.getQ().getXCoord().toBigInteger().equals(qx)
               && bcPub.getQ().getYCoord().toBigInteger().equals(qy);

    recordResult(spec, "gost->bc param", dOk && qOk);
  }

  // ==========================================================
  // 3. BC -> crypto-gost param conversion
  // ==========================================================

  static void testBcToGost(CurveSpec spec, ECParameters params) {
    ECCurve bcCurve = new ECCurve.Fp(params.p, params.a, params.b);
    org.bouncycastle.math.ec.ECPoint bcG = bcCurve.createPoint(params.gx, params.gy);
    ECDomainParameters bcDomain = new ECDomainParameters(bcCurve, bcG, params.n);

    ECKeyPairGenerator gen = new ECKeyPairGenerator();
    gen.init(new ECKeyGenerationParameters(bcDomain, RND));
    AsymmetricCipherKeyPair bcPair = gen.generateKeyPair();

    ECPrivateKeyParameters bcPriv = (ECPrivateKeyParameters) bcPair.getPrivate();
    ECPublicKeyParameters bcPub = (ECPublicKeyParameters) bcPair.getPublic();

    BigInteger d = bcPriv.getD();
    BigInteger qx = bcPub.getQ().getXCoord().toBigInteger();
    BigInteger qy = bcPub.getQ().getYCoord().toBigInteger();

    PrivateKeyParameters gostPriv = new PrivateKeyParameters(d, params);
    ECPoint gostQ = ECPoint.affine(qx, qy, params);
    PublicKeyParameters gostPub = new PublicKeyParameters(gostQ, params);

    ECPoint qNorm = gostPub.getQ().normalize();
    boolean qOk = qNorm.getX().equals(qx) && qNorm.getY().equals(qy);
    boolean dOk = gostPriv.getD().equals(d);

    ECPoint g = ECPoint.affine(params.gx, params.gy, params);
    ECPoint expectedQ = g.multiply(d).normalize();
    boolean valid = expectedQ.getX().equals(qx) && expectedQ.getY().equals(qy);

    recordResult(spec, "bc->gost param", dOk && qOk && valid);
  }

  // ==========================================================
  // 4. ASN.1 DER structure via BC parser
  // ==========================================================

  static void testDerStructure(CurveSpec spec, ECParameters params) {
    KeyPair pair = KeyGenerator.generateKeyPair(params);

    byte[] pubDer = GostDerCodec.encodePublicKey(pair.getPublic());
    byte[] privDer = GostDerCodec.encodePrivateKey(pair.getPrivate());

    String expectedSignOid = params.hlen == 32 ? GostCurves.OID_SIGN_256 : GostCurves.OID_SIGN_512;
    String expectedCurveOid = GostCurves.oidOf(params);

    boolean pubOk = true;
    boolean privOk = true;

    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pubDer);
      String algOid = spki.getAlgorithm().getAlgorithm().getId();
      if (!algOid.equals(expectedSignOid)) {
        pubOk = false;
      }
      ASN1Sequence paramsSeq = ASN1Sequence.getInstance(spki.getAlgorithm().getParameters());
      String curveOid = ASN1ObjectIdentifier.getInstance(paramsSeq.getObjectAt(0)).getId();
      if (!curveOid.equals(expectedCurveOid)) {
        pubOk = false;
      }
    } catch (Exception e) {
      pubOk = false;
    }

    try {
      PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privDer);
      String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
      if (!algOid.equals(expectedSignOid)) {
        privOk = false;
      }
      ASN1Sequence paramsSeq = ASN1Sequence.getInstance(pki.getPrivateKeyAlgorithm().getParameters());
      String curveOid = ASN1ObjectIdentifier.getInstance(paramsSeq.getObjectAt(0)).getId();
      if (!curveOid.equals(expectedCurveOid)) {
        privOk = false;
      }
    } catch (Exception e) {
      privOk = false;
    }

    boolean sizeOk = pubDer.length > 0 && privDer.length > 0;

    recordResult(spec, "ASN.1 struct", pubOk && privOk && sizeOk);
  }

  // ==========================================================
  // Helpers
  // ==========================================================

  static void recordResult(CurveSpec spec, String label, boolean pass) {
    total++;
    if (pass) { ok++; } else { fail++; }
    String s = pass ? "OK" : "FAIL";
    System.out.printf("  %-18s %-15s  %s%s%n",
        spec.name(), label, s, pass ? "" : "  <<< FAIL");
  }
}
