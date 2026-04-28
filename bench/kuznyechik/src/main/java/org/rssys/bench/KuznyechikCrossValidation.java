package org.rssys.bench;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

import java.security.SecureRandom;
import java.util.Arrays;

public class KuznyechikCrossValidation {

  private static final byte[] CTR_IV =
      {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  private static final byte[] BLOCK_IV = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };

  private static final byte[] MGM_ICN = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
  };

  private static final int[] ALL_SIZES   = {0, 1, 16, 255, 10000};
  private static final int[] BLOCK_SIZES = {16, 256, 1024};
  // Размеры для теста со случайными данными (SecureRandom)
  private static final int[] RANDOM_SIZES = {1, 100, 1000, 10000};

  private static int total = 0;
  private static int ok = 0;
  private static int fail = 0;

  public static void main(String[] args) throws Exception {
    SymmetricKey gostKey = KeyGenerator.generateSymmetricKey();
    byte[] keyBytes = gostKey.getKey();

    System.out.println("=".repeat(72));
    System.out.println("  \u041A\u0440\u043E\u0441\u0441-\u0432\u0430\u043B\u0438\u0434\u0430\u0446\u0438\u044F: crypto-gost \u2194 BouncyCastle 1.83");
    System.out.println("  \u0428\u0438\u0444\u0440: \u041A\u0443\u0437\u043D\u0435\u0447\u0438\u043A (\u0413\u041E\u0421\u0422 \u0420 34.12-2015)");
    System.out.println("=".repeat(72));
    System.out.println();

    testMode("CTR", () -> testCtr(gostKey, keyBytes));
    testMode("CBC / PKCS7", () -> testCbcPkcs7(gostKey, keyBytes));
    testMode("CBC / NoPadding", () -> testCbcNoPad(gostKey, keyBytes));
    testMode("CFB", () -> testCfb(gostKey, keyBytes));
    testMode("OFB", () -> testOfb(gostKey, keyBytes));
    testMode("MGM", () -> testMgm(gostKey));
    testMode("Random data (CTR+CFB)", () -> testRandomData(gostKey, keyBytes));

    System.out.println("=".repeat(72));
    System.out.println("  \u0421\u0432\u043E\u0434\u043A\u0430:");
    System.out.printf("    \u0412\u0441\u0435\u0433\u043E \u043F\u0440\u043E\u0432\u0435\u0440\u043E\u043A:  %d%n", total);
    System.out.printf("    \u041F\u0440\u043E\u0439\u0434\u0435\u043D\u043E:        %d%n", ok);
    System.out.printf("    \u041E\u0448\u0438\u0431\u043E\u043A:          %d%n", fail);
    System.out.printf("    \u0421\u0442\u0430\u0442\u0443\u0441:          %s%n",
        fail == 0 ? "\u0423\u0421\u041F\u0415\u0425" : "\u041F\u0420\u041E\u0412\u0410\u041B");
    System.out.println("=".repeat(72));

    System.exit(fail > 0 ? 1 : 0);
  }

  interface ThrowingRunnable { void run() throws Exception; }

  static void testMode(String name, ThrowingRunnable fn) {
    System.out.println("--- " + name + " ---");
    try {
      fn.run();
    } catch (Exception e) {
      System.out.printf("    \u041E\u0448\u0438\u0431\u043A\u0430: %s%n", e.getMessage());
    }
    System.out.println();
  }

  // ======================== CTR ========================

  static void testCtr(SymmetricKey gostKey, byte[] keyBytes) throws Exception {
    for (int sz : ALL_SIZES) {
      byte[] msg = msg(sz);
      boolean a = Arrays.equals(msg, bcCtr(Cipher.encrypt(msg, gostKey, CTR_IV, Cipher.Mode.CTR), keyBytes, CTR_IV));
      boolean b = Arrays.equals(msg, Cipher.decrypt(bcCtr(msg, keyBytes, CTR_IV), gostKey, CTR_IV, Cipher.Mode.CTR));
      printResult("CTR", sz, a, b);
    }
  }

  static byte[] bcCtr(byte[] data, byte[] key, byte[] iv8) throws Exception {
    if (data.length == 0) return new byte[0];
    // BC SICBlockCipher требует 16-байтный IV.
    // ГОСТ Р 34.13-2015 §4.4: CTR-IV = 8 байт, счётчик = IV || 0x00..00 (8 нулей).
    // OpenSSL kuznyechik-ctr интерпретирует IV аналогично: первые 8 байт + 8 нулей.
    byte[] ctr = new byte[16];
    System.arraycopy(iv8, 0, ctr, 0, Math.min(iv8.length, 8));
    SICBlockCipher c = new SICBlockCipher(new GOST3412_2015Engine());
    c.init(true, new ParametersWithIV(new KeyParameter(key), ctr));
    // processBytes для потокового режима — корректен для любой длины
    byte[] out = new byte[data.length];
    c.processBytes(data, 0, data.length, out, 0);
    return out;
  }

  // ======================== CBC / PKCS7 ========================

  static void testCbcPkcs7(SymmetricKey gostKey, byte[] keyBytes) throws Exception {
    for (int sz : ALL_SIZES) {
      byte[] msg = msg(sz);
      byte[] gCt = Cipher.encrypt(msg, gostKey, BLOCK_IV, Cipher.Mode.CBC, Cipher.Padding.PKCS7);
      boolean a = Arrays.equals(msg, bcCbcPad(gCt, keyBytes, BLOCK_IV, false));
      byte[] bCt = bcCbcPad(msg, keyBytes, BLOCK_IV, true);
      boolean b = Arrays.equals(msg, Cipher.decrypt(bCt, gostKey, BLOCK_IV, Cipher.Mode.CBC, Cipher.Padding.PKCS7));
      printResult("CBC/PKCS7", sz, a, b);
    }
  }

  static byte[] bcCbcPad(byte[] data, byte[] key, byte[] iv, boolean enc) throws Exception {
    PaddedBufferedBlockCipher c = new PaddedBufferedBlockCipher(
        new CBCBlockCipher(new GOST3412_2015Engine()), new PKCS7Padding());
    c.init(enc, new ParametersWithIV(new KeyParameter(key), iv));
    byte[] buf = new byte[c.getOutputSize(data.length)];
    int l1 = c.processBytes(data, 0, data.length, buf, 0);
    int l2 = c.doFinal(buf, l1);
    return Arrays.copyOf(buf, l1 + l2);
  }

  // ======================== CBC / NoPadding ========================

  static void testCbcNoPad(SymmetricKey gostKey, byte[] keyBytes) throws Exception {
    for (int sz : BLOCK_SIZES) {
      byte[] msg = msg(sz);
      boolean a = Arrays.equals(msg, bcCbc(Cipher.encrypt(msg, gostKey, BLOCK_IV, Cipher.Mode.CBC, Cipher.Padding.NONE), keyBytes, BLOCK_IV, false));
      boolean b = Arrays.equals(msg, Cipher.decrypt(bcCbc(msg, keyBytes, BLOCK_IV, true), gostKey, BLOCK_IV, Cipher.Mode.CBC, Cipher.Padding.NONE));
      printResult("CBC/NoPad", sz, a, b);
    }
  }

  static byte[] bcCbc(byte[] data, byte[] key, byte[] iv, boolean enc) throws Exception {
    CBCBlockCipher c = new CBCBlockCipher(new GOST3412_2015Engine());
    c.init(enc, new ParametersWithIV(new KeyParameter(key), iv));
    byte[] out = new byte[data.length];
    for (int off = 0; off < data.length; off += 16) {
      c.processBlock(data, off, out, off);
    }
    return out;
  }

  // ======================== CFB ========================

  static void testCfb(SymmetricKey gostKey, byte[] keyBytes) throws Exception {
    for (int sz : ALL_SIZES) {
      byte[] msg = msg(sz);
      boolean a = Arrays.equals(msg, bcCfb(Cipher.encrypt(msg, gostKey, BLOCK_IV, Cipher.Mode.CFB), keyBytes, BLOCK_IV, false));
      boolean b = Arrays.equals(msg, Cipher.decrypt(bcCfb(msg, keyBytes, BLOCK_IV, true), gostKey, BLOCK_IV, Cipher.Mode.CFB));
      printResult("CFB", sz, a, b);
    }
  }

  static byte[] bcCfb(byte[] data, byte[] key, byte[] iv, boolean enc) throws Exception {
    if (data.length == 0) return new byte[0];
    CFBBlockCipher c = new CFBBlockCipher(new GOST3412_2015Engine(), 128);
    c.init(enc, new ParametersWithIV(new KeyParameter(key), iv));
    // processBytes корректно обрабатывает произвольную длину включая некратную блоку
    byte[] out = new byte[data.length];
    c.processBytes(data, 0, data.length, out, 0);
    return out;
  }

  // ======================== OFB ========================

  static void testOfb(SymmetricKey gostKey, byte[] keyBytes) throws Exception {
    for (int sz : ALL_SIZES) {
      byte[] msg = msg(sz);
      boolean a = Arrays.equals(msg, bcOfb(Cipher.encrypt(msg, gostKey, BLOCK_IV, Cipher.Mode.OFB), keyBytes, BLOCK_IV, false));
      boolean b = Arrays.equals(msg, Cipher.decrypt(bcOfb(msg, keyBytes, BLOCK_IV, true), gostKey, BLOCK_IV, Cipher.Mode.OFB));
      printResult("OFB", sz, a, b);
    }
  }

  static byte[] bcOfb(byte[] data, byte[] key, byte[] iv, boolean enc) throws Exception {
    if (data.length == 0) return new byte[0];
    OFBBlockCipher c = new OFBBlockCipher(new GOST3412_2015Engine(), 128);
    c.init(enc, new ParametersWithIV(new KeyParameter(key), iv));
    // processBytes корректно обрабатывает произвольную длину включая некратную блоку
    byte[] out = new byte[data.length];
    c.processBytes(data, 0, data.length, out, 0);
    return out;
  }

  // ======================== MGM (gost roundtrip) ========================
  // Примечание: BouncyCastle 1.83 не реализует MGM (ГОСТ Р 34.13-2015 §5.4).
  // Поэтому MGM тестируется только как внутренний roundtrip crypto-gost:
  //   1. Корректность шифрования/расшифрования (с AAD и без)
  //   2. Отказ расшифрования при неверном AAD (защита аутентификации)

  static void testMgm(SymmetricKey gostKey) throws Exception {
    int[] sizes = {0, 1, 16, 255, 10000};
    for (int sz : sizes) {
      byte[] msg = msg(sz);
      byte[] aad = {0x41, 0x42, 0x43};

      boolean a = testMgmRoundtrip(msg, gostKey, aad);
      boolean b = testMgmRoundtrip(msg, gostKey, new byte[0]);
      printResult("MGM (w AAD)", sz, a, b);

      boolean caught = false;
      try {
        byte[] pkt = MgmCipher.sealWithIcn(msg, gostKey, MGM_ICN, aad);
        MgmCipher.open(pkt, gostKey, new byte[0]);
      } catch (AuthenticationException e) {
        caught = true;
      }
      total++;
      if (caught) { ok++; } else { fail++; }
      String s = caught ? "OK" : "FAIL";
      System.out.printf("  %-18s size=%-5d  AAD guard=%-3s%s%n", "MGM (AAD guard)", sz, s, caught ? "" : "  <<< FAIL");
    }
  }

  static boolean testMgmRoundtrip(byte[] msg, SymmetricKey key, byte[] aad) {
    try {
      byte[] pkt = MgmCipher.sealWithIcn(msg, key, MGM_ICN, aad);
      return Arrays.equals(msg, MgmCipher.open(pkt, key, aad));
    } catch (Exception e) {
      return false;
    }
  }

  // ======================== Random data ========================

  /**
   * Тест со случайными данными (SecureRandom).
   * <p>
   * Детерминированные тесты msg() проверяют корректность алгоритма,
   * но JIT может оптимизировать работу с предсказуемыми данными.
   * Этот тест гарантирует корректность при реальных условиях использования.
   */
  static void testRandomData(SymmetricKey gostKey, byte[] keyBytes) throws Exception {
    SecureRandom rnd = new SecureRandom();
    for (int sz : RANDOM_SIZES) {
      byte[] msg = new byte[sz];
      rnd.nextBytes(msg);

      // CTR: случайные данные и случайный IV, оба направления
      byte[] ctrIv = new byte[8];
      rnd.nextBytes(ctrIv);
      // gost→bc: crypto-gost шифрует, BC расшифровывает
      boolean ctrGostToBc = Arrays.equals(msg,
          bcCtr(Cipher.encrypt(msg, gostKey, ctrIv, Cipher.Mode.CTR), keyBytes, ctrIv));
      // bc→gost: BC шифрует, crypto-gost расшифровывает
      boolean ctrBcToGost = Arrays.equals(msg,
          Cipher.decrypt(bcCtr(msg, keyBytes, ctrIv), gostKey, ctrIv, Cipher.Mode.CTR));
      printResult("CTR/random", sz, ctrGostToBc, ctrBcToGost);

      // CFB: случайные данные и случайный IV, оба направления
      byte[] cfbIv = new byte[16];
      rnd.nextBytes(cfbIv);
      // gost→bc
      boolean cfbGostToBc = Arrays.equals(msg,
          bcCfb(Cipher.encrypt(msg, gostKey, cfbIv, Cipher.Mode.CFB), keyBytes, cfbIv, false));
      // bc→gost
      boolean cfbBcToGost = Arrays.equals(msg,
          Cipher.decrypt(bcCfb(msg, keyBytes, cfbIv, true), gostKey, cfbIv, Cipher.Mode.CFB));
      printResult("CFB/random", sz, cfbGostToBc, cfbBcToGost);
    }
  }

  // ======================== Утилиты ========================

  static byte[] msg(int sz) {
    byte[] m = new byte[sz];
    for (int i = 0; i < sz; i++) m[i] = (byte)(i & 0xFF);
    return m;
  }



  static void printResult(String label, int sz, boolean gostToBc, boolean bcToGost) {
    total += 2;
    String a = gostToBc ? "OK" : "FAIL";
    String b = bcToGost ? "OK" : "FAIL";
    if (gostToBc && bcToGost) {
      ok += 2;
    } else {
      if (!gostToBc) fail++;
      if (!bcToGost) fail++;
    }
    String suffix = (gostToBc && bcToGost) ? "" : "  <<< FAIL";
    System.out.printf("  %-18s size=%-5d  gost->bc=%-3s  bc->gost=%-3s%s%n", label, sz, a, b, suffix);
  }
}
