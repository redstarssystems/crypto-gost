package org.rssys.gost.signature;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.digest.Digest;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Обёртка для электронной подписи ГОСТ Р 34.10-2012, совмещающая хэширование
 * и подпись в одном интерфейсе {@link Signer}.
 * <p>
 * Принимает данные через {@link #update(byte[], int, int)}, затем:
 * <ul>
 *   <li>{@link #sign()} — вычисляет хэш и вырабатывает подпись r||s</li>
 *   <li>{@link #verify(byte[])} — вычисляет хэш и проверяет подпись</li>
 * </ul>
 * <p>
 * Подпись кодируется как конкатенация r и s в big-endian, каждая длиной rolen байт,
 * где rolen = ceil(n.bitLength() / 8). Итоговая длина: 2 * rolen.
 */
public final class DigestSigner implements Signer {
  private final ECDSASigner signer;
  private final Digest digest;
  private ECParameters params;

  public DigestSigner(ECDSASigner signer, Digest digest) {
    this.signer = signer;
    this.digest = digest;
  }

  @Override
  public void init(boolean forSigning, CipherParameters params) {
    digest.reset();
    signer.init(forSigning, params);
    if (params instanceof PrivateKeyParameters) {
      this.params = ((PrivateKeyParameters) params).getParams();
    } else if (params instanceof PublicKeyParameters) {
      this.params = ((PublicKeyParameters) params).getParams();
    }
  }

  @Override
  public void update(byte b) {
    digest.update(b);
  }

  @Override
  public void update(byte[] in, int inOff, int len) {
    digest.update(in, inOff, len);
  }

  @Override
  public byte[] sign() {
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    BigInteger[] sig = signer.generateSignature(hash);
    return encode(sig[0], sig[1]);
  }

  @Override
  public boolean verify(byte[] signature) {
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    BigInteger[] sig = decode(signature);
    return signer.verifySignature(hash, sig[0], sig[1]);
  }

  @Override
  public void reset() {
    digest.reset();
  }

  private void checkInitialized() {
    if (params == null) {
      throw new IllegalStateException("DigestSigner not initialized — call init() first");
    }
  }

  private byte[] encode(BigInteger r, BigInteger s) {
    checkInitialized();
    int rolen = (params.n.bitLength() + 7) / 8;
    byte[] result = new byte[2 * rolen];
    byte[] rBytes = r.toByteArray();
    byte[] sBytes = s.toByteArray();
    int rLen = Math.min(rBytes.length, rolen);
    int sLen = Math.min(sBytes.length, rolen);
    System.arraycopy(rBytes, Math.max(0, rBytes.length - rLen), result, rolen - rLen, rLen);
    System.arraycopy(sBytes, Math.max(0, sBytes.length - sLen), result, 2 * rolen - sLen, sLen);
    return result;
  }

  private BigInteger[] decode(byte[] signature) {
    checkInitialized();
    int rolen = (params.n.bitLength() + 7) / 8;
    if (signature.length != 2 * rolen) {
      throw new IllegalArgumentException(
          "Invalid signature length: expected " + (2 * rolen) + " bytes, got " + signature.length);
    }
    byte[] rBytes = Arrays.copyOfRange(signature, 0, rolen);
    byte[] sBytes = Arrays.copyOfRange(signature, rolen, 2 * rolen);
    return new BigInteger[]{new BigInteger(1, rBytes), new BigInteger(1, sBytes)};
  }
}
