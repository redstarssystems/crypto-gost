package org.rssys.gost.signature;

import java.math.BigInteger;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.digest.Digest;

/**
 * Обёртка для электронной подписи ГОСТ Р 34.10-2012, совмещающая хэширование
 * и подпись в одном интерфейсе {@link Signer}.
 * <p>
 * Принимает данные через {@link #update(byte[], int, int)}, затем:
 * <ul>
 *   <li>{@link #sign()} — вычисляет хэш и вырабатывает подпись s||r (X.509-формат)</li>
 *   <li>{@link #verify(byte[])} — вычисляет хэш и проверяет подпись</li>
 * </ul>
 * <p>
 * Подпись кодируется как конкатенация s и r в big-endian (X.509-формат), каждая длиной rolen байт,
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
        return SignatureCodec.encode(r, s, params);
    }

    private BigInteger[] decode(byte[] signature) {
        checkInitialized();
        return SignatureCodec.decode(signature, params);
    }
}
