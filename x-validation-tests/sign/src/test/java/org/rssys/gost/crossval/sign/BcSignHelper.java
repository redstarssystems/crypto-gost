package org.rssys.gost.crossval.sign;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;

/**
 * Stateless обёртка над BouncyCastle для кросс-валидации подписи ГОСТ Р 34.10-2012.
 */
public final class BcSignHelper {

    private BcSignHelper() {}

    /**
     * Создаёт ECDomainParameters BouncyCastle из ECParameters crypto-gost.
     */
    public static ECDomainParameters buildBcDomain(ECParameters params) {
        ECCurve curve = new ECCurve.Fp(params.p, params.a, params.b);
        org.bouncycastle.math.ec.ECPoint g = curve.createPoint(params.gx, params.gy);
        return new ECDomainParameters(curve, g, params.n);
    }

    /**
     * Конвертирует закрытый ключ crypto-gost в закрытый ключ BouncyCastle.
     */
    public static ECPrivateKeyParameters toBcPrivKey(PrivateKeyParameters gostPriv,
                                                      ECDomainParameters bcDomain) {
        return new ECPrivateKeyParameters(gostPriv.getD(), bcDomain);
    }

    /**
     * Конвертирует открытый ключ crypto-gost в открытый ключ BouncyCastle.
     */
    public static ECPublicKeyParameters toBcPubKey(PublicKeyParameters gostPub,
                                                    ECDomainParameters bcDomain) {
        org.rssys.gost.signature.ECPoint q = gostPub.getQ().normalize();
        ECCurve curve = bcDomain.getCurve();
        org.bouncycastle.math.ec.ECPoint bcQ = curve.createPoint(q.getX(), q.getY());
        return new ECPublicKeyParameters(bcQ, bcDomain);
    }

    /**
     * BouncyCastle подписывает сообщение (без внешнего хэширования — BC хэширует внутри).
     * Возвращает подпись в формате s||r (X.509 big-endian).
     */
    public static byte[] bcSign(byte[] msg, ECPrivateKeyParameters bcPriv, int rolen) {
        int digestSize = rolen == 32 ? 32 : 64;
        Digest bcDigest = newDigest(rolen);
        byte[] hash = new byte[digestSize];
        bcDigest.update(msg, 0, msg.length);
        bcDigest.doFinal(hash, 0);

        ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
        signer.init(true, bcPriv);
        BigInteger[] sig = signer.generateSignature(hash);

        return encodeSig(sig[0], sig[1], rolen);
    }

    /**
     * BouncyCastle верифицирует подпись (без внешнего хэширования — BC хэширует внутри).
     * Подпись ожидается в формате s||r (X.509 big-endian).
     */
    public static boolean bcVerify(byte[] msg, byte[] sig,
                                    ECPublicKeyParameters bcPub, int rolen) {
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 0, rolen));
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sig, rolen, 2 * rolen));

        int digestSize = rolen == 32 ? 32 : 64;
        Digest bcDigest = newDigest(rolen);
        byte[] hash = new byte[digestSize];
        bcDigest.update(msg, 0, msg.length);
        bcDigest.doFinal(hash, 0);

        ECGOST3410_2012Signer verifier = new ECGOST3410_2012Signer();
        verifier.init(false, bcPub);
        return verifier.verifySignature(hash, r, s);
    }

    /**
     * Кодирует r,s BigInteger в формат s||r (X.509 big-endian).
     */
    public static byte[] encodeSig(BigInteger r, BigInteger s, int rolen) {
        byte[] result = new byte[2 * rolen];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        int rStart = (rBytes[0] == 0) ? 1 : 0;
        int sStart = (sBytes[0] == 0) ? 1 : 0;
        int rLen = rBytes.length - rStart;
        int sLen = sBytes.length - sStart;
        if (rLen > rolen || sLen > rolen) {
            throw new IllegalStateException(
                    "r или s превышает rolen: rLen=" + rLen + " sLen=" + sLen + " rolen=" + rolen);
        }
        System.arraycopy(sBytes, sStart, result, rolen - sLen, sLen);
        System.arraycopy(rBytes, rStart, result, 2 * rolen - rLen, rLen);
        return result;
    }

    /**
     * Создаёт BC-дайджест Streebog нужной разрядности.
     */
    static Digest newDigest(int rolen) {
        if (rolen == 32) {
            return new GOST3411_2012_256Digest();
        } else {
            return new GOST3411_2012_512Digest();
        }
    }
}
