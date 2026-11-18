package org.rssys.gost.jca.spi;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.spec.GostUkmParameterSpec;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * JCA {@link javax.crypto.KeyAgreementSpi} для VKO_GOSTR3410_2012 (RFC 7836 §4.3): согласование
 * ключа на основе ECDH и хэш-функции Стрибог.
 *
 * <p>Поддерживает однофазный VKO: {@code engineInit(privKey, ukmSpec)} ->
 * {@code engineDoPhase(pubKey, true)} -> {@code engineGenerateSecret()}.
 *
 * <p>UKM обязателен и передаётся через {@link GostUkmParameterSpec} на этапе инициализации; он
 * сохраняется после {@code generateSecret}, как и закрытый ключ.
 *
 * <p>Варианты: {@link Vko256} (§4.3.1, 32 байта, ключи 256 и 512 бит) и {@link Vko512} (§4.3.2,
 * 64 байта, только ключи 512 бит; на 256-битном ключе {@code init} бросает
 * {@link InvalidKeyException}).
 */
public abstract class GostVkoKeyAgreementSpi extends AbstractGostKeyAgreementSpi {

    private BigInteger ukm;

    /**
     * Инициализация без UKM запрещена: VKO требует UKM.
     */
    @Override
    protected void acceptParameters(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof GostUkmParameterSpec ukmSpec)) {
            throw new InvalidAlgorithmParameterException(
                    params == null
                            ? "UKM is required: use init(Key, GostUkmParameterSpec)"
                            : "Expected GostUkmParameterSpec, got: " + params.getClass().getName());
        }
        this.ukm = ukmSpec.getUkm();
    }

    /** Вычисляет KEK_VKO с UKM, заданным при инициализации. */
    @Override
    protected final byte[] derive(PrivateKeyParameters priv, PublicKeyParameters peer) {
        return deriveWithUkm(priv, peer, ukm);
    }

    /** Вариант VKO: выбирает хэш-функцию и длину результата. */
    protected abstract byte[] deriveWithUkm(
            PrivateKeyParameters priv, PublicKeyParameters peer, BigInteger ukm);

    /**
     * VKO_GOSTR3410_2012_256 (RFC 7836 §4.3.1): результат 32 байта, в том числе на 512-битных
     * ключах. Регистрируется как {@code KeyAgreement.VKOGOST3410-2012-256}.
     */
    public static final class Vko256 extends GostVkoKeyAgreementSpi {

        @Override
        protected String algorithm() {
            return "VKOGOST3410-2012-256";
        }

        @Override
        protected byte[] deriveWithUkm(
                PrivateKeyParameters priv, PublicKeyParameters peer, BigInteger ukm) {
            return KeyAgreement.vkoGostR3410_2012_256(priv, peer, ukm);
        }
    }

    /**
     * VKO_GOSTR3410_2012_512 (RFC 7836 §4.3.2): результат 64 байта, только для 512-битных ключей
     * (на 256-битной кривой {@code init} бросает {@link InvalidKeyException}). Регистрируется как
     * {@code KeyAgreement.VKOGOST3410-2012-512}.
     */
    public static final class Vko512 extends GostVkoKeyAgreementSpi {

        @Override
        protected String algorithm() {
            return "VKOGOST3410-2012-512";
        }

        /** Вариант на 512 бит допустим только для 512-битных ключей (RFC 7836 §4.3.2). */
        @Override
        protected void checkOwnKey(PrivateKeyParameters priv) throws InvalidKeyException {
            if (priv.getParams().hlen < Streebog512.DIGEST_SIZE) {
                throw new InvalidKeyException(
                        algorithm()
                                + " requires a 512-bit key, got a "
                                + priv.getParams().hlen * 8
                                + "-bit curve");
            }
        }

        @Override
        protected byte[] deriveWithUkm(
                PrivateKeyParameters priv, PublicKeyParameters peer, BigInteger ukm) {
            return KeyAgreement.vkoGostR3410_2012_512(priv, peer, ukm);
        }
    }
}
