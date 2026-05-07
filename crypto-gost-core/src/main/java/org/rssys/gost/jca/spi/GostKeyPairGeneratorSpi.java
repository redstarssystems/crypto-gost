package org.rssys.gost.jca.spi;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.signature.ECParameters;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import org.rssys.gost.util.CryptoRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * Реализация {@link KeyPairGeneratorSpi} для генерации ключевых пар
 * алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Кривая задаётся через {@link ECGenParameterSpec} с одним из поддерживаемых
 * имён или OID. По умолчанию используется {@code "cryptopro-A"} (наиболее
 * распространённая кривая в российской инфраструктуре, RFC 4357 §11.2).
 * <p>
 * Использование через JCA:
 * <pre>{@code
 * KeyPairGenerator kpg =
 *     KeyPairGenerator.getInstance("ECGOST3410-2012", provider);
 * kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
 * KeyPair pair = kpg.generateKeyPair();
 * }</pre>
 * <p>
 * Регистрируется в провайдере как {@code "ECGOST3410-2012"}.
 *
 * @see GostCurves
 */
public final class GostKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    /** Кривая по умолчанию — CryptoPro-A (RFC 4357 §11.2). */
    private static final ECParameters DEFAULT_CURVE = ECParameters.cryptoProA();

    /** Параметры кривой для генерации. */
    private ECParameters curveParams = DEFAULT_CURVE;

    /** Генератор случайных чисел. */
    private SecureRandom random = CryptoRandom.INSTANCE;

    /**
     * Инициализирует генератор с параметрами кривой.
     * <p>
     * Принимает {@link ECGenParameterSpec} с именем кривой или строкой OID
     * из реестра {@link GostCurves}.
     *
     * @param params {@link ECGenParameterSpec} с именем/OID кривой
     * @param random генератор случайных чисел (может быть {@code null})
     * @throws InvalidAlgorithmParameterException если тип параметра не поддерживается
     *         или имя кривой не распознано
     */
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof ECGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                "Expected ECGenParameterSpec, got: "
                + (params == null ? "null" : params.getClass().getName()));
        }
        String curveName = ((ECGenParameterSpec) params).getName();
        try {
            this.curveParams = GostCurves.byName(curveName);
        } catch (IllegalArgumentException e) {
            throw new InvalidAlgorithmParameterException(
                "Unknown GOST curve: " + curveName
                + ". Supported: tc26-gost-A-256, tc26-gost-A-512, tc26-gost-B-512, "
                + "tc26-gost-C-512, cryptopro-A, cryptopro-B, cryptopro-C "
                + "(or corresponding OIDs)", e);
        }
        this.random = (random != null) ? random : CryptoRandom.INSTANCE;
    }

    /**
     * Инициализирует генератор с размером ключа в битах.
     * <p>
     * Для совместимости: 256 бит → {@code "cryptopro-A"}, 512 бит → {@code "tc26-gost-A-512"}.
     * Для выбора конкретной кривой используйте {@link #initialize(AlgorithmParameterSpec, SecureRandom)}.
     *
     * @param keysize 256 или 512
     * @param random  генератор случайных чисел
     * @throws java.security.InvalidParameterException если keysize не 256 и не 512
     */
    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize == 256) {
            this.curveParams = ECParameters.cryptoProA();
        } else if (keysize == 512) {
            this.curveParams = ECParameters.tc26a512();
        } else {
            throw new java.security.InvalidParameterException(
                "ECGOST3410-2012 supports key sizes 256 and 512, got " + keysize);
        }
        this.random = (random != null) ? random : CryptoRandom.INSTANCE;
    }

    /**
     * Генерирует новую ключевую пару ГОСТ Р 34.10-2012.
     *
     * @return {@link KeyPair} с {@link GostECPublicKey} и {@link GostECPrivateKey}
     */
    @Override
    public KeyPair generateKeyPair() {
        org.rssys.gost.api.KeyPair gostPair = KeyGenerator.generateKeyPair(curveParams, random);
        return new KeyPair(
            new GostECPublicKey(gostPair.getPublic()),
            new GostECPrivateKey(gostPair.getPrivate())
        );
    }
}
