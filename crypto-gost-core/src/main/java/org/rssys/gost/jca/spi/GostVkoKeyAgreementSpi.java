package org.rssys.gost.jca.spi;

import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.jca.spec.GostUkmParameterSpec;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * JCA {@link KeyAgreementSpi} для алгоритма VKO_GOSTR3410_2012_256
 * (RFC 7836 §4.3.1) — согласование 256-битного ключа на основе
 * ECDH и хэш-функции Стрибог-256.
 *
 * <p>Поддерживает однофазный VKO:
 * {@code engineInit(privKey, ukmSpec)} →
 * {@code engineDoPhase(pubKey, true)} →
 * {@code engineGenerateSecret()}.
 *
 * <p>UKM обязателен и передаётся через {@link GostUkmParameterSpec}
 * на этапе инициализации. Результат — 32 байта (Streebog-256).
 *
 * <p>Делегирует вычисление {@link KeyAgreement#vkoGostR3410_2012_256(
 * PrivateKeyParameters, PublicKeyParameters, BigInteger)}.
 *
 * <p>Регистрируется в {@code RssysGostProvider} как
 * {@code KeyAgreement.VKOGOST3410-2012-256}.
 */
public final class GostVkoKeyAgreementSpi extends KeyAgreementSpi {

    private static final String SUPPORTED_ALGORITHM = "VKOGOST3410-2012-256";

    private PrivateKeyParameters myPriv;
    private BigInteger ukm;
    private boolean initialized;
    private PublicKeyParameters peerPub;

    /**
     * Инициализация без UKM — запрещена, VKO требует UKM.
     */
    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        throw new InvalidKeyException(
                "UKM is required: use engineInit(Key, AlgorithmParameterSpec, SecureRandom)");
    }

    /**
     * Инициализирует VKO закрытым ключом и UKM.
     *
     * @param key    закрытый ключ {@link GostECPrivateKey}
     * @param params {@link GostUkmParameterSpec} с UKM
     * @param random не используется
     */
    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof GostECPrivateKey)) {
            throw new InvalidKeyException("Expected GostECPrivateKey, got: " + key.getClass().getName());
        }
        if (!(params instanceof GostUkmParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "Expected GostUkmParameterSpec, got: " + (params == null ? "null" : params.getClass().getName()));
        }
        GostECPrivateKey gostKey = (GostECPrivateKey) key;
        this.myPriv = gostKey.toPrivateKeyParameters();
        if (this.myPriv.isDestroyed()) {
            throw new InvalidKeyException("Private key has been destroyed");
        }
        this.ukm = ((GostUkmParameterSpec) params).getUkm();
        this.peerPub = null;
        this.initialized = true;
    }

    /**
     * Выполняет фазу согласования ключа. Для VKO требуется ровно одна фаза.
     *
     * @param key      открытый ключ удалённой стороны {@link GostECPublicKey}
     * @param lastPhase должен быть {@code true}
     * @return {@code null} (VKO не производит промежуточных ключей)
     */
    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
        if (!initialized) {
            throw new IllegalStateException("KeyAgreement is not initialized");
        }
        if (!lastPhase) {
            throw new InvalidKeyException(
                    "VKOGOST3410-2012-256 requires exactly one phase (lastPhase must be true)");
        }
        if (!(key instanceof GostECPublicKey)) {
            throw new InvalidKeyException("Expected GostECPublicKey, got: " + key.getClass().getName());
        }
        this.peerPub = ((GostECPublicKey) key).toPublicKeyParameters();
        return null;
    }

    /**
     * Возвращает KEK_VKO (32 байта) — результат VKO_GOSTR3410_2012_256.
     *
     * @return KEK_VKO как byte[]
     * @throws IllegalStateException если {@code engineInit} или {@code engineDoPhase} не вызваны
     */
    @Override
    protected byte[] engineGenerateSecret() {
        checkState();
        return KeyAgreement.vkoGostR3410_2012_256(myPriv, peerPub, ukm);
    }

    /**
     * Записывает KEK_VKO в предоставленный буфер.
     *
     * @param sharedSecret буфер для записи
     * @param offset       смещение в буфере
     * @return количество записанных байт (32)
     */
    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws ShortBufferException {
        byte[] secret = engineGenerateSecret();
        try {
            if (sharedSecret.length - offset < secret.length) {
                throw new ShortBufferException("Output buffer too small");
            }
            System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
            return secret.length;
        } finally {
            java.util.Arrays.fill(secret, (byte) 0);
        }
    }

    /**
     * Возвращает KEK_VKO как {@link SecretKey}.
     *
     * <p>Поддерживаемые алгоритмы: {@code "VKOGOST3410-2012-256"} и {@code "RAW"}.
     *
     * @param algorithm имя алгоритма для возвращаемого {@link SecretKey}
     * @return {@link GostSecretKey} с KEK_VKO (32 байта)
     * @throws NoSuchAlgorithmException если алгоритм не поддерживается
     */
    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws NoSuchAlgorithmException {
        if (!SUPPORTED_ALGORITHM.equals(algorithm) && !"RAW".equals(algorithm)) {
            throw new NoSuchAlgorithmException(
                    "Unsupported algorithm: " + algorithm + ". Supported: " + SUPPORTED_ALGORITHM);
        }
        byte[] secret = engineGenerateSecret();
        try {
            return new GostSecretKey(algorithm, secret);
        } finally {
            java.util.Arrays.fill(secret, (byte) 0);
        }
    }

    private void checkState() {
        if (!initialized) {
            throw new IllegalStateException("KeyAgreement is not initialized");
        }
        if (peerPub == null) {
            throw new IllegalStateException(
                    "engineDoPhase has not been called with peer public key");
        }
    }
}
