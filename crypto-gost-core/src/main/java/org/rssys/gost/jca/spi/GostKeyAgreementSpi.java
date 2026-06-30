package org.rssys.gost.jca.spi;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * JCA {@link KeyAgreementSpi} для алгоритма ECDH (ГОСТ Р 34.10-2012).
 *
 * <p>Поддерживает однофазный ECDH: {@code engineInit(privKey)} -> {@code engineDoPhase(pubKey, true)} ->
 * {@code engineGenerateSecret()}.
 *
 * <p>Delegates to {@link KeyAgreement#computeSharedSecret(PrivateKeyParameters, PublicKeyParameters)}.
 *
 * <p>Регистрируется в {@code RssysGostProvider} как {@code KeyAgreement.ECDHGOST2012}.
 */
public final class GostKeyAgreementSpi extends KeyAgreementSpi {

    private static final String SUPPORTED_ALGORITHM = "ECDHGOST2012";

    private PrivateKeyParameters myPriv;
    private boolean initialized;
    private PublicKeyParameters peerPub;

    /**
     * Инициализирует KeyAgreement закрытым ключом.
     *
     * @param key    закрытый ключ {@link GostECPrivateKey}
     * @param random не используется (принимается для совместимости с JCA)
     */
    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof GostECPrivateKey)) {
            throw new InvalidKeyException(
                    "Expected GostECPrivateKey, got: " + key.getClass().getName());
        }
        GostECPrivateKey gostKey = (GostECPrivateKey) key;
        this.myPriv = gostKey.toPrivateKeyParameters();
        if (this.myPriv.isDestroyed()) {
            throw new InvalidKeyException("Private key has been destroyed");
        }
        this.peerPub = null;
        this.initialized = true;
    }

    /**
     * ECDH по ГОСТ не использует дополнительные параметры на этапе инициализации —
     * все параметры уже зашиты в ключе (кривая). Принимаем только null.
     */
    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameterSpec not supported for ECDHGOST2012");
        }
        engineInit(key, random);
    }

    /**
     * Выполняет фазу согласования ключа. Для ECDH требуется ровно одна фаза.
     *
     * @param key      открытый ключ удалённой стороны {@link GostECPublicKey}
     * @param lastPhase должен быть {@code true}
     * @return {@code null} (ECDH не производит промежуточных ключей)
     */
    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
        if (!initialized) {
            throw new IllegalStateException("KeyAgreement is not initialized");
        }
        if (!lastPhase) {
            throw new InvalidKeyException(
                    "ECDH requires exactly one phase (lastPhase must be true)");
        }
        if (!(key instanceof GostECPublicKey)) {
            throw new InvalidKeyException(
                    "Expected GostECPublicKey, got: " + key.getClass().getName());
        }
        this.peerPub = ((GostECPublicKey) key).toPublicKeyParameters();
        return null;
    }

    /**
     * Возвращает сырой общий секрет (X-координата d·Qpeer в LE).
     *
     * @return shared secret как byte[]
     * @throws IllegalStateException если {@code engineInit} или {@code engineDoPhase} не вызваны
     */
    @Override
    protected byte[] engineGenerateSecret() {
        checkState();
        return KeyAgreement.computeSharedSecret(myPriv, peerPub);
    }

    /**
     * Записывает общий секрет в предоставленный буфер.
     *
     * @param sharedSecret буфер для записи
     * @param offset       смещение в буфере
     * @return количество записанных байт
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
     * Возвращает общий секрет как {@link SecretKey}.
     *
     * <p>Поддерживаемые алгоритмы: {@code "ECDHGOST2012"} и {@code "RAW"}.
     *
     * @param algorithm имя алгоритма для возвращаемого {@link SecretKey}
     * @return {@link GostSecretKey} с общим секретом
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
