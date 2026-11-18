package org.rssys.gost.jca.spi;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Общая часть JCA-согласования ключей ГОСТ Р 34.10-2012: однофазный обмен
 * {@code engineInit(privKey)} -> {@code engineDoPhase(pubKey, true)} -> {@code engineGenerateSecret()}.
 *
 * <p>Подкласс задаёт имя алгоритма, принимаемые параметры инициализации и вычисление секрета.
 *
 * <p>После {@code generateSecret} объект возвращается в состояние сразу после {@code init} (тот же
 * закрытый ключ и параметры, открытый ключ партнёра сброшен): так требует контракт
 * {@link javax.crypto.KeyAgreement}.
 */
abstract class AbstractGostKeyAgreementSpi extends KeyAgreementSpi {

    private static final String RAW = "RAW";

    private PrivateKeyParameters myPriv;
    private PublicKeyParameters peerPub;
    private boolean initialized;

    /** Имя алгоритма в JCA: для сообщений об ошибках и для {@code generateSecret(String)}. */
    protected abstract String algorithm();

    /**
     * Вычисляет секрет по ключам сторон.
     *
     * @return секрет; затирание возвращённого массива берёт на себя вызывающий
     */
    protected abstract byte[] derive(PrivateKeyParameters priv, PublicKeyParameters peer);

    /**
     * Принимает параметры инициализации (UKM для VKO). По умолчанию параметры не поддерживаются.
     * Вызывается до изменения состояния: при отказе объект остаётся прежним.
     *
     * @param params параметры из {@code init} или {@code null}, если их не передали
     */
    protected void acceptParameters(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameterSpec not supported for " + algorithm());
        }
    }

    /**
     * Дополнительная проверка своего закрытого ключа (например, допустимый размер кривой).
     * Вызывается из {@code init} до изменения состояния: ошибка в ключе по контракту JCA это
     * {@link InvalidKeyException} в {@code init}, а не отказ при {@code generateSecret}.
     */
    protected void checkOwnKey(PrivateKeyParameters priv) throws InvalidKeyException {}

    @Override
    protected final void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        PrivateKeyParameters priv = privateKeyOf(key);
        try {
            acceptParameters(null);
        } catch (InvalidAlgorithmParameterException e) {
            // Сигнатура JCA без параметров не оставляет другого исключения
            throw new InvalidKeyException(e.getMessage(), e);
        }
        commit(priv);
    }

    @Override
    protected final void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        PrivateKeyParameters priv = privateKeyOf(key);
        acceptParameters(params);
        commit(priv);
    }

    /**
     * Выполняет фазу согласования ключа. Требуется ровно одна фаза.
     *
     * @param key       открытый ключ удалённой стороны {@link GostECPublicKey}
     * @param lastPhase должен быть {@code true}
     * @return {@code null}: промежуточных ключей нет
     */
    @Override
    protected final Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
        if (!initialized) {
            throw new IllegalStateException("KeyAgreement is not initialized");
        }
        if (!lastPhase) {
            throw new InvalidKeyException(
                    algorithm() + " requires exactly one phase (lastPhase must be true)");
        }
        if (!(key instanceof GostECPublicKey publicKey)) {
            throw new InvalidKeyException("Expected GostECPublicKey, got: " + className(key));
        }
        PublicKeyParameters peer = publicKey.toPublicKeyParameters();
        // Ключи разных кривых дают несвязанный секрет: отказ здесь, а не позже в generateSecret
        if (!myPriv.getParams().equals(peer.getParams())) {
            throw new InvalidKeyException(
                    "Peer public key curve does not match the private key curve");
        }
        this.peerPub = peer;
        return null;
    }

    @Override
    protected final byte[] engineGenerateSecret() {
        if (!initialized) {
            throw new IllegalStateException("KeyAgreement is not initialized");
        }
        if (peerPub == null) {
            throw new IllegalStateException(
                    "engineDoPhase has not been called with peer public key");
        }
        PublicKeyParameters peer = peerPub;
        // Контракт KeyAgreement.generateSecret: объект возвращается в состояние после init
        this.peerPub = null;
        return derive(myPriv, peer);
    }

    @Override
    protected final int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws ShortBufferException {
        byte[] secret = engineGenerateSecret();
        try {
            if (sharedSecret.length - offset < secret.length) {
                throw new ShortBufferException("Output buffer too small");
            }
            System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
            return secret.length;
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /**
     * Возвращает секрет как {@link SecretKey}. Поддерживаются имя алгоритма и {@code "RAW"}.
     *
     * @throws NoSuchAlgorithmException если имя не поддерживается
     */
    @Override
    protected final SecretKey engineGenerateSecret(String algorithm)
            throws NoSuchAlgorithmException {
        if (!algorithm().equals(algorithm) && !RAW.equals(algorithm)) {
            throw new NoSuchAlgorithmException(
                    "Unsupported algorithm: " + algorithm + ". Supported: " + algorithm());
        }
        byte[] secret = engineGenerateSecret();
        try {
            return new GostSecretKey(algorithm, secret);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /** Проверяет тип и состояние закрытого ключа до любых изменений состояния. */
    private PrivateKeyParameters privateKeyOf(Key key) throws InvalidKeyException {
        if (!(key instanceof GostECPrivateKey gostKey)) {
            throw new InvalidKeyException("Expected GostECPrivateKey, got: " + className(key));
        }
        PrivateKeyParameters priv;
        try {
            priv = gostKey.toPrivateKeyParameters();
        } catch (IllegalStateException e) {
            throw new InvalidKeyException("Private key has been destroyed", e);
        }
        checkOwnKey(priv);
        return priv;
    }

    private void commit(PrivateKeyParameters priv) {
        this.myPriv = priv;
        this.peerPub = null;
        this.initialized = true;
    }

    /** Имя класса для сообщения об ошибке; {@code null}-ключ даёт отказ, а не NPE. */
    private static String className(Key key) {
        return key == null ? "null" : key.getClass().getName();
    }
}
