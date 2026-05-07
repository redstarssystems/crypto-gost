package org.rssys.gost.jca.spi;

import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Реализация {@link SignatureSpi} для алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Предоставляет два конкретных подкласса:
 * <ul>
 *   <li>{@link Ecgost3410_256Spi} — для 256-битных кривых (hlen=32), хэш Стрибог-256,
 *       OID подписи {@code 1.2.643.7.1.1.3.2}, длина подписи 64 байта (r || s)</li>
 *   <li>{@link Ecgost3410_512Spi} — для 512-битных кривых (hlen=64), хэш Стрибог-512,
 *       OID подписи {@code 1.2.643.7.1.1.3.3}, длина подписи 128 байт (r || s)</li>
 * </ul>
 * <p>
 * Формат подписи по RFC 7091: конкатенация r || s в big-endian,
 * каждая компонента длиной {@code hlen} байт.
 * <p>
 * Нонс k вырабатывается детерминированно по RFC 6979 §3.2 с HMAC-Стрибог
 * (реализовано в {@link org.rssys.gost.signature.ECDSASigner}).
 * <p>
 * Метод {@link #engineUpdate} накапливает данные в памяти; хэширование выполняется
 * внутри {@link Signature#sign} и {@link Signature#verify} за один вызов.

 */
public abstract class GostSignatureSpi extends SignatureSpi {

    /** Ожидаемый размер хэша: 32 для 256-бит кривых, 64 для 512-бит. */
    private final int hlen;

    /** Буфер накопленных данных для подписи/верификации. */
    private ByteArrayOutputStream dataBuffer;

    /** Закрытый ключ (режим подписи). */
    private PrivateKeyParameters privateKey;

    /** Открытый ключ (режим верификации). */
    private PublicKeyParameters publicKey;

    /** Признак режима: true — подпись, false — верификация. */
    private boolean signingMode;

    /**
     * @param hlen ожидаемый размер хэша в байтах (32 или 64)
     */
    protected GostSignatureSpi(int hlen) {
        this.hlen = hlen;
    }

    /**
     * Инициализирует в режим подписи.
     *
     * @param privateKey закрытый ключ ({@link GostECPrivateKey})
     * @throws InvalidKeyException если ключ неверного типа или размера кривой
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof GostECPrivateKey)) {
            throw new InvalidKeyException(
                "Expected GostECPrivateKey, got: " + privateKey.getClass().getName());
        }
        GostECPrivateKey gostKey = (GostECPrivateKey) privateKey;
        validateHlen(gostKey.toPrivateKeyParameters().getParams().hlen, "private");

        this.privateKey  = gostKey.toPrivateKeyParameters();
        this.publicKey   = null;
        this.signingMode = true;
        this.dataBuffer  = new ByteArrayOutputStream();
    }

    /**
     * Инициализирует в режим проверки подписи.
     *
     * @param publicKey открытый ключ ({@link GostECPublicKey})
     * @throws InvalidKeyException если ключ неверного типа или размера кривой
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof GostECPublicKey)) {
            throw new InvalidKeyException(
                "Expected GostECPublicKey, got: " + publicKey.getClass().getName());
        }
        GostECPublicKey gostKey = (GostECPublicKey) publicKey;
        validateHlen(gostKey.toPublicKeyParameters().getParams().hlen, "public");

        this.publicKey   = gostKey.toPublicKeyParameters();
        this.privateKey  = null;
        this.signingMode = false;
        this.dataBuffer  = new ByteArrayOutputStream();
    }

    /** Добавляет один байт к накапливаемым данным. */
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        checkInitialized();
        dataBuffer.write(b);
    }

    /** Добавляет часть массива к накапливаемым данным. */
    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        checkInitialized();
        dataBuffer.write(b, off, len);
    }

    /**
     * Вычисляет подпись накопленных данных.
     *
     * @return подпись r || s (64 или 128 байт)
     * @throws SignatureException если шифр не инициализирован или ключ уничтожен
     */
    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!signingMode || privateKey == null) {
            throw new SignatureException("Signature not initialized for signing");
        }
        byte[] data = dataBuffer.toByteArray();
        try {
            byte[] sig = Signature.sign(data, privateKey);
            // Сбрасываем буфер для повторного использования
            dataBuffer.reset();
            return sig;
        } catch (Exception e) {
            throw new SignatureException("GOST signature failed: " + e.getMessage(), e);
        }
    }

    /**
     * Проверяет подпись накопленных данных.
     *
     * @param sigBytes байты подписи r || s
     * @return {@code true} если подпись верна
     * @throws SignatureException если шифр не инициализирован
     */
    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (signingMode || publicKey == null) {
            throw new SignatureException("Signature not initialized for verification");
        }
        byte[] data = dataBuffer.toByteArray();
        try {
            boolean result = Signature.verify(data, sigBytes, publicKey);
            // Сбрасываем буфер для повторного использования
            dataBuffer.reset();
            return result;
        } catch (Exception e) {
            throw new SignatureException("GOST signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Устаревший метод JCA — не поддерживается.
     * Обязательная реализация абстрактного метода {@link SignatureSpi}.
     *
     * @throws InvalidParameterException всегда
     */
    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new InvalidParameterException("setParameter not supported for ECGOST3410-2012");
    }

    /**
     * Устаревший метод JCA — не поддерживается.
     * Обязательная реализация абстрактного метода {@link SignatureSpi}.
     *
     * @throws InvalidParameterException всегда
     */
    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("getParameter not supported for ECGOST3410-2012");
    }

    /**
     * Проверяет что hlen ключа соответствует hlen данного SPI.
     * Предотвращает использование 256-битного ключа с 512-битным SPI и наоборот.
     */
    private void validateHlen(int keyHlen, String keyType) throws InvalidKeyException {
        if (keyHlen != hlen) {
            throw new InvalidKeyException(
                "Key hlen mismatch for " + keyType + " key: SPI expects " + hlen
                + " bytes, key has " + keyHlen + " bytes. "
                + "Use ECGOST3410-2012-256 for 256-bit curves, ECGOST3410-2012-512 for 512-bit");
        }
    }

    private void checkInitialized() throws SignatureException {
        if (dataBuffer == null) {
            throw new SignatureException("Signature not initialized — call initSign/initVerify first");
        }
    }

    /**
     * ГОСТ Р 34.10-2012 для 256-битных кривых.
     * <p>
     * Хэш: Стрибог-256. Длина подписи: 64 байта.
     * OID: {@code 1.2.643.7.1.1.3.2}.
     * Регистрируется как {@code "ECGOST3410-2012-256"}.
     */
    public static final class Ecgost3410_256Spi extends GostSignatureSpi {
        /** Создаёт SPI для 256-битных кривых (hlen=32). */
        public Ecgost3410_256Spi() {
            super(32);
        }
    }

    /**
     * ГОСТ Р 34.10-2012 для 512-битных кривых.
     * <p>
     * Хэш: Стрибог-512. Длина подписи: 128 байт.
     * OID: {@code 1.2.643.7.1.1.3.3}.
     * Регистрируется как {@code "ECGOST3410-2012-512"}.
     */
    public static final class Ecgost3410_512Spi extends GostSignatureSpi {
        /** Создаёт SPI для 512-битных кривых (hlen=64). */
        public Ecgost3410_512Spi() {
            super(64);
        }
    }
}
