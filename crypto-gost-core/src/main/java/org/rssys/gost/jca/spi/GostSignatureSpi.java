package org.rssys.gost.jca.spi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.spec.GostSignatureParameterSpec;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.signature.SignatureCodec;

/**
 * Реализация {@link SignatureSpi} для алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Предоставляет два конкретных подкласса:
 * <ul>
 *   <li>{@link Ecgost3410_256Spi} — для 256-битных кривых (hlen=32), хэш Стрибог-256,
 *       OID подписи {@code 1.2.643.7.1.1.3.2}, длина подписи 64 байта (s || r)</li>
 *   <li>{@link Ecgost3410_512Spi} — для 512-битных кривых (hlen=64), хэш Стрибог-512,
 *       OID подписи {@code 1.2.643.7.1.1.3.3}, длина подписи 128 байт (s || r)</li>
 * </ul>
 * <p>
 * Формат подписи (X.509, RFC 7091): конкатенация s || r в big-endian,
 * каждая компонента длиной {@code hlen} байт.
 * <p>
 * Нонс k вырабатывается через HMAC-Стрибог по схеме RFC 6979 §3.2, затравка включает число e и
 * идентификатор кривой (реализовано в {@link org.rssys.gost.signature.ECDSASigner}). Режим нонса
 * ({@link NonceMode}) выбирается через {@code setParameter(GostSignatureParameterSpec)}, пока он
 * не задан, действует {@link NonceMode#DEFAULT}. Источник случайности гибридного режима
 * задаётся {@code initSign(key, random)}; без него используется {@code CryptoRandom.INSTANCE}.
 * <p>
 * Сообщение хэшируется потоково: {@link #engineUpdate} сразу подаёт данные в Стрибог, в памяти
 * держится только состояние дайджеста, поэтому подпись большого файла не требует буфера по его
 * размеру. Подпись и проверка выполняются над готовым хэшем
 * ({@link Signature#signHash}, {@link Signature#verifyHash}).
 * <p>
 * После {@link #engineSign} и {@link #engineVerify} объект возвращается в состояние сразу после
 * инициализации и при ошибке тоже: данные неудавшегося вызова не попадают в следующий.
 *
 */
public abstract class GostSignatureSpi extends SignatureSpi {

    /** Ожидаемый размер хэша: 32 для 256-бит кривых, 64 для 512-бит. */
    private final int hlen;

    /** Потоковый дайджест сообщения (Стрибог-256 или Стрибог-512 по {@link #hlen}). */
    private Digest digest;

    /** Закрытый ключ (режим подписи). */
    private PrivateKeyParameters privateKey;

    /** Открытый ключ (режим верификации). */
    private PublicKeyParameters publicKey;

    /** Признак режима: true — подпись, false — верификация. */
    private boolean signingMode;

    /**
     * Режим нонса: параметр подписи, а не ключа. Сохраняется между {@code initSign} и меняется
     * только {@link #engineSetParameter(AlgorithmParameterSpec)}.
     */
    private NonceMode nonceMode = NonceMode.DEFAULT;

    /**
     * Источник случайности подписи; {@code null} означает {@code CryptoRandom.INSTANCE}. Свой
     * экземпляр поля, а не {@code appRandom} базового класса: однопараметрическая форма
     * {@code initSign} поле базового класса не сбрасывает, и от предыдущей инициализации в нём
     * остался бы чужой источник. Сбрасывается в каждом {@code initSign(key)} и {@code initVerify}.
     */
    private SecureRandom signingRandom;

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
        if (!(privateKey instanceof GostECPrivateKey gostKey)) {
            throw new InvalidKeyException(
                    "Expected GostECPrivateKey, got: "
                            + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        PrivateKeyParameters keyParameters;
        try {
            keyParameters = gostKey.toPrivateKeyParameters();
        } catch (IllegalStateException e) {
            throw new InvalidKeyException("Private key has been destroyed", e);
        }
        validateHlen(keyParameters.getParams().hlen, "private");

        this.privateKey = keyParameters;
        this.publicKey = null;
        this.signingMode = true;
        this.signingRandom = null;
        resetDigest();
    }

    /**
     * Инициализирует в режим подписи с источником случайности для гибридного режима.
     * Форма {@code initSign(key)} источник сбрасывает, поэтому чужой датчик не переживает
     * повторную инициализацию.
     *
     * @param privateKey закрытый ключ ({@link GostECPrivateKey})
     * @param random     источник случайности; {@code null} означает {@code CryptoRandom.INSTANCE}
     * @throws InvalidKeyException если ключ неверного типа или размера кривой
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        engineInitSign(privateKey);
        this.signingRandom = random;
    }

    /**
     * Инициализирует в режим проверки подписи.
     *
     * @param publicKey открытый ключ ({@link GostECPublicKey})
     * @throws InvalidKeyException если ключ неверного типа или размера кривой
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof GostECPublicKey gostKey)) {
            throw new InvalidKeyException(
                    "Expected GostECPublicKey, got: "
                            + (publicKey == null ? "null" : publicKey.getClass().getName()));
        }
        PublicKeyParameters keyParameters = gostKey.toPublicKeyParameters();
        validateHlen(keyParameters.getParams().hlen, "public");

        this.publicKey = keyParameters;
        this.privateKey = null;
        this.signingMode = false;
        this.signingRandom = null;
        resetDigest();
    }

    /** Подаёт один байт сообщения в дайджест. */
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        checkInitialized();
        digest.update(b);
    }

    /** Подаёт часть массива сообщения в дайджест. */
    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        checkInitialized();
        // Дайджест границы не проверяет; вызывающий JCA их проверяет, но SPI может вызываться
        // напрямую
        Objects.checkFromIndexSize(off, len, b.length);
        digest.update(b, off, len);
    }

    /**
     * Вычисляет подпись сообщения, поданного через {@code update}.
     * <p>
     * Состояние дайджеста сбрасывается в любом исходе, в том числе при исключении: иначе
     * недоделанное сообщение склеилось бы со следующим.
     *
     * @return подпись s || r (64 или 128 байт)
     * @throws SignatureException если объект не инициализирован для подписи или ключ уничтожен
     */
    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!signingMode || privateKey == null) {
            throw new SignatureException("Signature not initialized for signing");
        }
        byte[] hash = new byte[hlen];
        try {
            digest.doFinal(hash, 0);
            return Signature.signHash(hash, privateKey, nonceMode, signingRandom);
        } catch (Exception e) {
            throw new SignatureException("GOST signature failed: " + e.getMessage(), e);
        } finally {
            Arrays.fill(hash, (byte) 0);
            // destroy, а не reset: reset не затирает рабочие слова дайджеста (последний блок
            // сообщения вместе с дополненным хвостом до 63 байт и значения, выведенные из входа)
            digest.destroy();
        }
    }

    /**
     * Проверяет подпись сообщения, поданного через {@code update}.
     * <p>
     * Состояние дайджеста сбрасывается в любом исходе, в том числе при исключении (подпись
     * неверной длины): иначе сообщение неудавшейся проверки склеилось бы со следующим, и подпись
     * над их конкатенацией была бы принята.
     *
     * @param sigBytes байты подписи s || r
     * @return {@code true} если подпись верна
     * @throws SignatureException если объект не инициализирован для проверки или подпись
     *     некорректна по длине
     */
    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (signingMode || publicKey == null) {
            throw new SignatureException("Signature not initialized for verification");
        }
        byte[] hash = new byte[hlen];
        try {
            digest.doFinal(hash, 0);
            // Контракт JCA: подпись неверной формы это SignatureException, а не false. Api-слой
            // отвечает false, поэтому длину проверяем здесь, не полагаясь на него.
            if (!SignatureCodec.hasValidLength(sigBytes, publicKey.getParams())) {
                throw new SignatureException(
                        "Invalid signature length: "
                                + (sigBytes == null ? "null" : sigBytes.length));
            }
            return Signature.verifyHash(hash, sigBytes, publicKey);
        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureException(
                    "GOST signature verification failed: " + e.getMessage(), e);
        } finally {
            Arrays.fill(hash, (byte) 0);
            digest.destroy();
        }
    }

    /**
     * Задаёт режим нонса подписи.
     *
     * <p>Режим сохраняется между вызовами {@code initSign} и меняется только новым вызовом
     * этого метода; можно вызывать до и после {@code initSign}. На проверку подписи режим не
     * влияет.
     *
     * @param params {@link GostSignatureParameterSpec}
     * @throws InvalidAlgorithmParameterException если параметр равен {@code null} или не
     *                                            {@link GostSignatureParameterSpec}
     */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof GostSignatureParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException(
                    "Expected GostSignatureParameterSpec, got: "
                            + (params == null ? "null" : params.getClass().getName()));
        }
        this.nonceMode = spec.getNonceMode();
    }

    /**
     * Возвращает {@code null}: режим нонса только задаётся ({@link
     * #engineSetParameter(AlgorithmParameterSpec)}), читать его через {@link AlgorithmParameters}
     * не предусмотрено.
     *
     * @return всегда {@code null}
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Устаревший метод JCA — не поддерживается.
     * Обязательная реализация абстрактного метода {@link SignatureSpi}.
     *
     * @throws InvalidParameterException всегда
     */
    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
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
                    "Key hlen mismatch for "
                            + keyType
                            + " key: SPI expects "
                            + hlen
                            + " bytes, key has "
                            + keyHlen
                            + " bytes. "
                            + "Use ECGOST3410-2012-256 for 256-bit curves, ECGOST3410-2012-512 for 512-bit");
        }
    }

    /**
     * Приводит дайджест в начальное состояние для нового сообщения.
     * <p>
     * Существующий дайджест затирается (повторная инициализация другим ключом не должна
     * оставлять в памяти хвост прежнего сообщения), а не пересоздаётся втихую.
     */
    private void resetDigest() {
        if (digest == null) {
            digest = (hlen == Streebog256.DIGEST_SIZE) ? new Streebog256() : new Streebog512();
        } else {
            digest.destroy();
        }
    }

    private void checkInitialized() throws SignatureException {
        if (digest == null) {
            throw new SignatureException(
                    "Signature not initialized — call initSign/initVerify first");
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
            super(Streebog256.DIGEST_SIZE);
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
            super(Streebog512.DIGEST_SIZE);
        }
    }
}
