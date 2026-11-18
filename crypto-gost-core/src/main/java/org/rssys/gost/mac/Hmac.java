package org.rssys.gost.mac;

import java.util.Arrays;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Digest;

/**
 * HMAC (Hash-based Message Authentication Code) по RFC 2104.
 * Ссылки:
 *   - RFC 2104: https://www.rfc-editor.org/rfc/rfc2104
 *   - RFC 7836 Appendix B (тест-векторы HMAC-Streebog)
 */
public final class Hmac implements Mac {

    private static final byte IPAD = 0x36;
    private static final byte OPAD = 0x5C;

    private final Digest digest;
    private final int digestSize;
    private final int blockLen;
    private final byte[] inputPad;
    private final byte[] outputPad;

    /**
     * Признак инициализации ключом. Без него нулевые pads дали бы значение, не зависящее
     * от секрета (H(0ᴮ ‖ H(M))), поэтому все операции над данными проверяют флаг.
     */
    private boolean initialized;

    public Hmac(Digest digest) {
        if (digest == null) {
            throw new IllegalArgumentException("digest must not be null");
        }
        this.digest = digest;
        this.digestSize = digest.getDigestSize();
        this.blockLen = digest.getByteLength();
        this.inputPad = new byte[blockLen];
        this.outputPad = new byte[blockLen];
    }

    @Override
    public String getAlgorithmName() {
        return digest.getAlgorithmName() + "/HMAC";
    }

    @Override
    public int getMacSize() {
        return digestSize;
    }

    /**
     * Инициализирует HMAC ключом в виде байтового массива.
     *
     * <p>Используется внутри низкоуровневых примитивов (RFC 6979 в {@code ECDSASigner}),
     * где ключевой материал существует только как временный {@code byte[]} и не должен
     * оборачиваться в {@link SymmetricKey}.
     *
     * <p>Пустой ключ допустим (RFC 2104). Неудачный вызов (например, {@code null}) переводит
     * объект в неинициализированное состояние и затирает прежний ключевой материал
     * (как {@link #clear()}): прежний ключ после пойманного исключения не используется.
     *
     * @param key ключевой материал (defensive copy)
     * @throws IllegalArgumentException если {@code key == null}
     */
    public void init(byte[] key) {
        // Полное затирание до проверки аргументов: неудачный init не должен ни оставлять
        // рабочим старый ключ, ни хранить его производные (pads) в памяти.
        clear();
        if (key == null) {
            throw new IllegalArgumentException("HMAC key must not be null");
        }
        initWithKeyBytes(key);
    }

    /**
     * Инициализирует HMAC симметричным ключом. Неудачный вызов переводит объект в
     * неинициализированное состояние (см. {@link #init(byte[])}).
     *
     * @throws IllegalArgumentException если {@code params} не {@link SymmetricKey}
     */
    @Override
    public void init(CipherParameters params) {
        clear();
        if (!(params instanceof SymmetricKey)) {
            throw new IllegalArgumentException("HMac requires SymmetricKey");
        }
        // getKey() отдаёт копию: её затираем сами, иначе ключ останется в куче.
        byte[] keyCopy = ((SymmetricKey) params).getKey();
        try {
            initWithKeyBytes(keyCopy);
        } finally {
            Arrays.fill(keyCopy, (byte) 0);
        }
    }

    /**
     * Общая логика инициализации HMAC по RFC 2104:
     * если ключ длиннее блока — хэшируется; затем формируются ipad и opad.
     */
    private void initWithKeyBytes(byte[] key) {
        digest.reset();

        byte[] k;
        if (key.length > blockLen) {
            digest.update(key, 0, key.length);
            k = new byte[digestSize];
            digest.doFinal(k, 0);
        } else {
            k = Arrays.copyOf(key, key.length);
        }

        Arrays.fill(inputPad, IPAD);
        Arrays.fill(outputPad, OPAD);

        for (int i = 0; i < k.length; i++) {
            inputPad[i] ^= k[i];
            outputPad[i] ^= k[i];
        }

        Arrays.fill(k, (byte) 0);

        digest.reset();
        digest.update(inputPad, 0, blockLen);
        initialized = true;
    }

    @Override
    public void update(byte in) {
        checkInitialized();
        digest.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        checkInitialized();
        digest.update(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        checkInitialized();
        byte[] inner = new byte[digestSize];
        digest.doFinal(inner, 0);

        digest.reset();
        digest.update(outputPad, 0, blockLen);
        digest.update(inner, 0, inner.length);
        int len = digest.doFinal(out, outOff);

        Arrays.fill(inner, (byte) 0); // затираем промежуточные значения от утечек

        digest.reset();
        digest.update(inputPad, 0, blockLen);

        return len;
    }

    @Override
    public void reset() {
        checkInitialized();
        digest.reset();
        digest.update(inputPad, 0, blockLen);
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("HMAC not initialized — call init() first");
        }
    }

    /**
     * Уничтожает ключевой материал, обнуляя внутренние буферы {@code inputPad} и {@code outputPad}.
     *
     * <p>Отличие от {@link #reset()}: {@code reset()} сбрасывает состояние дайджеста и
     * заново загружает {@code inputPad}, готовя экземпляр к следующему вычислению, но
     * сами буферы {@code inputPad} / {@code outputPad} остаются нетронутыми — они по-прежнему
     * содержат данные, производные от ключа. Метод {@code clear()} обнуляет эти буферы,
     * делая восстановление ключевого материала из памяти невозможным.
     *
     * <p>Дополнительно затираются рабочие буферы дайджеста ({@link Digest#destroy()}):
     * в них остаётся последний обработанный блок, то есть {@code K ⊕ ipad}.
     *
     * <p>После вызова объект неинициализирован: {@code update}, {@code doFinal} и
     * {@code reset} бросают {@link IllegalStateException} до повторного {@code init}.
     *
     * <p>Используется в коде электронной подписи ({@code ECDSASigner}) для уничтожения
     * временных HMAC-буферов после выработки нонса {@code k} по RFC 6979.
     */
    public void clear() {
        Arrays.fill(inputPad, (byte) 0);
        Arrays.fill(outputPad, (byte) 0);
        // Флаг снимаем до destroy(): если сторонний Digest бросит исключение, объект не должен
        // остаться «инициализированным» с нулевыми pads и считать MAC от нулевого ключа.
        initialized = false;
        // reset() оставил бы в рабочих буферах дайджеста последний блок входа (K ⊕ ipad)
        digest.destroy();
    }

    /**
     * Уничтожает ключевой материал; то же, что {@link #clear()}. После вызова объект
     * неинициализирован и требует повторного {@code init}.
     */
    @Override
    public void destroy() {
        clear();
    }
}
