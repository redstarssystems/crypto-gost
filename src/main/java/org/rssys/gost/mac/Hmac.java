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
public class Hmac implements Mac {

    private static final byte IPAD = 0x36;
    private static final byte OPAD = 0x5C;

    private final Digest digest;
    private final int digestSize;
    private final int blockLen;
    private final byte[] inputPad;
    private final byte[] outputPad;

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
     * @param key ключевой материал (не копируется, используется напрямую)
     */
    public void init(byte[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("HMAC key must not be null or empty");
        }
        initWithKeyBytes(key);
    }

    @Override
    public void init(CipherParameters params) {
        if (!(params instanceof SymmetricKey)) {
            throw new IllegalArgumentException("HMac requires SymmetricKey");
        }
        initWithKeyBytes(((SymmetricKey) params).getKey());
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
            k = key;
        }

        Arrays.fill(inputPad, IPAD);
        Arrays.fill(outputPad, OPAD);

        for (int i = 0; i < k.length; i++) {
            inputPad[i]  ^= k[i];
            outputPad[i] ^= k[i];
        }

        digest.reset();
        digest.update(inputPad, 0, blockLen);
    }

    @Override
    public void update(byte in) {
        digest.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        digest.update(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
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
        digest.reset();
        digest.update(inputPad, 0, blockLen);
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
     * <p>Используется в коде электронной подписи ({@code ECDSASigner}) для уничтожения
     * временных HMAC-буферов после генерации детерминированного нonce {@code k} по RFC 6979.
     */
    public void clear() {
        Arrays.fill(inputPad,  (byte) 0);
        Arrays.fill(outputPad, (byte) 0);
        digest.reset();
    }
}
