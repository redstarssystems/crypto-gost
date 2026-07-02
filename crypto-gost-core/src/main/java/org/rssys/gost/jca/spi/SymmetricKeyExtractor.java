package org.rssys.gost.jca.spi;

import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;

/**
 * Извлекает низкоуровневый {@link SymmetricKey} из JCA-ключа для SPI шифров Кузнечика.
 * <p>
 * Общая логика для {@link GostCipherSpi}, {@link GostMgmCipherSpi} и
 * {@link GostCtrAcpkmCipherSpi}: устраняет дублирование и гарантирует затирание
 * временной копии ключевых байт, возвращённой {@link Key#getEncoded()}.
 */
final class SymmetricKeyExtractor {

    private SymmetricKeyExtractor() {}

    /**
     * Извлекает {@link SymmetricKey} из {@link GostSecretKey} или любого
     * {@link SecretKey} с форматом {@code RAW} и длиной {@link Kuznyechik#KEY_SIZE}.
     *
     * @param key JCA-ключ
     * @return {@link SymmetricKey} с собственной копией ключевых байт
     * @throws InvalidKeyException если ключ отсутствует, неподдерживаемого типа
     *                             или неверной длины
     */
    static SymmetricKey fromKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        if (key instanceof GostSecretKey gsk) {
            return gsk.toSymmetricKey();
        }
        if (key instanceof SecretKey && "RAW".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            try {
                if (encoded == null || encoded.length != Kuznyechik.KEY_SIZE) {
                    throw new InvalidKeyException(
                            "Kuznyechik requires "
                                    + Kuznyechik.KEY_SIZE
                                    + "-byte key, got "
                                    + (encoded == null ? "null" : encoded.length));
                }
                // Конструктор SymmetricKey делает собственную копию, поэтому
                // orphan-копию encoded затираем сразу после использования.
                return new SymmetricKey(encoded);
            } finally {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        }
        throw new InvalidKeyException(
                "Unsupported key type: "
                        + key.getClass().getName()
                        + ". Expected GostSecretKey or SecretKey with RAW format");
    }
}
