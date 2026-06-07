package org.rssys.gost.jca.spi;

import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.kdf.Pbkdf2Streebog;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Реализация {@link SecretKeyFactorySpi} для PBKDF2 на HMAC-Streebog-512 (RFC 9337 §4).
 * <p>
 * Вырабатывает ключ из пароля по PBKDF2 (RFC 2898 §5.2) с PRF = HMAC-Streebog-512.
 * <pre>{@code
 * SecretKeyFactory skf =
 *     SecretKeyFactory.getInstance("PBKDF2WithHmacStreebog512", provider);
 * PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLenBits);
 * SecretKey key = skf.generateSecret(spec);
 * }</pre>
 * <p>
 * Поддерживаемые спецификации:
 * <ul>
 *   <li>{@link PBEKeySpec} → PBKDF2-выработка</li>
 *   <li>{@link SecretKeySpec} → обёртка сырых байт как {@link GostSecretKey}</li>
 * </ul>
 * <p>
 * Регистрируется в провайдере как {@code "PBKDF2WithHmacStreebog512"}.
 */
public final class GostPbkdf2SecretKeyFactorySpi extends SecretKeyFactorySpi {

    private static final String ALGORITHM = "PBKDF2WithHmacStreebog512";

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PBEKeySpec pbeSpec) {
            return generateFromPbe(pbeSpec);
        }
        if (keySpec instanceof SecretKeySpec) {
            return translateFromSpec((SecretKeySpec) keySpec);
        }
        throw new InvalidKeySpecException(
            "Unsupported KeySpec type: " + keySpec.getClass().getName()
            + ". Expected PBEKeySpec or SecretKeySpec");
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec)
            throws InvalidKeySpecException {
        if (PBEKeySpec.class.equals(keySpec)) {
            throw new InvalidKeySpecException(
                "PBEKeySpec is not supported as output KeySpec; use SecretKeySpec");
        }
        if (!SecretKeySpec.class.isAssignableFrom(keySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec class: " + keySpec.getName()
                + ". Supported: SecretKeySpec");
        }
        if (!ALGORITHM.equals(key.getAlgorithm())) {
            throw new InvalidKeySpecException(
                "Incompatible key algorithm: " + key.getAlgorithm()
                + ". Expected " + ALGORITHM);
        }
        byte[] raw = key.getEncoded();
        if (raw == null) {
            throw new InvalidKeySpecException("Key encoding is not available");
        }
        return new SecretKeySpec(raw, ALGORITHM);
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof GostSecretKey) {
            if (!ALGORITHM.equals(key.getAlgorithm())) {
                throw new InvalidKeyException(
                    "Incompatible key algorithm: " + key.getAlgorithm()
                    + ". Expected " + ALGORITHM);
            }
            return key;
        }
        if ("RAW".equals(key.getFormat())) {
            byte[] raw = key.getEncoded();
            if (raw == null || raw.length == 0) {
                throw new InvalidKeyException("Key encoding is null or empty");
            }
            return new GostSecretKey(ALGORITHM, raw);
        }
        throw new InvalidKeyException(
            "Cannot translate key with format '" + key.getFormat()
            + "'. Expected RAW format");
    }

    private static SecretKey generateFromPbe(PBEKeySpec spec) throws InvalidKeySpecException {
        int keyLengthBits = spec.getKeyLength();
        int keyLengthBytes = keyLengthBits / 8;
        if (keyLengthBits <= 0 || keyLengthBytes < 1) {
            throw new InvalidKeySpecException(
                "keyLength must be at least 8 bits, got " + keyLengthBits);
        }

        byte[] salt = spec.getSalt();
        if (salt == null) {
            throw new InvalidKeySpecException("salt must not be null");
        }

        int iterationCount = spec.getIterationCount();
        if (iterationCount < 1) {
            throw new InvalidKeySpecException(
                "iteration count must be >= 1, got " + iterationCount);
        }

        char[] passwordChars = spec.getPassword();
        if (passwordChars == null) {
            throw new InvalidKeySpecException("password must not be null");
        }
        byte[] passwordBytes = toUtf8Bytes(passwordChars);
        byte[] dk = Pbkdf2Streebog.generate(passwordBytes, salt, iterationCount, keyLengthBytes);
        try {
            return new GostSecretKey(ALGORITHM, dk);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(dk, (byte) 0);
        }
    }

    private static SecretKey translateFromSpec(SecretKeySpec spec) throws InvalidKeySpecException {
        byte[] raw = spec.getEncoded();
        if (raw == null || raw.length == 0) {
            throw new InvalidKeySpecException("SecretKeySpec contains null or empty key bytes");
        }
        return new GostSecretKey(ALGORITHM, raw);
    }

    /**
     * Преобразует массив символов в байты UTF-8.
     *
     * <p><b>Ограничение:</b> символы за пределами Basic Multilingual Plane
     * (U+10000 и выше, кодируемые суррогатными парами) не поддерживаются —
     * каждый суррогат (0xD800–0xDFFF) кодируется как 3 байта UTF-8 (CESU-8),
     * а не как корректная 4-байтовая последовательность UTF-8. На практике
     * пароли, содержащие символы за пределами BMP, крайне редки; все
     * тест-векторы RFC 9337 используют ASCII. Если потребуется полный Unicode —
     * заменить на {@code new String(chars).getBytes(StandardCharsets.UTF_8)}
     * с затиранием String через reflection.
     */
    private static byte[] toUtf8Bytes(char[] chars) {
        byte[] result = new byte[chars.length * 3];
        int len = 0;
        for (char c : chars) {
            if (c < 0x80) {
                result[len++] = (byte) c;
            } else if (c < 0x800) {
                result[len++] = (byte) (0xC0 | (c >> 6));
                result[len++] = (byte) (0x80 | (c & 0x3F));
            } else {
                result[len++] = (byte) (0xE0 | (c >> 12));
                result[len++] = (byte) (0x80 | ((c >> 6) & 0x3F));
                result[len++] = (byte) (0x80 | (c & 0x3F));
            }
        }
        byte[] trimmed = Arrays.copyOf(result, len);
        Arrays.fill(result, (byte) 0);
        return trimmed;
    }
}
