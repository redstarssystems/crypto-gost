package org.rssys.gost.jca.spi;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.util.PasswordUtf8;

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
 *   <li>{@link PBEKeySpec} -> PBKDF2-выработка</li>
 *   <li>{@link SecretKeySpec} -> обёртка сырых байт как {@link GostSecretKey}</li>
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
                "Unsupported KeySpec type: "
                        + keySpec.getClass().getName()
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
                    "Unsupported KeySpec class: "
                            + keySpec.getName()
                            + ". Supported: SecretKeySpec");
        }
        if (!ALGORITHM.equals(key.getAlgorithm())) {
            throw new InvalidKeySpecException(
                    "Incompatible key algorithm: "
                            + key.getAlgorithm()
                            + ". Expected "
                            + ALGORITHM);
        }
        byte[] raw;
        try {
            raw = key.getEncoded();
        } catch (IllegalStateException e) {
            throw new InvalidKeySpecException("Key has been destroyed", e);
        }
        if (raw == null) {
            throw new InvalidKeySpecException("Key encoding is not available");
        }
        try {
            return new SecretKeySpec(raw, ALGORITHM);
        } finally {
            // SecretKeySpec хранит собственную копию; эта иначе остаётся в куче
            Arrays.fill(raw, (byte) 0);
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof GostSecretKey) {
            if (!ALGORITHM.equals(key.getAlgorithm())) {
                throw new InvalidKeyException(
                        "Incompatible key algorithm: "
                                + key.getAlgorithm()
                                + ". Expected "
                                + ALGORITHM);
            }
            if (key.isDestroyed()) {
                throw new InvalidKeyException("Key has been destroyed");
            }
            return key;
        }
        if ("RAW".equals(key.getFormat())) {
            byte[] raw;
            try {
                raw = key.getEncoded();
            } catch (IllegalStateException e) {
                throw new InvalidKeyException("Key has been destroyed", e);
            }
            if (raw == null || raw.length == 0) {
                throw new InvalidKeyException("Key encoding is null or empty");
            }
            try {
                return new GostSecretKey(ALGORITHM, raw);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        }
        throw new InvalidKeyException(
                "Cannot translate key with format '" + key.getFormat() + "'. Expected RAW format");
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

        // getPassword() возвращает копию: затираем её на любом исходе, иначе она остаётся в куче
        char[] passwordChars = spec.getPassword();
        if (passwordChars == null) {
            throw new InvalidKeySpecException("password must not be null");
        }
        try {
            byte[] passwordBytes;
            try {
                passwordBytes = PasswordUtf8.encode(passwordChars);
            } catch (IllegalArgumentException e) {
                // Непарный суррогат: молчаливая замена дала бы ключ от другого пароля
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
            byte[] dk = null;
            try {
                dk = Pbkdf2Streebog.generate(passwordBytes, salt, iterationCount, keyLengthBytes);
                return new GostSecretKey(ALGORITHM, dk);
            } finally {
                Arrays.fill(passwordBytes, (byte) 0);
                if (dk != null) {
                    Arrays.fill(dk, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    private static SecretKey translateFromSpec(SecretKeySpec spec) throws InvalidKeySpecException {
        byte[] raw = spec.getEncoded();
        try {
            if (raw == null || raw.length == 0) {
                throw new InvalidKeySpecException("SecretKeySpec contains null or empty key bytes");
            }
            return new GostSecretKey(ALGORITHM, raw);
        } finally {
            if (raw != null) {
                Arrays.fill(raw, (byte) 0);
            }
        }
    }
}
