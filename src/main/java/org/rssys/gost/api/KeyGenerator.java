package org.rssys.gost.api;

import org.rssys.crypto.util.SCrypt;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Генератор ключей
 *
 * <p>Поддерживает:
 * <ul>
 *   <li>Симметричный ключ для Кузнечика (ГОСТ Р 34.12-2015) — 256 бит</li>
 *   <li>Ключевая пара для ЭП (ГОСТ Р 34.10-2012) — 256 или 512 бит</li>
 *   <li>Вывод симметричного ключа из пароля (scrypt, RFC 7914)</li>
 * </ul>
 *
 * <p>Все методы класса являются статическими и потокобезопасными.
 *
 * <p><b>Пример использования:</b>
 * <pre>{@code
 * // Симметричный ключ
 * SymmetricKey key = KeyGenerator.generateSymmetricKey();
 *
 * // Ключевая пара ЭП
 * KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
 * // ... использование ...
 * pair.getPrivate().destroy(); // обязательно после завершения
 *
 * // Вывод ключа из пароля
 * SymmetricKey derived = KeyGenerator.deriveKey(password, salt);
 * Arrays.fill(password, (byte) 0); // очистка пароля — ответственность вызывающего
 * }</pre>
 */
public final class KeyGenerator {

    private KeyGenerator() {}

    /**
     * Генерирует случайный симметричный ключ для шифра Кузнечик.
     *
     * <p>Ключ имеет длину 32 байта (256 бит)
     * Использует {@link SecureRandom} по умолчанию.
     *
     * @return {@link SymmetricKey}
     */
    public static SymmetricKey generateSymmetricKey() {
        return generateSymmetricKey(CryptoRandom.INSTANCE);
    }

    /**
     * Генерирует случайный симметричный ключ для шифра Кузнечик с заданным генератором.
     *
     * @param rng генератор случайных чисел
     * @return {@link SymmetricKey}
     */
    public static SymmetricKey generateSymmetricKey(SecureRandom rng) {
        // Кузнечик: длина ключа строго 32 байта (ГОСТ Р 34.12-2015)
        byte[] keyBytes = new byte[Cipher.KEY_SIZE];
        rng.nextBytes(keyBytes);
        return new SymmetricKey(keyBytes);
    }

    /**
     * Генерирует ключевую пару для алгоритма ЭП ГОСТ Р 34.10-2012.
     *
     * <p>Закрытый ключ d вырабатывается как случайное целое число из диапазона (0, q),
     * открытый ключ Q = d·G вычисляется через скалярное умножение базовой точки.
     *
     * <p>Дополнительные байты (rolen + 8) при генерации обеспечивают равномерное
     * распределение d по всему диапазону (0, q).
     *
     * @param params параметры кривой (например, {@link ECParameters#cryptoProA()})
     * @return ключевая пара {@link KeyPair}
     */
    public static KeyPair generateKeyPair(ECParameters params) {
        return generateKeyPair(params, CryptoRandom.INSTANCE);
    }

    /**
     * Генерирует ключевую пару с заданным генератором случайных чисел.
     *
     * @param params параметры кривой
     * @param rng    генератор случайных чисел
     * @return ключевая пара {@link KeyPair}
     */
    public static KeyPair generateKeyPair(ECParameters params, SecureRandom rng) {
        int rolen = params.hlen; // 32 для 256-бит, 64 для 512-бит кривых

        // Генерируем закрытый ключ d ∈ (0, q)
        // RFC 7091 §5.2: 0 < d < q
        // Дополнительные 8 байт обеспечивают равномерность распределения
        BigInteger d;
        do {
            byte[] raw = new byte[rolen + 8];
            rng.nextBytes(raw);
            d = new BigInteger(1, raw).mod(params.n);
        } while (d.signum() == 0);

        // Вычисляем открытый ключ Q = d·G
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint q = g.multiply(d).normalize();

        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);
        PublicKeyParameters  pub  = new PublicKeyParameters(q, params);

        return new KeyPair(priv, pub);
    }

    // -----------------------------------------------------------------------
    // Генерация симметричного ключа из пароля (scrypt, RFC 7914)
    // -----------------------------------------------------------------------

    /**
     * Получает симметричный ключ из пароля и соли с помощью scrypt (RFC 7914).
     *
     * <p>Параметры по умолчанию:
     * <ul>
     *   <li>N = 524288 (2^19) — параметр стоимости CPU/памяти</li>
     *   <li>r = 8 — размер блока</li>
     *   <li>p = 1 — параллелизм</li>
     *   <li>dkLen = 32 байта (256 бит) — длина ключа для Кузнечика</li>
     * </ul>
     *
     * <p><b>Внимание:</b> массив {@code password} не обнуляется методом.
     * После вызова рекомендуется: {@code Arrays.fill(password, (byte) 0)}.
     *
     * @param password пароль в виде байтового массива
     * @param salt     соль (рекомендуется случайная, не менее 16 байт)
     * @return {@link SymmetricKey} с производным ключом 32 байта
     * @throws GeneralSecurityException если HmacSHA256 недоступен в JCA
     */
    public static SymmetricKey deriveKey(byte[] password, byte[] salt)
        throws GeneralSecurityException {
        // Параметры scrypt, рекомендованные RFC 7914 и OWASP
        return deriveKey(password, salt, 524288, 8, 1);
    }

    /**
     * Выводит симметричный ключ из пароля с явно заданными параметрами scrypt.
     *
     * @param password пароль
     * @param salt     соль
     * @param N        параметр стоимости (степень 2, > 1)
     * @param r        размер блока (≥ 1)
     * @param p        параллелизм (≥ 1)
     * @return {@link SymmetricKey} с производным ключом 32 байта
     * @throws GeneralSecurityException если HmacSHA256 недоступен в JCA
     */
    public static SymmetricKey deriveKey(byte[] password, byte[] salt, int N, int r, int p)
        throws GeneralSecurityException {
        byte[] keyBytes = SCrypt.generate(password, salt, N, r, p, Cipher.KEY_SIZE);
        return new SymmetricKey(keyBytes);
    }
}
