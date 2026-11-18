package org.rssys.gost.api;

import java.util.Arrays;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * API для аутентифицированного шифрования Кузнечик-MGM
 * (Multilinear Galois Mode, RFC 9058).
 * Стандартизован в России как Р 1323565.1.026-2019 (рекомендация по стандартизации, не ГОСТ).
 *
 * <p>Параметры:
 * <ul>
 *   <li>Ключ: 32 байта (256 бит, ГОСТ Р 34.12-2015)</li>
 *   <li>ICN (Initial Counter Nonce): 16 байт — уникален для каждого сообщения при данном ключе</li>
 *   <li>Тег аутентификации: 16 байт (полный блок)</li>
 *   <li>AAD (Additional Authenticated Data): произвольная длина, не шифруется</li>
 * </ul>
 *
 * <p>Формат пакета {@link #seal}:
 * <pre>
 *   [ICN (16 байт)] [шифртекст (N байт)] [тег (16 байт)]
 * </pre>
 *
 * <h3>Пример использования:</h3>
 * <pre>{@code
 * SymmetricKey key = KeyGenerator.generateSymmetricKey();
 *
 * // Шифрование с AAD
 * byte[] packet = MgmCipher.seal(plaintext, key, aad);
 *
 * // Расшифрование
 * byte[] plain = MgmCipher.open(packet, key, aad);
 *
 * // Без AAD
 * byte[] packet = MgmCipher.seal(plaintext, key);
 * byte[] plain  = MgmCipher.open(packet, key);
 * }</pre>
 *
 * <h3>Безопасность:</h3>
 * <ul>
 *   <li>ICN генерируется случайно через {@link CryptoRandom} — повтор ICN
 *       при том же ключе нарушает конфиденциальность и целостность.</li>
 *   <li>При неверном теге {@link #open} бросает {@link AuthenticationException}
 *       <em>до</em> возврата каких-либо данных.</li>
 * </ul>
 *
 * <h3>Thread-safety:</h3>
 * Все статические методы потокобезопасны.
 */
public final class MgmCipher {

    /**
     * Длина ICN в байтах (= blockSize = 16 для Кузнечика).
     * ICN ∈ V_{n-1} — 127-битное значение, хранится в 16 байт со старшим битом = 0 (RFC 9058 §3).
     */
    public static final int ICN_LEN = Kuznyechik.BLOCK_SIZE;

    /**
     * Размер тега аутентификации в байтах.
     */
    public static final int TAG_LEN = Kuznyechik.BLOCK_SIZE;

    /**
     * Минимальный размер пакета: ICN + тег.
     */
    public static final int MIN_PACKET_LEN = ICN_LEN + TAG_LEN;

    private MgmCipher() {}

    // -----------------------------------------------------------------------
    // Шифрование
    // -----------------------------------------------------------------------

    /**
     * Шифрует данные без AAD.
     * <p>
     * Генерирует случайный ICN. Возвращает зашифрованный блок данных в формате {@code [ICN][ciphertext][tag]}.
     *
     * @param plaintext открытый текст (не должен быть пустым: без AAD тег пустого сообщения не
     *                  зависит от ICN, RFC 9058 §6)
     * @param key       симметричный ключ (32 байта)
     * @return зашифрованный блок данных
     * @throws IllegalArgumentException если открытый текст пуст
     */
    public static byte[] seal(byte[] plaintext, SymmetricKey key) {
        return seal(plaintext, key, new byte[0]);
    }

    /**
     * Шифрует данные с AAD.
     * <p>
     * Генерирует случайный ICN. Возвращает зашифрованный блок данных в формате {@code [ICN][ciphertext][tag]}.
     * AAD включается в тег, но не в пакет.
     *
     * @param plaintext открытый текст
     * @param key       симметричный ключ (32 байта)
     * @param aad       ассоциированные данные (могут быть пустыми, но не одновременно с пустым
     *                  открытым текстом, RFC 9058 §6); {@code null} равнозначен пустому массиву
     * @return зашифрованный блок данных
     * @throws IllegalArgumentException если открытый текст и AAD пусты одновременно
     */
    public static byte[] seal(byte[] plaintext, SymmetricKey key, byte[] aad) {
        byte[] icn = new byte[ICN_LEN];
        CryptoRandom.INSTANCE.nextBytes(icn);
        // Гарантируем MSB = 0 (RFC 9058 §3: ICN ∈ V_{n-1})
        icn[0] &= 0x7F;
        return sealWithIcn(plaintext, key, icn, aad);
    }

    /**
     * Шифрует данные с явно заданным ICN.
     *
     * <p>Предназначен для детерминированных тестов и интеграции с внешними системами,
     * требующими фиксированного ICN. В продуктивном коде используйте {@link #seal} —
     * он гарантирует уникальный случайный ICN при каждом вызове.
     *
     * @apiNote Повтор ICN при одном и том же ключе нарушает конфиденциальность и
     *          целостность данных. Вызывающий несёт ответственность за уникальность ICN.
     *
     * @param plaintext открытый текст
     * @param key       симметричный ключ
     * @param icn       Initial Counter Nonce (ровно 16 байт, старший бит должен быть 0)
     * @param aad       ассоциированные данные (открытый текст и AAD не могут быть пусты одновременно,
     *                  RFC 9058 §6); {@code null} равнозначен пустому массиву
     * @return зашифрованный пакет {@code [ICN (16)][ciphertext (N)][tag (16)]}
     * @throws IllegalArgumentException если открытый текст и AAD пусты одновременно
     */
    public static byte[] sealWithIcn(byte[] plaintext, SymmetricKey key, byte[] icn, byte[] aad) {
        requireKey(key);
        if (icn.length != ICN_LEN) {
            throw new IllegalArgumentException(
                    "MGM ICN must be " + ICN_LEN + " bytes, got " + icn.length);
        }

        // Пакет: [ICN (16)] [шифртекст (N)] [тег (16)]
        byte[] encrypted_buffer = new byte[ICN_LEN + plaintext.length + TAG_LEN];
        System.arraycopy(icn, 0, encrypted_buffer, 0, ICN_LEN);

        Mgm mgm = new Mgm(new Kuznyechik());
        try {
            mgm.init(true, new ParametersWithIV(key, icn));

            if (aad != null && aad.length > 0) {
                mgm.updateAAD(aad, 0, aad.length);
            }

            mgm.processBytes(plaintext, 0, plaintext.length, encrypted_buffer, ICN_LEN);
            mgm.finishEncryption(encrypted_buffer, ICN_LEN + plaintext.length);

            return encrypted_buffer;
        } finally {
            mgm.destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Расшифрование
    // -----------------------------------------------------------------------

    /**
     * Расшифровывает пакет без AAD.
     *
     * @param encryptedData пакет {@code [ICN (16)][ciphertext (N)][tag (16)]}
     * @param key           ключ расшифрования
     * @return открытый текст
     * @throws AuthenticationException если тег не прошёл проверку
     */
    public static byte[] open(byte[] encryptedData, SymmetricKey key)
            throws AuthenticationException {
        return open(encryptedData, key, new byte[0]);
    }

    /**
     * Расшифровывает пакет с AAD.
     *
     * @param encryptedData пакет {@code [ICN (16)][ciphertext (N)][tag (16)]}
     * @param key           ключ расшифрования
     * @param aad           ассоциированные данные (должны совпадать с переданными при шифровании);
     *                      {@code null} равнозначен пустому массиву
     * @return открытый текст
     * @throws AuthenticationException если пакет {@code null}, короче {@link #MIN_PACKET_LEN},
     *                                  содержит недопустимый ICN (старший бит равен 1), тег не
     *                                  прошёл проверку или нет ни шифртекста, ни AAD
     *                                  (RFC 9058 §6): пакет приходит из недоверенного источника,
     *                                  и вызывающему нужен один тип отказа для любого повреждения
     */
    public static byte[] open(byte[] encryptedData, SymmetricKey key, byte[] aad)
            throws AuthenticationException {
        if (encryptedData == null || encryptedData.length < MIN_PACKET_LEN) {
            throw new AuthenticationException(
                    "MGM packet too short: minimum "
                            + MIN_PACKET_LEN
                            + " bytes, got "
                            + (encryptedData == null ? "null" : encryptedData.length));
        }
        if ((encryptedData[0] & 0x80) != 0) {
            throw new AuthenticationException("MGM packet has an invalid ICN (MSB must be 0)");
        }
        requireKey(key);

        // ICN нужен отдельным массивом (параметр IV); шифртекст и тег читаются прямо из пакета
        byte[] icn = Arrays.copyOfRange(encryptedData, 0, ICN_LEN);
        int ctLen = encryptedData.length - ICN_LEN - TAG_LEN;
        // тег находится в конце буфера

        byte[] plaintext = new byte[ctLen];
        boolean authenticated = false;

        Mgm mgm = new Mgm(new Kuznyechik());
        try {
            mgm.init(false, new ParametersWithIV(key, icn));

            if (aad != null && aad.length > 0) {
                mgm.updateAAD(aad, 0, aad.length);
            }

            mgm.processBytes(encryptedData, ICN_LEN, ctLen, plaintext, 0);

            // Проверяем тег — бросает AuthenticationException при несовпадении
            mgm.finishDecryption(encryptedData, ICN_LEN + ctLen);

            authenticated = true;
            return plaintext;
        } finally {
            // Непроверенный открытый текст не должен остаться в куче; на успешном пути plaintext
            // возвращается вызывающему, его затирать нельзя.
            if (!authenticated) {
                Arrays.fill(plaintext, (byte) 0);
            }
            mgm.destroy();
        }
    }

    /** Ключ {@code null} это ошибка вызывающего, а не повреждение пакета: отдельный отказ. */
    private static void requireKey(SymmetricKey key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }
    }
}
