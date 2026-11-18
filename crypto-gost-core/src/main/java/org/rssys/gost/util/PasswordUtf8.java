package org.rssys.gost.util;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Кодирование пароля в UTF-8 для функций вывода ключа (PBKDF2, PKCS#12, PBES2).
 *
 * <p>Один общий путь для всех мест, где пароль {@code char[]} превращается в байты, чтобы
 * ключ не зависел от того, через какой API он выведен. Кодирование строгое (стандартный UTF-8):
 * суррогатная пара даёт одну 4-байтовую последовательность, а одиночный (непарный) суррогат
 * отвергается. Замена такого суррогата на {@code ?}, как делает {@code Charset.encode}, молча дала
 * бы ключ от другого пароля.
 *
 * <p>Пароль не копируется в {@code String} (его нельзя затереть): кодирование идёт прямо из
 * {@code char[]} вызывающего, а промежуточный буфер затирается. Результат затирает вызывающий.
 */
public final class PasswordUtf8 {

    private PasswordUtf8() {}

    /**
     * Кодирует пароль в UTF-8.
     *
     * @param password пароль; {@code null} и пустой массив дают пустой результат
     * @return байты UTF-8; вызывающий обязан затереть массив после использования
     * @throws IllegalArgumentException если пароль содержит непарный суррогат (в сообщении нет
     *     содержимого пароля)
     */
    public static byte[] encode(char[] password) {
        if (password == null || password.length == 0) {
            return new byte[0];
        }
        CharsetEncoder encoder =
                StandardCharsets.UTF_8
                        .newEncoder()
                        // REPORT - поведение по умолчанию у newEncoder(); задаём явно, чтобы
                        // замену на «?» (как у Charset.encode) не внесли рефакторингом
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
        // Не более maxBytesPerChar (3 для UTF-8) байт на char: пара из двух char даёт 4 байта
        byte[] buffer =
                new byte[Math.multiplyExact(password.length, (int) encoder.maxBytesPerChar())];
        ByteBuffer out = ByteBuffer.wrap(buffer);
        try {
            CoderResult result = encoder.encode(CharBuffer.wrap(password), out, true);
            if (result.isError()) {
                throw new IllegalArgumentException(
                        "Password contains an unpaired surrogate and cannot be encoded as UTF-8");
            }
            // Буфер рассчитан на максимум байт на символ, поэтому переполнение недостижимо; но
            // усечённый пароль дал бы ключ от другого пароля, и молча пропустить его нельзя
            if (result.isOverflow()) {
                throw new IllegalStateException("UTF-8 password buffer is too small");
            }
            result = encoder.flush(out);
            if (!result.isUnderflow()) {
                throw new IllegalStateException("Unexpected UTF-8 encoder state: " + result);
            }
            return Arrays.copyOf(buffer, out.position());
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }
}
