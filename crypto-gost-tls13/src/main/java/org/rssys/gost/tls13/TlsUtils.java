package org.rssys.gost.tls13;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Утилиты для TLS 1.3 модуля.
 */
public final class TlsUtils {

    private TlsUtils() {
    }

    /**
     * Проверяет список протоколов ALPN на соответствие RFC 7301 §3.1:
     * — не null, не пуст
     * — каждый протокол: ASCII, длина 1-255 байт
     * — суммарно не более 2^16-1 байт (wire limit ProtocolNameList)
     *
     * @param protocols список протоколов ALPN
     * @throws IllegalArgumentException если список не проходит валидацию
     */
    public static void validateAlpnProtocols(List<String> protocols) {
        if (protocols == null || protocols.isEmpty()) {
            throw new IllegalArgumentException("ALPN protocol list must not be null or empty");
        }
        int totalBytes = 0;
        for (String p : protocols) {
            if (p == null || p.isEmpty()) {
                throw new IllegalArgumentException("ALPN protocol must not be null or empty");
            }
            // RFC 7301 §3.1: ProtocolName — это последовательность ASCII-байт (0x00-0x7F).
            // Если клиент передаст UTF-8 строку, не-ASCII байты не пройдут проверку,
            // что предотвращает неверное согласование протокола (например, h2≠h₂).
            for (int i = 0; i < p.length(); i++) {
                if (p.charAt(i) > 127) {
                    throw new IllegalArgumentException("ALPN protocol must be ASCII: " + p);
                }
            }
            byte[] bytes = p.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length > 255) {
                throw new IllegalArgumentException("ALPN protocol too long: " + bytes.length);
            }
            totalBytes += bytes.length;
        }
        if (totalBytes > 65535) {
            throw new IllegalArgumentException("ALPN protocol list too large");
        }
    }

    /**
     * Затирает массив байт (заполняет нулями).
     * Безопасный вызов для null-массива — не бросает исключение.
     *
     * <p><b>Известное ограничение платформы:</b>
     * HotSpot JIT может удалить {@link Arrays#fill(byte[], byte)} как dead code
     * если докажет, что результат не наблюдается (DCE-оптимизация).
     * На практике это маловероятно для массивов, переданных в криптооперации
     * и хранящихся в полях объекта, но полностью не исключено.
     * Дополнительная угроза: байты могут остаться в heap до GC и попасть
     * в heap dump. Гарантированная очистка ключевого материала на чистой Java
     * невозможна — см. {@code java.lang.ref.Cleaner} для детерминированного
     * момента вызова, {@code sun.misc.Unsafe.setMemory()} для обхода JIT
     * (но непортабельно).
     */
    public static void wipeArray(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
