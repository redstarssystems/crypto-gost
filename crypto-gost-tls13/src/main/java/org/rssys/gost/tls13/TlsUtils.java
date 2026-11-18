package org.rssys.gost.tls13;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.util.SafeText;

/**
 * Утилиты для TLS 1.3 модуля.
 */
public final class TlsUtils {

    /**
     * Текст из данных собеседника для записи журнала: очищенный {@link SafeText#printableAscii},
     * отсутствующее значение (нет SNI или ALPN) читается как {@code none}.
     *
     * @param text значение или {@code null}
     * @return безопасная для журнала строка
     */
    public static String peerTextForLog(String text) {
        return text == null
                ? "none"
                : SafeText.printableAscii(text, TlsConstants.LOG_PEER_STRING_LIMIT);
    }

    private TlsUtils() {}

    /** Состояние разбора совместимого change_cipher_spec. */
    public enum CcsStatus {
        /** Запись не является change_cipher_spec, буфер не изменён. */
        NOT_CCS,
        /** Заголовок или тело записи пришли не полностью, буфер не изменён. */
        INCOMPLETE,
        /** Корректный CCS потреблён целиком, позиция буфера сдвинута. */
        CONSUMED
    }

    /**
     * Результат {@link #consumeCompatibilityCcs(ByteBuffer)}.
     *
     * @param status   состояние разбора
     * @param consumed число потреблённых байт (только для {@link CcsStatus#CONSUMED})
     */
    public record CcsResult(CcsStatus status, int consumed) {}

    private static final CcsResult CCS_NOT_CCS = new CcsResult(CcsStatus.NOT_CCS, 0);
    private static final CcsResult CCS_INCOMPLETE = new CcsResult(CcsStatus.INCOMPLETE, 0);

    /**
     * Потребляет совместимый change_cipher_spec (RFC 8446 §5, §D.4), если очередная запись им
     * является. Корректный CCS (длина 1, значение 0x01) отбрасывается без обработки; любое
     * иное содержимое - нарушение протокола.
     *
     * <p>Состояние (до ClientHello, после Finished) проверяет вызывающий: оно известно только ему.
     * Буфер меняется лишь при {@link CcsStatus#CONSUMED}.</p>
     *
     * @param src буфер, позиция указывает на начало записи
     * @return результат разбора
     * @throws TlsException {@code unexpected_message}, если длина не равна 1 или значение не 0x01
     */
    public static CcsResult consumeCompatibilityCcs(ByteBuffer src) throws TlsException {
        int pos = src.position();
        if (!src.hasRemaining() || src.get(pos) != TlsConstants.CT_CHANGE_CIPHER_SPEC) {
            return CCS_NOT_CCS;
        }
        if (src.remaining() < TlsConstants.RECORD_HEADER_SIZE) {
            return CCS_INCOMPLETE;
        }
        int declaredLen = ((src.get(pos + 3) & 0xFF) << 8) | (src.get(pos + 4) & 0xFF);
        // Неверную длину отвергаем сразу, не дожидаясь остатка записи
        if (declaredLen != TlsConstants.CCS_COMPAT_PAYLOAD_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Invalid change_cipher_spec length: " + declaredLen);
        }
        int total = TlsConstants.RECORD_HEADER_SIZE + declaredLen;
        if (src.remaining() < total) {
            return CCS_INCOMPLETE;
        }
        if (src.get(pos + TlsConstants.RECORD_HEADER_SIZE) != TlsConstants.CCS_COMPAT_VALUE) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Invalid change_cipher_spec value");
        }
        src.position(pos + total);
        return new CcsResult(CcsStatus.CONSUMED, total);
    }

    /**
     * Собирает открытую запись совместимого change_cipher_spec (RFC 8446 §5, §D.4).
     *
     * <p>Пара к {@link #consumeCompatibilityCcs(ByteBuffer)}: сервер отправляет такую запись
     * сразу после первого handshake-сообщения, если клиент прислал непустой
     * {@code legacy_session_id}. Запись не входит в транскрипт и не шифруется.</p>
     *
     * @return запись {@code 14 03 03 00 01 01}
     */
    public static byte[] buildCompatibilityCcsRecord() {
        return TlsMessageBuilder.buildPlaintextRecord(
                TlsConstants.CT_CHANGE_CIPHER_SPEC, new byte[] {TlsConstants.CCS_COMPAT_VALUE});
    }

    /**
     * Проверяет длину тела alert-записи (RFC 8446 §5.4, §5.1): нулевая длина недопустима
     * ({@code unexpected_message}), длина не равная 2 - усечённый alert или несколько alert в одной
     * записи ({@code decode_error}).
     *
     * <p>Вынесено отдельно от {@link #alertDescription(byte[])}, чтобы открытый alert с неверной
     * длиной отвергался по одному заголовку записи, не дожидаясь тела.</p>
     *
     * @param length длина тела alert-записи
     * @throws TlsException при длине, отличной от 2
     */
    public static void requireAlertLength(int length) throws TlsException {
        if (length == 0) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Empty alert record");
        }
        if (length != TlsConstants.ALERT_BODY_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Malformed alert record: length " + length);
        }
    }

    /**
     * Проверяет формат тела alert-записи пира {@code [level, description]} (RFC 8446 §6) и
     * возвращает описание.
     *
     * <p>Единая проверка для открытой и зашифрованной записи, рукопожатия и фазы данных, для
     * {@code TlsSession} и {@code GostSSLEngine}. Решение по описанию остаётся у вызывающего:
     * {@code close_notify} это закрытие своей стороны (в сессии {@link PeerClosedException}, в
     * движке смена состояния), остальное - ошибка пира. Поле level не учитывается, любой alert,
     * кроме {@code close_notify}, закрывает соединение: fail-closed, в том числе для
     * {@code user_canceled}, который RFC 8446 §6.1 относит к закрывающим и допускает с уровнем
     * warning.</p>
     *
     * @param body тело alert-записи
     * @return код описания alert
     * @throws TlsException при нарушении формата
     */
    public static byte alertDescription(byte[] body) throws TlsException {
        requireAlertLength(body.length);
        return body[1];
    }

    /**
     * Проверяет OCSP-ответ для stapling: {@code null} допустим (stapling отключён), иначе длина
     * 1..{@link TlsConstants#MAX_OCSP_STAPLE_SIZE}.
     * <p>
     * Верхний предел строже uint24 из RFC 6066 §8: ответ вместе с заголовками обязан поместиться
     * в блок extensions записи CertificateEntry, длина которого - uint16. Больший ответ
     * молча переполнил бы поле длины и испортил бы сообщение.
     * <p>
     * Проверка вынесена в один метод, чтобы ошибка конфигурации выявлялась при её создании, а не
     * в середине рукопожатия.
     *
     * @param ocspResponse сырой OCSPResponse DER или {@code null}
     * @throws IllegalArgumentException если массив пуст или длиннее допустимого предела
     */
    public static void validateOcspResponse(byte[] ocspResponse) {
        if (ocspResponse != null
                && (ocspResponse.length == 0
                        || ocspResponse.length > TlsConstants.MAX_OCSP_STAPLE_SIZE)) {
            throw new IllegalArgumentException(
                    "OCSP response length must be 1.."
                            + TlsConstants.MAX_OCSP_STAPLE_SIZE
                            + ", got "
                            + ocspResponse.length);
        }
    }

    /**
     * Проверяет список протоколов ALPN на соответствие RFC 7301 §3.1:
     * — не null, не пуст
     * — каждое имя: от 1 до 255 символов, каждый символ не выше U+00FF
     * — суммарно не более 2^16-1 байт (wire limit ProtocolNameList)
     * <p>
     * RFC 7301 определяет ProtocolName как произвольную непустую последовательность байт, а не
     * как ASCII. Строка кодируется ISO-8859-1 (символ 0..0xFF соответствует одному байту, как в
     * SunJSSE с Java SE 16), поэтому любое имя передаётся без искажений, включая GREASE-значения
     * вида {@code "\u008A\u008A"} (RFC 8701). Символ выше U+00FF в один байт не помещается и
     * молча искажался бы, поэтому такое имя отвергается.
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
            for (int i = 0; i < p.length(); i++) {
                if (p.charAt(i) > 0xFF) {
                    throw new IllegalArgumentException(
                            "ALPN protocol character does not fit one byte (ISO-8859-1): "
                                    + SafeText.printableAscii(
                                            p, TlsConstants.LOG_PEER_STRING_LIMIT));
                }
            }
            // В ISO-8859-1 один символ - один байт, поэтому длина в байтах равна длине строки
            if (p.length() > TlsConstants.ALPN_PROTOCOL_NAME_MAX_LENGTH) {
                throw new IllegalArgumentException("ALPN protocol too long: " + p.length());
            }
            totalBytes += p.length();
        }
        if (totalBytes > TlsConstants.ALPN_PROTOCOL_LIST_MAX_LENGTH) {
            throw new IllegalArgumentException("ALPN protocol list too large");
        }
    }

    /**
     * Проверяет список протоколов ALPN, если он задан и не пуст.
     * <p>
     * Для путей мимо конфигураций (сеттеры движка, {@code SSLParameters}): {@code null} и пустой
     * список означают «ALPN не используем» и не ошибка. Правила имён те же, что у
     * {@link #validateAlpnProtocols}.
     *
     * @param protocols список протоколов ALPN или {@code null}
     * @throws IllegalArgumentException если непустой список не проходит {@link #validateAlpnProtocols}
     */
    public static void validateAlpnProtocolsIfPresent(List<String> protocols) {
        if (protocols != null && !protocols.isEmpty()) {
            validateAlpnProtocols(protocols);
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

    /**
     * Проверяет, что код {@code max_fragment_length} допустим (RFC 6066 §4): 1=512, 2=1024,
     * 3=2048, 4=4096. Ноль означает «расширение не используется» и допустимым кодом не считается.
     *
     * @param code код расширения
     * @return true для кодов 1..4
     */
    public static boolean isMaxFragmentLengthCode(int code) {
        return code >= TlsConstants.MAX_FRAG_LEN_512 && code <= TlsConstants.MAX_FRAG_LEN_4096;
    }

    /**
     * Размер фрагмента открытого текста в байтах по коду {@code max_fragment_length}
     * (RFC 6066 §4). Для нуля и любого недопустимого кода возвращает
     * {@link TlsConstants#MAX_PLAINTEXT_LENGTH}: так отсутствие договорённости не уменьшает
     * фрагмент, а неверный код не приводит к выходу за границы массива.
     *
     * @param code код расширения
     * @return максимальная длина открытого текста одной записи
     */
    public static int maxFragmentLength(int code) {
        return switch (code) {
            case TlsConstants.MAX_FRAG_LEN_512 -> 512;
            case TlsConstants.MAX_FRAG_LEN_1024 -> 1024;
            case TlsConstants.MAX_FRAG_LEN_2048 -> 2048;
            case TlsConstants.MAX_FRAG_LEN_4096 -> 4096;
            default -> TlsConstants.MAX_PLAINTEXT_LENGTH;
        };
    }
}
