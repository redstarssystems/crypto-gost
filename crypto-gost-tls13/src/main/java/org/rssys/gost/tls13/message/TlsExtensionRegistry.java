package org.rssys.gost.tls13.message;

import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Таблица «расширение × сообщение» (RFC 8446 §4.2) для сообщений, которые принимает пир.
 * <p>
 * В таблице только расширения TLS 1.3, которые библиотека знает или использует; остальные типы
 * (TLS 1.2, расширения из других RFC) считаются неизвестными. «Известные типы» - объединение строк
 * таблицы и типов, допустимых только в ClientHello.
 * <p>
 * Правила (RFC 8446 §4.2), ответы (ServerHello, HelloRetryRequest, EncryptedExtensions,
 * Certificate) проверяются {@link #checkResponse} в таком порядке:
 * <ol>
 *   <li>известное расширение не в своём сообщении - {@code illegal_parameter};</li>
 *   <li>расширение, которого клиент не отправлял (в том числе неизвестное) -
 *       {@code unsupported_extension}; исключение - {@code cookie} в HelloRetryRequest.</li>
 * </ol>
 * Запросы сервера (CertificateRequest, NewSessionTicket) проверяются {@link #checkRequest}: только
 * первый шаг, неизвестные типы игнорируются, так как сервер вправе расширять запросы.
 */
final class TlsExtensionRegistry {

    /** Сообщения, расширения которых проверяет принимающая сторона. */
    enum Message {
        SERVER_HELLO,
        HELLO_RETRY_REQUEST,
        ENCRYPTED_EXTENSIONS,
        CERTIFICATE,
        CERTIFICATE_REQUEST,
        NEW_SESSION_TICKET
    }

    private static final Map<Message, Set<Integer>> ALLOWED = new EnumMap<>(Message.class);

    static {
        ALLOWED.put(
                Message.SERVER_HELLO,
                Set.of(
                        TlsConstants.EXT_KEY_SHARE,
                        TlsConstants.EXT_PRE_SHARED_KEY,
                        TlsConstants.EXT_SUPPORTED_VERSIONS));
        ALLOWED.put(
                Message.HELLO_RETRY_REQUEST,
                Set.of(
                        TlsConstants.EXT_KEY_SHARE,
                        TlsConstants.EXT_COOKIE,
                        TlsConstants.EXT_SUPPORTED_VERSIONS));
        ALLOWED.put(
                Message.ENCRYPTED_EXTENSIONS,
                Set.of(
                        TlsConstants.EXT_SERVER_NAME,
                        TlsConstants.EXT_MAX_FRAGMENT_LENGTH,
                        TlsConstants.EXT_SUPPORTED_GROUPS,
                        TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                        TlsConstants.EXT_EARLY_DATA));
        ALLOWED.put(Message.CERTIFICATE, Set.of(TlsConstants.EXT_STATUS_REQUEST));
        ALLOWED.put(
                Message.CERTIFICATE_REQUEST,
                Set.of(
                        TlsConstants.EXT_STATUS_REQUEST,
                        TlsConstants.EXT_SIGNATURE_ALGORITHMS,
                        TlsConstants.EXT_SIGNATURE_ALGORITHMS_CERT,
                        TlsConstants.EXT_CERTIFICATE_AUTHORITIES,
                        TlsConstants.EXT_OID_FILTERS));
        // По RFC 8446 §4.2 в NewSessionTicket сервер вправе слать расширения и без запроса,
        // поэтому early_data принимается без сверки с ClientHello (см. checkRequest)
        ALLOWED.put(Message.NEW_SESSION_TICKET, Set.of(TlsConstants.EXT_EARLY_DATA));
    }

    /**
     * Типы, допустимые только в ClientHello: ответ на них ни в каком сообщении не допускается, но
     * тип известен (клиент его отправляет), поэтому в ответе он {@code illegal_parameter}, а не
     * неизвестный.
     */
    private static final Set<Integer> CLIENT_HELLO_ONLY =
            Set.of(TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES);

    /** Известные типы: объединение допустимых типов всех сообщений и типов только ClientHello. */
    private static final Set<Integer> KNOWN = buildKnownTypes();

    private static Set<Integer> buildKnownTypes() {
        Set<Integer> known = new HashSet<>(CLIENT_HELLO_ONLY);
        for (Set<Integer> allowed : ALLOWED.values()) {
            known.addAll(allowed);
        }
        return Set.copyOf(known);
    }

    private TlsExtensionRegistry() {}

    /**
     * Проверяет расширения ответа сервера (или клиента в Certificate) по таблице и по факту запроса.
     * <p>
     * Сначала все типы проверяются на допустимость в сообщении, и только потом на факт запроса,
     * в отсортированном порядке: код alert не зависит от порядка расширений в сообщении, а при
     * нескольких нарушениях в тексте ошибки называется один и тот же тип.
     *
     * @param message     сообщение, которому принадлежит блок расширений
     * @param present     типы расширений, присутствующих в сообщении
     * @param sentTypes   типы расширений, отправленных в запросе, на который это ответ
     * @throws TlsException {@code illegal_parameter} для известного расширения не из этого
     *                      сообщения, {@code unsupported_extension} для расширения без запроса
     */
    static void checkResponse(Message message, Set<Integer> present, Set<Integer> sentTypes)
            throws TlsException {
        checkRequest(message, present);
        // Отсортированный обход: при нескольких нарушениях в тексте ошибки называется один и тот же
        // тип
        for (int type : new TreeSet<>(present)) {
            boolean cookieInRetryRequest =
                    message == Message.HELLO_RETRY_REQUEST && type == TlsConstants.EXT_COOKIE;
            if (!sentTypes.contains(type) && !cookieInRetryRequest) {
                throw new TlsException(
                        TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                        message + ": extension " + type + " was not requested");
            }
        }
    }

    /**
     * Проверяет расширения запроса сервера (CertificateRequest, NewSessionTicket): известное
     * расширение не из этого сообщения - {@code illegal_parameter}, неизвестное игнорируется.
     *
     * @param message сообщение, которому принадлежит блок расширений
     * @param present типы расширений, присутствующих в сообщении
     * @throws TlsException {@code illegal_parameter} для известного расширения не из этого сообщения
     */
    static void checkRequest(Message message, Set<Integer> present) throws TlsException {
        Set<Integer> allowed = ALLOWED.get(message);
        for (int type : new TreeSet<>(present)) {
            if (KNOWN.contains(type) && !allowed.contains(type)) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        message + ": extension " + type + " is not allowed in this message");
            }
        }
    }
}
