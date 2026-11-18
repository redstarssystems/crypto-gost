package org.rssys.gost.tls13.config;

/**
 * Функциональный интерфейс для выбора сертификата клиента по запросу сервера (CertificateRequest,
 * RFC 8446 §4.3.2).
 * <p>
 * Аналог {@link SniCertificateSelector}, но для клиентской аутентификации. Заданный селектор
 * единственный источник учётных данных клиента: цепочка из {@link TlsClientConfig} при его наличии не
 * подставляется, а {@code null} означает пустой certificate_list (RFC 8446 §4.4.2.3).
 * <p>
 * Вызывается на каждый CertificateRequest, в том числе без {@code oid_filters} и
 * {@code certificate_authorities}: запрос несёт и схемы подписи сервера, а ключ, которым клиент
 * подпишет CertificateVerify, обязан быть из их списка (RFC 8446 §4.4.3). Реализация MUST быть
 * thread-safe, быстрой и неблокирующей, так как вызывается синхронно во время handshake.
 * <p>
 * Контракт результата: цепочка не пуста (конструктор {@link TlsClientCredentials} бросает
 * {@link IllegalArgumentException}), у листа есть открытый ключ. Исключение из селектора внутри
 * рукопожатия превращается в {@code internal_error}.
 *
 * @see ClientCertificateRequest
 * @see OIDFilter
 * @see TlsClientCredentials
 */
@FunctionalInterface
public interface ClientCertificateSelector {

    /**
     * Выбирает учётные данные клиента, подходящие серверу.
     *
     * @param request запрос сервера: DN удостоверяющих центров, OID-фильтры, запрос OCSP-staple и
     *                схемы подписи; неизменяем
     * @return учётные данные клиента или null, если подходящего сертификата нет (в этом случае
     *         клиент отправляет пустой certificate_list)
     */
    TlsClientCredentials select(ClientCertificateRequest request);
}
