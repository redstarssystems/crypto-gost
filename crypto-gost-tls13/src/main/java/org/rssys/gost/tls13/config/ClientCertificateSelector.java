package org.rssys.gost.tls13.config;

import java.util.List;

/**
 * Функциональный интерфейс для выбора сертификата клиента на основе
 * фильтров из CertificateRequest (RFC 8446 §4.2.5).
 * <p>
 * Аналог {@link SniCertificateSelector}, но для клиентской аутентификации.
 * Вызывается при получении CertificateRequest с непустым oid_filters
 * или certificate_authorities. Реализация MUST быть thread-safe, быстрой
 * и неблокирующей, так как вызывается синхронно во время handshake.
 *
 * @see OIDFilter
 * @see TlsClientCredentials
 */
@FunctionalInterface
public interface ClientCertificateSelector {

    /**
     * Выбирает учётные данные клиента, удовлетворяющие фильтрам сервера.
     *
     * @param acceptedCaDns список Distinguished Name из certificate_authorities
     *                      (RFC 8446 §4.2.4), может быть пустым
     * @param oidFilters    список OID-фильтров из oid_filters
     *                      (RFC 8446 §4.2.5), может быть пустым
     * @return учётные данные клиента или null, если подходящий сертификат не найден
     *         (в этом случае клиент отправляет пустой certificate_list)
     */
    TlsClientCredentials select(List<byte[]> acceptedCaDns, List<OIDFilter> oidFilters);
}
