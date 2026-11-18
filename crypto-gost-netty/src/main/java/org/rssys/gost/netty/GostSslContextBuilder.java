package org.rssys.gost.netty;

import io.netty.handler.ssl.ClientAuth;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.EndpointIdentificationMode;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.util.CryptoRandom;

/**
 * Fluent builder для {@link GostSslContext}.
 * <p>
 * Точка входа — статические методы {@link #forClient()}, {@link #forServer(GostX509KeyManager)} и
 * {@link #forServer(KeyManagerFactory)}.
 * После конфигурации вызывать {@link #build()}.
 * <p>
 * Единые правила: {@code null} в любом сеттере и точке входа отвергается сразу с
 * {@link IllegalArgumentException} (имя метода в сообщении), а настройка, не относящаяся к роли
 * (например, {@link #clientAuth} на клиенте), даёт {@link IllegalStateException} сразу, а не при
 * сборке. Значения, которые ничего не меняют ({@code ClientAuth.NONE}, {@code ClientOcspPolicy.OFF}),
 * допустимы в обеих ролях: так одну общую конфигурацию можно применять к клиенту и серверу.
 * <p>
 * Пример использования (клиент):
 * <pre>{@code
 * GostX509TrustManager tm =
 *         GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert));
 * GostSslContext ctx = GostSslContextBuilder.forClient()
 *         .trustManager(tm)
 *         .build();
 * SslHandler handler = ctx.newHandler(alloc, "example.com", 443);
 * }</pre>
 * <p>
 * Для настройки лимитов CRL/OCSP передавайте полностью сконфигурированный
 * {@code GostX509TrustManager} (полная перегрузка {@code fromTrustAnchors}) или
 * используйте {@code GostTrustManagerParameters} через {@code TrustManagerFactory.init(...)}:
 * <pre>{@code
 * GostX509TrustManager tm = GostX509TrustManager.fromTrustAnchors(
 *         anchors, ocspPolicy, ocspFetcher, crlPolicy, crlFetcher,
 *         maxCrlSize, maxRevokedEntries, crlCacheMaxBytes, maxOcspAgeMs, maxThisUpdateAge);
 * GostSslContext ctx = GostSslContextBuilder.forClient().trustManager(tm).build();
 * }</pre>
 * <p>
 * Пример использования (сервер, mTLS и ALPN):
 * <pre>{@code
 * GostX509KeyManager km = new GostX509KeyManager();
 * km.addKeyEntry("default", certChain, privateKey);
 * GostSslContext ctx = GostSslContextBuilder.forServer(km)
 *         .trustManager(clientCaTrustManager)
 *         .clientAuth(ClientAuth.REQUIRE)
 *         .applicationProtocols("h2", "http/1.1")
 *         .build();
 * }</pre>
 * <p>
 * Провайдер {@code RssysGostJsseProvider} в {@code java.security.Security} builder не
 * регистрирует: он создаёт собственный экземпляр провайдера и передаёт его в
 * {@code SSLContext.getInstance}. Регистрация нужна только для поиска провайдера по имени
 * через JCA.
 */
public final class GostSslContextBuilder {

    private final boolean isClient;
    private KeyManagerFactory keyManagerFactory;
    private GostX509KeyManager keyManager;
    private TrustManagerFactory trustManagerFactory;
    private GostX509TrustManager trustManager;
    private ClientAuth clientAuth = ClientAuth.NONE;
    private ClientOcspPolicy clientOcspPolicy = ClientOcspPolicy.OFF;
    private boolean interopAcceptGostBaseSigScheme;
    private List<String> alpnProtocols = List.of();
    private boolean sessionCacheSizeSet;
    private int sessionCacheSize;
    private boolean sessionTimeoutSet;
    private int sessionTimeout;

    /** Внешний сессионный контекст для разделения PSK между клиентом и сервером. */
    private GostSSLSessionContext externalSessionContext;

    private boolean withoutHostnameVerification;

    private GostSslContextBuilder(boolean isClient) {
        this.isClient = isClient;
    }

    // ========================================================================
    // Точки входа
    // ========================================================================

    /**
     * Создаёт builder для клиентского GostSslContext.
     * <p>
     * TrustManager обязателен (fail-closed — клиент должен проверять сервер).
     * KeyManager опционален (нужен только для mTLS).
     * <p>
     * Клиентский контекст проверяет имя узла в сертификате сервера (RFC 6125), поэтому
     * обработчик нужно создавать с узлом: {@code newHandler(alloc, host, port)}. Без узла
     * рукопожатие отказывает, пока проверка не отключена через
     * {@link #withoutHostnameVerification()}.
     */
    public static GostSslContextBuilder forClient() {
        return new GostSslContextBuilder(true);
    }

    /**
     * Создаёт builder для серверного GostSslContext с готовым KeyManagerFactory.
     * <p>
     * Фабрика должна быть инициализирована до вызова build().
     *
     * @param kmf инициализированная фабрика менеджеров ключей (не null)
     * @throws IllegalArgumentException если kmf равен null
     */
    public static GostSslContextBuilder forServer(KeyManagerFactory kmf) {
        GostSslContextBuilder b = new GostSslContextBuilder(false);
        b.keyManagerFactory = requireNonNull(kmf, "forServer", "KeyManagerFactory");
        return b;
    }

    /**
     * Создаёт builder для серверного GostSslContext с единственным KeyManager.
     *
     * @param km менеджер ключей с серверным сертификатом (не null)
     * @throws IllegalArgumentException если km равен null
     */
    public static GostSslContextBuilder forServer(GostX509KeyManager km) {
        GostSslContextBuilder b = new GostSslContextBuilder(false);
        b.keyManager = requireNonNull(km, "forServer", "KeyManager");
        return b;
    }

    // ========================================================================
    // Fluent setters
    // ========================================================================

    /**
     * Задаёт TrustManagerFactory для проверки сертификатов пира.
     * Фабрика должна быть инициализирована до вызова build(); тип выдаваемых менеджеров
     * проверяет {@code SSLContext.init} при сборке (допустим только один
     * {@code GostX509TrustManager}).
     *
     * @throws IllegalArgumentException если tmf равен null
     */
    public GostSslContextBuilder trustManager(TrustManagerFactory tmf) {
        this.trustManagerFactory = requireNonNull(tmf, "trustManager", "TrustManagerFactory");
        this.trustManager = null;
        return this;
    }

    /**
     * Задаёт TrustManager для проверки сертификатов пира. Принимается только
     * {@code GostX509TrustManager}: сторонние менеджеры движок не поддерживает.
     *
     * @throws IllegalArgumentException если tm равен null
     */
    public GostSslContextBuilder trustManager(GostX509TrustManager tm) {
        this.trustManager = requireNonNull(tm, "trustManager", "TrustManager");
        this.trustManagerFactory = null;
        return this;
    }

    /**
     * Задаёт KeyManagerFactory для серверного сертификата (или клиентского при mTLS).
     * Фабрика должна быть инициализирована до вызова build().
     * Переопределяет менеджер, заданный через {@code forServer(GostX509KeyManager)}.
     *
     * @throws IllegalArgumentException если kmf равен null
     */
    public GostSslContextBuilder keyManager(KeyManagerFactory kmf) {
        this.keyManagerFactory = requireNonNull(kmf, "keyManager", "KeyManagerFactory");
        this.keyManager = null;
        return this;
    }

    /**
     * Задаёт KeyManager для серверного сертификата (или клиентского при mTLS).
     *
     * @throws IllegalArgumentException если km равен null
     */
    public GostSslContextBuilder keyManager(GostX509KeyManager km) {
        this.keyManager = requireNonNull(km, "keyManager", "KeyManager");
        this.keyManagerFactory = null;
        return this;
    }

    /**
     * Режим аутентификации клиента. Имеет смысл только для серверного контекста.
     *
     * @throws IllegalArgumentException если clientAuth равен null
     * @throws IllegalStateException если builder клиентский и режим отличен от
     *     {@code ClientAuth.NONE}: на клиенте режим молча игнорировался бы
     */
    public GostSslContextBuilder clientAuth(ClientAuth clientAuth) {
        requireNonNull(clientAuth, "clientAuth", "ClientAuth");
        if (isClient && clientAuth != ClientAuth.NONE) {
            throw new IllegalStateException(
                    "clientAuth(" + clientAuth + ") has no effect on client side");
        }
        this.clientAuth = clientAuth;
        return this;
    }

    /**
     * Политика сервера в отношении OCSP-staple клиентского сертификата (RFC 8446 §4.4.2.1).
     * Серверная настройка: действует только при аутентификации клиента, поэтому вместе с
     * {@code ClientAuth.NONE} значение, отличное от {@code OFF}, отвергается при {@link #build()}.
     *
     * @throws IllegalArgumentException если policy равен null
     * @throws IllegalStateException если builder клиентский и политика отлична от {@code OFF}
     */
    public GostSslContextBuilder clientOcspPolicy(ClientOcspPolicy policy) {
        requireNonNull(policy, "clientOcspPolicy", "ClientOcspPolicy");
        if (isClient && policy != ClientOcspPolicy.OFF) {
            throw new IllegalStateException(
                    "clientOcspPolicy(" + policy + ") is a server-side setting");
        }
        this.clientOcspPolicy = policy;
        return this;
    }

    /**
     * Принимать базовые signature scheme от серверов openssl-gost-provider (сервер шлёт 0x0709
     * или 0x070D независимо от реальной кривой сертификата). Только для совместимости. Действует
     * в обеих ролях: клиент принимает такую схему от сервера, сервер от клиента.
     *
     * @return этот builder
     */
    public GostSslContextBuilder interopAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
        return this;
    }

    /**
     * Протоколы прикладного уровня для ALPN (RFC 7301), например {@code "h2"}, {@code "http/1.1"}.
     * Пустой список отключает ALPN (по умолчанию ALPN отключён). Имена проверяются сразу.
     * <p>
     * Политика выбора: приоритет у списка сервера. Если списки есть у обеих сторон и общего
     * протокола нет, сервер завершает рукопожатие алертом {@code no_application_protocol} (120).
     * Если ALPN настроен только у одной стороны, рукопожатие проходит, а
     * {@code applicationProtocol()} равен {@code null}: запасной вариант выбирает приложение
     * (например, {@code ApplicationProtocolNegotiationHandler}).
     *
     * @throws IllegalArgumentException если protocols равен null или имя протокола недопустимо
     */
    public GostSslContextBuilder applicationProtocols(String... protocols) {
        requireNonNull(protocols, "applicationProtocols", "protocols");
        List<String> copy = Arrays.asList(protocols.clone());
        TlsUtils.validateAlpnProtocolsIfPresent(copy);
        this.alpnProtocols = List.copyOf(copy);
        return this;
    }

    /**
     * Размер кэша JSSE-сессий. 0 снимает предел (контракт {@code SSLSessionContext}); по
     * умолчанию 20 480 записей. Ограничивает только карту JSSE-сессий: тикеты возобновления
     * (PSK) лежат в отдельном хранилище с фиксированным пределом 1000 записей, и этот размер
     * на него не влияет.
     *
     * @throws IllegalArgumentException если значение отрицательное
     */
    public GostSslContextBuilder sessionCacheSize(int sessionCacheSize) {
        if (sessionCacheSize < 0) {
            throw new IllegalArgumentException("sessionCacheSize must be non-negative");
        }
        this.sessionCacheSize = sessionCacheSize;
        this.sessionCacheSizeSet = true;
        return this;
    }

    /**
     * Тайм-аут сессий SSL в секундах. 0 = без ограничения (предел срока тикета тогда задаёт
     * RFC 8446 §4.6.1, семь суток). По умолчанию — 86400 (24 часа).
     *
     * @throws IllegalArgumentException если значение отрицательное
     */
    public GostSslContextBuilder sessionTimeout(int sessionTimeout) {
        if (sessionTimeout < 0) {
            throw new IllegalArgumentException("sessionTimeout must be non-negative");
        }
        this.sessionTimeout = sessionTimeout;
        this.sessionTimeoutSet = true;
        return this;
    }

    /**
     * Задаёт внешний сессионный контекст: PSK-тикеты сохраняются в нём и переживают
     * пересоздание {@code GostSslContext}. Подменяется только сторона этого builder (клиентский
     * или серверный контекст сессий).
     * <p>
     * Что общее, а что остаётся у создаваемого контекста:
     * <ul>
     *   <li>общее: хранилище PSK-тикетов и привязки host:port к тикетам; предел хранилища
     *       фиксирован (1000 записей);</li>
     *   <li>свои: тайм-аут сессий ({@link #sessionTimeout}) - срок жизни тикета вычисляется
     *       один раз, при его сохранении, тайм-аутом того контекста, который тикет получил или
     *       выдал, а другой контекст, читающий из общего хранилища, свой тайм-аут к уже
     *       сохранённому тикету не применяет; размер кэша JSSE-сессий
     *       ({@link #sessionCacheSize}), режим проверки имени, {@link #clientOcspPolicy},
     *       {@link #interopAcceptGostBaseSigScheme}. Настройки внешнего контекста сессий на
     *       них не влияют.</li>
     * </ul>
     * Ограничения:
     * <ul>
     *   <li>не используйте один контекст сессий для клиента и для сервера: клиентская и
     *       серверная записи с одним тикетом имеют разные привязки, а ключ хранилища - байты
     *       тикета, поэтому они затирают друг друга и возобновление молча отключается;</li>
     *   <li>общий контекст сессий между клиентскими контекстами с разными менеджерами доверия
     *       не даёт возобновления: тикет привязан к экземпляру менеджера доверия, это
     *       намеренно.</li>
     * </ul>
     * Потокобезопасность: метод предназначен для вызова в однопоточном контексте
     * строителя, до начала handshake через создаваемый контекст.
     *
     * @param sessionContext внешний контекст сессий (не null)
     * @return этот builder
     * @throws IllegalArgumentException если sessionContext равен null
     */
    public GostSslContextBuilder sessionContext(GostSSLSessionContext sessionContext) {
        this.externalSessionContext =
                requireNonNull(sessionContext, "sessionContext", "GostSSLSessionContext");
        return this;
    }

    /**
     * Отключает проверку имени узла в сертификате сервера для клиентского контекста.
     *
     * <p>По умолчанию клиентский контекст сверяет имя узла с сертификатом (RFC 6125), и это
     * не зависит от глобальных настроек Netty: свойство
     * {@code io.netty.handler.ssl.defaultEndpointVerificationAlgorithm} ({@code NONE},
     * {@code LDAP}) игнорируется, а {@code null} в {@code SSLParameters}, который Netty
     * передаёт при настройке engine, проверку не снимает. Узел обязателен
     * ({@code newHandler(alloc, host, port)}); без него рукопожатие отказывает, пока проверка не
     * отключена этим методом.</p>
     *
     * <p><b>Небезопасно:</b> без проверки имени сертификат любого доверенного УЦ принимается
     * для любого узла. Допустимо только для mesh-сервисов, внутренних соединений и тестов, где
     * аутентификация УЦ обязательна, а имя узла не используется. Решение действует на уровне
     * контекста: чтобы вернуть проверку, создайте новый контекст. В журнал пишется одно
     * предупреждение на контекст.</p>
     *
     * @return этот builder
     * @throws IllegalStateException если builder серверный: на сервере метод не имеет смысла
     */
    public GostSslContextBuilder withoutHostnameVerification() {
        if (!isClient) {
            throw new IllegalStateException(
                    "withoutHostnameVerification() has no effect on server side");
        }
        this.withoutHostnameVerification = true;
        return this;
    }

    // ========================================================================
    // build
    // ========================================================================

    /**
     * Собирает GostSslContext с текущей конфигурацией.
     *
     * @throws SSLException если конфигурация невалидна (нет менеджера ключей сервера или
     *     менеджера доверия, неинициализированная фабрика, сторонний тип менеджера, политика
     *     OCSP клиента без аутентификации клиента) или произошла ошибка инициализации
     */
    public GostSslContext build() throws SSLException {
        KeyManager[] keyManagers = resolveKeyManagers();
        TrustManager[] trustManagers = resolveTrustManagers();
        validate(keyManagers, trustManagers);

        // Собственный экземпляр: глобальная регистрация в Security не нужна и была бы
        // побочным эффектом на всё приложение
        Provider provider = new RssysGostJsseProvider();
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3, provider);
        } catch (NoSuchAlgorithmException e) {
            // Не должно случиться — наш провайдер регистрирует TLSv1.3
            throw new SSLException("GostSslContext: TLSv1.3 not available from RssysGostJsse", e);
        }

        try {
            sslContext.init(keyManagers, trustManagers, CryptoRandom.INSTANCE);
        } catch (KeyManagementException e) {
            // Тип менеджеров проверяет SPI; причина в сообщении, чтобы не прятать её в cause
            throw new SSLException(
                    "GostSslContext: failed to init SSLContext: " + e.getMessage(), e);
        }

        GostSSLSessionContext ownContext =
                (GostSSLSessionContext)
                        (isClient
                                ? sslContext.getClientSessionContext()
                                : sslContext.getServerSessionContext());
        GostSSLSessionContext otherContext =
                (GostSSLSessionContext)
                        (isClient
                                ? sslContext.getServerSessionContext()
                                : sslContext.getClientSessionContext());
        configureSessionContexts(ownContext, otherContext);

        // Подмена хранилища PSK только на стороне этого builder: чужая сторона контекста
        // не используется, а перенаправление «на всякий случай» расширило бы поверхность
        // смешения клиентских и серверных тикетов
        if (externalSessionContext != null) {
            ownContext.redirectToSharedState(externalSessionContext);
        }

        if (isClient) {
            ownContext.setEndpointIdentificationMode(
                    withoutHostnameVerification
                            ? EndpointIdentificationMode.DISABLED
                            : EndpointIdentificationMode.STRICT);
        } else {
            ownContext.setClientOcspPolicy(clientOcspPolicy);
        }

        return new GostSslContext(sslContext, isClient, clientAuth, alpnProtocols);
    }

    // ========================================================================
    // Внутренние методы
    // ========================================================================

    /**
     * Ролевые правила. Тип менеджеров здесь не проверяется: это делает
     * {@code SSLContext.init}, и вторая копия проверки расходилась бы с ним.
     */
    private void validate(KeyManager[] keyManagers, TrustManager[] trustManagers)
            throws SSLException {
        if (!isClient && (keyManagers == null || keyManagers.length == 0)) {
            throw new SSLException("GostSslContext: server requires at least one KeyManager");
        }
        boolean trustRequired = isClient || clientAuth != ClientAuth.NONE;
        if (trustRequired && (trustManagers == null || trustManagers.length == 0)) {
            throw new SSLException(
                    "GostSslContext: "
                            + (isClient ? "client" : "server with clientAuth")
                            + " requires at least one GostX509TrustManager");
        }
        if (!isClient
                && clientOcspPolicy != ClientOcspPolicy.OFF
                && clientAuth == ClientAuth.NONE) {
            // Движок отказал бы на первом рукопожатии с internal_error; ошибку конфигурации
            // нужно показать при сборке
            throw new SSLException(
                    "GostSslContext: clientOcspPolicy("
                            + clientOcspPolicy
                            + ") requires clientAuth OPTIONAL or REQUIRE");
        }
    }

    private KeyManager[] resolveKeyManagers() throws SSLException {
        if (keyManagerFactory != null) {
            try {
                return keyManagerFactory.getKeyManagers();
            } catch (IllegalStateException e) {
                throw new SSLException("GostSslContext: KeyManagerFactory is not initialized", e);
            }
        }
        return keyManager == null ? null : new KeyManager[] {keyManager};
    }

    private TrustManager[] resolveTrustManagers() throws SSLException {
        if (trustManagerFactory != null) {
            try {
                return trustManagerFactory.getTrustManagers();
            } catch (IllegalStateException e) {
                throw new SSLException("GostSslContext: TrustManagerFactory is not initialized", e);
            }
        }
        return trustManager == null ? null : new TrustManager[] {trustManager};
    }

    /**
     * Лимиты и interop применяются к обеим сторонам SSLContext: роль engine определяет
     * {@code setUseClientMode}, а контекст сессий выбирается по роли.
     */
    private void configureSessionContexts(
            GostSSLSessionContext ownContext, GostSSLSessionContext otherContext) {
        for (GostSSLSessionContext sessions : List.of(ownContext, otherContext)) {
            if (sessionCacheSizeSet) {
                sessions.setSessionCacheSize(sessionCacheSize);
            }
            if (sessionTimeoutSet) {
                sessions.setSessionTimeout(sessionTimeout);
            }
            if (interopAcceptGostBaseSigScheme) {
                sessions.setInteropAcceptGostBaseSigScheme(true);
            }
        }
    }

    private static <T> T requireNonNull(T value, String method, String argument) {
        if (value == null) {
            throw new IllegalArgumentException(
                    "GostSslContextBuilder." + method + ": " + argument + " must not be null");
        }
        return value;
    }
}
