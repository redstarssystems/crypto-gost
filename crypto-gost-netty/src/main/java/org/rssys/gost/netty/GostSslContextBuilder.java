package org.rssys.gost.netty;

import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.CipherSuiteFilter;
import io.netty.handler.ssl.ClientAuth;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.util.CryptoRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Fluent builder для {@link GostSslContext}.
 * <p>
 * Точка входа — статические методы {@link #forClient()} и {@link #forServer(KeyManager)}.
 * После конфигурации вызывать {@link #build()}.
 * <p>
 * Пример использования (клиент):
 * <pre>{@code
 * GostX509TrustManager tm = new GostX509TrustManager(caPub, false);
 * GostSslContext ctx = GostSslContextBuilder.forClient()
 *         .trustManager(tm)
 *         .build();
 * }</pre>
 * <p>
 * Пример использования (сервер):
 * <pre>{@code
 * GostX509KeyManager km = new GostX509KeyManager();
 * km.addKeyEntry("default", certChain, privateKey);
 * GostSslContext ctx = GostSslContextBuilder.forServer(km)
 *         .build();
 * }</pre>
 */
public final class GostSslContextBuilder {

    private static final CipherSuiteFilter PASSTHROUGH_FILTER =
            (ciphers, defaultCiphers, supportedCiphers) -> {
                List<String> result = new ArrayList<>();
                for (String c : ciphers) {
                    if (supportedCiphers == null || supportedCiphers.contains(c)) {
                        result.add(c);
                    }
                }
                return result.toArray(new String[0]);
            };

    private final boolean isClient;
    private KeyManagerFactory keyManagerFactory;
    private KeyManager[] keyManagers;
    private TrustManagerFactory trustManagerFactory;
    private TrustManager[] trustManagers;
    private ClientAuth clientAuth = ClientAuth.NONE;
    private String[] alpnProtocols;
    private boolean sessionCacheSizeSet;
    private long sessionCacheSize;
    private boolean sessionTimeoutSet;
    private int sessionTimeout;

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
     */
    public static GostSslContextBuilder forClient() {
        return new GostSslContextBuilder(true);
    }

    /**
     * Создаёт builder для серверного GostSslContext с готовым KeyManagerFactory.
     * <p>
     * Фабрика должна быть инициализирована до вызова build().
     */
    public static GostSslContextBuilder forServer(KeyManagerFactory kmf) {
        GostSslContextBuilder b = new GostSslContextBuilder(false);
        b.keyManagerFactory = kmf;
        return b;
    }

    /**
     * Создаёт builder для серверного GostSslContext с единственным KeyManager.
     *
     * @throws IllegalArgumentException если km равен null
     */
    public static GostSslContextBuilder forServer(KeyManager km) {
        if (km == null) {
            throw new IllegalArgumentException("GostSslContextBuilder.forServer: KeyManager must not be null");
        }
        GostSslContextBuilder b = new GostSslContextBuilder(false);
        b.keyManagers = new KeyManager[]{km};
        return b;
    }

    // ========================================================================
    // Fluent setters
    // ========================================================================

    /**
     * Задаёт TrustManagerFactory для проверки сертификатов пира.
     * Фабрика должна быть инициализирована до вызова build().
     */
    public GostSslContextBuilder trustManager(TrustManagerFactory tmf) {
        this.trustManagerFactory = tmf;
        this.trustManagers = null;
        return this;
    }

    /**
     * Задаёт единственный TrustManager для проверки сертификатов пира.
     */
    public GostSslContextBuilder trustManager(TrustManager tm) {
        this.trustManagers = new TrustManager[]{tm};
        this.trustManagerFactory = null;
        return this;
    }

    /**
     * Задаёт массив TrustManager для проверки сертификатов пира.
     */
    public GostSslContextBuilder trustManager(TrustManager... tms) {
        this.trustManagers = tms.clone();
        this.trustManagerFactory = null;
        return this;
    }

    /**
     * Задаёт KeyManagerFactory для серверного сертификата (или клиентского при mTLS).
     * Фабрика должна быть инициализирована до вызова build().
     * Переопределяет keyManager, заданный через forServer(KeyManager).
     */
    public GostSslContextBuilder keyManager(KeyManagerFactory kmf) {
        this.keyManagerFactory = kmf;
        this.keyManagers = null;
        return this;
    }

    /**
     * Задаёт единственный KeyManager для серверного сертификата (или клиентского при mTLS).
     */
    public GostSslContextBuilder keyManager(KeyManager km) {
        this.keyManagers = new KeyManager[]{km};
        this.keyManagerFactory = null;
        return this;
    }

    /**
     * Режим аутентификации клиента.
     * Имеет смысл только для серверного контекста.
     */
    public GostSslContextBuilder clientAuth(ClientAuth clientAuth) {
        this.clientAuth = clientAuth;
        return this;
    }

    /**
     * Протоколы прикладного уровня для ALPN (RFC 7301).
     * Например, "h2", "http/1.1". Если не заданы — ALPN отключён.
     */
    public GostSslContextBuilder applicationProtocols(String... protocols) {
        this.alpnProtocols = protocols != null ? protocols.clone() : null;
        return this;
    }

    /**
     * Размер кэша сессий SSL.
     * 0 — значение по умолчанию (размер кэша из SSLContext).
     */
    public GostSslContextBuilder sessionCacheSize(long sessionCacheSize) {
        this.sessionCacheSize = sessionCacheSize;
        this.sessionCacheSizeSet = true;
        return this;
    }

    /**
     * Таймаут сессий SSL в секундах.
     * 0 = без ограничения (JSSE-контракт, RFC_MAX_TICKET_LIFETIME).
     * По умолчанию — 86400 (24 часа).
     */
    public GostSslContextBuilder sessionTimeout(int sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
        this.sessionTimeoutSet = true;
        return this;
    }

    // ========================================================================
    // build
    // ========================================================================

    /**
     * Собирает GostSslContext с текущей конфигурацией.
     *
     * @throws SSLException если конфигурация невалидна или произошла ошибка
     * @throws IllegalStateException если KeyManagerFactory/TrustManagerFactory
     *         не инициализированы
     */
    public GostSslContext build() throws SSLException {
        validate();

        Provider provider = new RssysGostJsseProvider();
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3, provider);
        } catch (NoSuchAlgorithmException e) {
            // Не должно случиться — наш провайдер регистрирует TLSv1.3
            throw new SSLException("GostSslContext: TLSv1.3 not available from RssysGostJsse", e);
        }

        KeyManager[] kmArray = resolveKeyManagers();
        TrustManager[] tmArray = resolveTrustManagers();

        try {
            sslContext.init(kmArray, tmArray, CryptoRandom.INSTANCE);
        } catch (KeyManagementException e) {
            throw new SSLException("GostSslContext: failed to init SSLContext", e);
        }

        if (sessionCacheSizeSet || sessionTimeoutSet) {
            configureSessionContext(sslContext);
        }

        ApplicationProtocolConfig apnConfig = buildApnConfig();
        List<String> gostCiphers = Arrays.asList(GostJsseConstants.SUPPORTED_CIPHER_SUITES);

        GostSslContext gostCtx = new GostSslContext(
                sslContext, isClient,
                gostCiphers, PASSTHROUGH_FILTER,
                apnConfig, clientAuth,
                GostJsseConstants.SUPPORTED_PROTOCOLS,
                false);

        verifyCipherSuites(gostCtx, gostCiphers);

        return gostCtx;
    }

    // ========================================================================
    // Внутренние методы
    // ========================================================================

    private void validate() throws SSLException {
        if (isClient) {
            TrustManager[] tm = resolveTrustManagers();
            if (tm == null || tm.length == 0) {
                throw new SSLException(
                        "GostSslContext: client requires at least one TrustManager");
            }
        } else {
            KeyManager[] km = resolveKeyManagers();
            if (km == null || km.length == 0) {
                throw new SSLException(
                        "GostSslContext: server requires at least one KeyManager");
            }
            if (clientAuth != ClientAuth.NONE) {
                TrustManager[] tm = resolveTrustManagers();
                if (tm == null || tm.length == 0) {
                    throw new SSLException(
                            "GostSslContext: server with clientAuth requires TrustManager");
                }
            }
        }
    }

    private KeyManager[] resolveKeyManagers() {
        if (keyManagerFactory != null) {
            return keyManagerFactory.getKeyManagers();
        }
        return keyManagers;
    }

    private TrustManager[] resolveTrustManagers() {
        if (trustManagerFactory != null) {
            return trustManagerFactory.getTrustManagers();
        }
        return trustManagers;
    }

    private void configureSessionContext(SSLContext sslContext) {
        for (SSLSessionContext ss : new SSLSessionContext[]{
                sslContext.getClientSessionContext(),
                sslContext.getServerSessionContext()}) {
            if (ss == null) continue;
            if (sessionCacheSizeSet) {
                ss.setSessionCacheSize((int) Math.min(sessionCacheSize, Integer.MAX_VALUE));
            }
            if (sessionTimeoutSet) {
                ss.setSessionTimeout(sessionTimeout);
            }
        }
    }

    // WHY: GostSSLEngine при ALPN mismatch возвращает null из селектора —
    // handshake продолжается без ALPN (applicationProtocol = null).
    // NO_ADVERTISE + ACCEPT отражают реальное поведение: mismatch не роняет
    // handshake, а просто не включает ALPN-расширение в EncryptedExtensions.
    // FATAL_ALERT приводил к флапанию: JdkAlpnSslEngine (JDK 9+ path)
    // интерпретировал его буквально и бросал SSLHandshakeException.
    private ApplicationProtocolConfig buildApnConfig() {
        if (alpnProtocols == null || alpnProtocols.length == 0) {
            return ApplicationProtocolConfig.DISABLED;
        }
        return new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                Arrays.asList(alpnProtocols));
    }

    private static void verifyCipherSuites(GostSslContext ctx, List<String> allowedSuites)
            throws SSLException {
        List<String> effective = ctx.cipherSuites();
        Set<String> allowed = new HashSet<>(allowedSuites);
        List<String> nonGost = new ArrayList<>();

        for (String s : effective) {
            if (!allowed.contains(s)) {
                nonGost.add(s);
            }
        }

        if (effective.isEmpty()) {
            throw new SSLException(
                    "GostSslContext: no cipher suites enabled. "
                            + "Expected GOST suites: " + allowedSuites);
        }
        if (!nonGost.isEmpty()) {
            throw new SSLException(
                    "GostSslContext: non-GOST cipher suites detected: " + nonGost
                            + ". Only GOST suites are allowed: " + allowedSuites);
        }
    }
}
