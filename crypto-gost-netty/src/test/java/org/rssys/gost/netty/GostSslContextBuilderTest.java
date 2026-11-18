package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.handler.ssl.ClientAuth;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

class GostSslContextBuilderTest {

    private static final Provider TEST_PROVIDER = new Provider("test", "1.0", "test") {};

    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostX509TrustManager trust;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        trust = GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert));
    }

    // ========================================================================
    // Сборка и обязательные менеджеры
    // ========================================================================

    /**
     * Клиентский GostSslContext собирается с TrustManager.
     * cipherSuites() должен содержать только ГОСТ-наборы.
     */
    @Test
    @DisplayName("Клиент: сборка с TrustManager, наборы и протоколы ровно ГОСТ")
    void testClientBuild() throws Exception {
        GostSslContext ctx = GostSslContextBuilder.forClient().trustManager(trust).build();

        assertTrue(ctx.isClient(), "должен быть клиентский контекст");
        assertEquals(
                List.of(GostJsseConstants.supportedCipherSuites()),
                ctx.cipherSuites(),
                "наборы шифров должны быть ровно ГОСТ-списком провайдера");
        assertArrayEquals(
                GostJsseConstants.supportedProtocols(),
                ctx.newHandler(io.netty.buffer.UnpooledByteBufAllocator.DEFAULT, "localhost", 0)
                        .engine()
                        .getEnabledProtocols(),
                "включённые протоколы должны быть ровно ГОСТ-списком провайдера");
    }

    @Test
    @DisplayName("Клиент без TrustManager: fail-closed")
    void testClientWithoutTrustManagerFails() {
        SSLException ex =
                assertThrows(SSLException.class, () -> GostSslContextBuilder.forClient().build());
        assertTrue(
                ex.getMessage().contains("TrustManager"),
                () -> "ожидалась ошибка TrustManager, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Сервер без клиентской аутентификации собирается без TrustManager")
    void testServerWithoutClientAuthAllowsNullTrustManager() throws Exception {
        GostSslContext ctx = GostSslContextBuilder.forServer(new GostX509KeyManager()).build();

        assertNotNull(ctx, "серверный контекст без mTLS должен собираться");
    }

    @Test
    @DisplayName("Сервер requireClientAuth без TrustManager: fail-closed")
    void testServerRequireClientAuthWithoutTrustManagerFails() {
        GostX509KeyManager km = new GostX509KeyManager();

        SSLException ex =
                assertThrows(
                        SSLException.class,
                        () ->
                                GostSslContextBuilder.forServer(km)
                                        .clientAuth(ClientAuth.REQUIRE)
                                        .build());
        assertTrue(
                ex.getMessage().contains("TrustManager"),
                () -> "ожидалась ошибка TrustManager, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Фабрики менеджеров: клиент и сервер собираются из инициализированных фабрик")
    void testFactoriesAccepted() throws Exception {
        TrustManagerFactory tmf = trustFactory(trust);
        KeyManagerFactory kmf = keyFactory(new GostX509KeyManager());

        assertNotNull(GostSslContextBuilder.forClient().trustManager(tmf).build());
        assertNotNull(GostSslContextBuilder.forServer(kmf).build());
        assertNotNull(
                GostSslContextBuilder.forServer(new GostX509KeyManager())
                        .keyManager(kmf)
                        .trustManager(tmf)
                        .clientAuth(ClientAuth.OPTIONAL)
                        .build());
    }

    // ========================================================================
    // Сторонние и некорректные менеджеры из фабрик (тип проверяет SPI)
    // ========================================================================

    @Test
    @DisplayName("Фабрика выдала сторонний TrustManager: fail-closed")
    void testForeignTrustManagerFromFactoryRejected() {
        TrustManagerFactory foreign = trustFactory(new TrustManager() {});

        SSLException ex =
                assertThrows(
                        SSLException.class,
                        () -> GostSslContextBuilder.forClient().trustManager(foreign).build());
        assertTrue(
                ex.getMessage().contains("GostX509TrustManager"),
                () -> "ожидалась ошибка типа TrustManager, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Фабрика выдала null-элемент TrustManager: fail-closed")
    void testNullTrustManagerElementFromFactoryRejected() {
        TrustManagerFactory withNull = trustFactory((TrustManager) null);

        SSLException ex =
                assertThrows(
                        SSLException.class,
                        () -> GostSslContextBuilder.forClient().trustManager(withNull).build());
        assertTrue(
                ex.getMessage().contains("TrustManager"),
                () -> "ожидалась ошибка TrustManager, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Фабрика выдала сторонний KeyManager: ошибка при сборке, а не при рукопожатии")
    void testForeignKeyManagerFromFactoryRejected() {
        KeyManagerFactory foreign = keyFactory(new KeyManager() {});

        SSLException ex =
                assertThrows(
                        SSLException.class, () -> GostSslContextBuilder.forServer(foreign).build());
        assertTrue(
                ex.getMessage().contains("GostX509KeyManager"),
                () -> "ожидалась ошибка типа KeyManager, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Фабрика выдала два разных GostX509KeyManager: ошибка при сборке")
    void testTwoDistinctKeyManagersFromFactoryRejected() {
        KeyManagerFactory two = keyFactory(new GostX509KeyManager(), new GostX509KeyManager());

        SSLException ex =
                assertThrows(
                        SSLException.class, () -> GostSslContextBuilder.forServer(two).build());
        assertTrue(
                ex.getMessage().contains("GostX509KeyManager"),
                () -> "ожидалась ошибка менеджеров ключей, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Фабрика без менеджеров ключей у сервера: fail-closed")
    void testServerEmptyKeyManagerFactoryRejected() {
        KeyManagerFactory empty = keyFactory();

        SSLException ex =
                assertThrows(
                        SSLException.class, () -> GostSslContextBuilder.forServer(empty).build());
        assertTrue(
                ex.getMessage().contains("KeyManager"),
                () -> "ожидалась ошибка KeyManager, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Неинициализированные фабрики: SSLException с понятным текстом")
    void testUninitializedFactoriesRejected() {
        TrustManagerFactory badTrust =
                new TrustManagerFactory(
                        new TrustManagerFactorySpi() {
                            @Override
                            protected void engineInit(KeyStore ks) {}

                            @Override
                            protected void engineInit(ManagerFactoryParameters spec) {}

                            @Override
                            protected TrustManager[] engineGetTrustManagers() {
                                throw new IllegalStateException("not initialized");
                            }
                        },
                        TEST_PROVIDER,
                        "test") {};
        KeyManagerFactory badKeys =
                new KeyManagerFactory(
                        new KeyManagerFactorySpi() {
                            @Override
                            protected void engineInit(KeyStore ks, char[] password) {}

                            @Override
                            protected void engineInit(ManagerFactoryParameters spec) {}

                            @Override
                            protected KeyManager[] engineGetKeyManagers() {
                                throw new IllegalStateException("not initialized");
                            }
                        },
                        TEST_PROVIDER,
                        "test") {};

        SSLException trustEx =
                assertThrows(
                        SSLException.class,
                        () -> GostSslContextBuilder.forClient().trustManager(badTrust).build());
        SSLException keyEx =
                assertThrows(
                        SSLException.class, () -> GostSslContextBuilder.forServer(badKeys).build());
        assertTrue(trustEx.getMessage().contains("TrustManagerFactory is not initialized"));
        assertTrue(keyEx.getMessage().contains("KeyManagerFactory is not initialized"));
    }

    // ========================================================================
    // Единый контракт null
    // ========================================================================

    @Test
    @DisplayName("null в точках входа и сеттерах: IllegalArgumentException с именем метода")
    void testNullArgumentsRejectedImmediately() {
        GostSslContextBuilder client = GostSslContextBuilder.forClient();
        GostX509KeyManager km = new GostX509KeyManager();

        assertNullRejected(
                "forServer", () -> GostSslContextBuilder.forServer((GostX509KeyManager) null));
        assertNullRejected(
                "forServer", () -> GostSslContextBuilder.forServer((KeyManagerFactory) null));
        assertNullRejected("trustManager", () -> client.trustManager((GostX509TrustManager) null));
        assertNullRejected("trustManager", () -> client.trustManager((TrustManagerFactory) null));
        assertNullRejected("keyManager", () -> client.keyManager((GostX509KeyManager) null));
        assertNullRejected("keyManager", () -> client.keyManager((KeyManagerFactory) null));
        assertNullRejected(
                "clientAuth", () -> GostSslContextBuilder.forServer(km).clientAuth(null));
        assertNullRejected(
                "clientOcspPolicy",
                () -> GostSslContextBuilder.forServer(km).clientOcspPolicy(null));
        assertNullRejected(
                "applicationProtocols", () -> client.applicationProtocols((String[]) null));
        assertNullRejected("sessionContext", () -> client.sessionContext(null));
    }

    private static void assertNullRejected(String method, Runnable call) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, call::run);
        assertTrue(
                ex.getMessage().contains(method),
                () -> "в сообщении должно быть имя метода " + method + ": " + ex.getMessage());
    }

    // ========================================================================
    // Ролевые правила
    // ========================================================================

    @Test
    @DisplayName("clientAuth на клиенте: значимый режим отвергается, NONE допустим")
    void testClientAuthOnClientRejected() {
        GostSslContextBuilder client = GostSslContextBuilder.forClient();

        assertThrows(IllegalStateException.class, () -> client.clientAuth(ClientAuth.REQUIRE));
        assertThrows(IllegalStateException.class, () -> client.clientAuth(ClientAuth.OPTIONAL));
        assertDoesNotThrow(() -> client.clientAuth(ClientAuth.NONE));
    }

    @Test
    @DisplayName("clientOcspPolicy на клиенте: значимая политика отвергается, OFF допустим")
    void testClientOcspPolicyOnClientRejected() {
        GostSslContextBuilder client = GostSslContextBuilder.forClient();

        assertThrows(
                IllegalStateException.class,
                () -> client.clientOcspPolicy(ClientOcspPolicy.REQUIRE));
        assertDoesNotThrow(() -> client.clientOcspPolicy(ClientOcspPolicy.OFF));
    }

    @Test
    @DisplayName("clientOcspPolicy на сервере без клиентской аутентификации: ошибка при сборке")
    void testServerOcspPolicyWithoutClientAuthRejected() {
        GostX509KeyManager km = new GostX509KeyManager();

        SSLException ex =
                assertThrows(
                        SSLException.class,
                        () ->
                                GostSslContextBuilder.forServer(km)
                                        .clientOcspPolicy(ClientOcspPolicy.REQUIRE)
                                        .build());
        assertTrue(
                ex.getMessage().contains("clientOcspPolicy"),
                () -> "ожидалась ошибка политики OCSP, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("clientOcspPolicy и interop применяются к контексту сессий сервера")
    void testOcspPolicyAndInteropApplied() throws Exception {
        GostSslContext ctx =
                GostSslContextBuilder.forServer(new GostX509KeyManager())
                        .trustManager(trust)
                        .clientAuth(ClientAuth.REQUIRE)
                        .clientOcspPolicy(ClientOcspPolicy.REQUIRE)
                        .interopAcceptGostBaseSigScheme(true)
                        .build();

        GostSSLSessionContext sessions = (GostSSLSessionContext) ctx.sessionContext();
        assertEquals(ClientOcspPolicy.REQUIRE, sessions.getClientOcspPolicy());
        assertTrue(sessions.isInteropAcceptGostBaseSigScheme(), "interop должен быть включён");
    }

    @Test
    @DisplayName("interopAcceptGostBaseSigScheme применяется и к клиентскому контексту")
    void testInteropAppliedToClient() throws Exception {
        GostSslContext ctx =
                GostSslContextBuilder.forClient()
                        .trustManager(trust)
                        .interopAcceptGostBaseSigScheme(true)
                        .build();

        assertTrue(
                ((GostSSLSessionContext) ctx.sessionContext()).isInteropAcceptGostBaseSigScheme(),
                "interop должен быть включён");
    }

    // ========================================================================
    // Сессии
    // ========================================================================

    @Test
    @DisplayName("sessionTimeout(0) == без ограничения")
    void testSessionTimeoutZero() throws Exception {
        GostSslContext ctx =
                GostSslContextBuilder.forClient().trustManager(trust).sessionTimeout(0).build();

        assertEquals(
                0,
                ctx.context().getClientSessionContext().getSessionTimeout(),
                "sessionTimeout(0) должен быть 0 (без ограничения по JSSE-контракту)");
    }

    @Test
    @DisplayName("sessionCacheSize: по умолчанию 20 480, 0 снимает предел, N применяется")
    void testSessionCacheSize() throws Exception {
        GostSslContextBuilder base = GostSslContextBuilder.forClient().trustManager(trust);

        assertEquals(
                GostSSLSessionContext.DEFAULT_SESSION_CACHE_SIZE,
                base.build().sessionContext().getSessionCacheSize(),
                "по умолчанию действует предел контекста сессий");
        assertEquals(
                0,
                GostSslContextBuilder.forClient()
                        .trustManager(trust)
                        .sessionCacheSize(0)
                        .build()
                        .sessionContext()
                        .getSessionCacheSize(),
                "0 снимает предел");
        assertEquals(
                5,
                GostSslContextBuilder.forClient()
                        .trustManager(trust)
                        .sessionCacheSize(5)
                        .build()
                        .sessionContext()
                        .getSessionCacheSize(),
                "заданный размер должен применяться");
    }

    @Test
    @DisplayName("Отрицательные sessionCacheSize и sessionTimeout отвергаются в сеттере")
    void testNegativeSessionLimitsRejected() {
        GostSslContextBuilder client = GostSslContextBuilder.forClient();

        assertThrows(IllegalArgumentException.class, () -> client.sessionCacheSize(-1));
        assertThrows(IllegalArgumentException.class, () -> client.sessionTimeout(-1));
    }

    @Test
    @DisplayName("Внешний sessionContext вместе с лимитами builder допустим, лимиты свои")
    void testExternalSessionContextWithLimits() throws Exception {
        GostSSLSessionContext shared =
                new GostSSLSessionContext(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

        GostSslContext ctx =
                GostSslContextBuilder.forClient()
                        .trustManager(trust)
                        .sessionContext(shared)
                        .sessionCacheSize(7)
                        .sessionTimeout(60)
                        .build();

        assertEquals(7, ctx.sessionContext().getSessionCacheSize(), "лимит builder применяется");
        assertEquals(60, ctx.sessionContext().getSessionTimeout(), "тайм-аут builder применяется");
        assertEquals(
                GostSSLSessionContext.DEFAULT_SESSION_CACHE_SIZE,
                shared.getSessionCacheSize(),
                "настройки внешнего контекста builder не меняет");
    }

    // ========================================================================
    // ALPN
    // ========================================================================

    @Test
    @DisplayName(
            "applicationProtocols: недопустимое имя отвергается сразу, пустой список отключает")
    void testApplicationProtocolsValidation() {
        GostSslContextBuilder client = GostSslContextBuilder.forClient();

        assertThrows(IllegalArgumentException.class, () -> client.applicationProtocols("h2", ""));
        assertThrows(
                IllegalArgumentException.class, () -> client.applicationProtocols("x".repeat(256)));
        assertDoesNotThrow(() -> client.applicationProtocols());
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static TrustManagerFactory trustFactory(TrustManager... managers) {
        return new TrustManagerFactory(
                new TrustManagerFactorySpi() {
                    @Override
                    protected void engineInit(KeyStore ks) {}

                    @Override
                    protected void engineInit(ManagerFactoryParameters spec) {}

                    @Override
                    protected TrustManager[] engineGetTrustManagers() {
                        return managers;
                    }
                },
                TEST_PROVIDER,
                "test") {};
    }

    private static KeyManagerFactory keyFactory(KeyManager... managers) {
        return new KeyManagerFactory(
                new KeyManagerFactorySpi() {
                    @Override
                    protected void engineInit(KeyStore ks, char[] password) {}

                    @Override
                    protected void engineInit(ManagerFactoryParameters spec) {}

                    @Override
                    protected KeyManager[] engineGetKeyManagers() {
                        return managers;
                    }
                },
                TEST_PROVIDER,
                "test") {};
    }
}
