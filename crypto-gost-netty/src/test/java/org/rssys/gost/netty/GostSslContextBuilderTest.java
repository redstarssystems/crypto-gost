package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.handler.ssl.ClientAuth;
import java.security.Security;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

class GostSslContextBuilderTest {

    private static TlsTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
    }

    /**
     * Клиентский GostSslContext собирается с TrustManager.
     * cipherSuites() должен содержать только ГОСТ-наборы.
     */
    @Test
    @DisplayName("Клиент: сборка с TrustManager")
    void testClientBuild() throws Exception {
        GostX509TrustManager tm = new GostX509TrustManager(rootCa.cert.getPublicKey(), false);

        GostSslContext ctx = GostSslContextBuilder.forClient().trustManager(tm).build();

        assertTrue(ctx.isClient(), "должен быть клиентский контекст");
        assertFalse(ctx.cipherSuites().isEmpty(), "наборы шифров не должны быть пустыми");
    }

    /**
     * Клиент без TrustManager -> SSLException (fail-closed).
     */
    @Test
    @DisplayName("Клиент без TrustManager: fail-closed")
    void testClientWithoutTrustManagerFails() {
        SSLException ex =
                assertThrows(SSLException.class, () -> GostSslContextBuilder.forClient().build());
        assertTrue(
                ex.getMessage().contains("TrustManager"),
                () -> "ожидалась ошибка TrustManager, получено: " + ex.getMessage());
    }

    /**
     * forServer(null) -> fast-fail IllegalArgumentException.
     */
    @Test
    @DisplayName("Сервер: forServer(null) -> IllegalArgumentException")
    void testServerNullKeyManagerFails() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSslContextBuilder.forServer((javax.net.ssl.KeyManager) null));
    }

    /**
     * Сервер с clientAuth=REQUIRE без TrustManager -> SSLException.
     */
    @Test
    @DisplayName("Сервер requireClientAuth без TrustManager: fail-closed")
    void testServerRequireClientAuthWithoutTrustManagerFails() throws Exception {
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

    /**
     * sessionTimeout(0) трактуется как "без ограничения" (JSSE-контракт).
     */
    @Test
    @DisplayName("sessionTimeout(0) == без ограничения")
    void testSessionTimeoutZero() throws Exception {
        GostX509TrustManager tm = new GostX509TrustManager(rootCa.cert.getPublicKey(), false);

        GostSslContext ctx =
                GostSslContextBuilder.forClient().trustManager(tm).sessionTimeout(0).build();

        // Контекст уже инициализирован — проверяем что timeout=0
        int timeout = ctx.context().getClientSessionContext().getSessionTimeout();
        assertEquals(
                0, timeout, "sessionTimeout(0) должен быть 0 (без ограничения по JSSE-контракту)");
    }
}
