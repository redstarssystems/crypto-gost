package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;

@DisplayName("GostSslBuilder: флаги режима доходят до GostSSLSessionContext")
class GostSslBuilderInteropTest {

    private static GostSSLSessionContext clientSession(GostSslBuilder builder) throws Exception {
        return (GostSSLSessionContext) builder.buildClientContext().getClientSessionContext();
    }

    private static GostSSLSessionContext serverSession(GostSslBuilder builder) throws Exception {
        SSLContext ctx = builder.buildServerContext();
        return (GostSSLSessionContext) ctx.getServerSessionContext();
    }

    @Test
    @DisplayName("Без вызовов builder-методов и при явном false все флаги выключены")
    void flagsAreOffByDefaultAndWhenExplicitlyFalse() throws Exception {
        GostSSLSessionContext client = clientSession(GostSsl.builder().trustAll());
        GostSSLSessionContext server = serverSession(GostSsl.builder().trustAll());
        GostSSLSessionContext explicitFalse =
                clientSession(GostSsl.builder().trustAll().interopAcceptGostBaseSigScheme(false));

        assertFalse(client.isInteropAcceptGostBaseSigScheme(), "interop по умолчанию выключен");
        assertFalse(server.isNeedClientAuth(), "needClientAuth по умолчанию выключен");
        assertFalse(server.isWantClientAuth(), "wantClientAuth по умолчанию выключен");
        assertFalse(
                explicitFalse.isInteropAcceptGostBaseSigScheme(),
                "после interopAcceptGostBaseSigScheme(false) флаг выключен");
    }

    @Test
    @DisplayName("interopAcceptGostBaseSigScheme(true): флаг доходит до клиентского и серверного")
    void interopFlagReachesBothSessionContexts() throws Exception {
        GostSslBuilder builder = GostSsl.builder().trustAll().interopAcceptGostBaseSigScheme(true);

        assertTrue(
                clientSession(builder).isInteropAcceptGostBaseSigScheme(),
                "флаг должен дойти до clientSessionContext");
        assertTrue(
                serverSession(builder).isInteropAcceptGostBaseSigScheme(),
                "флаг должен дойти до serverSessionContext");
    }

    @Test
    @DisplayName("needClientAuth(true) включает обязательный режим")
    void needClientAuthReachesServerSessionContext() throws Exception {
        GostSSLSessionContext server =
                serverSession(GostSsl.builder().trustAll().needClientAuth(true));

        assertTrue(server.isNeedClientAuth(), "флаг должен быть true после needClientAuth(true)");
    }

    @Test
    @DisplayName("wantClientAuth(true) включает запрос, но не обязательный режим")
    void wantClientAuthDoesNotEnableNeedMode() throws Exception {
        GostSSLSessionContext server =
                serverSession(GostSsl.builder().trustAll().wantClientAuth(true));

        assertTrue(server.isWantClientAuth(), "флаг должен быть true после wantClientAuth(true)");
        assertFalse(
                server.isNeedClientAuth(), "wantClientAuth не должен включать обязательный режим");
    }
}
