package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;

@DisplayName(
        "GostSslBuilder.interopAcceptGostBaseSigScheme — флаг доходит до GostSSLSessionContext")
class GostSslBuilderInteropTest {

    @Test
    @DisplayName(
            "флаг true через builder: sessionContext.isInteropAcceptGostBaseSigScheme() == true")
    void testFlagPropagatedToSessionContext() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustAll()
                        .interopAcceptGostBaseSigScheme(true)
                        .buildClientContext();

        GostSSLSessionContext sessionCtx = (GostSSLSessionContext) ctx.getClientSessionContext();
        assertTrue(
                sessionCtx.isInteropAcceptGostBaseSigScheme(),
                "флаг должен быть true после interopAcceptGostBaseSigScheme(true)");
    }

    @Test
    @DisplayName("флаг false по умолчанию: без вызова builder-метода")
    void testFlagDefaultFalse() throws Exception {
        SSLContext ctx = GostSsl.builder().trustAll().buildClientContext();

        GostSSLSessionContext sessionCtx = (GostSSLSessionContext) ctx.getClientSessionContext();
        assertFalse(
                sessionCtx.isInteropAcceptGostBaseSigScheme(),
                "флаг должен быть false по умолчанию");
    }

    @Test
    @DisplayName("флаг false после явного .interopAcceptGostBaseSigScheme(false)")
    void testFlagExplicitFalse() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustAll()
                        .interopAcceptGostBaseSigScheme(false)
                        .buildClientContext();

        GostSSLSessionContext sessionCtx = (GostSSLSessionContext) ctx.getClientSessionContext();
        assertFalse(
                sessionCtx.isInteropAcceptGostBaseSigScheme(),
                "флаг должен быть false после interopAcceptGostBaseSigScheme(false)");
    }

    @Test
    @DisplayName("серверный контекст: флаг доходит до serverSessionContext")
    void testFlagServerContext() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustAll()
                        .interopAcceptGostBaseSigScheme(true)
                        .buildServerContext();

        GostSSLSessionContext sessionCtx = (GostSSLSessionContext) ctx.getServerSessionContext();
        assertTrue(
                sessionCtx.isInteropAcceptGostBaseSigScheme(),
                "флаг должен доходить до serverSessionContext");
    }

    @Test
    @DisplayName("needClientAuth true: доходит до serverSessionContext.isNeedClientAuth()")
    void testNeedClientAuthTrue() throws Exception {
        SSLContext ctx = GostSsl.builder().trustAll().needClientAuth(true).buildServerContext();

        GostSSLSessionContext sessionCtx = (GostSSLSessionContext) ctx.getServerSessionContext();
        assertTrue(
                sessionCtx.isNeedClientAuth(), "флаг должен быть true после needClientAuth(true)");
    }

    @Test
    @DisplayName("needClientAuth false по умолчанию: без вызова needClientAuth")
    void testNeedClientAuthDefaultFalse() throws Exception {
        SSLContext ctx = GostSsl.builder().trustAll().buildServerContext();

        GostSSLSessionContext sessionCtx = (GostSSLSessionContext) ctx.getServerSessionContext();
        assertFalse(sessionCtx.isNeedClientAuth(), "флаг должен быть false по умолчанию");
    }
}
