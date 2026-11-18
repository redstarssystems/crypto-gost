package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.SslHandler;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.netty.NettyTestSupport.Fixture;
import org.rssys.gost.netty.NettyTestSupport.Outcome;
import org.rssys.gost.tls13.TlsConstants;

/**
 * ALPN через Netty: политика выбора, оба пути создания обработчика ({@code newHandler} с сырым
 * движком и {@code newEngine} с обёрткой Netty) и доступ к {@code GostSSLEngine}.
 */
@DisplayName("Netty: ALPN")
class GostSslContextAlpnTest {

    private static final UnpooledByteBufAllocator ALLOC = UnpooledByteBufAllocator.DEFAULT;
    private static final String HOST = "localhost";

    private static Fixture fixture;

    @BeforeAll
    static void setUp() throws Exception {
        fixture = new Fixture();
    }

    private static GostSslContext server(String... protocols) throws Exception {
        return GostSslContextBuilder.forServer(fixture.serverKeyManager())
                .applicationProtocols(protocols)
                .build();
    }

    private static GostSslContext client(String... protocols) throws Exception {
        return GostSslContextBuilder.forClient()
                .trustManager(fixture.rootTrust())
                .applicationProtocols(protocols)
                .build();
    }

    private static SslHandler handlerOf(GostSslContext ctx) {
        return ctx.newHandler(ALLOC, HOST, 0);
    }

    /** Обработчик поверх обёртки Netty: путь {@code newEngine}. */
    private static SslHandler newEngineHandlerOf(GostSslContext ctx) {
        return new SslHandler(ctx.newEngine(ALLOC, HOST, 0));
    }

    // ========================================================================
    // Согласование и приоритет списка сервера
    // ========================================================================

    @Test
    @DisplayName("newHandler: h2 согласован, протокол виден в обработчике и в движке")
    void negotiationThroughHandler() throws Exception {
        SslHandler cs = handlerOf(client("h2", "http/1.1"));
        SslHandler ss = handlerOf(server("h2", "http/1.1"));

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertTrue(outcome.succeeded(), "рукопожатие должно пройти: " + outcome);
        assertEquals("h2", cs.applicationProtocol(), "клиентский протокол");
        assertEquals("h2", ss.applicationProtocol(), "серверный протокол");
        assertEquals("h2", ((GostSSLEngine) cs.engine()).getApplicationProtocol());
        assertEquals("h2", ((GostSSLEngine) ss.engine()).getApplicationProtocol());
    }

    @Test
    @DisplayName("Приоритет списка сервера одинаков на путях newHandler и newEngine")
    void serverPriorityIsSameOnBothPaths() throws Exception {
        // клиент предпочёл бы http/1.1, но выбирает сервер: у него приоритетнее h2
        GostSslContext cli = client("http/1.1", "h2");
        GostSslContext srv = server("h2", "http/1.1");

        SslHandler cs = handlerOf(cli);
        SslHandler ss = handlerOf(srv);
        assertTrue(NettyTestSupport.handshake(cs, ss).succeeded());
        assertEquals("h2", cs.applicationProtocol(), "newHandler: приоритет сервера");

        SslHandler newEngineClient = newEngineHandlerOf(cli);
        SslHandler newEngineServer = newEngineHandlerOf(srv);
        assertTrue(NettyTestSupport.handshake(newEngineClient, newEngineServer).succeeded());
        assertEquals("h2", newEngineClient.applicationProtocol(), "newEngine: приоритет сервера");
    }

    // ========================================================================
    // Несовпадение: алерт 120 на проводе
    // ========================================================================

    @Test
    @DisplayName("Непересекающиеся списки (newHandler): клиент получает алерт 120")
    void mismatchDeliversAlertThroughHandler() throws Exception {
        SslHandler cs = handlerOf(client("h2"));
        SslHandler ss = handlerOf(server("http/1.1"));

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertFalse(outcome.succeeded(), "рукопожатие должно завершиться отказом");
        assertInstanceOf(SSLException.class, outcome.serverFailure(), "сервер: SSL-отказ");
        assertTrue(
                outcome.clientSawAlert(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL),
                "клиент должен получить no_application_protocol (120): " + outcome.clientFailure());
    }

    @Test
    @DisplayName("Непересекающиеся списки (newEngine): клиент получает алерт 120")
    void mismatchDeliversAlertThroughWrappedEngine() throws Exception {
        SslHandler cs = newEngineHandlerOf(client("h2"));
        SslHandler ss = newEngineHandlerOf(server("http/1.1"));

        Outcome outcome = NettyTestSupport.handshake(cs, ss);

        assertFalse(outcome.succeeded(), "рукопожатие должно завершиться отказом");
        assertInstanceOf(SSLException.class, outcome.serverFailure(), "сервер: SSL-отказ");
        assertTrue(
                outcome.clientSawAlert(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL),
                "клиент должен получить no_application_protocol (120): " + outcome.clientFailure());
    }

    // ========================================================================
    // ALPN только у одной стороны: рукопожатие проходит
    // ========================================================================

    @Test
    @DisplayName("ALPN только у сервера: рукопожатие проходит на обоих путях, протокол null")
    void serverOnlyAlpnSucceeds() throws Exception {
        for (boolean viaNewEngine : new boolean[] {false, true}) {
            SslHandler cs = viaNewEngine ? newEngineHandlerOf(client()) : handlerOf(client());
            SslHandler ss =
                    viaNewEngine ? newEngineHandlerOf(server("h2")) : handlerOf(server("h2"));

            Outcome outcome = NettyTestSupport.handshake(cs, ss);

            assertTrue(outcome.succeeded(), "viaNewEngine=" + viaNewEngine + ": " + outcome);
            assertNull(
                    cs.applicationProtocol(),
                    "viaNewEngine=" + viaNewEngine + ": протокол клиента");
            assertNull(
                    ss.applicationProtocol(),
                    "viaNewEngine=" + viaNewEngine + ": протокол сервера");
        }
    }

    @Test
    @DisplayName("ALPN только у клиента: рукопожатие проходит на обоих путях, протокол null")
    void clientOnlyAlpnSucceeds() throws Exception {
        for (boolean viaNewEngine : new boolean[] {false, true}) {
            SslHandler cs =
                    viaNewEngine ? newEngineHandlerOf(client("h2")) : handlerOf(client("h2"));
            SslHandler ss = viaNewEngine ? newEngineHandlerOf(server()) : handlerOf(server());

            Outcome outcome = NettyTestSupport.handshake(cs, ss);

            assertTrue(outcome.succeeded(), "viaNewEngine=" + viaNewEngine + ": " + outcome);
            assertNull(
                    cs.applicationProtocol(),
                    "viaNewEngine=" + viaNewEngine + ": протокол клиента");
            assertNull(
                    ss.applicationProtocol(),
                    "viaNewEngine=" + viaNewEngine + ": протокол сервера");
        }
    }

    @Test
    @DisplayName("Движок после рукопожатия без ALPN отдаёт пустую строку, до рукопожатия null")
    void engineReportsEmptyProtocolWithoutAlpn() throws Exception {
        SslHandler cs = handlerOf(client("h2"));
        SslHandler ss = handlerOf(server());
        assertNull(
                ((GostSSLEngine) cs.engine()).getApplicationProtocol(),
                "до рукопожатия протокол не определён");

        assertTrue(NettyTestSupport.handshake(cs, ss).succeeded());

        assertEquals("", ((GostSSLEngine) cs.engine()).getApplicationProtocol());
        assertEquals("", ((GostSSLEngine) ss.engine()).getApplicationProtocol());
    }

    // ========================================================================
    // ApplicationProtocolNegotiationHandler
    // ========================================================================

    /** Фиксирует протокол, с которым Netty настроил конвейер. */
    private static final class RecordingNegotiationHandler
            extends ApplicationProtocolNegotiationHandler {
        final List<String> configured = new ArrayList<>();

        RecordingNegotiationHandler(String fallbackProtocol) {
            super(fallbackProtocol);
        }

        @Override
        protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
            configured.add(protocol);
        }
    }

    @Test
    @DisplayName("ApplicationProtocolNegotiationHandler: при согласовании получает h2")
    void negotiationHandlerSeesNegotiatedProtocol() throws Exception {
        SslHandler cs = handlerOf(client("h2", "http/1.1"));
        SslHandler ss = handlerOf(server("h2"));
        RecordingNegotiationHandler negotiation = new RecordingNegotiationHandler("http/1.1");

        Outcome outcome =
                NettyTestSupport.handshake(
                        new EmbeddedChannel(cs, negotiation), new EmbeddedChannel(ss), cs, ss);

        assertTrue(outcome.succeeded(), "рукопожатие должно пройти: " + outcome);
        assertEquals(List.of("h2"), negotiation.configured, "протокол из ALPN");
    }

    @Test
    @DisplayName("ApplicationProtocolNegotiationHandler: без ALPN у сервера работает запасной")
    void negotiationHandlerFallsBack() throws Exception {
        SslHandler cs = handlerOf(client("h2", "http/1.1"));
        SslHandler ss = handlerOf(server());
        RecordingNegotiationHandler negotiation = new RecordingNegotiationHandler("http/1.1");

        Outcome outcome =
                NettyTestSupport.handshake(
                        new EmbeddedChannel(cs, negotiation), new EmbeddedChannel(ss), cs, ss);

        assertTrue(outcome.succeeded(), "рукопожатие должно пройти: " + outcome);
        assertEquals(List.of("http/1.1"), negotiation.configured, "запасной протокол");
    }

    // ========================================================================
    // Доступ к движку и ограничение пути newEngine
    // ========================================================================

    @Test
    @DisplayName("newHandler с ALPN: engine() остаётся GostSSLEngine")
    void handlerEngineIsGostEngineWithAlpn() throws Exception {
        assertInstanceOf(GostSSLEngine.class, handlerOf(client("h2")).engine());
        assertInstanceOf(GostSSLEngine.class, handlerOf(server("h2")).engine());
    }

    @Test
    @DisplayName("newEngine с ALPN: движок в обёртке Netty (задокументированное ограничение)")
    void newEngineIsWrappedWithAlpn() throws Exception {
        SSLEngine engine = client("h2").newEngine(ALLOC, HOST, 0);

        assertFalse(engine instanceof GostSSLEngine, "обёртка Netty скрывает GostSSLEngine");
    }

    // ========================================================================
    // Сверка настроек двух путей
    // ========================================================================

    @Test
    @DisplayName("Настройки движков newHandler и newEngine совпадают (клиент)")
    void clientEngineSettingsMatchBetweenPaths() throws Exception {
        GostSslContext ctx = client("h2", "http/1.1");

        SSLEngine direct = handlerOf(ctx).engine();
        SSLEngine wrapped = ctx.newEngine(ALLOC, HOST, 0);

        assertSettingsMatch(direct, wrapped);
        assertArrayEquals(
                wrapped.getSSLParameters().getApplicationProtocols(),
                direct.getSSLParameters().getApplicationProtocols(),
                "списки ALPN клиента");
        assertEquals(
                "HTTPS",
                direct.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "строгий режим сохраняет проверку имени");
    }

    @Test
    @DisplayName("Настройки движков newHandler и newEngine совпадают (сервер, три режима клиента)")
    void serverEngineSettingsMatchBetweenPaths() throws Exception {
        for (io.netty.handler.ssl.ClientAuth auth : io.netty.handler.ssl.ClientAuth.values()) {
            GostSslContextBuilder builder =
                    GostSslContextBuilder.forServer(fixture.serverKeyManager())
                            .trustManager(fixture.rootTrust())
                            .clientAuth(auth)
                            .applicationProtocols("h2");
            GostSslContext ctx = builder.build();

            SSLEngine direct = handlerOf(ctx).engine();
            SSLEngine wrapped = ctx.newEngine(ALLOC, HOST, 0);

            assertSettingsMatch(direct, wrapped);
            assertEquals(wrapped.getNeedClientAuth(), direct.getNeedClientAuth(), "need: " + auth);
            assertEquals(wrapped.getWantClientAuth(), direct.getWantClientAuth(), "want: " + auth);
        }
    }

    private static void assertSettingsMatch(SSLEngine direct, SSLEngine wrapped) {
        assertArrayEquals(
                wrapped.getEnabledCipherSuites(), direct.getEnabledCipherSuites(), "наборы шифров");
        assertArrayEquals(wrapped.getEnabledProtocols(), direct.getEnabledProtocols(), "протоколы");
        assertEquals(wrapped.getUseClientMode(), direct.getUseClientMode(), "роль");
        assertEquals(
                wrapped.getSSLParameters().getEndpointIdentificationAlgorithm(),
                direct.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "алгоритм проверки имени");
    }
}
