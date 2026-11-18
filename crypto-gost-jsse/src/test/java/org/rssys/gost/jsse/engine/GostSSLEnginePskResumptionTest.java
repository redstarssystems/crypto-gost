package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Возобновление по PSK в {@link GostSSLEngine}: возраст тикета и привязка тикета к серверу и
 * модели доверия. Клиент и сервер используют раздельные контексты сессий, как в работе: общий
 * контекст затирал бы клиентскую запись серверной с тем же ключом (байты тикета).
 */
@DisplayName("GostSSLEngine: возобновление по PSK")
class GostSSLEnginePskResumptionTest {

    /** Только ключ для identityByHost, не реальный сетевой порт. */
    private static final int PORT = 443;

    private static final String HOST = "localhost";

    private static TlsCiphersuite cs;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {HOST},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
    }

    private static GostSSLSessionContext newContext() {
        return new GostSSLSessionContext(cs);
    }

    private static GostSSLEngine server(GostSSLSessionContext ctx) {
        return GostSSLEngine.createForServer(
                serverKm, GostX509TrustManager.insecureTrustAll(), HOST, 0, ctx);
    }

    /**
     * Клиент с заданным менеджером доверия. Тикет привязан к экземпляру менеджера, поэтому
     * повторные подключения, которые должны возобновляться, используют один и тот же экземпляр.
     */
    private static GostSSLEngine client(GostSSLSessionContext ctx, GostX509TrustManager trust) {
        return GostSSLEngine.createForClient(new GostX509KeyManager(), trust, HOST, PORT, ctx);
    }

    /** Клиент без проверки имени узла (явный opt-out на engine). */
    private static GostSSLEngine clientWithoutHostnameCheck(
            GostSSLSessionContext ctx, GostX509TrustManager trust) {
        return GostSSLEngine.createForClientNoHostnameCheck(
                new GostX509KeyManager(), trust, HOST, PORT, ctx);
    }

    /** Рукопожатие и доставка NewSessionTicket клиенту, чтобы тикет попал в его хранилище. */
    private static void handshakeAndDeliverTicket(GostSSLEngine client, GostSSLEngine server)
            throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        if (server.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            server.wrap(ByteBuffer.allocate(0), net);
            net.flip();
            if (net.hasRemaining()) {
                byte[] nst = new byte[net.remaining()];
                net.get(nst);
                pair.getServerTransport().sendRecord(nst);
            }
        }
        byte[] nstIn = pair.getClientTransport().receiveRecord();
        if (nstIn != null) {
            net.clear();
            net.put(nstIn);
            net.flip();
            client.unwrap(net, ByteBuffer.allocate(0));
        }
    }

    private static byte[] clientTicket(GostSSLSessionContext clientCtx, GostSSLEngine client) {
        PskEntry entry = clientCtx.getForClientResumption(HOST, PORT, client.clientPskBinding());
        assertNotNull(entry, "клиент должен получить тикет");
        return entry.getTicket();
    }

    // ========================================================================
    // Возраст тикета: миллисекунды
    // ========================================================================

    @ParameterizedTest(name = "возраст тикета {0} мс")
    @ValueSource(longs = {0, 120_000})
    @DisplayName(
            "Свежий тикет и тикет старше допуска сервера (120 с) возобновляются: возраст идёт в"
                    + " миллисекундах")
    void ticketOfAnyAgeWithinLifetimeResumes(long ageMs) throws Exception {
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
        GostSSLEngine first = client(clientCtx, trust);
        handshakeAndDeliverTicket(first, server(serverCtx));
        if (ageMs > 0) {
            byte[] ticket = clientTicket(clientCtx, first);
            PskTestSupport.age(clientCtx, ticket, ageMs);
            PskTestSupport.age(serverCtx, ticket, ageMs);
        }

        GostSSLEngine second = client(clientCtx, trust);
        GostSSLEngine server = server(serverCtx);
        GostSSLEngineLoopbackTest.doLoopback(second, server, InMemoryTlsTransport.newPair());

        assertTrue(second.wasResumed(), "тикет возраста " + ageMs + " мс должен возобновляться");
        assertTrue(server.wasResumed(), "сервер должен принять возобновление");
    }

    @Test
    @DisplayName(
            "Тикет в 65492 байта не помещается в ClientHello: полное рукопожатие без исключения, тикет удалён")
    void ticketThatDoesNotFitIsDroppedAndHandshakeIsFull() throws Exception {
        GostSSLSessionContext clientCtx = newContext();
        GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
        // Тикет наибольшей длины проходит грубый фильтр при сохранении, но вместе с остальными
        // расширениями блок ClientHello выходит за 65535
        GostSSLEngine probe = client(clientCtx, trust);
        PskBinding binding = probe.clientPskBinding();
        byte[] hugeTicket = new byte[TlsPskHelper.maxIdentityLength(cs.getHashLen())];
        hugeTicket[0] = 1;
        clientCtx.saveNewSessionTicket(
                HOST,
                PORT,
                new byte[cs.getHashLen()],
                TlsMessageParser.parseNewSessionTicket(
                        TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], hugeTicket)),
                binding,
                PskEntry.NO_CERTIFICATE_BOUND);
        assertNotNull(
                clientCtx.getForClientResumption(HOST, PORT, binding),
                "предусловие: тикет сохранён и подлежит предъявлению");

        GostSSLEngine second = client(clientCtx, trust);
        GostSSLEngine server = server(newContext());
        GostSSLEngineLoopbackTest.doLoopback(second, server, InMemoryTlsTransport.newPair());

        assertFalse(second.wasResumed(), "PSK не предъявлялся: рукопожатие полное");
        assertNull(
                clientCtx.getForClientResumption(HOST, PORT, binding),
                "тикет, который не поместился, удалён из кэша");
        assertNull(clientCtx.getPskStore().peek(hugeTicket), "и из хранилища тоже");
    }

    @Test
    @DisplayName("Первое рукопожатие без тикета - полное")
    void firstHandshakeIsFull() throws Exception {
        GostSSLEngine client = client(newContext(), GostX509TrustManager.insecureTrustAll());
        GostSSLEngine server = server(newContext());
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        assertFalse(client.wasResumed(), "без тикета возобновления быть не может");
    }

    // ========================================================================
    // Привязка jsse-клиента: режим проверки имени и менеджер доверия
    // ========================================================================

    @ParameterizedTest(name = "тикет получен при проверке имени: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Тикет не используется engine с другим режимом проверки имени (HTTPS)")
    void ticketIsNotUsedAcrossHostnameCheckModes(boolean issuedWithHostnameCheck) throws Exception {
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
        GostSSLEngine issuer =
                issuedWithHostnameCheck
                        ? client(clientCtx, trust)
                        : clientWithoutHostnameCheck(clientCtx, trust);
        handshakeAndDeliverTicket(issuer, server(serverCtx));

        GostSSLEngine other =
                issuedWithHostnameCheck
                        ? clientWithoutHostnameCheck(clientCtx, trust)
                        : client(clientCtx, trust);
        GostSSLEngineLoopbackTest.doLoopback(
                other, server(serverCtx), InMemoryTlsTransport.newPair());

        assertFalse(
                other.wasResumed(),
                "режимы проверки имени не должны смешиваться: тикет другого режима не годится");
    }

    @Test
    @DisplayName("Разные менеджеры доверия при общем контексте сессий не делят тикеты")
    void differentTrustManagersDoNotShareTickets() throws Exception {
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        handshakeAndDeliverTicket(
                client(clientCtx, GostX509TrustManager.insecureTrustAll()), server(serverCtx));

        // Тот же набор настроек, но другой экземпляр менеджера: решение о принятии сервера
        // зависит и от загрузчиков отзыва, поэтому тикет не переносится
        GostSSLEngine other = client(clientCtx, GostX509TrustManager.insecureTrustAll());
        GostSSLEngineLoopbackTest.doLoopback(
                other, server(serverCtx), InMemoryTlsTransport.newPair());

        assertFalse(
                other.wasResumed(),
                "тикет одного менеджера доверия не должен использоваться другим");
    }

    @Test
    @DisplayName("Клиент без менеджера доверия начинает рукопожатие без NPE: PSK не предлагается")
    void clientWithoutTrustManagerStartsHandshake() throws Exception {
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(), null, HOST, PORT, newContext());
        client.beginHandshake();

        ByteBuffer clientHello =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), clientHello);

        assertTrue(clientHello.position() > 0, "ClientHello должен быть отправлен");
        assertThrows(
                IllegalStateException.class,
                client::wasResumed,
                "итог возобновления неизвестен до завершения рукопожатия");
    }

    @Test
    @DisplayName("Контекст сессий игнорирует запись с чужой привязкой")
    void sessionContextIgnoresForeignBinding() throws Exception {
        GostSSLSessionContext ctx = newContext();
        PskBinding stored = new PskBinding(HOST, "model-a");
        ctx.saveNewSessionTicket(
                HOST,
                PORT,
                new byte[32],
                TlsMessageParser.parseNewSessionTicket(
                        TlsMessageBuilder.buildNewSessionTicket(
                                3600, 0, new byte[8], new byte[] {1})),
                stored,
                PskEntry.NO_CERTIFICATE_BOUND);

        assertNotNull(ctx.getForClientResumption(HOST, PORT, stored));
        assertNull(
                ctx.getForClientResumption(HOST, PORT, new PskBinding(HOST, "model-b")),
                "запись другой модели доверия возвращаться не должна");
    }

    @Test
    @DisplayName("Имя узла в ключе тикета не зависит от регистра")
    void hostCaseDoesNotMatter() throws Exception {
        GostSSLSessionContext ctx = newContext();
        PskBinding binding = new PskBinding("Bank.Example", "model-a");
        ctx.saveNewSessionTicket(
                "Bank.Example",
                PORT,
                new byte[32],
                TlsMessageParser.parseNewSessionTicket(
                        TlsMessageBuilder.buildNewSessionTicket(
                                3600, 0, new byte[8], new byte[] {1})),
                binding,
                PskEntry.NO_CERTIFICATE_BOUND);

        assertNotNull(
                ctx.getForClientResumption("bank.example", PORT, binding),
                "Bank.Example и bank.example - один сервер");
    }
}
