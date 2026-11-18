package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper.CertBundle;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/** Тикет PSK не переживает срок сертификатов сервера: выдача, сохранение, возобновление. */
@DisplayName("GostSSLEngine: тикет PSK и срок сертификата сервера")
class GostSSLEnginePskCertBoundTest {

    private static final int PORT = 443;
    private static final String HOST = "localhost";
    private static final String NOT_BEFORE = "20240501120000Z";
    private static final String FAR_FUTURE = "21060101120000Z";
    private static final DateTimeFormatter ASN1_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final long TWO_HOURS_SECONDS = Duration.ofHours(2).toSeconds();
    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] KU_DIGITAL_SIGNATURE = {(byte) 0x80};
    private static final byte[] KU_KEY_CERT_SIGN = {(byte) 0x04};

    private static TlsCiphersuite cs;

    @BeforeAll
    static void setUp() {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static String inFuture(Duration delta) {
        return ASN1_TIME.format(Instant.now().plus(delta));
    }

    private static GostSSLSessionContext newContext() {
        return new GostSSLSessionContext(cs);
    }

    private static CertBundle ca(CertBundle issuer, String notAfter) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                notAfter,
                null,
                null,
                KU_KEY_CERT_SIGN,
                null,
                true,
                null);
    }

    private static CertBundle leaf(CertBundle issuer, String notAfter) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                notAfter,
                new String[] {HOST},
                KU_DIGITAL_SIGNATURE,
                null,
                false,
                null);
    }

    private static GostX509KeyManager keyManager(CertBundle leaf, GostCertificate... rest)
            throws Exception {
        GostCertificate[] chain = new GostCertificate[rest.length + 1];
        chain[0] = leaf.cert;
        System.arraycopy(rest, 0, chain, 1, rest.length);
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", CertificateBridge.toJca(List.of(chain)), leaf.priv);
        return km;
    }

    private static GostSSLEngine server(GostX509KeyManager km, GostSSLSessionContext ctx) {
        return GostSSLEngine.createForServer(
                km, GostX509TrustManager.insecureTrustAll(), HOST, 0, ctx);
    }

    private static GostSSLEngine client(GostSSLSessionContext ctx, GostX509TrustManager trust) {
        return GostSSLEngine.createForClient(new GostX509KeyManager(), trust, HOST, PORT, ctx);
    }

    /** Рукопожатие и доставка NewSessionTicket клиенту (если сервер его отправил). */
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

    private static PskEntry clientEntry(GostSSLSessionContext ctx, GostSSLEngine client) {
        return ctx.getForClientResumption(HOST, PORT, client.clientPskBinding());
    }

    // ========================================================================
    // Выдача и сохранение
    // ========================================================================

    @Test
    @DisplayName("Граница клиента и сервера равна notAfter leaf; срок тикета ограничен остатком")
    void boundaryEqualsLeafNotAfter() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle leaf = leaf(root, inFuture(Duration.ofHours(2)));
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        GostSSLEngine client = client(clientCtx, GostX509TrustManager.insecureTrustAll());
        long before = System.currentTimeMillis();

        handshakeAndDeliverTicket(client, server(keyManager(leaf, root.cert), serverCtx));

        PskEntry clientEntry = clientEntry(clientCtx, client);
        assertNotNull(clientEntry, "клиент должен сохранить тикет");
        PskEntry serverEntry = serverCtx.getPskStore().peek(clientEntry.getTicket());
        assertNotNull(serverEntry, "сервер должен сохранить запись о тикете");
        long notAfter = leaf.cert.getNotAfter().toEpochMilli();
        assertEquals(notAfter, clientEntry.getValidUntil(), "граница клиента");
        assertEquals(notAfter, serverEntry.getValidUntil(), "граница сервера");
        long maxRemaining = Math.floorDiv(notAfter - before, 1000L);
        for (PskEntry entry : List.of(clientEntry, serverEntry)) {
            assertTrue(
                    entry.getTicketLifetime() <= maxRemaining,
                    "срок тикета не должен превышать остаток срока сертификата");
            assertTrue(
                    entry.getTicketLifetime() > TWO_HOURS_SECONDS - 60,
                    "срок тикета не должен быть занижен сверх округления");
        }
    }

    @Test
    @DisplayName("Режим без проверки цепочки: граница по leaf, остальные присланные не учитываются")
    void insecureTrustAllUsesLeafOnly() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle shortCa = ca(root, inFuture(Duration.ofHours(1)));
        CertBundle leaf = leaf(shortCa, FAR_FUTURE);
        GostSSLSessionContext clientCtx = newContext();
        GostSSLEngine client = client(clientCtx, GostX509TrustManager.insecureTrustAll());

        // Цепочка в этом режиме не проверяется, поэтому присланный коротко живущий CA границу
        // доверия не определяет: срок проверен только у leaf. Сервер при этом ограничивает свои
        // тикеты собственной цепочкой целиком, и клиент берёт меньшее из двух через срок тикета
        handshakeAndDeliverTicket(client, server(keyManager(leaf, shortCa.cert), newContext()));

        PskEntry entry = clientEntry(clientCtx, client);
        assertNotNull(entry, "клиент должен сохранить тикет");
        assertEquals(
                leaf.cert.getNotAfter().toEpochMilli(),
                entry.getValidUntil(),
                "граница клиента в этом режиме определяется только leaf");
    }

    @Test
    @DisplayName("Сертификат сервера истёк в пределах допуска часов: сервер не выдаёт тикет")
    void serverDoesNotIssueTicketPastItsOwnCertificate() throws Exception {
        // Валидатор допускает просрочку до CLOCK_SKEW_MS, поэтому соединение состоится, а вот
        // тикет сервер выдавать не должен: его сертификат уже не действует
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle leaf = leaf(root, inFuture(Duration.ofSeconds(-60)));
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        GostSSLEngine client = client(clientCtx, GostX509TrustManager.insecureTrustAll());

        // Доставлять нечего: receiveRecord блокируется, если сервер тикет не отправил
        GostSSLEngineLoopbackTest.doLoopback(
                client,
                server(keyManager(leaf, root.cert), serverCtx),
                InMemoryTlsTransport.newPair());

        assertEquals(0, serverCtx.getPskStore().size(), "сервер не должен хранить запись");
        assertNull(clientEntry(clientCtx, client), "клиент не должен получать тикет");
    }

    @Test
    @DisplayName("saveNewSessionTicket: граница в прошлом - тикет не сохраняется")
    void saveRejectsTicketPastBoundary() throws Exception {
        GostSSLSessionContext ctx = newContext();
        PskBinding binding = new PskBinding(HOST, "model-a");

        ctx.saveNewSessionTicket(
                HOST,
                PORT,
                new byte[32],
                TlsMessageParser.parseNewSessionTicket(nst()),
                binding,
                System.currentTimeMillis() - 1_000L);

        assertNull(ctx.getForClientResumption(HOST, PORT, binding), "тикет за границей не нужен");
        assertEquals(0, ctx.getPskStore().size(), "хранилище должно остаться пустым");
    }

    @Test
    @DisplayName("saveNewSessionTicket: срок тикета ограничивается остатком, граница сохраняется")
    void saveClampsLifetimeAndKeepsBoundary() throws Exception {
        GostSSLSessionContext ctx = newContext();
        PskBinding binding = new PskBinding(HOST, "model-a");
        long validUntil = System.currentTimeMillis() + 600_000L;

        ctx.saveNewSessionTicket(
                HOST,
                PORT,
                new byte[32],
                TlsMessageParser.parseNewSessionTicket(nst()),
                binding,
                validUntil);

        PskEntry entry = ctx.getForClientResumption(HOST, PORT, binding);
        assertNotNull(entry, "тикет до границы должен сохраниться");
        assertEquals(validUntil, entry.getValidUntil(), "граница должна сохраниться как есть");
        assertTrue(entry.getTicketLifetime() <= 600, "срок тикета ограничен остатком до границы");
        assertTrue(entry.getTicketLifetime() > 590, "срок тикета не должен быть занижен");
    }

    // ========================================================================
    // Возобновление
    // ========================================================================

    @Test
    @DisplayName("Новый тикет возобновлённой сессии наследует границу прежней записи")
    void resumedSessionInheritsBoundary() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle shortAnchor = ca(root, inFuture(Duration.ofHours(2)));
        CertBundle leaf = leaf(shortAnchor, FAR_FUTURE);
        // Сервер якорь не присылает, поэтому его граница позднее клиентской (якорь при REJECT):
        // без наследования границы возобновлённого тикета различие было бы видно
        GostX509KeyManager km = keyManager(leaf);
        GostX509TrustManager trust =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(shortAnchor.cert)
                                .withExpiryPolicy(AnchorExpiryPolicy.REJECT));
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        GostSSLEngine first = client(clientCtx, trust);
        handshakeAndDeliverTicket(first, server(km, serverCtx));
        PskEntry firstEntry = clientEntry(clientCtx, first);
        assertNotNull(firstEntry, "первый тикет должен сохраниться");
        assertEquals(
                shortAnchor.cert.getNotAfter().toEpochMilli(),
                firstEntry.getValidUntil(),
                "граница клиента должна определяться якорем");

        GostSSLEngine second = client(clientCtx, trust);
        handshakeAndDeliverTicket(second, server(km, serverCtx));

        assertTrue(second.wasResumed(), "второе соединение должно возобновиться");
        PskEntry secondEntry = clientEntry(clientCtx, second);
        assertNotNull(secondEntry, "возобновлённая сессия выдаёт новый тикет");
        assertEquals(
                firstEntry.getValidUntil(),
                secondEntry.getValidUntil(),
                "граница возобновлённого тикета должна совпасть с прежней");
    }

    @Test
    @DisplayName("Сервер не принимает собственный тикет после границы своего сертификата")
    void serverRejectsOwnTicketPastBoundary() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle leaf = leaf(root, FAR_FUTURE);
        GostX509KeyManager km = keyManager(leaf, root.cert);
        GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
        GostSSLSessionContext serverCtx = newContext();
        GostSSLSessionContext clientCtx = newContext();
        GostSSLEngine first = client(clientCtx, trust);
        handshakeAndDeliverTicket(first, server(km, serverCtx));
        byte[] ticket = clientEntry(clientCtx, first).getTicket();
        InMemoryPskStore store = serverCtx.getPskStore();
        PskEntry issued = store.peek(ticket);
        store.remove(ticket);
        store.onTicketReceived(
                new PskEntry(
                        issued.getTicket(),
                        issued.getTicketLifetime(),
                        issued.getTicketAgeAdd(),
                        issued.getTicketNonce(),
                        issued.getPsk(),
                        issued.getIssueTime(),
                        issued.getBinding(),
                        System.currentTimeMillis() - 1_000L));

        GostSSLEngine second = client(clientCtx, trust);
        GostSSLEngine server = server(km, serverCtx);
        GostSSLEngineLoopbackTest.doLoopback(second, server, InMemoryTlsTransport.newPair());

        assertFalse(server.wasResumed(), "сервер не должен принять тикет за границей");
        assertFalse(second.wasResumed(), "клиент должен получить полное рукопожатие");
    }

    private static byte[] nst() throws Exception {
        return TlsMessageBuilder.buildNewSessionTicket(
                86_400L, 0, new byte[8], new byte[] {1, 2, 3, 4});
    }
}
