package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.util.CryptoRandom;

/** Тесты контекста сессий: хранение сессий, привязка тикетов PSK к узлу, одноразовость тикета. */
@DisplayName("GostSSLSessionContext: сессии и тикеты PSK клиента")
class GostSSLSessionContextTest {

    /** Привязка для тестов, которые кладут тикеты в контекст напрямую. */
    private static final PskBinding TEST_BINDING = new PskBinding("test.example", "test-id");

    private static TlsCiphersuite cs;

    @BeforeAll
    static void setUp() {
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    // ========================================================================
    // GostSSLSessionContext — создание, хранение, инвалидация
    // ========================================================================

    @Test
    @DisplayName("SessionContext: put/get/remove сессии, таймаут, инвалидация")
    void testSessionContextBasic() throws Exception {
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs);

        assertEquals(86400, ctx.getSessionTimeout());
        assertEquals(GostSSLSessionContext.DEFAULT_SESSION_CACHE_SIZE, ctx.getSessionCacheSize());

        GostSSLSession session =
                new GostSSLSession(
                        cs.getIanaName(),
                        "localhost",
                        PskTestSupport.BINDING_PORT,
                        new java.security.cert.X509Certificate[0],
                        new java.security.cert.X509Certificate[0]);

        assertNull(ctx.getSession(session.getId()));

        ctx.putSession(session);
        assertSame(session, ctx.getSession(session.getId()));
        assertTrue(session.isValid());

        session.invalidate();
        assertFalse(session.isValid());
        assertNull(ctx.getSession(session.getId()));

        // setSessionTimeout задаёт TTL сессии — по истечении сессия невалидна
        ctx.setSessionTimeout(1);
        GostSSLSession session2 =
                new GostSSLSession(
                        cs.getIanaName(),
                        "localhost",
                        PskTestSupport.BINDING_PORT,
                        new java.security.cert.X509Certificate[0],
                        new java.security.cert.X509Certificate[0]);
        ctx.putSession(session2);
        // срок сессии 1 с: ждём до истечения с запасом по времени, но не дольше необходимого
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
        while (session2.isValid() && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        assertFalse(session2.isValid(), "по истечении срока сессия невалидна");
    }

    // ========================================================================
    // PSK host binding — разные host:port дают независимые PSK
    // ========================================================================

    @Test
    @DisplayName("PSK: host:port привязка — разным серверам разные тикеты")
    void testPskHostBinding() throws Exception {
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs);

        byte[] rms = new byte[32];
        // разные nonce -> разные деривации PSK; разные ticket-идентификаторы
        // -> разные ключи в хранилище. Без этого тест ломается при single-use PSK
        // (RFC 8446 §8.1), потому что одинаковые тикеты маппятся в один ключ.
        byte[] nstBody =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {1});
        byte[] nstBody2 =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {2});

        ctx.saveNewSessionTicket(
                "server1.com",
                PskTestSupport.BINDING_PORT,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBody),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);
        ctx.saveNewSessionTicket(
                "server2.com",
                PskTestSupport.BINDING_PORT,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBody2),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);

        // если host:port не маппится — PSK не должен быть найден
        assertNotNull(
                ctx.getForClientResumption(
                        "server1.com", PskTestSupport.BINDING_PORT, TEST_BINDING));
        assertNull(ctx.getForClientResumption("server1.com", 444, TEST_BINDING));
        assertNotNull(
                ctx.getForClientResumption(
                        "server2.com", PskTestSupport.BINDING_PORT, TEST_BINDING));
        assertNull(
                ctx.getForClientResumption(
                        "unknown.com", PskTestSupport.BINDING_PORT, TEST_BINDING));
    }

    @Test
    @DisplayName("PSK: тикет без имени узла (null, пустой, blank) не сохраняется")
    void pskNotSavedWithoutPeerHost() throws Exception {
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs);
        byte[] rms = new byte[32];
        byte[] nstBody =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {7});

        for (String host : new String[] {null, "", " "}) {
            ctx.saveNewSessionTicket(
                    host,
                    PskTestSupport.BINDING_PORT,
                    rms,
                    TlsMessageParser.parseNewSessionTicket(nstBody),
                    TEST_BINDING,
                    PskEntry.NO_CERTIFICATE_BOUND);
            assertNull(
                    ctx.getForClientResumption(host, PskTestSupport.BINDING_PORT, TEST_BINDING),
                    "тикет без имени узла не должен попадать в кэш: '" + host + "'");
        }
    }

    @Test
    @DisplayName("PSK: peek не сжигает тикет, только явный remove")
    void pskTicketSingleUse() throws Exception {
        // клиентский peek() не удаляет запись — тикет должен быть
        // удалён только после подтверждения PSK сервером (ServerHello c PSK).
        // Тест верифицирует: (1) peek отдаёт тикет, (2) повторный peek
        // тоже отдаёт (не потреблён), (3) после явного remove — null.
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs);
        byte[] rms = new byte[32];
        byte[] nonce = new byte[8];
        byte[] ticket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(rms);
        CryptoRandom.INSTANCE.nextBytes(nonce);
        CryptoRandom.INSTANCE.nextBytes(ticket);
        byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(3600, 0, nonce, ticket);

        ctx.saveNewSessionTicket(
                "host",
                PskTestSupport.BINDING_PORT,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBody),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);

        assertNotNull(
                ctx.getForClientResumption("host", PskTestSupport.BINDING_PORT, TEST_BINDING),
                "PSK доступен при первом запросе");
        assertNotNull(
                ctx.getForClientResumption("host", PskTestSupport.BINDING_PORT, TEST_BINDING),
                "peek не сжигает тикет — второй запрос тоже не null");
        ctx.getPskStore().remove(ticket);
        assertNull(
                ctx.getForClientResumption("host", PskTestSupport.BINDING_PORT, TEST_BINDING),
                "После явного remove тикет недоступен");
    }
}
