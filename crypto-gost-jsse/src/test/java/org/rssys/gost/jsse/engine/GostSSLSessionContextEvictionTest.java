package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.util.CryptoRandom;

/**
 * Eviction-тесты для GostSSLSessionContext.
 * Проверяют LRU-вытеснение sessions и identityByHost.
 */
@DisplayName("GostSSLSessionContext: вытеснение сессий")
class GostSSLSessionContextEvictionTest {

    private static final PskBinding TEST_BINDING = new PskBinding("test.example", "test-id");

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private GostSSLSessionContext ctx;

    @BeforeAll
    static void setUpProvider() {
        Security.addProvider(new RssysGostJsseProvider());
    }

    @BeforeEach
    void setUp() {
        ctx = new GostSSLSessionContext(CS);
    }

    @Test
    @DisplayName("Вытеснение сессий: размер кэша 5, добавлено 10, остаются 5 последних")
    void testSessionEviction() {
        ctx.setSessionCacheSize(5);

        for (int i = 0; i < 10; i++) {
            GostSSLSession s =
                    new GostSSLSession(
                            "TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L",
                            "host" + i,
                            443,
                            new X509Certificate[0],
                            new X509Certificate[0]);
            ctx.putSession(s);
        }

        // Копируем ID-шники в массив до итерации с getSession —
        // accessOrder=true в LinkedHashMap вызывает ConcurrentModification
        Enumeration<byte[]> ids = ctx.getIds();
        java.util.ArrayList<byte[]> idList = new java.util.ArrayList<>();
        while (ids.hasMoreElements()) {
            idList.add(ids.nextElement());
        }
        assertEquals(5, idList.size(), "После вытеснения должно остаться только 5 сессий");

        java.util.Set<String> survivingHosts = new java.util.TreeSet<>();
        for (byte[] id : idList) {
            SSLSession s = ctx.getSession(id);
            assertNotNull(s);
            survivingHosts.add(s.getPeerHost());
        }
        assertEquals(
                new java.util.TreeSet<>(
                        java.util.List.of("host5", "host6", "host7", "host8", "host9")),
                survivingHosts,
                "вытесняются самые старые сессии, остаются пять последних");
    }

    @Test
    @DisplayName(
            "Предел кэша по умолчанию 20 480 у нового контекста и у обоих контекстов SSLContext")
    void defaultCacheLimitForClientAndServer() throws Exception {
        assertEquals(20_480, new GostSSLSessionContext(CS).getSessionCacheSize());

        javax.net.ssl.SSLContext context =
                javax.net.ssl.SSLContext.getInstance(
                        org.rssys.gost.jsse.GostJsseConstants.PROTOCOL_TLS_1_3,
                        org.rssys.gost.jsse.GostJsseConstants.PROVIDER_NAME);
        context.init(null, null, null);
        assertEquals(
                20_480,
                context.getServerSessionContext().getSessionCacheSize(),
                "серверный кэш без предела рос бы с каждым полным рукопожатием");
        assertEquals(20_480, context.getClientSessionContext().getSessionCacheSize());
    }

    @Test
    @DisplayName("Вытеснение сессий: sessionCacheSize=0 — вытеснение отключено")
    void testNoEvictionWhenSizeZero() {
        ctx.setSessionCacheSize(0);

        for (int i = 0; i < 10; i++) {
            GostSSLSession s =
                    new GostSSLSession(
                            "TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L",
                            "host" + i,
                            443,
                            new X509Certificate[0],
                            new X509Certificate[0]);
            ctx.putSession(s);
        }

        // Все 10 должны остаться — sessionCacheSize=0 отключает LRU-вытеснение
        Enumeration<byte[]> ids = ctx.getIds();
        int count = 0;
        while (ids.hasMoreElements()) {
            ids.nextElement();
            count++;
        }
        assertEquals(10, count, "Все 10 сессий должны остаться при sessionCacheSize=0");
    }

    @Test
    @DisplayName("Вытеснение сессий: removeSession удаляет сессию из кэша")
    void testRemoveSession() {
        ctx.setSessionCacheSize(10);
        GostSSLSession s =
                new GostSSLSession(
                        "TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L",
                        "host",
                        443,
                        new X509Certificate[0],
                        new X509Certificate[0]);
        ctx.putSession(s);
        assertNotNull(ctx.getSession(s.getId()));

        ctx.removeSession(s);
        assertNull(ctx.getSession(s.getId()));
    }

    @Test
    @DisplayName("Таймаут сессии: timeout=0 — TTL PSK не ограничен")
    void testSessionTimeoutZero() {
        ctx.setSessionTimeout(0);
        assertEquals(0, ctx.getSessionTimeout());
    }

    @Test
    @DisplayName("identityByHost eviction — ConcurrentHashMap без LRU, проверка лимита")
    void testIdentityByHostEviction() throws Exception {
        ctx.setMaxIdentityEntries(3);
        byte[] rms = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(rms);
        // разные тикеты — иначе все host'ы маппятся в один ключ хранилища,
        // и single-use PSK (RFC 8446 §8.1) удалит его при первом запросе.
        byte[] nstBodyA =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {1});
        byte[] nstBodyB =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {2});
        byte[] nstBodyC =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {3});
        byte[] nstBodyD =
                TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {4});

        ctx.saveNewSessionTicket(
                "a",
                443,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBodyA),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);
        ctx.saveNewSessionTicket(
                "b",
                443,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBodyB),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);
        ctx.saveNewSessionTicket(
                "c",
                443,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBodyC),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);
        // size=3, вытеснения ещё нет
        assertEquals(3, ctx.getPskStore().size(), "3 PSK до эвикции");

        ctx.saveNewSessionTicket(
                "d",
                443,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBodyD),
                TEST_BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);
        // size=4 > maxIdentityEntries=3: один host:port вытеснен из identityByHost.
        // Вытесненный даст null при getForClientResumption (identity не найден).
        // Остальные 3 — дадут не-null (PSK ещё не потреблены, т.к. единственный
        // вызов getForClientResumption происходит прямо сейчас).
        // single-use PSK не влияет: мы вызываем getForClientResumption ровно
        // один раз для каждого (host, port), то есть каждую запись потребляем
        // ровно один раз — как и должно быть по RFC 8446 §8.1.
        int count = 0;
        if (ctx.getForClientResumption("a", 443, TEST_BINDING) != null) count++;
        if (ctx.getForClientResumption("b", 443, TEST_BINDING) != null) count++;
        if (ctx.getForClientResumption("c", 443, TEST_BINDING) != null) count++;
        if (ctx.getForClientResumption("d", 443, TEST_BINDING) != null) count++;
        assertEquals(3, count, "ровно 3 entry после вытеснения");
    }

    @Test
    @DisplayName("Предел привязок: значение меньше единицы отвергается")
    void identityLimitMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> ctx.setMaxIdentityEntries(0));
        assertThrows(IllegalArgumentException.class, () -> ctx.setMaxIdentityEntries(-1));
        ctx.setMaxIdentityEntries(1);
    }
}
