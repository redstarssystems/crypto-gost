package org.rssys.gost.jsse.engine;
import org.rssys.gost.jsse.RssysGostJsseProvider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.util.CryptoRandom;

import javax.net.ssl.SSLSession;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T-7: Eviction-тесты для GostSSLSessionContext.
 * Проверяют LRU-вытеснение sessions и identityByHost.
 */
class GostSSLSessionContextEvictionTest {

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private GostSSLSessionContext ctx;

    @BeforeAll
    static void setUpProvider() {
        Security.addProvider(new RssysGostJsseProvider());
    }

    @BeforeEach
    void setUp() {
        ctx = new GostSSLSessionContext(CS, 32);
    }

    @Test
    @DisplayName("Вытеснение сессий: размер кэша 5, добавлено 10, остаются 5 последних")
    void testSessionEviction() {
        ctx.setSessionCacheSize(5);

        for (int i = 0; i < 10; i++) {
            GostSSLSession s = new GostSSLSession(
                    "TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L",
                    "host" + i, 443,
                    new X509Certificate[0], new X509Certificate[0]);
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

        for (byte[] id : idList) {
            SSLSession s = ctx.getSession(id);
            assertNotNull(s);
        }
    }

    @Test
    @DisplayName("Вытеснение сессий: sessionCacheSize=0 — вытеснение отключено")
    void testNoEvictionWhenSizeZero() {
        ctx.setSessionCacheSize(0);

        for (int i = 0; i < 10; i++) {
            GostSSLSession s = new GostSSLSession(
                    "TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L",
                    "host" + i, 443,
                    new X509Certificate[0], new X509Certificate[0]);
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
        GostSSLSession s = new GostSSLSession(
                "TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L",
                "host", 443,
                new X509Certificate[0], new X509Certificate[0]);
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
        // WHY: разные тикеты — иначе все host'ы маппятся в один ключ хранилища,
        // и single-use PSK (RFC 8446 §8.1) удалит его при первом запросе.
        byte[] nstBodyA = TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[]{1});
        byte[] nstBodyB = TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[]{2});
        byte[] nstBodyC = TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[]{3});
        byte[] nstBodyD = TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[]{4});

        ctx.saveNewSessionTicket("a", 443, rms, nstBodyA);
        ctx.saveNewSessionTicket("b", 443, rms, nstBodyB);
        ctx.saveNewSessionTicket("c", 443, rms, nstBodyC);
        // size=3, вытеснения ещё нет
        assertEquals(3, ctx.getPskStore().size(), "3 PSK до эвикции");

        ctx.saveNewSessionTicket("d", 443, rms, nstBodyD);
        // size=4 > maxIdentityEntries=3: один host:port вытеснен из identityByHost.
        // Вытесненный даст null при getForClientResumption (identity не найден).
        // Остальные 3 — дадут не-null (PSK ещё не потреблены, т.к. единственный
        // вызов getForClientResumption происходит прямо сейчас).
        // single-use PSK не влияет: мы вызываем getForClientResumption ровно
        // один раз для каждого (host, port), то есть каждую запись потребляем
        // ровно один раз — как и должно быть по RFC 8446 §8.1.
        int count = 0;
        if (ctx.getForClientResumption("a", 443) != null) count++;
        if (ctx.getForClientResumption("b", 443) != null) count++;
        if (ctx.getForClientResumption("c", 443) != null) count++;
        if (ctx.getForClientResumption("d", 443) != null) count++;
        assertEquals(3, count, "ровно 3 entry после вытеснения");
    }

}
