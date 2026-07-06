package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit-тесты для {@link CrlCache}.
 */
@DisplayName("CrlCache: кэш CRL-ответов")
class CrlCacheTest {

    @Test
    @DisplayName("lookup() для отсутствующего ключа -> crlDer=null, crlNumber=null")
    void testLookupMissing() {
        CrlCache cache = new CrlCache();
        CrlCache.CrlCacheEntry entry = cache.lookup("http://crl.example.com/root.crl");
        assertNull(entry.crlDer(), "отсутствующий ключ: crlDer должен быть null");
        assertNull(entry.lastKnownCrlNumber(), "отсутствующий ключ: crlNumber должен быть null");
    }

    @Test
    @DisplayName("put + lookup возвращает данные и cRLNumber")
    void testPutLookup() {
        CrlCache cache = new CrlCache();
        byte[] data = new byte[] {0x30, 0x00};
        cache.put("http://crl.example.com/root.crl", data);
        CrlCache.CrlCacheEntry entry = cache.lookup("http://crl.example.com/root.crl");
        assertNotNull(entry.crlDer(), "crlDer не должен быть null после put");
        assertEquals(data.length, entry.crlDer().length, "длина данных");
    }

    @Test
    @DisplayName("put для другого ключа не виден в lookup")
    void testDifferentKeys() {
        CrlCache cache = new CrlCache();
        cache.put("http://crl.example.com/a.crl", new byte[] {0x01});
        CrlCache.CrlCacheEntry entry = cache.lookup("http://crl.example.com/b.crl");
        assertNull(entry.crlDer(), "разный ключ: crlDer должен быть null");
        assertNull(entry.lastKnownCrlNumber(), "разный ключ: crlNumber должен быть null");
    }

    @Test
    @DisplayName("clear() очищает кэш")
    void testClear() {
        CrlCache cache = new CrlCache();
        cache.put("http://crl.example.com/root.crl", new byte[] {0x30, 0x00});
        cache.clear();
        assertEquals(0, cache.size());
        CrlCache.CrlCacheEntry entry = cache.lookup("http://crl.example.com/root.crl");
        assertNull(entry.crlDer(), "после clear: crlDer должен быть null");
    }

    @Test
    @DisplayName("size() отражает количество записей")
    void testSize() {
        CrlCache cache = new CrlCache();
        assertEquals(0, cache.size());
        cache.put("http://crl.example.com/a.crl", new byte[] {0x01});
        assertEquals(1, cache.size());
        cache.put("http://crl.example.com/b.crl", new byte[] {0x02});
        assertEquals(2, cache.size());
    }

    @Test
    @DisplayName("put с null URI -> NullPointerException")
    void testPutNullUri() {
        CrlCache cache = new CrlCache();
        assertThrows(NullPointerException.class, () -> cache.put(null, new byte[] {0x01}));
    }

    @Test
    @DisplayName("put с null данными -> NullPointerException")
    void testPutNullData() {
        CrlCache cache = new CrlCache();
        assertThrows(
                NullPointerException.class, () -> cache.put("http://crl.example.com/a.crl", null));
    }

    @Test
    @DisplayName("lookup с null URI -> NullPointerException")
    void testLookupNullUri() {
        CrlCache cache = new CrlCache();
        assertThrows(NullPointerException.class, () -> cache.lookup(null));
    }

    // ========================================================================
    // Тесты cRLNumber (RFC 5280 §5.2.3)
    // ========================================================================

    @Test
    @DisplayName("lookup() для отсутствующего ключа -> lastKnownCrlNumber=null")
    void testLookupMissingCrlNumber() {
        CrlCache cache = new CrlCache();
        assertNull(
                cache.lookup("http://crl.example.com/none.crl").lastKnownCrlNumber(),
                "отсутствующий ключ должен вернуть crlNumber=null");
    }

    @Test
    @DisplayName("lookup() после put -> crlNumber=ожидаемое")
    void testPutLookupCrlNumber() {
        CrlCache cache = new CrlCache();
        BigInteger crlNum = BigInteger.valueOf(42);
        cache.putForTest(
                "http://crl.example.com/root.crl",
                new byte[] {0x30, 0x00},
                crlNum,
                System.currentTimeMillis() + 3600_000L);
        CrlCache.CrlCacheEntry entry = cache.lookup("http://crl.example.com/root.crl");
        assertNotNull(entry.crlDer(), "crlDer не должен быть null");
        assertEquals(crlNum, entry.lastKnownCrlNumber(), "crlNumber должен совпадать");
    }

    @Test
    @DisplayName("lookup() для expired записи -> crlDer=null, crlNumber сохраняется")
    void testLookupExpiredKeepsCrlNumber() {
        CrlCache cache = new CrlCache();
        BigInteger crlNum = BigInteger.valueOf(5);
        cache.putForTest("http://crl.example.com/root.crl", new byte[] {0x30, 0x00}, crlNum, 0L);
        CrlCache.CrlCacheEntry entry = cache.lookup("http://crl.example.com/root.crl");
        assertNull(entry.crlDer(), "expired запись: crlDer должен быть null");
        assertEquals(
                crlNum,
                entry.lastKnownCrlNumber(),
                "expired запись: crlNumber должен сохраняться для rollback-защиты");
    }

    @Test
    @DisplayName("put CRL без cRLNumber -> crlNumber=null в lookup")
    void testPutCrlWithoutCrlNumber() {
        CrlCache cache = new CrlCache();
        cache.putForTest(
                "http://crl.example.com/root.crl",
                new byte[] {0x30, 0x00},
                null,
                System.currentTimeMillis() + 3600_000L);
        assertNull(
                cache.lookup("http://crl.example.com/root.crl").lastKnownCrlNumber(),
                "CRL без cRLNumber: crlNumber должен быть null");
    }
}
