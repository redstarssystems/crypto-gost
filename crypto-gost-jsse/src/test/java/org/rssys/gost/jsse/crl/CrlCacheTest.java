package org.rssys.gost.jsse.crl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit-тесты для {@link CrlCache}.
 */
@DisplayName("CrlCache: кэш CRL-ответов")
class CrlCacheTest {

    @Test
    @DisplayName("get() для отсутствующего ключа → null")
    void testGetMissing() {
        CrlCache cache = new CrlCache();
        assertNull(cache.get("http://crl.example.com/root.crl"));
    }

    @Test
    @DisplayName("put + get возвращает данные")
    void testPutGet() {
        CrlCache cache = new CrlCache();
        byte[] data = new byte[]{0x30, 0x00};
        cache.put("http://crl.example.com/root.crl", data);
        assertArrayEquals(data, cache.get("http://crl.example.com/root.crl"));
    }

    @Test
    @DisplayName("put для другого ключа не виден в get")
    void testDifferentKeys() {
        CrlCache cache = new CrlCache();
        cache.put("http://crl.example.com/a.crl", new byte[]{0x01});
        assertNull(cache.get("http://crl.example.com/b.crl"));
    }

    @Test
    @DisplayName("clear() очищает кэш")
    void testClear() {
        CrlCache cache = new CrlCache();
        cache.put("http://crl.example.com/root.crl", new byte[]{0x30, 0x00});
        cache.clear();
        assertEquals(0, cache.size());
        assertNull(cache.get("http://crl.example.com/root.crl"));
    }

    @Test
    @DisplayName("size() отражает количество записей")
    void testSize() {
        CrlCache cache = new CrlCache();
        assertEquals(0, cache.size());
        cache.put("http://crl.example.com/a.crl", new byte[]{0x01});
        assertEquals(1, cache.size());
        cache.put("http://crl.example.com/b.crl", new byte[]{0x02});
        assertEquals(2, cache.size());
    }

    @Test
    @DisplayName("put с null URI → NullPointerException")
    void testPutNullUri() {
        CrlCache cache = new CrlCache();
        assertThrows(NullPointerException.class, () -> cache.put(null, new byte[]{0x01}));
    }

    @Test
    @DisplayName("put с null данными → NullPointerException")
    void testPutNullData() {
        CrlCache cache = new CrlCache();
        assertThrows(NullPointerException.class,
                () -> cache.put("http://crl.example.com/a.crl", null));
    }

    @Test
    @DisplayName("get с null URI → NullPointerException")
    void testGetNullUri() {
        CrlCache cache = new CrlCache();
        assertThrows(NullPointerException.class, () -> cache.get(null));
    }
}
