package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Настройки менеджера доверия: срок кэша OCSP, вытеснение из кэша по ближайшему сроку,
 * нормализация {@code null} в политике OCSP, проверка бюджета кэша CRL.
 */
@DisplayName("GostX509TrustManager: настройки и вытеснение кэша OCSP")
class GostX509TrustManagerSettingsTest {

    @Test
    @DisplayName("setOcspCacheTtlMs: нуль и отрицательное значение отвергаются")
    void ocspCacheTtlMustBePositive() throws Exception {
        GostX509TrustManager manager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(
                                PkixCertTestHelper.createRootCA(ECParameters.tc26a256()).cert));

        manager.setOcspCacheTtlMs(1);
        assertThrows(IllegalArgumentException.class, () -> manager.setOcspCacheTtlMs(0));
        assertThrows(IllegalArgumentException.class, () -> manager.setOcspCacheTtlMs(-5));
    }

    @Test
    @DisplayName("Вытеснение кэша OCSP: уходит запись с ближайшим сроком, остальные остаются")
    void evictionRemovesEntryWithNearestExpiry() {
        ConcurrentHashMap<GostX509TrustManager.OcspCacheKey, GostX509TrustManager.CachedOcspStatus>
                cache = new ConcurrentHashMap<>();
        GostX509TrustManager.OcspCacheKey soonest = key("a");
        GostX509TrustManager.OcspCacheKey middle = key("b");
        GostX509TrustManager.OcspCacheKey latest = key("c");
        cache.put(latest, status(3_000));
        cache.put(soonest, status(1_000));
        cache.put(middle, status(2_000));

        GostX509TrustManager.evictNearestExpiry(cache);

        assertFalse(cache.containsKey(soonest), "ближайший срок должен быть вытеснен");
        assertTrue(cache.containsKey(middle), "средний срок остаётся");
        assertTrue(cache.containsKey(latest), "дальний срок остаётся");
        assertEquals(2, cache.size());
    }

    @Test
    @DisplayName("Вытеснение пустого кэша ничего не делает")
    void evictionOfEmptyCacheIsHarmless() {
        ConcurrentHashMap<GostX509TrustManager.OcspCacheKey, GostX509TrustManager.CachedOcspStatus>
                cache = new ConcurrentHashMap<>();

        GostX509TrustManager.evictNearestExpiry(cache);

        assertEquals(0, cache.size());
    }

    @Test
    @DisplayName(
            "Параметры менеджера доверия: ocspPolicy(null) равна IF_PRESENT, как crlPolicy(null)")
    void nullOcspPolicyMeansIfPresent() throws Exception {
        GostTrustManagerParameters parameters =
                GostTrustManagerParameters.builder()
                        .trustAnchors(
                                TrustAnchors.ofCertificate(
                                        PkixCertTestHelper.createRootCA(ECParameters.tc26a256())
                                                .cert))
                        .ocspPolicy(null)
                        .build();

        assertEquals(OcspPolicy.IF_PRESENT, parameters.getOcspPolicy());
    }

    @Test
    @DisplayName("Бюджет кэша CRL: нуль допустим, отрицательное значение отвергается")
    void crlCacheBudgetValidation() {
        assertEquals(
                0, CrlCache.requireValidMaxBytes(0), "нуль - не хранить CRL между соединениями");
        assertThrows(IllegalArgumentException.class, () -> CrlCache.requireValidMaxBytes(-1));
    }

    private static GostX509TrustManager.OcspCacheKey key(String serial) {
        return new GostX509TrustManager.OcspCacheKey("issuer", serial);
    }

    private static GostX509TrustManager.CachedOcspStatus status(long expiresAt) {
        return new GostX509TrustManager.CachedOcspStatus(new byte[] {1}, null, expiresAt);
    }
}
