package org.rssys.gost.jsse.crl;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.rssys.gost.pkix.cert.CrlVerifier;

/**
 * Кэш CRL-ответов с инвалидацией по nextUpdate (RFC 5280 §5.1.2.4).
 * <p>
 * Ключ — URI CRLDistributionPoints (строка). Хранит сырой DER CRL.
 * Срок жизни: nextUpdate + 1 час grace. Если nextUpdate отсутствует — TTL 1 час.
 * <p>
 * Инвалидация inline при get() — без ScheduledExecutorService.
 */
public final class CrlCache {

    private static final Logger LOG = System.getLogger("org.rssys.gost.jsse.crl.CrlCache");

    /** Grace-период после nextUpdate для перекоса часов */
    private static final long GRACE_MS = 3600_000L; // 1 час

    /** Default TTL если nextUpdate отсутствует */
    private static final long DEFAULT_TTL_MS = 3600_000L; // 1 час

    /** Максимальное количество записей (soft cap — защита от OOM при аномальном числе CDP) */
    private static final int MAX_ENTRIES = 100;

    private final ConcurrentHashMap<String, CachedCrl> cache = new ConcurrentHashMap<>();

    /**
     * Возвращает закэшированный CRL или null.
     */
    public byte[] get(String crlUri) {
        Objects.requireNonNull(crlUri);
        CachedCrl entry = cache.get(crlUri);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            cache.remove(crlUri);
            LOG.log(Level.DEBUG, "CRL cache expired for {0}", crlUri);
            return null;
        }
        return entry.crlDer;
    }

    /**
     * Помещает CRL в кэш. Парсит nextUpdate для определения expiresAt.
     */
    public void put(String crlUri, byte[] crlDer) {
        Objects.requireNonNull(crlUri);
        Objects.requireNonNull(crlDer);
        long expiresAt;
        try {
            Instant nextUpdate = CrlVerifier.extractNextUpdate(crlDer);
            if (nextUpdate != null) {
                expiresAt = nextUpdate.toEpochMilli() + GRACE_MS;
            } else {
                expiresAt = System.currentTimeMillis() + DEFAULT_TTL_MS;
            }
        } catch (Exception e) {
            expiresAt = System.currentTimeMillis() + DEFAULT_TTL_MS;
        }
        cache.put(crlUri, new CachedCrl(crlDer, expiresAt));
        if (cache.size() > MAX_ENTRIES) {
            cache.keySet().stream().findAny().ifPresent(cache::remove);
        }
        LOG.log(
                Level.DEBUG,
                "CRL cached for {0}, expires at {1}",
                crlUri,
                Instant.ofEpochMilli(expiresAt));
    }

    /**
     * Удаляет все записи (для тестов).
     */
    public void clear() {
        cache.clear();
    }

    public int size() {
        return cache.size();
    }

    private static final class CachedCrl {
        final byte[] crlDer;
        final long expiresAt;

        CachedCrl(byte[] crlDer, long expiresAt) {
            this.crlDer = crlDer;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }
}
