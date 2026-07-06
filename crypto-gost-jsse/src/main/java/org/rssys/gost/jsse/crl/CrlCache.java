package org.rssys.gost.jsse.crl;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.rssys.gost.pkix.cert.CrlVerifier;

/**
 * Кэш CRL-ответов с инвалидацией по nextUpdate (RFC 5280 §5.1.2.4)
 * и защитой от CRL rollback через монотонность cRLNumber (RFC 5280 §5.2.3).
 * <p>
 * Ключ — URI CRLDistributionPoints (строка). Хранит сырой DER CRL и cRLNumber
 * для монотонной проверки при следующем fetch. Срок жизни: nextUpdate + 1 час grace.
 * Если nextUpdate отсутствует — TTL 1 час.
 * <p>
 * Инвалидация inline при lookup() — без ScheduledExecutorService.
 * <p>
 * Потокобезопасность: ConcurrentHashMap для всех операций.
 * {@link CrlCacheEntry#lastKnownCrlNumber()} возвращается даже для expired записей —
 * монотонное знание о последнем известном номере CRL не теряет актуальности после
 * истечения срока.
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
     * Запись кэша: сырой DER CRL (null если expired или отсутствует)
     * и последний известный cRLNumber для монотонной проверки.
     */
    public record CrlCacheEntry(byte[] crlDer, BigInteger lastKnownCrlNumber) {}

    /**
     * Атомарно возвращает закэшированный CRL и его cRLNumber.
     * <p>
     * Если запись expired — удаляет её и возвращает {@code crlDer = null},
     * но {@code lastKnownCrlNumber} из expired-записи сохраняется
     * для защиты от CRL rollback при последующем fetch.
     *
     * @param crlUri URI CRLDistributionPoints
     * @return запись кэша или {@code (null, null)} если ключ отсутствует
     */
    public CrlCacheEntry lookup(String crlUri) {
        Objects.requireNonNull(crlUri);
        CachedCrl entry = cache.get(crlUri);
        if (entry == null) {
            return new CrlCacheEntry(null, null);
        }
        if (entry.isExpired()) {
            cache.remove(crlUri);
            LOG.log(Level.DEBUG, "CRL cache expired for {0}", crlUri);
            return new CrlCacheEntry(null, entry.crlNumber);
        }
        return new CrlCacheEntry(entry.crlDer, entry.crlNumber);
    }

    /**
     * Помещает CRL в кэш. Парсит nextUpdate для определения expiresAt
     * и cRLNumber для монотонной проверки.
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
        BigInteger crlNumber = CrlVerifier.extractCrlNumber(crlDer);
        cache.put(crlUri, new CachedCrl(crlDer, crlNumber, expiresAt));
        if (cache.size() > MAX_ENTRIES) {
            String evictedKey = cache.keySet().stream().findAny().orElse(null);
            if (evictedKey != null) {
                CachedCrl evicted = cache.remove(evictedKey);
                if (evicted != null && evicted.crlNumber != null) {
                    LOG.log(
                            Level.WARNING,
                            "CRL cache evicted entry with cRLNumber={0} for {1}"
                                    + " — rollback protection reset for this CDP",
                            evicted.crlNumber,
                            evictedKey);
                }
            }
        }
        LOG.log(
                Level.DEBUG,
                "CRL cached for {0}, expires at {1}, cRLNumber={2}",
                crlUri,
                Instant.ofEpochMilli(expiresAt),
                crlNumber);
    }

    /**
     * Для тестов: помещает CRL с явным expiresAt и cRLNumber,
     * минуя парсинг nextUpdate/cRLNumber.
     */
    void putForTest(String crlUri, byte[] crlDer, BigInteger crlNumber, long expiresAt) {
        Objects.requireNonNull(crlUri);
        Objects.requireNonNull(crlDer);
        cache.put(crlUri, new CachedCrl(crlDer, crlNumber, expiresAt));
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
        final BigInteger crlNumber;
        final long expiresAt;

        CachedCrl(byte[] crlDer, BigInteger crlNumber, long expiresAt) {
            this.crlDer = crlDer;
            this.crlNumber = crlNumber;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }
}
