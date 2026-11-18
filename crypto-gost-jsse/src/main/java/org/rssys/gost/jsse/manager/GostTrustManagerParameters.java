package org.rssys.gost.jsse.manager;

import java.time.Duration;
import javax.net.ssl.ManagerFactoryParameters;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Параметры инициализации {@link GostTrustManagerFactorySpi} через
 * {@link javax.net.ssl.TrustManagerFactory#init(ManagerFactoryParameters)}.
 * <p>
 * Штатный {@code TrustManagerFactory} инициализируется только через {@code KeyStore}
 * и не имеет слота под политики/лимиты проверки CRL/OCSP. Этот класс — точка входа
 * для оператора, желающего сконфигурировать полный набор ограничений без прямого
 * создания {@link GostX509TrustManager}.
 * <p>
 * Иммутабелен; собирается через {@link Builder}.
 */
public final class GostTrustManagerParameters implements ManagerFactoryParameters {

    private final TrustAnchors trustAnchors;
    private final OcspPolicy ocspPolicy;
    private final OcspFetcher ocspFetcher;
    private final CrlPolicy crlPolicy;
    private final CrlFetcher crlFetcher;
    private final int maxCrlSize;
    private final int maxRevokedEntries;
    private final long crlCacheMaxBytes;
    private final Duration crlMaxAge;
    private final long maxOcspAgeMs;
    private final Duration maxThisUpdateAge;

    private GostTrustManagerParameters(Builder b) {
        this.trustAnchors = b.trustAnchors;
        this.ocspPolicy = b.ocspPolicy;
        this.ocspFetcher = b.ocspFetcher;
        this.crlPolicy = b.crlPolicy;
        this.crlFetcher = b.crlFetcher;
        this.maxCrlSize = b.maxCrlSize;
        this.maxRevokedEntries = b.maxRevokedEntries;
        this.crlCacheMaxBytes = b.crlCacheMaxBytes;
        this.crlMaxAge = b.crlMaxAge;
        this.maxOcspAgeMs = b.maxOcspAgeMs;
        this.maxThisUpdateAge = b.maxThisUpdateAge;
    }

    /** Доверенные якоря-сертификаты. */
    public TrustAnchors getTrustAnchors() {
        return trustAnchors;
    }

    /** Политика проверки OCSP. */
    public OcspPolicy getOcspPolicy() {
        return ocspPolicy;
    }

    /** Fetcher для client-side OCSP-запросов (может быть null). */
    public OcspFetcher getOcspFetcher() {
        return ocspFetcher;
    }

    /** Политика проверки CRL. */
    public CrlPolicy getCrlPolicy() {
        return crlPolicy;
    }

    /** Fetcher для CRL по CDP URI (может быть null). */
    public CrlFetcher getCrlFetcher() {
        return crlFetcher;
    }

    /** Максимальный размер CRL в байтах. */
    public int getMaxCrlSize() {
        return maxCrlSize;
    }

    /** Максимальное число отозванных записей в CRL. */
    public int getMaxRevokedEntries() {
        return maxRevokedEntries;
    }

    /** Бюджет кэша проверенных CRL в байтах оценки удержания; 0 - не хранить CRL. */
    public long getCrlCacheMaxBytes() {
        return crlCacheMaxBytes;
    }

    /**
     * Предельный возраст записи кэша CRL с последней успешной загрузки: запись старше
     * перепроверяется раньше {@code nextUpdate}. {@link Duration#ZERO} - перепроверка выключена.
     */
    public Duration getCrlMaxAge() {
        return crlMaxAge;
    }

    /** Максимальный возраст OCSP-ответа без {@code nextUpdate} в мс. */
    public long getMaxOcspAgeMs() {
        return maxOcspAgeMs;
    }

    /** Необязательный предел возраста {@code thisUpdate} OCSP-ответа или {@code null} - не задан. */
    public Duration getMaxThisUpdateAge() {
        return maxThisUpdateAge;
    }

    /** Создаёт билдер параметров. */
    public static Builder builder() {
        return new Builder();
    }

    /** Билдер {@link GostTrustManagerParameters}. Дефолты сохраняют безопасное поведение. */
    public static final class Builder {

        private TrustAnchors trustAnchors;
        private OcspPolicy ocspPolicy = OcspPolicy.IF_PRESENT;
        private OcspFetcher ocspFetcher;
        private CrlPolicy crlPolicy = CrlPolicy.DISABLED;
        private CrlFetcher crlFetcher;
        private int maxCrlSize = GostCrl.DEFAULT_MAX_CRL_SIZE;
        private int maxRevokedEntries = GostCrl.DEFAULT_MAX_REVOKED_ENTRIES;
        private long crlCacheMaxBytes = CrlCache.DEFAULT_MAX_BYTES;
        private Duration crlMaxAge = CrlCache.DEFAULT_MAX_AGE;
        private long maxOcspAgeMs = GostOids.MAX_OCSP_AGE_MS;
        private Duration maxThisUpdateAge;

        private Builder() {}

        /** Доверенные якоря-сертификаты. */
        public Builder trustAnchors(TrustAnchors trustAnchors) {
            this.trustAnchors = trustAnchors;
            return this;
        }

        /** Политика проверки OCSP; {@code null} - {@link OcspPolicy#IF_PRESENT} (как по умолчанию). */
        public Builder ocspPolicy(OcspPolicy ocspPolicy) {
            this.ocspPolicy = ocspPolicy != null ? ocspPolicy : OcspPolicy.IF_PRESENT;
            return this;
        }

        /** Fetcher для client-side OCSP. */
        public Builder ocspFetcher(OcspFetcher ocspFetcher) {
            this.ocspFetcher = ocspFetcher;
            return this;
        }

        /** Политика проверки CRL. */
        public Builder crlPolicy(CrlPolicy crlPolicy) {
            this.crlPolicy = crlPolicy != null ? crlPolicy : CrlPolicy.DISABLED;
            return this;
        }

        /** Fetcher для CRL по CDP URI. Требует политику CRL, отличную от DISABLED. */
        public Builder crlFetcher(CrlFetcher crlFetcher) {
            this.crlFetcher = crlFetcher;
            return this;
        }

        /**
         * Максимальный размер CRL в байтах. Предел загрузчика
         * {@link CrlFetcher#maxResponseSize()} должен быть не меньше: при включённой проверке CRL
         * это проверяется в {@link #build()}. Значение должно быть больше нуля, иначе
         * {@link #build()} бросит {@link IllegalArgumentException}.
         */
        public Builder maxCrlSize(int maxCrlSize) {
            this.maxCrlSize = maxCrlSize;
            return this;
        }

        /**
         * Максимальное число отозванных записей. Значение должно быть больше нуля, иначе
         * {@link #build()} бросит {@link IllegalArgumentException}.
         */
        public Builder maxRevokedEntries(int maxRevokedEntries) {
            this.maxRevokedEntries = maxRevokedEntries;
            return this;
        }

        /**
         * Бюджет кэша проверенных CRL в байтах оценки удержания (около шести байт кучи на байт
         * DER; по умолчанию {@link CrlCache#DEFAULT_MAX_BYTES}). Это верхняя граница, а не
         * занятая память. Бюджет общий для разобранных и сырых записей. Если разобранный CRL не
         * помещается, но помещается его DER, хранится сырой DER: сеть используется один раз, а
         * подпись и разбор повторяются на каждом соединении. Если не помещается и DER, CRL
         * загружается заново на каждом соединении. Значение 0 запрещает хранить любые CRL между
         * соединениями.
         *
         * @param crlCacheMaxBytes бюджет в байтах, не отрицательный
         */
        public Builder crlCacheMaxBytes(long crlCacheMaxBytes) {
            this.crlCacheMaxBytes = crlCacheMaxBytes;
            return this;
        }

        /**
         * Предельный возраст записи кэша проверенных CRL (по умолчанию
         * {@link CrlCache#DEFAULT_MAX_AGE}, 6 часов): запись старше, но ещё не истёкшая,
         * перепроверяется, при неудаче остаётся до {@code nextUpdate}. Это интервал перепроверки, а
         * не срок принятия отозванного сертификата: задержка равна предельному возрасту плюс
         * интервал выпуска CRL у УЦ. Для повышенных требований безопасности разумны 1-6 часов,
         * но большой CRL загружается чаще, а во время перепроверки в куче лежат старая и новая
         * записи. Подробнее - {@link GostSslBuilder#crlMaxAge(Duration)}.
         *
         * @param crlMaxAge {@link Duration#ZERO} - выключено, иначе от 1 минуты до 30 суток
         * @throws IllegalArgumentException если значение {@code null} или вне границ
         */
        public Builder crlMaxAge(Duration crlMaxAge) {
            this.crlMaxAge = CrlCache.requireValidMaxAge(crlMaxAge);
            return this;
        }

        /** Максимальный возраст OCSP-ответа без {@code nextUpdate} в мс. */
        public Builder maxOcspAgeMs(long maxOcspAgeMs) {
            this.maxOcspAgeMs = maxOcspAgeMs;
            return this;
        }

        /**
         * Необязательный предел возраста {@code thisUpdate} для всех OCSP-ответов, в том числе с
         * {@code nextUpdate} (Р 1323565.1.059-2024, п. 5.3). {@link #maxOcspAgeMs(long)} остаётся
         * в миллисекундах; без {@code nextUpdate} действует меньший из двух пределов. Предел должен
         * быть больше интервала обновления ответов службы.
         *
         * @param maxThisUpdateAge предел или {@code null} - не задан (так же сбрасывается)
         * @throws IllegalArgumentException если значение нулевое или отрицательное
         */
        public Builder maxThisUpdateAge(Duration maxThisUpdateAge) {
            this.maxThisUpdateAge = OcspVerifier.requireValidMaxThisUpdateAge(maxThisUpdateAge);
            return this;
        }

        /**
         * Собирает иммутабельный экземпляр параметров.
         *
         * @throws IllegalArgumentException если якоря не заданы или пусты либо бюджет кэша CRL
         *                                  отрицателен
         */
        public GostTrustManagerParameters build() {
            CrlCache.requireValidMaxBytes(crlCacheMaxBytes);
            if (trustAnchors == null) {
                throw new IllegalArgumentException("trustAnchors must be specified");
            }
            if (trustAnchors.isEmpty()) {
                throw new IllegalArgumentException("trustAnchors must not be empty");
            }
            // Значения не больше нуля - ошибка конфигурации, видимая сразу, а не фатальный отказ на
            // первом CRL
            new CrlLimits(maxCrlSize, maxRevokedEntries);
            // Загрузчик при отключённой проверке CRL не используется: оператор, задавший только
            // его, считал бы отзыв по CRL проверяемым
            if (crlFetcher != null && crlPolicy == CrlPolicy.DISABLED) {
                throw new IllegalArgumentException(
                        "crlFetcher requires crlPolicy other than DISABLED");
            }
            if (crlPolicy != CrlPolicy.DISABLED) {
                String fetcherProblem = CrlFetcher.limitProblem(crlFetcher, maxCrlSize);
                if (fetcherProblem != null) {
                    throw new IllegalArgumentException(fetcherProblem);
                }
            }
            return new GostTrustManagerParameters(this);
        }
    }
}
