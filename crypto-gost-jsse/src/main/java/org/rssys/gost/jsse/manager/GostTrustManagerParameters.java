package org.rssys.gost.jsse.manager;

import java.util.Collections;
import java.util.List;
import javax.net.ssl.ManagerFactoryParameters;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.signature.PublicKeyParameters;

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

    private final List<PublicKeyParameters> caPublicKeys;
    private final OcspPolicy ocspPolicy;
    private final OcspFetcher ocspFetcher;
    private final CrlPolicy crlPolicy;
    private final CrlFetcher crlFetcher;
    private final int maxCrlSize;
    private final int maxRevokedEntries;
    private final long maxOcspAgeMs;

    private GostTrustManagerParameters(Builder b) {
        this.caPublicKeys =
                b.caPublicKeys != null ? Collections.unmodifiableList(b.caPublicKeys) : null;
        this.ocspPolicy = b.ocspPolicy;
        this.ocspFetcher = b.ocspFetcher;
        this.crlPolicy = b.crlPolicy;
        this.crlFetcher = b.crlFetcher;
        this.maxCrlSize = b.maxCrlSize;
        this.maxRevokedEntries = b.maxRevokedEntries;
        this.maxOcspAgeMs = b.maxOcspAgeMs;
    }

    /** Список доверенных ключей CA (null или пустой = без проверки цепочки). */
    public List<PublicKeyParameters> getCaPublicKeys() {
        return caPublicKeys;
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

    /** Максимальный возраст OCSP-ответа без {@code nextUpdate} в мс. */
    public long getMaxOcspAgeMs() {
        return maxOcspAgeMs;
    }

    /** Создаёт билдер параметров. */
    public static Builder builder() {
        return new Builder();
    }

    /** Билдер {@link GostTrustManagerParameters}. Дефолты сохраняют безопасное поведение. */
    public static final class Builder {

        private List<PublicKeyParameters> caPublicKeys;
        private OcspPolicy ocspPolicy = OcspPolicy.IF_PRESENT;
        private OcspFetcher ocspFetcher;
        private CrlPolicy crlPolicy = CrlPolicy.DISABLED;
        private CrlFetcher crlFetcher;
        private int maxCrlSize = GostCrl.DEFAULT_MAX_CRL_SIZE;
        private int maxRevokedEntries = GostCrl.DEFAULT_MAX_REVOKED_ENTRIES;
        private long maxOcspAgeMs = GostOids.MAX_OCSP_AGE_MS;

        private Builder() {}

        /** Список доверенных ключей CA. */
        public Builder caPublicKeys(List<PublicKeyParameters> caPublicKeys) {
            this.caPublicKeys = caPublicKeys;
            return this;
        }

        /** Политика проверки OCSP. */
        public Builder ocspPolicy(OcspPolicy ocspPolicy) {
            this.ocspPolicy = ocspPolicy;
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

        /** Fetcher для CRL по CDP URI. */
        public Builder crlFetcher(CrlFetcher crlFetcher) {
            this.crlFetcher = crlFetcher;
            return this;
        }

        /** Максимальный размер CRL в байтах. */
        public Builder maxCrlSize(int maxCrlSize) {
            this.maxCrlSize = maxCrlSize;
            return this;
        }

        /** Максимальное число отозванных записей. */
        public Builder maxRevokedEntries(int maxRevokedEntries) {
            this.maxRevokedEntries = maxRevokedEntries;
            return this;
        }

        /** Максимальный возраст OCSP-ответа без {@code nextUpdate} в мс. */
        public Builder maxOcspAgeMs(long maxOcspAgeMs) {
            this.maxOcspAgeMs = maxOcspAgeMs;
            return this;
        }

        /** Собирает иммутабельный экземпляр параметров. */
        public GostTrustManagerParameters build() {
            return new GostTrustManagerParameters(this);
        }
    }
}
