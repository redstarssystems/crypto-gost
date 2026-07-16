package org.rssys.gost.jsse;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.List;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;

/**
 * Fluent builder для сложных случаев настройки {@link GostSsl}.
 * <p>
 * Покрывает OCSP stapling и session cache — то, что не входит
 * в простые статические методы {@link GostSsl}.
 */
public class GostSslBuilder {

    private static final Logger LOG = System.getLogger("org.rssys.gost.jsse.GostSslBuilder");

    private byte[] certDer;
    private byte[] keyDer;
    private byte[] p12Data;
    private char[] p12Password;
    private byte[][] trustedCaDers;
    private boolean ocspEnabled;
    private int sessionCacheSize = -1;
    private boolean trustAll;
    private CrlPolicy crlPolicy = CrlPolicy.DISABLED;
    private CrlFetcher crlFetcher;
    private int maxCrlSize = GostCrl.DEFAULT_MAX_CRL_SIZE;
    private int maxRevokedEntries = GostCrl.DEFAULT_MAX_REVOKED_ENTRIES;
    private OcspFetcher ocspFetcher;
    private long maxOcspAgeMs = GostOids.MAX_OCSP_AGE_MS;
    private boolean interopAcceptGostBaseSigScheme;
    private boolean needClientAuth;

    GostSslBuilder() {}

    /**
     * Устанавливает сертификат и ключ с авто-определением формата.
     * <p>
     * Каждый аргумент может быть в PEM или DER. PEM автоматически конвертируется
     * в DER через {@link GostCertificate#pemToDer(byte[])}.
     *
     * @param certData сертификат X.509 (PEM или DER)
     * @param keyData  закрытый ключ PKCS#8 (PEM или DER)
     * @return this для fluent API
     */
    public GostSslBuilder certificate(byte[] certData, byte[] keyData) {
        this.certDer =
                GostCertificate.isPem(certData) ? GostCertificate.pemToDer(certData) : certData;
        this.keyDer = GostCertificate.isPem(keyData) ? GostCertificate.pemToDer(keyData) : keyData;
        return this;
    }

    /**
     * Устанавливает сертификат и ключ из PKCS12.
     *
     * @param p12Data  байты PFX-контейнера
     * @param password пароль
     */
    public GostSslBuilder certificate(byte[] p12Data, char[] password) {
        this.p12Data = p12Data;
        this.p12Password = password;
        return this;
    }

    /**
     * Добавляет доверенный CA-сертификат в trust store.
     * <p>
     * Автоматически определяет формат: PEM (одиночный или цепочка) или DER.
     * Для PEM-цепочки добавляются все сертификаты из неё.
     * Добавленные CA используются все при проверке цепочки сертификатов.
     *
     * @param caData PEM- или DER-байты CA-сертификата
     * @return this для fluent API
     * @throws IllegalArgumentException если данные не содержат валидного сертификата
     */
    public GostSslBuilder trustCa(byte[] caData) {
        if (GostCertificate.isPem(caData)) {
            GostCertificate.listFromPem(caData).forEach(ca -> trustCaSingle(ca.getEncoded()));
        } else {
            trustCaSingle(caData);
        }
        return this;
    }

    private void trustCaSingle(byte[] caDer) {
        if (this.trustedCaDers == null) {
            this.trustedCaDers = new byte[][] {caDer};
        } else {
            byte[][] copy = new byte[trustedCaDers.length + 1][];
            System.arraycopy(trustedCaDers, 0, copy, 0, trustedCaDers.length);
            copy[trustedCaDers.length] = caDer;
            this.trustedCaDers = copy;
        }
    }

    /**
     * Добавляет все CA-сертификаты из PFX-контейнера в trust store.
     * <p>
     * Извлекает все сертификаты с флагом CA (isCA == true) из цепочки в PFX
     * и делегирует каждый в {@link #trustCa(byte[])}.
     *
     * @param pfxData  байты PFX-контейнера
     * @param password пароль PFX
     */
    public GostSslBuilder trustCa(byte[] pfxData, char[] password) {
        GostPkcs12Loader.Result r = GostPkcs12Loader.load(pfxData, password, true);
        List<GostCertificate> caCerts =
                r.getCertificateChain().stream()
                        .filter(GostCertificate::isCA)
                        .collect(Collectors.toList());
        if (caCerts.isEmpty()) {
            throw new IllegalArgumentException("No CA certificate found in PFX");
        }
        caCerts.forEach(ca -> trustCa(ca.getEncoded()));
        return this;
    }

    /**
     * Добавляет все CA-сертификаты из PEM-цепочки в trust store.
     * <p>Разбирает многострочный PEM, извлекает все сертификаты.
     *
     * @param pemChain PEM-байты с одним или несколькими сертификатами CA
     * @return this для fluent API
     * @throws IllegalArgumentException если PEM не содержит валидных сертификатов
     */
    public GostSslBuilder trustCaFromPem(byte[] pemChain) {
        GostCertificate.listFromPem(pemChain).forEach(ca -> trustCa(ca.getEncoded()));
        return this;
    }

    /**
     * Включает OCSP stapling.
     */
    public GostSslBuilder ocsp(boolean enabled) {
        this.ocspEnabled = enabled;
        return this;
    }

    /**
     * Устанавливает fetcher для client-side OCSP-запросов (при отсутствии stapling).
     *
     * @param fetcher реализация {@link OcspFetcher} (может быть null — отключает fetch)
     */
    public GostSslBuilder ocspFetcher(OcspFetcher fetcher) {
        this.ocspFetcher = fetcher;
        return this;
    }

    /**
     * Устанавливает максимальный возраст OCSP-ответа без {@code nextUpdate}
     * (RFC 6960 §2.4 — локальная политика свежести relying party).
     *
     * @param maxOcspAgeMs возраст в миллисекундах
     */
    public GostSslBuilder maxOcspAgeMs(long maxOcspAgeMs) {
        this.maxOcspAgeMs = maxOcspAgeMs;
        return this;
    }

    /**
     * Устанавливает политику проверки CRL. По умолчанию {@link CrlPolicy#DISABLED}.
     *
     * @param policy политика CRL
     */
    public GostSslBuilder crlPolicy(CrlPolicy policy) {
        this.crlPolicy = policy != null ? policy : CrlPolicy.DISABLED;
        return this;
    }

    /**
     * Устанавливает fetcher для скачивания CRL по CDP URI.
     *
     * @param fetcher реализация {@link CrlFetcher} (может быть null)
     */
    public GostSslBuilder crlFetcher(CrlFetcher fetcher) {
        this.crlFetcher = fetcher;
        return this;
    }

    /**
     * Устанавливает максимальный размер CRL в байтах (защита от DoS).
     * <p>
     * Если используется {@link org.rssys.gost.jsse.crl.JdkHttpCrlFetcher},
     * его {@code maxResponseSize} должен быть &ge; переданного значения.
     *
     * @param maxCrlSize размер в байтах
     */
    public GostSslBuilder maxCrlSize(int maxCrlSize) {
        this.maxCrlSize = maxCrlSize;
        return this;
    }

    /**
     * Устанавливает максимальное число отозванных записей в CRL (защита от DoS).
     *
     * @param maxRevokedEntries число записей
     */
    public GostSslBuilder maxRevokedEntries(int maxRevokedEntries) {
        this.maxRevokedEntries = maxRevokedEntries;
        return this;
    }

    /**
     * Устанавливает размер кэша сессий. 0 = без ограничения.
     */
    public GostSslBuilder sessionCacheSize(int size) {
        this.sessionCacheSize = size;
        return this;
    }

    /**
     * Включает режим trust-all (только для разработки).
     */
    public GostSslBuilder trustAll() {
        LOG.log(
                Level.WARNING,
                "trustAll() enabled — server certificate validation DISABLED. "
                        + "For production use .trustCa(byte[]) instead.");
        this.trustAll = true;
        return this;
    }

    /**
     * Включает обход openssl-gost-provider v3.6.0: сервер всегда шлёт
     * базовые signature scheme (0x0709 для 256-bit, 0x070D для 512-bit)
     * независимо от реальной кривой сертификата.
     * <p>
     * По умолчанию выключено. Включение — осознанное решение разработчика
     * для совместимости с openssl-gost-provider.
     *
     * @return this
     */
    public GostSslBuilder interopAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
        return this;
    }

    /**
     * Включает обязательную аутентификацию клиента (mTLS).
     * Аналог {@code SSLServerSocket.setNeedClientAuth(true)}.
     * <p>
     * Флаг устанавливается на {@code GostSSLSessionContext} и применяется
     * ко всем серверным engine, созданным через этот контекст.
     *
     * @param need true — клиентский сертификат обязателен
     * @return this
     */
    public GostSslBuilder needClientAuth(boolean need) {
        this.needClientAuth = need;
        return this;
    }

    /**
     * Строит серверный SSLContext.
     */
    public SSLContext buildServerContext() {
        SSLContext ctx =
                GostSsl.buildContext(
                        certDer,
                        keyDer,
                        p12Data,
                        p12Password,
                        trustedCaDers,
                        ocspEnabled,
                        sessionCacheSize,
                        trustAll,
                        crlPolicy,
                        crlFetcher,
                        maxCrlSize,
                        maxRevokedEntries,
                        ocspFetcher,
                        maxOcspAgeMs,
                        true);
        if (interopAcceptGostBaseSigScheme) {
            ((GostSSLSessionContext) ctx.getServerSessionContext())
                    .setInteropAcceptGostBaseSigScheme(true);
        }
        if (needClientAuth) {
            ((GostSSLSessionContext) ctx.getServerSessionContext()).setNeedClientAuth(true);
        }
        return ctx;
    }

    /**
     * Строит клиентский SSLContext.
     */
    public SSLContext buildClientContext() {
        SSLContext ctx =
                GostSsl.buildContext(
                        certDer,
                        keyDer,
                        p12Data,
                        p12Password,
                        trustedCaDers,
                        ocspEnabled,
                        sessionCacheSize,
                        trustAll,
                        crlPolicy,
                        crlFetcher,
                        maxCrlSize,
                        maxRevokedEntries,
                        ocspFetcher,
                        maxOcspAgeMs,
                        false);
        if (interopAcceptGostBaseSigScheme) {
            ((GostSSLSessionContext) ctx.getClientSessionContext())
                    .setInteropAcceptGostBaseSigScheme(true);
        }
        return ctx;
    }
}
