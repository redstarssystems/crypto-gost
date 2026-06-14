package org.rssys.gost.jsse;

import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.cert.GostPkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;

import javax.net.ssl.SSLContext;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Fluent builder для сложных случаев настройки {@link GostSsl}.
 * <p>
 * Покрывает OCSP stapling и session cache — то, что не входит
 * в простые статические методы {@link GostSsl}.
 */
public class GostSslBuilder {

    private byte[] certDer;
    private byte[] keyDer;
    private byte[] p12Data;
    private char[] p12Password;
    private byte[][] trustedCaDers;
    private boolean ocspEnabled;
    private int sessionCacheSize = -1;
    private boolean trustAll;

    GostSslBuilder() {}

    /**
     * Устанавливает сертификат и ключ с авто-определением формата.
     * <p>
     * Каждый аргумент может быть в PEM или DER. PEM автоматически конвертируется
     * в DER через {@link TlsCertificate#pemToDer(byte[])}.
     *
     * @param certData сертификат X.509 (PEM или DER)
     * @param keyData  закрытый ключ PKCS#8 (PEM или DER)
     * @return this для fluent API
     */
    public GostSslBuilder certificate(byte[] certData, byte[] keyData) {
        this.certDer = TlsCertificate.isPem(certData)
                ? TlsCertificate.pemToDer(certData) : certData;
        this.keyDer = TlsCertificate.isPem(keyData)
                ? TlsCertificate.pemToDer(keyData) : keyData;
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
        if (TlsCertificate.isPem(caData)) {
            TlsCertificate.listFromPem(caData)
                    .forEach(ca -> trustCaSingle(ca.getEncoded()));
        } else {
            trustCaSingle(caData);
        }
        return this;
    }

    private void trustCaSingle(byte[] caDer) {
        if (this.trustedCaDers == null) {
            this.trustedCaDers = new byte[][]{caDer};
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
        GostPkcs12Loader.Result r = GostPkcs12Loader.load(pfxData, password);
        List<TlsCertificate> caCerts = r.getCertificateChain().stream()
            .filter(TlsCertificate::isCA)
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
        TlsCertificate.listFromPem(pemChain).forEach(
                ca -> trustCa(ca.getEncoded()));
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
        this.trustAll = true;
        return this;
    }

    /**
     * Строит серверный SSLContext.
     */
    public SSLContext buildServerContext() {
        return GostSsl.buildContext(certDer, keyDer, p12Data, p12Password,
                trustedCaDers, ocspEnabled, sessionCacheSize, trustAll, true);
    }

    /**
     * Строит клиентский SSLContext.
     */
    public SSLContext buildClientContext() {
        return GostSsl.buildContext(certDer, keyDer, p12Data, p12Password,
                trustedCaDers, ocspEnabled, sessionCacheSize, trustAll, false);
    }
}
