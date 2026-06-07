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
     * Устанавливает сертификат и ключ из DER-байтов.
     *
     * @param certDer сертификат в DER (X.509)
     * @param keyDer  закрытый ключ в DER (PKCS#8 PrivateKeyInfo)
     */
    public GostSslBuilder certificate(byte[] certDer, byte[] keyDer) {
        this.certDer = certDer;
        this.keyDer = keyDer;
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
     * Добавляет доверенный CA-сертификат (DER X.509).
     * <p>
     * Добавленные CA используются все при проверке цепочки сертификатов.
     */
    public GostSslBuilder trustCa(byte[] caDer) {
        if (this.trustedCaDers == null) {
            this.trustedCaDers = new byte[][]{caDer};
        } else {
            byte[][] copy = new byte[trustedCaDers.length + 1][];
            System.arraycopy(trustedCaDers, 0, copy, 0, trustedCaDers.length);
            copy[trustedCaDers.length] = caDer;
            this.trustedCaDers = copy;
        }
        return this;
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
