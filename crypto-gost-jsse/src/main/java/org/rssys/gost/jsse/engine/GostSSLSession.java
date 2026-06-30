package org.rssys.gost.jsse.engine;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.util.CryptoRandom;

/**
 * Реализация SSLSession для ГОСТ TLS 1.3.
 * <p>
 * Создаётся после успешного handshake и содержит результаты согласования:
 * cipher suite, сертификаты пира, протокол, ALPN.
 * <p>
 * OCSP-ответ хранится в приватном поле, недоступном через {@link #getValue(String)}.
 */
public final class GostSSLSession extends ExtendedSSLSession {

    private final String cipherSuite;
    private final String protocol;
    private final String peerHost;
    private final int peerPort;
    private final X509Certificate[] peerCertificates;
    private final X509Certificate[] localCertificates;
    private final long creationTime;
    private final byte[] sessionId;
    private final String applicationProtocol;
    private final Map<String, Object> values = new HashMap<>();
    private volatile long lastAccessedTime;

    // Приватный канал для OCSP — невидим через getValue
    private byte[] ocspResponse;

    // Session context (задаётся после создания, в finishHandshake)
    private GostSSLSessionContext sessionContext;
    private volatile boolean invalidated;

    private static final String[] LOCAL_SIG_ALGS = {GostJsseConstants.KEY_ALG_ECGOST_2012};

    // Application buffer sizes — дефолты TLS 1.3
    private int applicationBufferSize = GostJsseConstants.DEFAULT_APPLICATION_BUFFER_SIZE;
    private int packetBufferSize = GostJsseConstants.DEFAULT_PACKET_BUFFER_SIZE;

    public GostSSLSession(
            String cipherSuite,
            String peerHost,
            int peerPort,
            X509Certificate[] peerCertificates,
            X509Certificate[] localCertificates) {
        this(cipherSuite, peerHost, peerPort, peerCertificates, localCertificates, null);
    }

    /**
     * Создаёт сессию со всеми параметрами согласования.
     * <p>
     * Предусловие: handshake успешно завершён, cipherSuite и hostname
     * зафиксированы. applicationProtocol может быть null (ALPN не использовался).
     * Постусловие: все поля immutable, sessionId сгенерирован через CryptoRandom.
     *
     * @param cipherSuite        IANA-имя согласованного cipher suite
     * @param peerHost           DNS-имя пира (может быть пустым)
     * @param peerPort           порт пира (-1 если неизвестен)
     * @param peerCertificates   сертификаты пира (leaf-first), не null
     * @param localCertificates  собственные сертификаты (leaf-first), не null
     * @param applicationProtocol согласованный протокол ALPN, или null
     */
    public GostSSLSession(
            String cipherSuite,
            String peerHost,
            int peerPort,
            X509Certificate[] peerCertificates,
            X509Certificate[] localCertificates,
            String applicationProtocol) {
        this.cipherSuite = cipherSuite;
        this.protocol = GostJsseConstants.PROTOCOL_TLS_1_3;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.peerCertificates =
                peerCertificates != null ? peerCertificates.clone() : new X509Certificate[0];
        this.localCertificates =
                localCertificates != null ? localCertificates.clone() : new X509Certificate[0];
        this.applicationProtocol = applicationProtocol;
        this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = creationTime;
        this.sessionId = new byte[TlsConstants.SESSION_ID_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(this.sessionId);
    }

    // ========================================================================
    // SSLSession
    // ========================================================================

    @Override
    public byte[] getId() {
        return sessionId.clone();
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    /**
     * Задаёт контекст сессии. Вызывается из GostSSLEngine.finishHandshake()
     * после создания сессии. Непубличный — контекст назначается один раз
     * и не должен меняться в течение жизни сессии.
     */
    void setSessionContext(GostSSLSessionContext ctx) {
        this.sessionContext = ctx;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    void touch() {
        this.lastAccessedTime = System.currentTimeMillis();
    }

    @Override
    public void invalidate() {
        invalidated = true;
        if (sessionContext != null) {
            sessionContext.removeSession(this);
        }
    }

    @Override
    public boolean isValid() {
        if (invalidated) return false;
        if (sessionContext == null) return true;
        int timeout = sessionContext.getSessionTimeout();
        if (timeout == 0) return true;
        long age = System.currentTimeMillis() - creationTime;
        return age < timeout * 1000L;
    }

    @Override
    public void putValue(String name, Object value) {
        if (name == null) throw new IllegalArgumentException("name must not be null");
        if (value == null) throw new IllegalArgumentException("value must not be null");
        Object old = values.put(name, value);
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public Object getValue(String name) {
        return values.get(name);
    }

    @Override
    public void removeValue(String name) {
        Object old = values.remove(name);
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public String[] getValueNames() {
        return values.keySet().toArray(new String[0]);
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
        return peerCertificates.clone();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return localCertificates.length > 0 ? localCertificates.clone() : null;
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() {
        // Deprecated — используем getPeerCertificates()
        throw new UnsupportedOperationException("Use getPeerCertificates()");
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
        return peerCertificates[0].getSubjectX500Principal();
    }

    @Override
    public Principal getLocalPrincipal() {
        if (localCertificates.length == 0) return null;
        return localCertificates[0].getSubjectX500Principal();
    }

    /**
     * @return согласованный протокол ALPN, или null если ALPN не использовался
     */
    public String getApplicationProtocol() {
        return applicationProtocol;
    }

    @Override
    public String getCipherSuite() {
        return cipherSuite;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public int getPacketBufferSize() {
        return packetBufferSize;
    }

    @Override
    public int getApplicationBufferSize() {
        return applicationBufferSize;
    }

    // ========================================================================
    // ExtendedSSLSession
    // ========================================================================

    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        return LOCAL_SIG_ALGS.clone();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms() {
        return new String[0];
    }

    @Override
    public List<byte[]> getStatusResponses() {
        if (ocspResponse != null) {
            return Collections.singletonList(ocspResponse.clone());
        }
        return Collections.emptyList();
    }

    // ========================================================================
    // Приватный канал для OCSP (package-private)
    // ========================================================================

    void setOcspResponse(byte[] ocspResponse) {
        this.ocspResponse = ocspResponse != null ? ocspResponse.clone() : null;
    }

    byte[] getOcspResponse() {
        return ocspResponse != null ? ocspResponse.clone() : null;
    }
}
