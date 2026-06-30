package org.rssys.gost.jsse.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;

/**
 * SSLServerSocket для ГОСТ TLS 1.3.
 * <p>
 * {@link #accept()} возвращает {@link GostSSLSocket} с серверным GostSSLEngine.
 * accept() НЕ запускает handshake — handshake триггерится первым
 * read()/write()/startHandshake() на принятом сокете.
 * <p>
 * Параметры серверного сокета (needClientAuth, enabledCipherSuites и т.д.)
 * копируются в каждый принятый сокет.
 */
public final class GostSSLServerSocket extends SSLServerSocket {

    private final GostX509KeyManager keyManager;
    private final GostX509TrustManager trustManager;
    private final GostSSLSessionContext sessionContext;

    private boolean needClientAuth;
    private boolean wantClientAuth;
    private boolean enableSessionCreation = true;
    private String[] enabledCipherSuites = GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
    private String[] enabledProtocols = GostJsseConstants.SUPPORTED_PROTOCOLS.clone();

    public GostSSLServerSocket(
            int port,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        super(port);
        this.keyManager = km;
        this.trustManager = tm;
        this.sessionContext = sessionContext;
    }

    public GostSSLServerSocket(
            int port,
            int backlog,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        super(port, backlog);
        this.keyManager = km;
        this.trustManager = tm;
        this.sessionContext = sessionContext;
    }

    public GostSSLServerSocket(
            int port,
            int backlog,
            InetAddress bindAddr,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        super(port, backlog, bindAddr);
        this.keyManager = km;
        this.trustManager = tm;
        this.sessionContext = sessionContext;
    }

    @Override
    public Socket accept() throws IOException {
        Socket raw = super.accept();
        GostSSLSocket ssl = new GostSSLSocket(raw, keyManager, trustManager, sessionContext);

        ssl.setNeedClientAuth(needClientAuth);
        ssl.setWantClientAuth(wantClientAuth);
        ssl.setEnableSessionCreation(enableSessionCreation);
        ssl.setEnabledCipherSuites(enabledCipherSuites);
        ssl.setEnabledProtocols(enabledProtocols);
        if (serverSelector != null) {
            ssl.setHandshakeApplicationProtocolSelector(serverSelector);
        }

        return ssl;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        if (suites == null) throw new IllegalArgumentException("Cipher suites must not be null");
        for (String s : suites) {
            if (org.rssys.gost.tls13.TlsCiphersuite.byIanaName(s) == null) {
                throw new IllegalArgumentException("Unsupported cipher suite: " + s);
            }
        }
        this.enabledCipherSuites = suites.clone();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null) throw new IllegalArgumentException("Protocols must not be null");
        for (String p : protocols) {
            if (!GostJsseConstants.PROTOCOL_TLS_1_3.equals(p)) {
                throw new IllegalArgumentException("Unsupported protocol: " + p);
            }
        }
        this.enabledProtocols = protocols.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public String[] getSupportedProtocols() {
        return GostJsseConstants.SUPPORTED_PROTOCOLS.clone();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        this.needClientAuth = need;
    }

    @Override
    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        this.wantClientAuth = want;
    }

    @Override
    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    @Override
    public void setUseClientMode(boolean mode) {
        if (mode) throw new IllegalArgumentException("Cannot set client mode on a server socket");
    }

    @Override
    public boolean getUseClientMode() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        this.enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

    /**
     * Устанавливает ALPN-selector для принятых сокетов.
     * <p>
     * Не override (SSLServerSocket не имеет этого метода).
     * Сохранённый selector применяется к каждому GostSSLSocket при accept().
     */
    @SuppressWarnings("unused")
    public void setHandshakeApplicationProtocolSelector(
            java.util.function.BiFunction<SSLSocket, java.util.List<String>, String> selector) {
        this.serverSelector = selector;
    }

    public java.util.function.BiFunction<SSLSocket, java.util.List<String>, String>
            getHandshakeApplicationProtocolSelector() {
        return serverSelector;
    }

    private java.util.function.BiFunction<SSLSocket, java.util.List<String>, String> serverSelector;
}
