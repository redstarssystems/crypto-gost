package org.rssys.gost.jsse.socket;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * SSLSocketFactory для ГОСТ TLS 1.3.
 * <p>
 * Создаёт {@link GostSSLSocket} с переданными менеджерами ключей/доверия.
 * Все socket-методы используют новый TCP-соединение (не-layered) или оборачивают
 * существующий socket (layered — для HttpsURLConnection через прокси).
 */
public final class GostSSLSocketFactory extends SSLSocketFactory {

    private final GostX509KeyManager keyManager;
    private final GostX509TrustManager trustManager;
    private final GostSSLSessionContext sessionContext;

    public GostSSLSocketFactory(GostX509KeyManager keyManager,
                                GostX509TrustManager trustManager,
                                GostSSLSessionContext sessionContext) {
        this.keyManager = keyManager;
        this.trustManager = trustManager;
        this.sessionContext = sessionContext;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return new GostSSLSocket(s, host, port, autoClose,
                keyManager, trustManager, sessionContext);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return new GostSSLSocket(host, port, keyManager, trustManager, sessionContext);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddr, int localPort) throws IOException {
        return new GostSSLSocket(host, port, localAddr, localPort,
                keyManager, trustManager, sessionContext);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return new GostSSLSocket(host, port, keyManager, trustManager, sessionContext);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
        return new GostSSLSocket(address, port, localAddr, localPort,
                keyManager, trustManager, sessionContext);
    }

}
