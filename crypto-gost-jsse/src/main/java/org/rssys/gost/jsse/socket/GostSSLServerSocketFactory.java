package org.rssys.gost.jsse.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;

/**
 * SSLServerSocketFactory для ГОСТ TLS 1.3.
 * <p>
 * Создаёт {@link GostSSLServerSocket} с переданными менеджерами ключей/доверия.
 */
public final class GostSSLServerSocketFactory extends SSLServerSocketFactory {

    private final GostX509KeyManager keyManager;
    private final GostX509TrustManager trustManager;
    private final GostSSLSessionContext sessionContext;

    public GostSSLServerSocketFactory(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            GostSSLSessionContext sessionContext) {
        this.keyManager = keyManager;
        this.trustManager = trustManager;
        this.sessionContext = sessionContext;
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
    public ServerSocket createServerSocket(int port) throws IOException {
        return new GostSSLServerSocket(port, keyManager, trustManager, sessionContext);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new GostSSLServerSocket(port, backlog, keyManager, trustManager, sessionContext);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddr)
            throws IOException {
        return new GostSSLServerSocket(
                port, backlog, ifAddr, keyManager, trustManager, sessionContext);
    }
}
