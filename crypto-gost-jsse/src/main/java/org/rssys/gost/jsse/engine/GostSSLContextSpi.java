package org.rssys.gost.jsse.engine;

import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLServerSocketFactory;
import org.rssys.gost.jsse.socket.GostSSLSocketFactory;
import org.rssys.gost.pkix.util.GostLogger;
import org.rssys.gost.pkix.util.GostLogger.Level;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * SSLContextSpi для ГОСТ TLS 1.3.
 * <p>
 * Создаёт GostSSLEngine с переданными KeyManager/TrustManager.
 * Дефолтные SSLParameters содержат только ГОСТ-наборы.
 */
public final class GostSSLContextSpi extends SSLContextSpi {

    private static GostLogger LOG = GostLogger.getLogger("org.rssys.gost.jsse.GostSSLContextSpi");

    private GostX509KeyManager keyManager;
    private GostX509TrustManager trustManager;
    private boolean initialized;
    private GostSSLSessionContext clientSessionContext;
    private GostSSLSessionContext serverSessionContext;

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) {
        this.keyManager = null;
        this.trustManager = null;

        if (km != null) {
            for (KeyManager k : km) {
                if (k instanceof GostX509KeyManager) {
                    this.keyManager = (GostX509KeyManager) k;
                    break;
                }
            }
        }
        if (this.keyManager == null) {
            this.keyManager = new GostX509KeyManager();
        }

        if (tm != null) {
            for (TrustManager t : tm) {
                if (t instanceof GostX509TrustManager) {
                    this.trustManager = (GostX509TrustManager) t;
                    break;
                }
            }
        }
        if (this.trustManager == null) {
            LOG.log(
                    Level.WARNING,
                    "GostX509TrustManager created without CA key - certificate chain validation disabled. "
                            + "For production use, pass caPublicKey to GostX509TrustManager.");
            this.trustManager = new GostX509TrustManager(null, false);
        }

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        this.clientSessionContext = new GostSSLSessionContext(cs, cs.getHashLen());
        this.clientSessionContext.setSessionCacheSize(20_480);
        this.serverSessionContext = new GostSSLSessionContext(cs, cs.getHashLen());

        this.initialized = true;
    }

    private void checkInitialized() {
        if (!initialized) throw new IllegalStateException("SSLContext not initialized");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        checkInitialized();
        return new GostSSLEngine(
                keyManager, trustManager, "", -1, true, clientSessionContext, serverSessionContext);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        checkInitialized();
        // Safe-by-default: при непустом host клиентский engine получает hostname
        // verification (HTTPS), как socket-путь. Устраняет расхождение socket vs engine.
        return GostSSLEngine.createForContextClient(
                keyManager, trustManager, host, port, clientSessionContext, serverSessionContext);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        checkInitialized();
        return new GostSSLSocketFactory(keyManager, trustManager, clientSessionContext);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        checkInitialized();
        return new GostSSLServerSocketFactory(keyManager, trustManager, serverSessionContext);
    }

    // Создаёт серверный GostSSLEngine с serverSessionContext.
    // Используется GostSSLServerSocket и будет полезен для Netty-адаптера в фазе 5.
    GostSSLEngine createServerEngine(String host, int port) {
        return GostSSLEngine.createForServer(
                keyManager, trustManager, host, port, serverSessionContext);
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(GostJsseConstants.SUPPORTED_CIPHER_SUITES);
        params.setProtocols(GostJsseConstants.SUPPORTED_PROTOCOLS);
        return params;
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
        return engineGetDefaultSSLParameters();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        checkInitialized();
        return clientSessionContext;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        checkInitialized();
        return serverSessionContext;
    }
}
