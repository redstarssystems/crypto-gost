package org.rssys.gost.jsse.engine;

import java.security.KeyManagementException;
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
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * SSLContextSpi для ГОСТ TLS 1.3.
 * <p>
 * Создаёт GostSSLEngine с переданными KeyManager/TrustManager.
 * Дефолтные SSLParameters содержат только ГОСТ-наборы.
 */
public final class GostSSLContextSpi extends SSLContextSpi {

    private GostX509KeyManager keyManager;
    private GostX509TrustManager trustManager;
    private boolean initialized;
    private GostSSLSessionContext clientSessionContext;
    private GostSSLSessionContext serverSessionContext;

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr)
            throws KeyManagementException {
        this.keyManager = null;
        this.trustManager = null;

        // Пустой менеджер (km == null или пустой массив) - клиент без mTLS: подмена пустым
        // менеджером нужна, чтобы фабрики сокетов и конструкторы движка не получали null.
        // Сторонний менеджер молча подменять нельзя: сервер с ним упал бы на рукопожатии
        // без внятной причины, как и выбор «первого из двух» потерял бы ключи остальных
        if (km != null) {
            for (KeyManager k : km) {
                if (!(k instanceof GostX509KeyManager)) {
                    throw new KeyManagementException(
                            "Only GostX509KeyManager is supported; got "
                                    + (k == null ? "null" : k.getClass().getName()));
                }
                if (this.keyManager == null) {
                    this.keyManager = (GostX509KeyManager) k;
                } else if (this.keyManager != k) {
                    throw new KeyManagementException(
                            "Only one GostX509KeyManager instance is supported");
                }
            }
        }
        if (this.keyManager == null) {
            this.keyManager = new GostX509KeyManager();
        }

        if (tm != null) {
            for (TrustManager t : tm) {
                if (!(t instanceof GostX509TrustManager)) {
                    throw new KeyManagementException(
                            "Only GostX509TrustManager is supported; got "
                                    + (t == null ? "null" : t.getClass().getName()));
                }
                if (this.trustManager == null) {
                    this.trustManager = (GostX509TrustManager) t;
                } else if (this.trustManager != t) {
                    // Молчаливый выбор первого менеджера потерял бы якоря остальных;
                    // объединение «любой из» требует составного менеджера, его здесь нет.
                    throw new KeyManagementException(
                            "Only one GostX509TrustManager instance is supported");
                }
            }
        }

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        // Оба контекста получают предел кэша по умолчанию (GostSSLSessionContext): PSK-тикеты
        // возобновления лежат в отдельном хранилище контекста со своим пределом
        this.clientSessionContext = new GostSSLSessionContext(cs);
        this.serverSessionContext = new GostSSLSessionContext(cs);

        this.initialized = true;
    }

    private void checkInitialized() {
        if (!initialized) throw new IllegalStateException("SSLContext not initialized");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        checkInitialized();
        // Через общую фабрику, чтобы умолчания режима проверки имени не расходились с путём
        // createSSLEngine(host, port); без узла HTTPS включается только в строгом режиме
        return GostSSLEngine.createForContextClient(
                keyManager, trustManager, "", -1, clientSessionContext, serverSessionContext);
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

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(GostJsseConstants.supportedCipherSuites());
        params.setProtocols(GostJsseConstants.supportedProtocols());
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
