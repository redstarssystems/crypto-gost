package org.rssys.gost.jsse.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.SslParameterNames;
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
    private String[] enabledCipherSuites = GostJsseConstants.supportedCipherSuites();
    private String[] enabledProtocols = GostJsseConstants.supportedProtocols();

    /**
     * Серверный сокет на указанном порту.
     *
     * @param port           порт ({@code 0} - любой свободный)
     * @param km             менеджер ключей (сертификат сервера)
     * @param tm             менеджер доверия (проверка клиентских сертификатов)
     * @param sessionContext контекст сессий (возобновление по PSK)
     * @throws IOException при ошибке открытия порта
     */
    public GostSSLServerSocket(
            int port,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(port, 0, null, km, tm, sessionContext);
    }

    /**
     * Серверный сокет с длиной очереди подключений.
     *
     * @param port           порт
     * @param backlog        максимальная длина очереди входящих подключений
     * @param km             менеджер ключей
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий
     * @throws IOException при ошибке открытия порта
     */
    public GostSSLServerSocket(
            int port,
            int backlog,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(port, backlog, null, km, tm, sessionContext);
    }

    /**
     * Серверный сокет с длиной очереди и локальным адресом.
     *
     * @param port           порт
     * @param backlog        максимальная длина очереди входящих подключений
     * @param bindAddr       локальный адрес привязки ({@code null} - любой)
     * @param km             менеджер ключей
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий
     * @throws IOException при ошибке открытия порта
     */
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

        // Применяется только действующий режим: сеттеры сокета и движка заменяют друг друга, и
        // второй вызов сбросил бы обязательный режим
        if (needClientAuth) {
            ssl.setNeedClientAuth(true);
        } else {
            ssl.setWantClientAuth(wantClientAuth);
        }
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
        this.enabledCipherSuites = SslParameterNames.checkedCipherSuites(suites);
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.supportedCipherSuites();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        this.enabledProtocols = SslParameterNames.checkedProtocols(protocols);
    }

    @Override
    public String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public String[] getSupportedProtocols() {
        return GostJsseConstants.supportedProtocols();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        // Как в SSLServerSocket: режим один, вызов заменяет предыдущий выбор
        this.needClientAuth = need;
        this.wantClientAuth = false;
    }

    @Override
    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        this.wantClientAuth = want;
        this.needClientAuth = false;
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
    public void setHandshakeApplicationProtocolSelector(
            BiFunction<SSLSocket, List<String>, String> selector) {
        this.serverSelector = selector;
    }

    /** @return селектор ALPN, применяемый к принятым сокетам, или null */
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return serverSelector;
    }

    private BiFunction<SSLSocket, List<String>, String> serverSelector;
}
