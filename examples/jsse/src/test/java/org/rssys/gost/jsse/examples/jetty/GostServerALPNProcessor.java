package org.rssys.gost.jsse.examples.jetty;

import java.util.List;
import javax.net.ssl.SSLEngine;
import org.eclipse.jetty.alpn.server.ALPNServerConnection;
import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.ssl.ALPNProcessor;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.io.ssl.SslHandshakeListener;
import org.rssys.gost.jsse.engine.GostSSLEngine;

/**
 * Серверный ALPN-процессор Jetty 12 для {@link GostSSLEngine}. Пример, а не поддерживаемый API.
 * <p>
 * Стандартный процессор Jetty ({@code JDK9ServerALPNProcessor}) применяется только к движкам из
 * {@code java.base}, поэтому для {@code GostSSLEngine} Jetty отвергает соединение:
 * {@code No ALPN Processor}. Этот процессор подключает те же средства JSSE (селектор протокола
 * из {@code SSLEngine}), но для движка библиотеки. Регистрируется через ServiceLoader: файл
 * {@code META-INF/services/org.eclipse.jetty.io.ssl.ALPNProcessor$Server} с именем этого класса.
 * <p>
 * Контракт селектора совпадает с JDK: {@code null} завершает рукопожатие алертом
 * {@code no_application_protocol}, имя протокола выбирает его.
 */
public final class GostServerALPNProcessor implements ALPNProcessor.Server {

    @Override
    public boolean appliesTo(SSLEngine sslEngine) {
        return sslEngine instanceof GostSSLEngine;
    }

    @Override
    public void configure(SSLEngine sslEngine, Connection connection) {
        ALPNServerConnection alpn = (ALPNServerConnection) connection;
        sslEngine.setHandshakeApplicationProtocolSelector(
                (engine, clientProtocols) -> select(alpn, clientProtocols));
        // Клиент без ALPN селектор не вызывает: протокол по умолчанию выбирается после рукопожатия
        SslConnection.SslEndPoint endPoint = (SslConnection.SslEndPoint) alpn.getEndPoint();
        endPoint.getSslConnection()
                .addHandshakeListener(
                        new SslHandshakeListener() {
                            @Override
                            public void handshakeSucceeded(Event event) {
                                if (alpn.getProtocol() == null) {
                                    alpn.unsupported();
                                }
                            }
                        });
    }

    private static String select(ALPNServerConnection alpn, List<String> clientProtocols) {
        try {
            alpn.select(clientProtocols);
            return alpn.getProtocol();
        } catch (RuntimeException e) {
            // Общего протокола нет: null по контракту JDK даёт алерт no_application_protocol
            return null;
        }
    }
}
