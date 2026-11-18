package org.rssys.gost.netty;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.IdentityCipherSuiteFilter;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslHandler;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLEngine;

/**
 * Netty SslContext для ГОСТ TLS 1.3 через JdkSslContext.
 * <p>
 * Создаётся исключительно через {@link GostSslContextBuilder}.
 * <p>
 * <b>Два пути создания обработчика.</b>
 * <ul>
 *   <li>{@code newHandler(...)} - основной путь. Обработчик работает с «сырым»
 *       {@link GostSSLEngine}: {@code ((GostSSLEngine) handler.engine())} доступен всегда, в том
 *       числе при ALPN, поэтому можно вызывать {@code setOcspResponse},
 *       {@code initiateKeyUpdate} и другие методы движка. Эти вызовы нужно сделать до
 *       добавления обработчика в канал: Netty начинает рукопожатие при добавлении в активный
 *       канал.</li>
 *   <li>{@code newEngine(...)} - метод {@code final} в Netty, поэтому возвращает движок в
 *       закрытой обёртке Netty. При ALPN приведение к {@code GostSSLEngine} невозможно. Путь
 *       нужен только фреймворкам, которые сами создают {@code SslHandler}.</li>
 * </ul>
 * <p>
 * <b>Клиент и имя узла.</b> Клиентский контекст проверяет имя узла в сертификате (RFC 6125), и
 * узел обязателен: используйте {@code newHandler(alloc, host, port)}. Без узла рукопожатие
 * отказывает до отправки ClientHello. Проверку можно отключить только осознанно через
 * {@link GostSslContextBuilder#withoutHostnameVerification()}.
 * <p>
 * <b>Настройка движка повторяет Netty.</b> Общий код настройки у двух путей вызвать нельзя:
 * её делает закрытый метод {@code JdkSslContext}. Поэтому {@link #createEngine} повторяет
 * настройку Netty (наборы шифров, протоколы, режим, {@code ClientAuth}, сброс алгоритма проверки
 * имени, ALPN), а расхождение путей ловит тест сверки.
 */
public final class GostSslContext extends JdkSslContext {

    // JdkSslContext хранит режим в закрытом поле, а повторить настройку движка нужно здесь
    private final ClientAuth requiredClientAuth;
    private final List<String> alpnProtocols;
    // Массивы создаются один раз на контекст, а не на каждое соединение: движок копирует их
    // при установке, поэтому общий экземпляр безопасно отдавать всем движкам
    private final String[] enabledCipherSuites;
    private final String[] enabledProtocols;

    GostSslContext(
            SSLContext sslContext,
            boolean isClient,
            ClientAuth clientAuth,
            List<String> alpnProtocols) {
        super(
                sslContext,
                isClient,
                Arrays.asList(GostJsseConstants.supportedCipherSuites()),
                IdentityCipherSuiteFilter.INSTANCE,
                buildApnConfig(alpnProtocols),
                clientAuth,
                GostJsseConstants.supportedProtocols(),
                false);
        this.requiredClientAuth = clientAuth;
        this.alpnProtocols = List.copyOf(alpnProtocols);
        this.enabledCipherSuites = GostJsseConstants.supportedCipherSuites();
        this.enabledProtocols = GostJsseConstants.supportedProtocols();
    }

    /**
     * Конфигурация ALPN для пути {@code newEngine}, где Netty оборачивает движок сам.
     * <p>
     * {@code FATAL_ALERT} для селектора и слушателя даёт ту же политику, что и путь
     * {@code newHandler}: при непересекающихся списках рукопожатие завершается алертом
     * {@code no_application_protocol}. Если ALPN есть только у одной стороны, Netty лишь
     * обнуляет протокол, и рукопожатие проходит.
     */
    private static ApplicationProtocolConfig buildApnConfig(List<String> protocols) {
        if (protocols.isEmpty()) {
            return ApplicationProtocolConfig.DISABLED;
        }
        return new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.FATAL_ALERT,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.FATAL_ALERT,
                protocols);
    }

    @Override
    protected SslHandler newHandler(ByteBufAllocator alloc, boolean startTls) {
        return new GostSslHandler(createEngine(null, -1), startTls, immediateExecutor());
    }

    @Override
    protected SslHandler newHandler(ByteBufAllocator alloc, boolean startTls, Executor executor) {
        return new GostSslHandler(createEngine(null, -1), startTls, executor);
    }

    @Override
    protected SslHandler newHandler(
            ByteBufAllocator alloc, String peerHost, int peerPort, boolean startTls) {
        return new GostSslHandler(createEngine(peerHost, peerPort), startTls, immediateExecutor());
    }

    @Override
    protected SslHandler newHandler(
            ByteBufAllocator alloc,
            String peerHost,
            int peerPort,
            boolean startTls,
            Executor executor) {
        return new GostSslHandler(createEngine(peerHost, peerPort), startTls, executor);
    }

    /**
     * Создаёт и настраивает движок так же, как {@code JdkSslContext.configureAndWrapEngine},
     * но без обёртки Netty.
     * <p>
     * Порядок важен: роль выставляется до параметров. Для серверного движка алгоритм проверки
     * имени сбрасывается явно: движок создан как клиентский через
     * {@code createSSLEngine(host, port)} и несёт HTTPS, который серверу не нужен. Для клиента
     * строгий режим контекста сессий сохраняет HTTPS при {@code null}.
     *
     * @param peerHost узел или null, если обработчик создаётся без узла
     * @param peerPort порт или -1
     */
    private GostSSLEngine createEngine(String peerHost, int peerPort) {
        SSLContext sslContext = context();
        GostSSLEngine engine =
                (GostSSLEngine)
                        (peerHost == null
                                ? sslContext.createSSLEngine()
                                : sslContext.createSSLEngine(peerHost, peerPort));
        engine.setEnabledCipherSuites(enabledCipherSuites);
        engine.setEnabledProtocols(enabledProtocols);
        engine.setUseClientMode(isClient());
        if (isServer()) {
            switch (requiredClientAuth) {
                case OPTIONAL -> engine.setWantClientAuth(true);
                case REQUIRE -> engine.setNeedClientAuth(true);
                case NONE -> {
                    // клиентский сертификат не запрашивается
                }
            }
        }
        SSLParameters params = engine.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(null);
        if (!alpnProtocols.isEmpty()) {
            params.setApplicationProtocols(alpnProtocols.toArray(new String[0]));
        }
        engine.setSSLParameters(params);
        if (isServer() && !alpnProtocols.isEmpty()) {
            engine.setHandshakeApplicationProtocolSelector(
                    (sslEngine, clientProtocols) -> selectByServerPriority(clientProtocols));
        }
        return engine;
    }

    /**
     * Выбор протокола на сервере: приоритет у списка сервера, как в Netty
     * ({@code NoFailProtocolSelector.select}). Возвращает {@code null}, если общего протокола
     * нет: по контракту JDK это отказ с алертом {@code no_application_protocol} (RFC 7301 §3.2).
     */
    private String selectByServerPriority(List<String> clientProtocols) {
        for (String serverProtocol : alpnProtocols) {
            if (clientProtocols.contains(serverProtocol)) {
                return serverProtocol;
            }
        }
        return null;
    }

    private static Executor immediateExecutor() {
        return io.netty.util.concurrent.ImmediateExecutor.INSTANCE;
    }
}
