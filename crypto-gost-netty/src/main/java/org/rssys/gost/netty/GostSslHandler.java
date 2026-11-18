package org.rssys.gost.netty;

import io.netty.handler.ssl.SslHandler;
import java.util.concurrent.Executor;
import org.rssys.gost.jsse.engine.GostSSLEngine;

/**
 * {@link SslHandler} над «сырым» {@link GostSSLEngine}, без обёртки Netty для ALPN.
 * <p>
 * Обёртка {@code JdkAlpnSslEngine}, которую Netty строит для ALPN, закрыта для пакета и скрывает
 * движок: приведение {@code (GostSSLEngine) handler.engine()} падало бы с
 * {@code ClassCastException}, а значит, были бы недоступны {@code setOcspResponse},
 * {@code initiateKeyUpdate} и другие методы движка. Здесь {@link #engine()} возвращает сам
 * {@code GostSSLEngine}, а результат ALPN отдаёт переопределённый {@link #applicationProtocol()}.
 * <p>
 * Класс создаётся только в {@link GostSslContext}.
 */
final class GostSslHandler extends SslHandler {

    GostSslHandler(GostSSLEngine engine, boolean startTls, Executor delegatedTaskExecutor) {
        super(engine, startTls, delegatedTaskExecutor);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Netty читает протокол через {@code ApplicationProtocolAccessor}, которого у сырого движка
     * нет, поэтому без переопределения {@code ApplicationProtocolNegotiationHandler} всегда видел
     * бы {@code null}. Пустая строка движка («ALPN не согласован») переводится в {@code null}, как
     * принято в Netty.
     */
    @Override
    public String applicationProtocol() {
        String negotiated = ((GostSSLEngine) engine()).getApplicationProtocol();
        return negotiated == null || negotiated.isEmpty() ? null : negotiated;
    }
}
