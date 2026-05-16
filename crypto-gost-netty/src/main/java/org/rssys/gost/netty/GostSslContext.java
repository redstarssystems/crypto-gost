package org.rssys.gost.netty;

import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.CipherSuiteFilter;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;

import javax.net.ssl.SSLContext;

/**
 * Netty SslContext для ГОСТ TLS 1.3 через JdkSslContext.
 * <p>
 * Создаётся исключительно через {@link GostSslContextBuilder}.
 * Тонкая обёртка над JdkSslContext: вся работа по интеграции с
 * Netty pipeline — {@link io.netty.handler.ssl.SslHandler},
 * cipher suite mapping, ALPN — на стороне JdkSslContext.
 */
public final class GostSslContext extends JdkSslContext {

    GostSslContext(SSLContext sslContext, boolean isClient,
                   Iterable<String> ciphers, CipherSuiteFilter cipherFilter,
                   ApplicationProtocolConfig apn, ClientAuth clientAuth,
                   String[] protocols, boolean startTls) {
        super(sslContext, isClient, ciphers, cipherFilter, apn, clientAuth, protocols, startTls);
    }
}
