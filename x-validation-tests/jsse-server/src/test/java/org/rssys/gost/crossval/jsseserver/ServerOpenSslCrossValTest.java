package org.rssys.gost.crossval.jsseserver;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;

import javax.net.ssl.SSLContext;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JSSE: кросс-валидация серверов приложений ↔ OpenSSL s_client (roundtrip)")
class ServerOpenSslCrossValTest {

    @BeforeAll
    static void preconditions() {
        Security.addProvider(new RssysGostJsseProvider());
        OpenSslChecker.assumeGostTls13();
    }

    @ParameterizedTest
    @EnumSource(ServerOpenSslHelper.ServerType.class)
    @DisplayName("Сервер + s_client GET → INTEROP_OK")
    void testServerRoundtrip(ServerOpenSslHelper.ServerType serverType) throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        ServerOpenSslHelper.ServerPkiBundle pki =
                ServerOpenSslHelper.createServerPki(params);
        GostX509KeyManager km = ServerOpenSslHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());
        GostX509TrustManager tm = new GostX509TrustManager(pki.caPub(), false);
        SSLContext sslContext = ServerOpenSslHelper.createSslContext(km, tm);

        int port = ServerOpenSslHelper.findFreePort();
        CountDownLatch ready = new CountDownLatch(1);
        CountDownLatch stop = new CountDownLatch(1);
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        switch (serverType) {
            case TOMCAT -> ServerOpenSslHelper.startTomcat(
                    port, sslContext, false, km, tm, ready, stop, serverError);
            case JETTY -> ServerOpenSslHelper.startJetty(
                    port, sslContext, false, ready, stop, serverError);
            case UNDERTOW -> ServerOpenSslHelper.startUndertow(
                    port, sslContext, ready, stop, serverError);
        }

        assertTrue(ready.await(15, TimeUnit.SECONDS),
                "Сервер " + serverType + " не запущен за 15с");
        assertNull(serverError.get(),
                "Ошибка сервера " + serverType + ": " + serverError.get());

        try {
            String clientOutput = ServerOpenSslHelper.runHttpGet(
                    port,
                    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
                    "GC256B");
            assertTrue(clientOutput.contains("INTEROP_OK"),
                    "s_client должен получить INTEROP_OK от " + serverType);
        } finally {
            stop.countDown();
        }
    }
}
