package org.rssys.gost.crossval.jsseserver;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;

import javax.net.ssl.SSLContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JSSE: кросс-валидация mTLS серверов приложений <-> OpenSSL s_client -cert")
class TomcatJettyMtlsCrossValTest {

    @BeforeAll
    static void preconditions() {
        Security.addProvider(new RssysGostJsseProvider());
        OpenSslChecker.assumeGostTls13();
    }

    @ParameterizedTest
    @CsvSource({
            "TOMCAT, TomcatTestSSLImpl",
            "JETTY, SslContextFactory.Server"
    })
    @DisplayName("mTLS: сервер + s_client -cert -> INTEROP_OK")
    void testMtls(String serverTypeName, String impl) throws Exception {
        // Используем TempDirUtils для автоматической очистки файлов сертификатов
        TempDirUtils.withTempDir("jsse-server-mtls-", tmpDir -> {
            ECParameters params = ECParameters.cryptoProA();
            ServerOpenSslHelper.ServerPkiBundle pki =
                    ServerOpenSslHelper.createServerPki(params);

            // Самоподписанный клиентский сертификат (self-signed — OpenSSL
            // не может загрузить PEM ГОСТ-серта, подписанного CA: "ca md too weak")
            byte[] cliKu = new byte[]{(byte) 0x80};
            TlsTestHelper.CertBundle clientBundle = TlsTestHelper.createCertWithKey(
                    params, "20240101120000Z", "21060101120000Z",
                    null, cliKu, new String[]{"1.3.6.1.5.5.7.3.2"});
            PublicKeyParameters clientPub = clientBundle.cert.getPublicKey();
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Files.writeString(clientKeyPem,
                    ServerOpenSslHelper.privateKeyToPem(
                            GostDerCodec.encodePrivateKey(clientBundle.priv)));

            // Серверный SSLContext с TrustManager от клиентского сертификата (mTLS)
            GostX509KeyManager km = ServerOpenSslHelper.createKeyManager(
                    pki.cert(), pki.caCert(), pki.priv());
            SSLContext sslContext = ServerOpenSslHelper.createMtlsSslContext(
                    km, clientPub);
            GostX509TrustManager tm = new GostX509TrustManager(
                    clientPub, false);

            int port = ServerOpenSslHelper.findFreePort();
            CountDownLatch ready = new CountDownLatch(1);
            CountDownLatch stop = new CountDownLatch(1);
            AtomicReference<Throwable> serverError = new AtomicReference<>();

            switch (serverTypeName) {
                case "TOMCAT" -> ServerOpenSslHelper.startTomcat(
                        port, sslContext, true, km, tm, ready, stop, serverError);
                case "JETTY" -> ServerOpenSslHelper.startJetty(
                        port, sslContext, true, ready, stop, serverError);
                default -> throw new IllegalArgumentException(
                        "Unknown server: " + serverTypeName);
            }

            ready.await(15, TimeUnit.SECONDS);
            assertNull(serverError.get(),
                    "Ошибка сервера " + serverTypeName + ": " + serverError.get());

            try {
                String clientOutput = ServerOpenSslHelper.runMtlsHttpGet(
                        port,
                        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
                        "GC256B",
                        clientCertPem.toString(),
                        clientKeyPem.toString(),
                        "gostr34102012_256b");
                assertTrue(clientOutput.contains("INTEROP_OK"),
                        "s_client -cert должен получить INTEROP_OK от "
                                + serverTypeName);
            } finally {
                stop.countDown();
            }
            return null;
        });
    }
}
