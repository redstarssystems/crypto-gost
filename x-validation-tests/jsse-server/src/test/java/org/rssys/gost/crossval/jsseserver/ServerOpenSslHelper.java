package org.rssys.gost.crossval.jsseserver;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;

import org.rssys.gost.util.CryptoRandom;

import javax.net.ssl.SSLContext;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class ServerOpenSslHelper {

    private ServerOpenSslHelper() {}

    enum ServerType { TOMCAT, JETTY, UNDERTOW }

    static String[] resolveTls13Flags() {
        return OpenSslChecker.resolveTls13Flags();
    }

    // ========================================================================
    // PKI
    // ========================================================================

    record ServerPkiBundle(TlsCertificate cert, PrivateKeyParameters priv,
                            TlsCertificate caCert, PublicKeyParameters caPub) {}

    static ServerPkiBundle createServerPki(ECParameters params) throws Exception {
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        PublicKeyParameters caPub = rootCa.cert.getPublicKey();
        TlsTestHelper.CertBundle serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        return new ServerPkiBundle(
                serverCert.cert, serverCert.priv,
                rootCa.cert, caPub);
    }

    static GostX509KeyManager createKeyManager(TlsCertificate serverCert,
                                                TlsCertificate caCert,
                                                PrivateKeyParameters priv) throws Exception {
        X509Certificate[] jcaChain = CertificateBridge.toJcaChain(serverCert, caCert);
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", jcaChain, priv);
        return km;
    }

    static SSLContext createSslContext(GostX509KeyManager km,
                                        GostX509TrustManager tm) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(new javax.net.ssl.KeyManager[]{km},
                new javax.net.ssl.TrustManager[]{tm}, CryptoRandom.INSTANCE);
        return ctx;
    }

    static SSLContext createMtlsSslContext(GostX509KeyManager km,
                                             PublicKeyParameters clientPub) throws Exception {
        GostX509TrustManager tm = new GostX509TrustManager(clientPub, false);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(new javax.net.ssl.KeyManager[]{km},
                new javax.net.ssl.TrustManager[]{tm}, CryptoRandom.INSTANCE);
        return ctx;
    }

    static String privateKeyToPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    static TlsTestHelper.CertBundle createClientCert(ECParameters params,
                                                      PrivateKeyParameters caPriv,
                                                      PublicKeyParameters caPub,
                                                      byte[] caSubjectDn,
                                                      Path outCertPem,
                                                      Path outKeyPem) throws Exception {
        byte[] cliKu = new byte[]{(byte) 0x80};
        TlsTestHelper.CertBundle clientCert = TlsTestHelper.createCertSignedBy(
                params, caPriv, caPub, caSubjectDn,
                "20240101120000Z", "21060101120000Z",
                null, cliKu, new String[]{"1.3.6.1.5.5.7.3.2"},
                false, null);
        Files.writeString(outCertPem, clientCert.cert.toPem());
        Files.writeString(outKeyPem,
                privateKeyToPem(
                        org.rssys.gost.jca.spec.GostDerCodec.encodePrivateKey(clientCert.priv)));
        return clientCert;
    }

    // ========================================================================
    // Запуск серверов
    // ========================================================================

    static int findFreePort() throws Exception {
        try (java.net.ServerSocket ss = new java.net.ServerSocket(0)) {
            return ss.getLocalPort();
        }
    }

    static void waitForPort(int port, int timeoutSec) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        while (System.currentTimeMillis() < deadline) {
            try (java.net.Socket s = new java.net.Socket()) {
                s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 500);
                return;
            } catch (java.io.IOException ignored) {
                Thread.sleep(100);
            }
        }
        throw new RuntimeException("Port " + port + " не начал слушать за " + timeoutSec + "с");
    }

    /**
     * Запускает сервер в фоновом daemon-потоке.
     * Останавливается при stop.countDown().
     * При ошибке старта заполняет errorRef.
     */
    /**
     * Запускает сервер в фоновом daemon-потоке.
     * ready.countDown() после того, как порт начал слушать.
     * stop.countDown() — сигнал остановить сервер.
     */
    static void startTomcat(int port, SSLContext sslContext,
                             boolean needClientAuth,
                             GostX509KeyManager km,
                             GostX509TrustManager tm,
                             CountDownLatch ready,
                             CountDownLatch stop,
                             AtomicReference<Throwable> error) {
        startServerThread(() -> {
            try { runTomcat(port, sslContext, needClientAuth, km, tm, ready, stop); }
            catch (Exception e) { error.set(e); }
        }, error);
    }

    static void startJetty(int port, SSLContext sslContext,
                            boolean needClientAuth,
                            CountDownLatch ready,
                            CountDownLatch stop,
                            AtomicReference<Throwable> error) {
        startServerThread(() -> {
            try { runJetty(port, sslContext, needClientAuth, ready, stop); }
            catch (Exception e) { error.set(e); }
        }, error);
    }

    static void startUndertow(int port, SSLContext sslContext,
                               CountDownLatch ready,
                               CountDownLatch stop,
                               AtomicReference<Throwable> error) {
        startServerThread(() -> {
            try { runUndertow(port, sslContext, ready, stop); }
            catch (Exception e) { error.set(e); }
        }, error);
    }

    private static void startServerThread(Runnable task,
                                           AtomicReference<Throwable> error) {
        Thread t = new Thread(() -> {
            try {
                task.run();
            } catch (Throwable e) {
                error.set(e);
            }
        });
        t.setDaemon(true);
        t.start();
    }

    @SuppressWarnings("IllegalCatch")
    private static void runTomcat(int port, SSLContext sslContext,
                                   boolean needClientAuth,
                                   GostX509KeyManager km,
                                   GostX509TrustManager tm,
                                   CountDownLatch ready,
                                   CountDownLatch stop) throws Exception {
        java.util.logging.Logger.getLogger("org.apache.catalina")
                .setLevel(java.util.logging.Level.SEVERE);
        java.util.logging.Logger.getLogger("org.apache.coyote")
                .setLevel(java.util.logging.Level.SEVERE);

        TomcatTestSSLImpl.setSslContext(sslContext, km, tm);
        org.apache.catalina.startup.Tomcat tomcat = new org.apache.catalina.startup.Tomcat();
        tomcat.setPort(0);

        org.apache.catalina.connector.Connector connector =
                new org.apache.catalina.connector.Connector("HTTP/1.1");
        connector.setPort(port);
        connector.setSecure(true);
        connector.setScheme("https");
        connector.setProperty("SSLEnabled", "true");
        connector.setProperty("sslImplementationName",
                TomcatTestSSLImpl.class.getName());

        org.apache.tomcat.util.net.SSLHostConfig sslHostConfig =
                new org.apache.tomcat.util.net.SSLHostConfig();
        sslHostConfig.setHostName("_default_");
        sslHostConfig.setSslProtocol("TLSv1.3");
        if (needClientAuth) {
            sslHostConfig.setCertificateVerification("required");
        }
        org.apache.tomcat.util.net.SSLHostConfigCertificate cert =
                new org.apache.tomcat.util.net.SSLHostConfigCertificate(
                        sslHostConfig,
                        org.apache.tomcat.util.net.SSLHostConfigCertificate.Type.UNDEFINED);
        sslHostConfig.addCertificate(cert);
        connector.addSslHostConfig(sslHostConfig);
        tomcat.getService().addConnector(connector);

        org.apache.catalina.Context appCtx = tomcat.addContext("",
                System.getProperty("java.io.tmpdir"));
        org.apache.catalina.startup.Tomcat.addServlet(appCtx, "echo",
                new jakarta.servlet.http.HttpServlet() {
                    @Override
                    protected void doGet(
                            jakarta.servlet.http.HttpServletRequest req,
                            jakarta.servlet.http.HttpServletResponse resp)
                            throws java.io.IOException {
                        resp.setStatus(200);
                        resp.setContentType("text/plain");
                        resp.setContentLength(10);
                        resp.getWriter().print("INTEROP_OK");
                    }
                });
        appCtx.addServletMappingDecoded("/*", "echo");

        tomcat.start();
        waitForPort(port, 15);
        ready.countDown();
        stop.await();
        tomcat.stop();
    }

    @SuppressWarnings("unused")
    public static final class TomcatTestSSLImpl
            extends org.apache.tomcat.util.net.SSLImplementation {
        private static volatile javax.net.ssl.SSLContext sharedCtx;
        private static volatile javax.net.ssl.X509KeyManager sharedKm;
        private static volatile javax.net.ssl.X509TrustManager sharedTm;

        public static void setSslContext(javax.net.ssl.SSLContext ctx,
                                          javax.net.ssl.X509KeyManager km,
                                          javax.net.ssl.X509TrustManager tm) {
            sharedCtx = ctx;
            sharedKm = km;
            sharedTm = tm;
        }

        @Override
        public org.apache.tomcat.util.net.SSLSupport getSSLSupport(
                javax.net.ssl.SSLSession session,
                java.util.Map<String, java.util.List<String>> additional) {
            return null;
        }

        @Override
        public org.apache.tomcat.util.net.SSLUtil getSSLUtil(
                org.apache.tomcat.util.net.SSLHostConfigCertificate certificate) {
            javax.net.ssl.SSLContext ctx = sharedCtx;
            javax.net.ssl.X509KeyManager km = sharedKm;
            javax.net.ssl.X509TrustManager tm = sharedTm;
            return new org.apache.tomcat.util.net.SSLUtil() {
                @Override
                public org.apache.tomcat.util.net.SSLContext createSSLContext(
                        java.util.List<String> negotiableProtocols) throws Exception {
                    return org.apache.tomcat.util.net.SSLUtil.createSSLContext(
                            ctx, km, tm);
                }

                @Override
                public javax.net.ssl.KeyManager[] getKeyManagers() {
                    return km != null
                            ? new javax.net.ssl.KeyManager[]{km}
                            : new javax.net.ssl.KeyManager[0];
                }

                @Override
                public javax.net.ssl.TrustManager[] getTrustManagers() {
                    return tm != null
                            ? new javax.net.ssl.TrustManager[]{tm}
                            : new javax.net.ssl.TrustManager[0];
                }

                @Override
                public void configureSessionContext(
                        javax.net.ssl.SSLSessionContext sslSessionContext) {}

                @Override
                public String[] getEnabledProtocols() {
                    return new String[]{"TLSv1.3"};
                }

                @Override
                public String[] getEnabledCiphers() {
                    return new String[0];
                }
            };
        }
    }

    private static void runJetty(int port, SSLContext sslContext,
                                  boolean needClientAuth,
                                  CountDownLatch ready,
                                  CountDownLatch stop) throws Exception {
        org.eclipse.jetty.util.ssl.SslContextFactory.Server scf =
                new org.eclipse.jetty.util.ssl.SslContextFactory.Server();
        scf.setSslContext(sslContext);
        scf.setIncludeProtocols("TLSv1.3");
        scf.setNeedClientAuth(needClientAuth);

        org.eclipse.jetty.server.Server server = new org.eclipse.jetty.server.Server();
        org.eclipse.jetty.server.ServerConnector connector =
                new org.eclipse.jetty.server.ServerConnector(server,
                        new org.eclipse.jetty.server.SslConnectionFactory(scf, "http/1.1"),
                        new org.eclipse.jetty.server.HttpConnectionFactory(
                                new org.eclipse.jetty.server.HttpConfiguration()));
        connector.setPort(port);
        server.addConnector(connector);

        server.setHandler(new org.eclipse.jetty.server.Handler.Abstract() {
            @Override
            public boolean handle(org.eclipse.jetty.server.Request request,
                                   org.eclipse.jetty.server.Response response,
                                   org.eclipse.jetty.util.Callback callback) {
                try {
                    response.setStatus(200);
                    response.getHeaders().put(
                            org.eclipse.jetty.http.HttpHeader.CONTENT_TYPE, "text/plain");
                    org.eclipse.jetty.io.Content.Sink.write(response, true,
                            "INTEROP_OK\n", callback);
                } catch (Exception e) {
                    callback.failed(e);
                }
                return true;
            }
        });

        server.start();
        waitForPort(port, 15);
        ready.countDown();
        stop.await();
        server.stop();
    }

    private static void runUndertow(int port, SSLContext sslContext,
                                     CountDownLatch ready,
                                     CountDownLatch stop) throws Exception {
        io.undertow.Undertow server = io.undertow.Undertow.builder()
                .addHttpsListener(port, "0.0.0.0", sslContext)
                .setHandler(exchange -> {
                    exchange.setStatusCode(200);
                    exchange.getResponseHeaders().put(
                            io.undertow.util.Headers.CONTENT_TYPE, "text/plain");
                    exchange.getResponseSender().send(
                            java.nio.ByteBuffer.wrap(
                                    "INTEROP_OK\n".getBytes(StandardCharsets.UTF_8)));
                })
                .build();
        server.start();
        waitForPort(port, 15);
        ready.countDown();
        try {
            stop.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            server.stop();
        }
    }

    // ========================================================================
    // openssl s_client
    // ========================================================================

    private static String runSClient(int port, String suiteName,
                                      String curveName,
                                      String... extraArgs) throws Exception {
        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String[] flags = resolveTls13Flags();

        String[] cmd = CrossValUtils.concat(
                new String[]{openssl, "s_client", "-connect", "127.0.0.1:" + port,
                        "-tls1_3", "-ciphersuites", suiteName,
                        "-curves", curveName,
                        "-servername", "localhost", "-ign_eof"},
                flags,
                extraArgs
        );

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.environment().putAll(OpenSslChecker.getOpenSslEnv());

        Process p = pb.start();
        try {
            OutputStream stdin = p.getOutputStream();
            stdin.write(("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            stdin.close();

            try (var exec = Executors.newVirtualThreadPerTaskExecutor()) {
                Future<String> output = exec.submit(() ->
                        new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8));

                if (!p.waitFor(30, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    throw new RuntimeException("s_client timed out (port=" + port + ")");
                }
                return output.get(5, TimeUnit.SECONDS);
            }
        } finally {
            if (p.isAlive()) {
                p.destroyForcibly();
            }
        }
    }

    static String runHttpGet(int port, String suiteName,
                              String curveName) throws Exception {
        return runSClient(port, suiteName, curveName);
    }

    static String runMtlsHttpGet(int port, String suiteName,
                                  String curveName,
                                  String clientCertPem,
                                  String clientKeyPem,
                                  String sigalgs) throws Exception {
        return runSClient(port, suiteName, curveName,
                "-cert", clientCertPem, "-key", clientKeyPem,
                "-sigalgs", sigalgs);
    }
}
