package org.rssys.gost.jsse;

import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.cert.Pkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Статический фасад для создания {@link SSLContext} с ГОСТ TLS 1.3.
 * <p>
 * Принцип — один вызов, готовый контекст. Никаких KeyManagerFactory,
 * TrustManagerFactory или JKS.
 * <p>
 * Поддерживаемые форматы входных данных:
 * <ul>
 *   <li>PKCS12 ({@code .p12}) + PEM/DER CA — самый удобный для пользователя
 *   <li>PEM-строки (сертификаты и ключи) — openssl-совместимый
 *   <li>DER-байты (X.509 сертификаты, PKCS#8 PrivateKeyInfo)
 * </ul>
 * <p>
 * Примеры:
 * <pre>{@code
 * // Сервер из PKCS12
 * byte[] p12 = Files.readAllBytes(Paths.get("server.p12"));
 * byte[] ca = Files.readAllBytes(Paths.get("ca.crt"));
 * SSLContext srv = GostSsl.serverContext(p12, "changeit".toCharArray(), ca);
 *
 * // Клиент из PEM
 * String cert = Files.readString(Paths.get("client.pem"));
 * String key  = Files.readString(Paths.get("client-key.pem"));
 * String ca   = Files.readString(Paths.get("ca.pem"));
 * SSLContext cli = GostSsl.clientContext(cert, key, ca);
 *
 * // Клиент без своего сертификата (только проверка сервера)
 * SSLContext cli = GostSsl.clientContext(caDer);
 *
 * // Разработка
 * SSLContext dev = GostSslDev.trustAllClientContextInsecure();
 * }</pre>
 * <p>
 * <b>Ограничения:</b>
 * <ul>
 *   <li>КриптоПро PKCS12 с нестандартным GOST PBE не поддерживается
 *   <li>Только TLS 1.3
 * </ul>
 */
public final class GostSsl {

    private GostSsl() {}

    // ========================================================================
    // SSLContext: PKCS12
    // ========================================================================

    /** Серверный SSLContext из PKCS12 + CA-сертификат (DER). */
    public static SSLContext serverContext(byte[] p12Data, char[] password, byte[] caDer) {
        return buildContext(null, null, p12Data, password,
                new byte[][]{caDer}, false, -1, false, true);
    }

    /** Клиентский SSLContext из PKCS12 + CA-сертификат (DER) — mTLS. */
    public static SSLContext clientContext(byte[] p12Data, char[] password, byte[] caDer) {
        return buildContext(null, null, p12Data, password,
                new byte[][]{caDer}, false, -1, false, false);
    }

    /** Клиентский SSLContext только с CA — без собственного сертификата. */
    public static SSLContext clientContext(byte[] caDer) {
        return buildContext(null, null, null, null,
                new byte[][]{caDer}, false, -1, false, false);
    }

    // ========================================================================
    // SSLContext: PEM
    // ========================================================================

    /** Серверный SSLContext из PEM-строк (cert, private key, CA). */
    public static SSLContext serverContext(String certPem, String keyPem, String caPem) {
        return buildContext(pemToDer(certPem), pemToDer(keyPem), null, null,
                new byte[][]{TlsCertificate.fromPemOrDer(caPem.getBytes(StandardCharsets.US_ASCII)).toDer()}, false, -1, false, true);
    }

    /** Клиентский SSLContext из PEM-строк — mTLS. */
    public static SSLContext clientContext(String certPem, String keyPem, String caPem) {
        return buildContext(pemToDer(certPem), pemToDer(keyPem), null, null,
                new byte[][]{TlsCertificate.fromPemOrDer(caPem.getBytes(StandardCharsets.US_ASCII)).toDer()}, false, -1, false, false);
    }

    /** Клиентский SSLContext из CA-сертификата PEM — без собственного сертификата. */
    public static SSLContext clientContext(String caPem) {
        return buildContext(null, null, null, null,
                new byte[][]{TlsCertificate.fromPemOrDer(caPem.getBytes(StandardCharsets.US_ASCII)).toDer()}, false, -1, false, false);
    }

    // ========================================================================
    // SSLContext: DER-байты
    // ========================================================================

    /**
     * Серверный SSLContext из DER-байтов.
     *
     * @param certDer сертификат X.509 DER
     * @param keyDer  закрытый ключ PKCS#8 PrivateKeyInfo DER
     * @param caDer   CA-сертификат X.509 DER
     */
    public static SSLContext serverContext(byte[] certDer, byte[] keyDer, byte[] caDer) {
        return buildContext(certDer, keyDer, null, null,
                new byte[][]{caDer}, false, -1, false, true);
    }

    /**
     * Клиентский SSLContext из DER-байтов — mTLS.
     *
     * @param certDer сертификат X.509 DER
     * @param keyDer  закрытый ключ PKCS#8 PrivateKeyInfo DER
     * @param caDer   CA-сертификат X.509 DER
     */
    public static SSLContext clientContext(byte[] certDer, byte[] keyDer, byte[] caDer) {
        return buildContext(certDer, keyDer, null, null,
                new byte[][]{caDer}, false, -1, false, false);
    }

    // ========================================================================
    // Socket shortcuts
    // ========================================================================

    /** Создаёт SSLSocket и выполняет handshake. */
    public static SSLSocket socket(String host, int port, SSLContext ctx)
            throws GostSslException {
        try {
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
            s.startHandshake();
            return s;
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLSocket: " + e.getMessage(), e);
        }
    }

    /** Создаёт SSLServerSocket на указанном порту. */
    public static SSLServerSocket serverSocket(int port, SSLContext ctx)
            throws GostSslException {
        try {
            return (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port);
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLServerSocket: " + e.getMessage(), e);
        }
    }

    /** Создаёт SSLServerSocket на указанном порту с backlog. */
    public static SSLServerSocket serverSocket(int port, int backlog, SSLContext ctx)
            throws GostSslException {
        try {
            return (SSLServerSocket) ctx.getServerSocketFactory()
                    .createServerSocket(port, backlog);
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLServerSocket: " + e.getMessage(), e);
        }
    }

    /** Создаёт SSLServerSocket на указанном порту с backlog и адресом. */
    public static SSLServerSocket serverSocket(int port, int backlog,
                                                InetAddress bindAddr, SSLContext ctx)
            throws GostSslException {
        try {
            return (SSLServerSocket) ctx.getServerSocketFactory()
                    .createServerSocket(port, backlog, bindAddr);
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLServerSocket: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // Builder
    // ========================================================================

    /** Возвращает builder для сложных случаев. */
    public static GostSslBuilder builder() {
        return new GostSslBuilder();
    }

    // ========================================================================
    // verify() — loopback-проверка
    // ========================================================================

    /**
     * Loopback-проверка mTLS: обе стороны с сертификатами.
     * Создаёт сервер и клиент на случайном порту, выполняет handshake.
     *
     * @throws GostSslException если handshake не удался
     */
    public static void verify(String serverCertPem, String serverKeyPem,
                               String clientCertPem, String clientKeyPem,
                               String caPem) throws GostSslException {
        verifyImpl(serverContext(serverCertPem, serverKeyPem, caPem),
                clientContext(clientCertPem, clientKeyPem, caPem));
    }

    /**
     * Loopback-проверка одностороннего TLS: сервер с сертификатом,
     * клиент только проверяет сервер по CA.
     *
     * @throws GostSslException если handshake не удался
     */
    public static void verifyServer(String serverCertPem, String serverKeyPem,
                                     String caPem) throws GostSslException {
        verifyImpl(serverContext(serverCertPem, serverKeyPem, caPem),
                clientContext(caPem));
    }

    private static void verifyImpl(SSLContext serverCtx, SSLContext clientCtx)
            throws GostSslException {
        AtomicReference<Exception> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket ss = (SSLServerSocket) serverCtx
                .getServerSocketFactory().createServerSocket(0)) {
            int port = ss.getLocalPort();

            Thread.ofVirtual().start(() -> {
                try (SSLSocket accepted = (SSLSocket) ss.accept()) {
                    accepted.startHandshake();
                } catch (Exception e) {
                    serverError.set(e);
                } finally {
                    serverDone.countDown();
                }
            });

            try (SSLSocket s = (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
                s.startHandshake();
            }

            if (!serverDone.await(10, TimeUnit.SECONDS)) {
                throw new GostSslException("TLS handshake timed out (server did not accept)");
            }
            if (serverError.get() != null) {
                throw new GostSslException("TLS handshake failed (server side)",
                        serverError.get());
            }
        } catch (GostSslException e) {
            throw e;
        } catch (SSLException e) {
            throw new GostSslException("TLS handshake failed (client side)", e);
        } catch (Exception e) {
            throw new GostSslException("TLS verify failed: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // Internal
    // ========================================================================

    static SSLContext buildContext(byte[] certDer, byte[] keyDer,
                                    byte[] p12Data, char[] p12Password,
                                    byte[][] trustedCaDers,
                                    boolean ocspEnabled, int sessionCacheSize,
                                    boolean trustAll, boolean serverMode) {
        try {
            if (Security.getProvider("RssysGostJsse") == null) {
                Security.addProvider(new RssysGostJsseProvider());
            }

            // KeyManager
            GostX509KeyManager km = null;
            if (certDer != null && keyDer != null) {
                km = createKeyManager(certDer, keyDer);
            } else if (p12Data != null) {
                Pkcs12Loader.Result result = Pkcs12Loader.load(p12Data, p12Password);
                km = new GostX509KeyManager();
                X509Certificate[] chain = CertificateBridge.toJca(result.getCertificateChain());
                km.addKeyEntry("default", chain, result.getPrivateKey());
            }

            // TrustManager
            GostX509TrustManager tm;
            if (trustAll) {
                tm = new GostX509TrustManager(null, false);
            } else if (trustedCaDers != null && trustedCaDers.length > 0) {
                // Распаковываем все доверенные CA в список ключей
                List<PublicKeyParameters> caKeys = new ArrayList<>(trustedCaDers.length);
                for (byte[] caDer : trustedCaDers) {
                    caKeys.add(new TlsCertificate(caDer).getPublicKey());
                }
                OcspPolicy policy = ocspEnabled
                        ? OcspPolicy.STAPLING_REQUIRED : OcspPolicy.IF_PRESENT;
                tm = new GostX509TrustManager(caKeys, policy, null);
            } else {
                throw new GostSslException("No CA certificate provided for trust verification");
            }

            // SSLContext
            SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
            ctx.init(km != null ? new javax.net.ssl.KeyManager[]{km} : null,
                    new javax.net.ssl.TrustManager[]{tm}, null);

            // Session cache
            if (sessionCacheSize >= 0) {
                ctx.getClientSessionContext().setSessionCacheSize(sessionCacheSize);
                ctx.getServerSessionContext().setSessionCacheSize(sessionCacheSize);
            }

            return ctx;
        } catch (GostSslException e) {
            throw e;
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLContext: " + e.getMessage(), e);
        }
    }

    private static GostX509KeyManager createKeyManager(byte[] certDer, byte[] keyDer) {
        X509Certificate cert;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
        } catch (Exception e) {
            throw new GostSslException("Failed to parse certificate DER", e);
        }
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", new X509Certificate[]{cert},
                GostDerCodec.decodePrivateKey(keyDer));
        return km;
    }

    private static byte[] pemToDer(String pem) {
        String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }
}
