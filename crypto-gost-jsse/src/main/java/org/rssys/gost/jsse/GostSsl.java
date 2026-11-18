package org.rssys.gost.jsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.*;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.GostPkcs12Parser;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Статический фасад для создания {@link SSLContext} с ГОСТ TLS 1.3.
 * <p>
 * Принцип — один вызов, готовый контекст. Никаких KeyManagerFactory,
 * TrustManagerFactory или JKS.
 * <p>
 * Поддерживаемые форматы входных данных:
 * <ul>
 *   <li>PKCS12 ({@code .p12}) + PEM/DER CA — самый удобный для пользователя
 *   <li>PKCS12 + PKCS12 CA — через {@link #builder()}.{@link GostSslBuilder#trustCaBundle(byte[], char[]) trustCaBundle(pfx, pwd)} или {@link GostSslBuilder#trustCaChain(byte[], char[]) trustCaChain(pfx, pwd)}
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
        return builder().certificate(p12Data, password).trustCa(caDer).buildServerContext();
    }

    /** Клиентский SSLContext из PKCS12 + CA-сертификат (DER) — mTLS. */
    public static SSLContext clientContext(byte[] p12Data, char[] password, byte[] caDer) {
        return builder().certificate(p12Data, password).trustCa(caDer).buildClientContext();
    }

    /** Клиентский SSLContext только с CA — без собственного сертификата. */
    public static SSLContext clientContext(byte[] caDer) {
        return builder().trustCa(caDer).buildClientContext();
    }

    // ========================================================================
    // SSLContext: PEM
    // ========================================================================

    /**
     * Серверный SSLContext из PEM-строк (cert, private key, CA).
     *
     * <p>{@code certPem} и {@code keyPem} - ровно один PEM-блок; {@code caPem} - один сертификат
     * или набор корней (как {@code --cacert} у curl): доверять естественно нескольким УЦ.</p>
     */
    public static SSLContext serverContext(String certPem, String keyPem, String caPem) {
        return pemBuilder(certPem, keyPem, caPem).buildServerContext();
    }

    /** Клиентский SSLContext из PEM-строк — mTLS. */
    public static SSLContext clientContext(String certPem, String keyPem, String caPem) {
        return pemBuilder(certPem, keyPem, caPem).buildClientContext();
    }

    /** Клиентский SSLContext из CA-сертификата PEM — без собственного сертификата. */
    public static SSLContext clientContext(String caPem) {
        return builder().trustCa(pemBytes(caPem)).buildClientContext();
    }

    private static GostSslBuilder pemBuilder(String certPem, String keyPem, String caPem) {
        return builder().certificate(pemBytes(certPem), pemBytes(keyPem)).trustCa(pemBytes(caPem));
    }

    private static byte[] pemBytes(String pem) {
        return pem.getBytes(StandardCharsets.US_ASCII);
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
        return builder().certificate(certDer, keyDer).trustCa(caDer).buildServerContext();
    }

    /**
     * Клиентский SSLContext из DER-байтов — mTLS.
     *
     * @param certDer сертификат X.509 DER
     * @param keyDer  закрытый ключ PKCS#8 PrivateKeyInfo DER
     * @param caDer   CA-сертификат X.509 DER
     */
    public static SSLContext clientContext(byte[] certDer, byte[] keyDer, byte[] caDer) {
        return builder().certificate(certDer, keyDer).trustCa(caDer).buildClientContext();
    }

    // ========================================================================
    // Загрузка закрытого ключа
    // ========================================================================

    /**
     * Загружает закрытый ключ из PEM или DER, авто-определение формата.
     * <p>Для зашифрованных ключей использует {@link #loadPrivateKey(byte[], char[])}.
     *
     * @param keyData PEM- или DER-байты ключа
     * @return закрытый ключ ГОСТ
     */
    public static PrivateKeyParameters loadPrivateKey(byte[] keyData) {
        if (GostCertificate.isPem(keyData)) {
            keyData = GostCertificate.pemToDer(keyData);
        }
        return GostDerCodec.decodePrivateKey(keyData);
    }

    /**
     * Загружает закрытый ключ из PEM или DER с паролем для расшифровки.
     * <p>Если ключ незашифрован — игнорирует пароль.
     * Зашифрованный ключ должен быть в ГОСТ PBES2, иначе {@link IllegalArgumentException}.
     *
     * @param keyData  PEM- или DER-байты ключа (plain или encrypted PKCS#8)
     * @param password пароль для расшифровки
     * @return закрытый ключ ГОСТ
     */
    public static PrivateKeyParameters loadPrivateKey(byte[] keyData, char[] password) {
        if (GostCertificate.isPem(keyData)) {
            keyData = GostCertificate.pemToDer(keyData);
        }
        if (isEncryptedPrivateKey(keyData)) {
            return GostPkcs12Loader.decryptPrivateKey(keyData, password);
        }
        return GostDerCodec.decodePrivateKey(keyData);
    }

    /**
     * Проверяет, является ли DER-данные зашифрованным ключом
     * (EncryptedPrivateKeyInfo, а не plain PrivateKeyInfo).
     * <p>Дискриминатор: {@code AlgorithmIdentifier} содержит PBES2 OID.
     */
    private static boolean isEncryptedPrivateKey(byte[] der) {
        try {
            GostPkcs12Parser.EncryptedPrivateKeyInfo epki =
                    GostPkcs12Parser.parseEncryptedPrivateKeyInfo(der);
            return GostOids.PBES2.equals(epki.getEncryptionAlgorithmOid());
        } catch (IllegalArgumentException e) {
            // Обычный PrivateKeyInfo по структуре не EncryptedPrivateKeyInfo: разбор отказывает.
            // Сообщение о неверном формате ключа даст следующий шаг (decodePrivateKey).
            return false;
        }
    }

    // ========================================================================
    // Методы создания сокетов
    // ========================================================================

    /** Создаёт SSLSocket с проверкой hostname (RFC 6125) и выполняет handshake. */
    public static SSLSocket socket(String host, int port, SSLContext ctx) {
        SSLSocket socket = null;
        try {
            socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
            startHttpsHandshake(socket);
            return socket;
        } catch (Exception e) {
            closeAfterFailure(socket);
            throw new GostSslException("Failed to create SSLSocket: " + e.getMessage(), e);
        }
    }

    /** Создаёт SSLServerSocket на указанном порту. */
    public static SSLServerSocket serverSocket(int port, SSLContext ctx) {
        return openServerSocket(ctx, factory -> factory.createServerSocket(port));
    }

    /** Создаёт SSLServerSocket на указанном порту с backlog. */
    public static SSLServerSocket serverSocket(int port, int backlog, SSLContext ctx) {
        return openServerSocket(ctx, factory -> factory.createServerSocket(port, backlog));
    }

    /** Создаёт SSLServerSocket на указанном порту с backlog и адресом. */
    public static SSLServerSocket serverSocket(
            int port, int backlog, InetAddress bindAddr, SSLContext ctx) {
        return openServerSocket(
                ctx, factory -> factory.createServerSocket(port, backlog, bindAddr));
    }

    @FunctionalInterface
    private interface ServerSocketOpener {
        ServerSocket open(SSLServerSocketFactory factory) throws IOException;
    }

    private static SSLServerSocket openServerSocket(SSLContext ctx, ServerSocketOpener opener) {
        try {
            return (SSLServerSocket) opener.open(ctx.getServerSocketFactory());
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLServerSocket: " + e.getMessage(), e);
        }
    }

    /** Включает проверку hostname (HTTPS) и выполняет handshake. */
    private static void startHttpsHandshake(SSLSocket socket) throws IOException {
        SSLParameters params = socket.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(GostJsseConstants.ENDPOINT_ID_HTTPS);
        socket.setSSLParameters(params);
        socket.startHandshake();
    }

    /** Закрывает сокет после неудачного handshake: вызывающий его не получит и не закроет сам. */
    private static void closeAfterFailure(SSLSocket socket) {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // основная ошибка уже известна и будет передана вызывающему
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
    public static void verify(
            String serverCertPem,
            String serverKeyPem,
            String clientCertPem,
            String clientKeyPem,
            String caPem) {
        // Сервер обязан запросить сертификат клиента: иначе клиентская цепочка не проверялась бы
        // вовсе, и verify() «подтвердил» бы mTLS с любым сертификатом клиента
        verifyImpl(
                serverContext(serverCertPem, serverKeyPem, caPem),
                clientContext(clientCertPem, clientKeyPem, caPem),
                true);
    }

    /**
     * Loopback-проверка одностороннего TLS: сервер с сертификатом,
     * клиент проверяет сервер по CA или по закреплённому leaf-сертификату.
     *
     * @throws GostSslException если handshake не удался
     */
    public static void verifyServer(String serverCertPem, String serverKeyPem, String caPem) {
        verifyImpl(serverContext(serverCertPem, serverKeyPem, caPem), clientContext(caPem), false);
    }

    private static void verifyImpl(
            SSLContext serverCtx, SSLContext clientCtx, boolean needClientAuth) {
        AtomicReference<Exception> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket ss =
                (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
            ss.setNeedClientAuth(needClientAuth);
            int port = ss.getLocalPort();

            new Thread(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) ss.accept()) {
                                    accepted.startHandshake();
                                } catch (Exception e) {
                                    serverError.set(e);
                                } finally {
                                    serverDone.countDown();
                                }
                            })
                    .start();

            try (SSLSocket s =
                    (SSLSocket) clientCtx.getSocketFactory().createSocket("localhost", port)) {
                startHttpsHandshake(s);
            }

            if (!serverDone.await(10, TimeUnit.SECONDS)) {
                throw new GostSslException("TLS handshake timed out (server did not accept)");
            }
            if (serverError.get() != null) {
                throw new GostSslException("TLS handshake failed (server side)", serverError.get());
            }
        } catch (GostSslException e) {
            throw e;
        } catch (SSLException e) {
            throw new GostSslException("TLS handshake failed (client side)", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GostSslException("TLS verify interrupted", e);
        } catch (Exception e) {
            throw new GostSslException("TLS verify failed: " + e.getMessage(), e);
        }
    }
}
