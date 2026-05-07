package org.rssys.gost.tls13;

import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.transport.SocketTlsTransport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Self-interop tests: наша библиотека выступает и клиентом, и сервером
 * через реальный TCP (SocketTlsTransport). Покрывает матрицу:
 *   L/S × non-mTLS/mTLS
 *
 * Основная ценность — сквозная интеграционная проверка полного стека:
 * транспорт → handshake engine → key schedule → record protection → data.
 * InMemoryTlsTransport тестирует engine изоляционно, а здесь проверяется,
 * что бинарный протокол по сети проходит без рассинхронизации.
 */
class TlsSelfInteropTest {

    private static final String HELLO = "Hello, TLS 1.3 GOST!";
    private static final String RESPONSE = "World";

    private static final class PlainCerts {
        final TlsCertificate cert;
        final PrivateKeyParameters priv;
        PlainCerts(TlsCertificate cert, PrivateKeyParameters priv) {
            this.cert = cert;
            this.priv = priv;
        }
    }

    private static final class MtlsCerts {
        final TlsCertificate cert;
        final PrivateKeyParameters priv;
        final PublicKeyParameters caPub;
        MtlsCerts(TlsCertificate cert, PrivateKeyParameters priv, PublicKeyParameters caPub) {
            this.cert = cert;
            this.priv = priv;
            this.caPub = caPub;
        }
    }

    // Самоподписанный сертификат для non-mTLS:
    // каждая сторона доверяет сертификату пира без external CA
    private static PlainCerts createPlainCerts() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle b = TlsTestHelper.createCertWithKey(params);
        return new PlainCerts(b.cert, b.priv);
    }

    // Для mTLS нужен единый CA: сертификаты сервера и клиента подписываются
    // одним корнем, обе стороны валидируют цепочку через caPublicKey.
    // createMtlsCertsFor возвращает entity cert + priv + общий caPub.
    // createMtlsCertsPair однократно создаёт общий CA и возвращает оба entity certа.
    private static final class MtlsCertPair {
        final MtlsCerts server;
        final MtlsCerts client;
        MtlsCertPair(MtlsCerts server, MtlsCerts client) {
            this.server = server; this.client = client;
        }
    }

    private static MtlsCerts createMtlsCertsFor(ECParameters params,
            PrivateKeyParameters caPriv, PublicKeyParameters caPub,
            byte[] caDn) throws Exception {
        TlsTestHelper.CertBundle entity = TlsTestHelper.createCertSignedBy(
                params, caPriv, caPub, caDn,
                "240501120000Z", "290501120000Z", null, null,
                null, false, null);
        return new MtlsCerts(entity.cert, entity.priv, caPub);
    }

    private static MtlsCertPair createMtlsCertsPair() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);
        PublicKeyParameters caPub = ca.cert.getPublicKey();
        byte[] caDn = ca.subjectDn;
        MtlsCerts server = createMtlsCertsFor(params, ca.priv, caPub, caDn);
        MtlsCerts client = createMtlsCertsFor(params, ca.priv, caPub, caDn);
        return new MtlsCertPair(server, client);
    }

    private void runSelfInterop(TlsCiphersuite cs, boolean mTls) throws Exception {
        PlainCerts plain = createPlainCerts();
        MtlsCertPair mtls = mTls ? createMtlsCertsPair() : null;
        MtlsCerts sCerts = mTls ? mtls.server : null;
        MtlsCerts cCerts = mTls ? mtls.client : null;

        CountDownLatch clientDone = new CountDownLatch(1);
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        AtomicReference<Throwable> clientError = new AtomicReference<>();

        // ServerSocket(0) — автоматический выбор свободного порта,
        // чтобы тесты не конфликтовали при параллельном запуске
        try (ServerSocket ss = new ServerSocket(0)) {
            int port = ss.getLocalPort();

            Thread serverThread = new Thread(() -> {
                try (Socket s = ss.accept()) {
                    SocketTlsTransport st = new SocketTlsTransport(s);
                    TlsServerConfig sc;
                    if (mTls) {
                        // withCaPublicKey включает CertificateRequest →
                        // сервер ждёт клиентский сертификат
                        sc = new TlsServerConfig(st, cs, sCerts.cert, sCerts.priv)
                                .withCaPublicKey(sCerts.caPub);
                    } else {
                        sc = new TlsServerConfig(st, cs, plain.cert, plain.priv);
                    }
                    TlsSession server = TlsSession.createServer(sc);

                    server.handshakeAsServer();
                    // 3 ключевых ассерта: handshake статус, cipher suite, данные
                    assertTrue(server.isHandshakeDone());
                    assertEquals(cs.getId(), server.getCipherSuite().getId());

                    // Сервер читает первым — deadlock prevention:
                    // на TCP уровне оба не могут одновременно ждать read()
                    byte[] req = server.read();
                    assertEquals(HELLO, new String(req, "UTF-8"));

                    server.write(RESPONSE.getBytes("UTF-8"));
                    server.close();
                } catch (Throwable e) {
                    serverError.set(e);
                }
            });

            Thread clientThread = new Thread(() -> {
                try {
                    // Прямое подключение: new Socket() завершает TCP handshake →
                    // ss.accept() на сервере разблокируется, сервер создаёт конфиг
                    try (Socket s = new Socket("127.0.0.1", port)) {
                        SocketTlsTransport ct = new SocketTlsTransport(s);
                        TlsClientConfig cc = new TlsClientConfig(ct, cs);
                        if (mTls) {
                            cc = cc.withClientCertificate(cCerts.cert)
                                   .withClientPrivateKey(cCerts.priv)
                                   .withCaPublicKey(cCerts.caPub);
                        }
                        TlsSession client = TlsSession.createClient(cc);

                        client.handshakeAsClient();
                        assertTrue(client.isHandshakeDone());
                        assertEquals(cs.getId(), client.getCipherSuite().getId());

                        // Клиент инициирует запись после того, как сервер уже в read()
                        client.write(HELLO.getBytes("UTF-8"));
                        byte[] resp = client.read();
                        assertEquals(RESPONSE, new String(resp, "UTF-8"));

                        client.close();
                    }
                } catch (Throwable e) {
                    clientError.set(e);
                } finally {
                    clientDone.countDown();
                }
            });

            serverThread.start();
            clientThread.start();

            assertTrue(clientDone.await(30, TimeUnit.SECONDS));

            if (serverError.get() != null) throw new RuntimeException(serverError.get());
            if (clientError.get() != null) throw new RuntimeException(clientError.get());

            serverThread.join(500);
            clientThread.join(500);
        }
    }

    @Test
    @DisplayName("L + non-mTLS: самоподписанный сертификат, полный handshake + E2E write/read")
    void testL_NonMtls() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.byId(0xC103);
        assert cs != null : "L ciphersuite not found";
        runSelfInterop(cs, false);
    }

    @Test
    @DisplayName("L + mTLS: CA-подписанные сертификаты, двухсторонняя аутентификация")
    void testL_Mtls() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.byId(0xC103);
        assert cs != null : "L ciphersuite not found";
        runSelfInterop(cs, true);
    }

    // S-вариант использует seal re-keying (TLSTREE-S) с лимитом 2^42-1 записей.
    // От L отличается C1/C2/C3 масками и SNMAX. Тестирование обоих вариантов
    // гарантирует, что record protection работает независимо от маски.
    @Test
    @DisplayName("S + non-mTLS: самоподписанный сертификат, полный handshake + E2E write/read")
    void testS_NonMtls() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.byId(0xC105);
        assert cs != null : "S ciphersuite not found";
        runSelfInterop(cs, false);
    }

    @Test
    @DisplayName("S + mTLS: CA-подписанные сертификаты, двухсторонняя аутентификация")
    void testS_Mtls() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.byId(0xC105);
        assert cs != null : "S ciphersuite not found";
        runSelfInterop(cs, true);
    }
}
