package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк полного handshake (клиент + сервер в одном JVM).
 * <p>
 * Зачем: измерить throughput полного TLS 1.3 handshake с ГОСТ-криптографией.
 * Это интегрированный тест, покрывающий ECDHE, key schedule, CertificateVerify,
 * Finished, и установку сессии. Каждая итерация = один полный handshake.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class FullHandshakeBench {

    private TlsCiphersuite cs;
    private BenchHelper.Bundle serverBundle;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverBundle = BenchHelper.createBundle();
    }

    @Benchmark
    public TlsSession handshake() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig = new TlsServerConfig(
                pair.getServerTransport(), cs, serverBundle.cert, serverBundle.priv);
        // caPublicKey НЕ ставим на сервер — это включает mTLS (CertificateRequest).
        // Сервер не проверяет свою цепочку на своей стороне.

        TlsClientConfig clientConfig = new TlsClientConfig(pair.getClientTransport(), cs)
                .withCaPublicKey(serverBundle.cert.getPublicKey());
        // caPublicKey сервера = публичный ключ его самоподписанного сертификата.
        // Это корректно: self-signed → свой же ключ как CA.

        TlsSession server = TlsSession.createServer(serverConfig);
        TlsSession client = TlsSession.createClient(clientConfig);

        // Полный handshake (сервер + клиент параллельно, но в одном потоке
        // поочерёдно, как это делает InMemoryTlsTransport).
        Thread serverThread = new Thread(() -> {
            try { server.handshakeAsServer(); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        serverThread.start();
        client.handshakeAsClient();
        serverThread.join();

        // Зачистка — важно для repeatable измерений: закрываем и даём GC.
        client.close();
        server.close();
        return client;
    }
}
