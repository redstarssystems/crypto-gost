package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк PSK resumption (сокращённый handshake).
 * <p>
 * Зачем: PSK resumption — ключевая оптимизация для повторных подключений.
 * Измеряем: полный handshake + NewSessionTicket → сокращённый handshake.
 * Сравнение с FullHandshakeBench показывает выигрыш от PSK.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class PskResumptionBench {

    private TlsCiphersuite cs;
    private BenchHelper.Bundle serverBundle;
    private PskStore clientPskStore;
    private byte[] pskTicket;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverBundle = BenchHelper.createBundle();

        // setup(): один полный handshake для получения PSK-тикета
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        PskStore serverPskStore = new InMemoryPskStore(100);
        clientPskStore = new InMemoryPskStore(100);

        TlsServerConfig serverConfig = new TlsServerConfig(
                cs, Collections.singletonList(serverBundle.cert), serverBundle.priv);
        // caPublicKey не ставим — иначе сервер запросит mTLS (CertificateRequest).

        TlsClientConfig clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(serverBundle.cert.getPublicKey());

        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        server.setPskStore(serverPskStore);
        TlsSession client = TlsSession.createClient(clientConfig, pair.getClientTransport());
        client.setPskStore(clientPskStore);
        CompletableFuture<Void> sf = CompletableFuture.runAsync(() -> {
            try { server.handshakeAsServer(); } catch (Exception e) { throw new RuntimeException(e); }
        });
        client.handshakeAsClient();
        sf.join();

        // Закрываем сервер (ставит close_notify в очередь), затем читаем NST + close
        server.close();
        try { client.read(); } catch (java.io.EOFException ignored) {}
        client.close();
        pair.getServerTransport().close();
        pair.getClientTransport().close();
    }

    @Benchmark
    public TlsSession resume() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        PskStore serverPskStore = new InMemoryPskStore(100);

        TlsServerConfig serverConfig = new TlsServerConfig(
                cs, Collections.singletonList(serverBundle.cert), serverBundle.priv);
        // caPublicKey не ставим — иначе сервер запросит mTLS.

        TlsClientConfig clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(serverBundle.cert.getPublicKey());

        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        server.setPskStore(serverPskStore);
        TlsSession client = TlsSession.createClient(clientConfig, pair.getClientTransport());
        client.setPskStore(clientPskStore);
        CompletableFuture<Void> sf = CompletableFuture.runAsync(() -> {
            try { server.handshakeAsServer(); } catch (Exception e) { throw new RuntimeException(e); }
        });
        client.handshakeAsClient();
        sf.join();
        client.close();
        server.close();
        pair.getClientTransport().close();
        pair.getServerTransport().close();
        return client;
    }
}
