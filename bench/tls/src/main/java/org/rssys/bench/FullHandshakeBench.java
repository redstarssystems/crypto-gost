package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class FullHandshakeBench {

    private TlsCiphersuite cs;
    private BenchHelper.Bundle serverBundle;
    private ExecutorService exec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverBundle = BenchHelper.createBundle();
        exec = Executors.newVirtualThreadPerTaskExecutor();
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        exec.shutdown();
    }

    @Benchmark
    public TlsSession handshake() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig = new TlsServerConfig(
                cs, Collections.singletonList(serverBundle.cert), serverBundle.priv);

        TlsClientConfig clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(serverBundle.caPublicKey);

        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        TlsSession client = TlsSession.createClient(clientConfig, pair.getClientTransport());

        CompletableFuture<Void> serverFuture = CompletableFuture.runAsync(() -> {
            try { server.handshakeAsServer(); }
            catch (Exception e) { throw new RuntimeException(e); }
        }, exec);
        client.handshakeAsClient();
        serverFuture.join();

        client.close();
        server.close();
        pair.getClientTransport().close();
        pair.getServerTransport().close();
        return client;
    }
}
