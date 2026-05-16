package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class NoVerifyHandshakeBench {

    private TlsServerConfig serverConfig;
    private TlsClientConfig clientConfig;
    private ExecutorService exec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        org.rssys.gost.signature.ECParameters params = org.rssys.gost.signature.ECParameters.tc26a256();
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(params,
                root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null, false, null);
        serverConfig = new TlsServerConfig(cs, java.util.List.of(leaf.cert), leaf.priv);
        clientConfig = new TlsClientConfig(cs);
        exec = Executors.newVirtualThreadPerTaskExecutor();
    }

    @TearDown(Level.Trial)
    public void tearDown() { exec.shutdown(); }

    @Benchmark
    public TlsSession handshake() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        TlsSession client = TlsSession.createClient(clientConfig, pair.getClientTransport());
        CompletableFuture<Void> sf = CompletableFuture.runAsync(() -> {
            try { server.handshakeAsServer(); } catch (Exception e) { throw new RuntimeException(e); }
        }, exec);
        client.handshakeAsClient();
        sf.join();
        client.close();
        server.close();
        return client;
    }
}
