package org.rssys.bench;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class NoVerifyHandshakeBench {

    private TlsServerConfig serverConfig;
    private TlsCiphersuite cs;
    private ExecutorService exec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        org.rssys.gost.signature.ECParameters params = org.rssys.gost.signature.ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf = PkixCertTestHelper.createCertSignedBy(params,
                root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null, false, null);
        serverConfig = new TlsServerConfig(cs, java.util.List.of(leaf.cert), leaf.priv);
        exec = Executors.newVirtualThreadPerTaskExecutor();
    }

    @TearDown(Level.Trial)
    public void tearDown() { exec.shutdown(); }

    @Benchmark
    public TlsSession handshake() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        TlsSession client = TlsSession.createClientWithoutServerAuth(
                pair.getClientTransport(), cs, null, null);
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
