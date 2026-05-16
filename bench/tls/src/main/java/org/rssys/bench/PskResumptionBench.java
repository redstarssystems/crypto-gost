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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class PskResumptionBench {

    private TlsCiphersuite cs;
    private BenchHelper.Bundle serverBundle;
    private PskStore clientPskStore;
    private PskStore serverPskStore;
    private ExecutorService exec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverBundle = BenchHelper.createBundle();
        exec = Executors.newVirtualThreadPerTaskExecutor();

        // Один полный handshake для получения PSK-тикета.
        // serverPskStore и clientPskStore живут до конца Trial — их данные
        // (PSK-тикет) используются в @Benchmark для сокращённого handshake.
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        serverPskStore = new InMemoryPskStore(100);
        clientPskStore = new InMemoryPskStore(100);

        TlsServerConfig serverConfig = new TlsServerConfig(
                cs, Collections.singletonList(serverBundle.cert), serverBundle.priv);

        TlsClientConfig clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(serverBundle.caPublicKey);

        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        server.setPskStore(serverPskStore);
        TlsSession client = TlsSession.createClient(clientConfig, pair.getClientTransport());
        client.setPskStore(clientPskStore);
        CompletableFuture<Void> sf = CompletableFuture.runAsync(() -> {
            try { server.handshakeAsServer(); } catch (Exception e) { throw new RuntimeException(e); }
        }, exec);
        client.handshakeAsClient();
        sf.join();

        // Закрываем сервер (ставит close_notify), затем читаем NST + close
        server.close();
        try { client.read(); } catch (java.io.EOFException ignored) {}
        client.close();
        pair.getServerTransport().close();
        pair.getClientTransport().close();

        // Диагностика PSK: оба store должны содержать 1 entry
        assert serverPskStore.size() > 0 : "Server PSK store empty after first handshake";
        assert clientPskStore.size() > 0 : "Client PSK store empty after first handshake";
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        exec.shutdown();
    }

    @Benchmark
    public TlsSession resume() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig = new TlsServerConfig(
                cs, Collections.singletonList(serverBundle.cert), serverBundle.priv);

        TlsClientConfig clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(serverBundle.caPublicKey);

        TlsSession server = TlsSession.createServer(serverConfig, pair.getServerTransport());
        // Используем serverPskStore из @Setup — в нём уже есть PSK-тикет
        // от первого handshake. Без этого сервер не найдёт PSK identity
        // и сделает полный handshake вместо сокращённого.
        server.setPskStore(serverPskStore);
        TlsSession client = TlsSession.createClient(clientConfig, pair.getClientTransport());
        client.setPskStore(clientPskStore);
        CompletableFuture<Void> sf = CompletableFuture.runAsync(() -> {
            try { server.handshakeAsServer(); } catch (Exception e) { throw new RuntimeException(e); }
        }, exec);
        client.handshakeAsClient();
        sf.join();

        if (!client.wasResumed()) {
            throw new AssertionError(
                    "PSK not used: full ECDHE handshake performed. " +
                    "Expected wasResumed()=true");
        }

        // Читаем NST для обновления PSK на следующую итерацию.
        // Сервер отправил NewSessionTicket после handshake (sendNewSessionTicket в runHandshake).
        // Без client.read() клиент не обновит свой PskStore, и на следующей итерации
        // сервер не найдёт старый entry (он удалён в pskStore.remove(pskIdentity) строке 355).
        server.close();
        try { client.read(); } catch (java.io.EOFException ignored) {}
        client.close();
        pair.getClientTransport().close();
        pair.getServerTransport().close();
        return client;
    }
}
