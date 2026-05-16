package org.rssys.bench.jsse;

import org.openjdk.jmh.annotations.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class JsseHandshakeBench {

    private SSLContext sslContext;
    private JsseBenchHelper.Bundle serverBundle;
    private ExecutorService exec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        if (Security.getProvider("RssysGostJsse") == null)
            Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        serverBundle = JsseBenchHelper.createBundle();
        sslContext = JsseBenchHelper.createSslContext(serverBundle);
        exec = Executors.newVirtualThreadPerTaskExecutor();
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        exec.shutdown();
    }

    private byte[] doOneHandshake(boolean needClientAuth) throws Exception {
        SSLEngine client = sslContext.createSSLEngine();
        client.setUseClientMode(true);
        SSLEngine server = sslContext.createSSLEngine("localhost", 443);
        server.setUseClientMode(false);
        if (needClientAuth) server.setNeedClientAuth(true);

        JsseBenchHelper.doHandshake(client, server, exec);
        byte[] sid = client.getSession().getId();
        client.closeOutbound();
        server.closeOutbound();
        return sid;
    }

    @Benchmark
    public byte[] fullHandshake() throws Exception {
        return doOneHandshake(false);
    }

    @Benchmark
    public byte[] mutualAuth() throws Exception {
        return doOneHandshake(true);
    }

    // PSK resumption JSSE-бенч требует настройки peerHost/peerPort
    // Требует настройки GostSSLSessionContext и peerHost для session lookup.
}
