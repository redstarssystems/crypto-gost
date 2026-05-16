package org.rssys.bench.jsse;

import org.openjdk.jmh.annotations.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class JsseRecordBench {

    private SSLEngine clientEngine;
    private SSLEngine serverEngine;
    @Param({"100", "1024", "16383"})
    private int dataSize;
    private ByteBuffer plaintext;
    private ByteBuffer ciphertext;
    private ByteBuffer unwrapBuffer;
    private ExecutorService exec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        if (Security.getProvider("RssysGostJsse") == null)
            Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());

        JsseBenchHelper.Bundle bundle = JsseBenchHelper.createBundle();
        SSLContext ctx = JsseBenchHelper.createSslContext(bundle);
        exec = Executors.newVirtualThreadPerTaskExecutor();

        clientEngine = ctx.createSSLEngine();
        clientEngine.setUseClientMode(true);
        serverEngine = ctx.createSSLEngine("localhost", 443);
        serverEngine.setUseClientMode(false);

        JsseBenchHelper.doHandshake(clientEngine, serverEngine, exec);

        plaintext = ByteBuffer.allocate(dataSize);
        new java.security.SecureRandom().nextBytes(plaintext.array());

        ciphertext = ByteBuffer.allocate(16640);
        unwrapBuffer = ByteBuffer.allocate(16640);
    }

    @TearDown
    public void tearDown() {
        exec.shutdown();
    }

    @Benchmark
    public ByteBuffer wrap() throws Exception {
        ciphertext.clear();
        plaintext.rewind();
        clientEngine.wrap(plaintext, ciphertext);
        return ciphertext;
    }

    @Benchmark
    public ByteBuffer roundTrip() throws Exception {
        ciphertext.clear();
        plaintext.rewind();
        clientEngine.wrap(plaintext, ciphertext);
        ciphertext.flip();
        unwrapBuffer.clear();
        serverEngine.unwrap(ciphertext, unwrapBuffer);
        return unwrapBuffer;
    }
}
