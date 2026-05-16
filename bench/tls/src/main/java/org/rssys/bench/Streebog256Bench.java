package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.util.CryptoRandom;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк Streebog-256 на разных размерах входных данных.
 * <p>
 * Зачем: понять, как Streebog масштабируется с размером.
 * 32B — размер хеша в подписи, 1KB — типичный HTTP chunk,
 * 16KB — полная TLS запись. Выделен в отдельный класс, чтобы
 * {@code @Param} не заставлял остальные бенчмарки
 * {@link HandshakeComponentsBench} прогоняться трижды.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class Streebog256Bench {

    @Param({"32", "1024", "16384"})
    private int dataSize;
    private byte[] data;

    @Setup(Level.Trial)
    public void setup() {
        data = new byte[dataSize];
        CryptoRandom.INSTANCE.nextBytes(data);
    }

    @Benchmark
    public byte[] hash() {
        Digest d = new Streebog256();
        d.update(data, 0, data.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }
}
