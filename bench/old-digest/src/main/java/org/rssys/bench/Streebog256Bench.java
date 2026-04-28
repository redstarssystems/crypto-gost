package org.rssys.bench;

import org.rssys.gost.digest.Streebog256;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.openjdk.jmh.annotations.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
public class Streebog256Bench {

    @Param({"1k", "10k", "100k", "1m", "10m"})
    public String size;

    private byte[] data;

    @Setup
    public void setup() throws Exception {
        Path path = Paths.get("data", "data-" + size + ".bin");
        data = Files.readAllBytes(path);
    }

    @Benchmark
    public byte[] hashCryptoGost() {
        Streebog256 d = new Streebog256();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] hashBouncyCastle() {
        GOST3411_2012_256Digest d = new GOST3411_2012_256Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }
}
