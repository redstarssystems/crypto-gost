package org.rssys.gost.signature;

import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.rssys.bench.LadderBench;

/**
 * Стоимость построения wNAF-таблицы {@code (2i+1)·P} при проверке подписи: показывает, какую
 * долю одной проверки занимает построение таблицы для базовой точки G (теперь она кэшируется в
 * {@code ECParameters}) и для открытого ключа Q (строится на каждой проверке).
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(2)
public class TableBench {

    @Param({"cryptoProA", "tc26a512"})
    public String curve;

    private ECParameters params;
    private ECPoint g;
    private int window;

    @Setup
    public void setup() {
        params = LadderBench.resolve(curve);
        g = ECPoint.affine(params.gx, params.gy, params);
        // То же окно, что у ECDSASigner: 4 для 256 бит, 5 для 512 бит
        window = params.n.bitLength() > 256 ? 5 : 4;
    }

    /** Построение таблицы заново (так было для G на каждой проверке; так остаётся для Q). */
    @Benchmark
    public ECPoint[] buildTable() {
        return g.buildWNafTable(window);
    }

    /** Таблица G из кэша {@code ECParameters}. */
    @Benchmark
    public ECPoint[] cachedGTable() {
        return params.gWnafTable(window);
    }
}
