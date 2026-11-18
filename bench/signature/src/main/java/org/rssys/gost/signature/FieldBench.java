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
import org.openjdk.jmh.infra.Blackhole;
import org.rssys.bench.LadderBench;

/**
 * JMH-микробенчмарк операций над элементом поля: {@code shiftLeft(1/2/3)}, {@code add(x, x)} и
 * {@code square()}.
 *
 * <p>{@code FieldElement} виден только внутри пакета {@code org.rssys.gost.signature}, поэтому
 * класс лежит в нём же. Результаты уходят в {@link Blackhole}, а не возвращаются: сгенерированный
 * JMH код живёт в подпакете {@code jmh_generated}, где закрытый тип недоступен, и не должен его
 * упоминать.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(2)
public class FieldBench {

    /** Кривая: от неё зависит модуль поля и число лимбов (4 или 8). */
    @Param({"cryptoProA", "tc26a256", "tc26a512", "tc26c512"})
    public String curve;

    private FieldElement fe;

    @Setup
    public void setup() {
        ECParameters params = LadderBench.resolve(curve);
        fe = FieldElement.of(LadderBench.randomScalar(params.p), params.montParams);
    }

    @Benchmark
    public void shiftLeft1(Blackhole bh) {
        bh.consume(fe.shiftLeft(1));
    }

    @Benchmark
    public void shiftLeft2(Blackhole bh) {
        bh.consume(fe.shiftLeft(2));
    }

    @Benchmark
    public void shiftLeft3(Blackhole bh) {
        bh.consume(fe.shiftLeft(3));
    }

    @Benchmark
    public void addSelf(Blackhole bh) {
        bh.consume(fe.add(fe));
    }

    @Benchmark
    public void square(Blackhole bh) {
        bh.consume(fe.square());
    }
}
