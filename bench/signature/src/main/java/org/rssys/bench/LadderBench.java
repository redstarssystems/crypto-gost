package org.rssys.bench;

import java.math.BigInteger;
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
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;

/**
 * JMH-микробенчмарк лестницы скалярного умножения и её составных частей на уровне точки:
 * {@code twice()}, {@code add()} и {@code multiply(k)} целиком. Операции поля меряет
 * {@code org.rssys.gost.signature.FieldBench}. Запуск с {@code -prof gc} показывает давление на
 * сборщик мусора.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(2)
public class LadderBench {

    /**
     * Кривая. CryptoPro-A и TC26-A-512 имеют a = -3 (ветка addComplete), TC26-A-256 и TC26-C-512
     * - произвольное a и кофактор 4 (ветка addCompleteGeneral), поэтому нужны все четыре.
     */
    @Param({"cryptoProA", "tc26a256", "tc26a512", "tc26c512"})
    public String curve;

    private ECPoint point;
    private ECPoint other;
    private BigInteger scalar;
    private ECDSASigner signer;
    private PrivateKeyParameters privateKey;

    @Setup
    public void setup() {
        ECParameters params = resolve(curve);
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        BigInteger k1 = randomScalar(params.n);
        BigInteger k2 = randomScalar(params.n);
        point = g.multiply(k1).normalize();
        other = g.multiply(k2).normalize();
        scalar = randomScalar(params.n);
        privateKey = KeyGenerator.generateKeyPair(params).getPrivate();
        signer = new ECDSASigner(params.n.bitLength() > 256 ? Streebog512::new : Streebog256::new);
    }

    /** Общий для замеров точки и поля выбор кривой по имени параметра {@code curve}. */
    public static ECParameters resolve(String name) {
        switch (name) {
            case "cryptoProA":
                return ECParameters.cryptoProA();
            case "tc26a256":
                return ECParameters.tc26a256();
            case "tc26a512":
                return ECParameters.tc26a512();
            case "tc26c512":
                return ECParameters.tc26c512();
            default:
                throw new IllegalArgumentException("Unknown curve: " + name);
        }
    }

    public static BigInteger randomScalar(BigInteger bound) {
        BigInteger k;
        do {
            k = new BigInteger(bound.bitLength(), CryptoRandom.INSTANCE);
        } while (k.signum() == 0 || k.compareTo(bound) >= 0);
        return k;
    }

    @Benchmark
    public ECPoint twice() {
        return point.twice();
    }

    @Benchmark
    public ECPoint add() {
        return point.add(other);
    }

    @Benchmark
    public ECPoint multiply() {
        return point.multiply(scalar);
    }

    /** Инициализация подписанта для подписи: у `Signature.sign` она выполняется на каждый вызов. */
    @Benchmark
    public ECDSASigner initForSigning() {
        signer.init(true, privateKey);
        return signer;
    }
}
