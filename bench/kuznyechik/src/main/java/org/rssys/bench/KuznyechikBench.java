package org.rssys.bench;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
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
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cfb;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.util.CryptoRandom;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк: пропускная способность шифрования Кузнечик (ГОСТ Р 34.12-2015)
 * в режимах CTR и CFB.
 *
 * <p>Сравнение: crypto-gost (низкоуровневый API) vs BouncyCastle 1.83.
 *
 * <p>Методика:
 * <ul>
 *   <li>Объекты шифра и их инициализация вынесены в {@code @Setup} —
 *       измеряется только обработка данных, без накладных расходов на создание объектов.</li>
 *   <li>IV инкрементируется между вызовами (последний байт) — исключает оптимизацию JIT
 *       за счёт одинаковых входных данных.</li>
 *   <li>5 итераций по 2 с прогрева + 5 итераций по 2 с замера — надёжная статистика.</li>
 *   <li>3 форка JVM — устраняет JIT-зависимости между запусками.</li>
 * </ul>
 *
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(3)
public class KuznyechikBench {

    @Param({"1k", "10k", "100k", "1m"})
    public String size;

    private byte[] data;
    private byte[] out;

    // --- crypto-gost: ключ и IV ---
    private SymmetricKey gostKey;
    private byte[] ivCtr;   // 8 байт (CTR по ГОСТ Р 34.13-2015 §4.4)
    private byte[] ivCfb;   // 16 байт

    // --- crypto-gost: объекты режимов (переиспользуются через reinit) ---
    private Ctr gostCtr;
    private Cfb gostCfb;

    // --- BouncyCastle: ключ и IV ---
    private byte[] bcKey;
    private byte[] bcIvCtr;
    private byte[] bcIvCfb;

    // --- BouncyCastle: объекты режимов ---
    private SICBlockCipher  bcCtrCipher;
    private CFBBlockCipher  bcCfbCipher;

    @Setup
    public void setup() throws Exception {
        // Загружаем тестовые данные из файла (генерируются make data)
        Path path = Paths.get("data", "data-" + size + ".bin");
        data = Files.readAllBytes(path);
        out  = new byte[data.length];

        // --- crypto-gost: генерация ключа ---
        gostKey = KeyGenerator.generateSymmetricKey();

        // IV: CTR — 8 байт (строго по ГОСТ Р 34.13-2015), CFB — 16 байт
        ivCtr = new byte[8];
        ivCfb = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(ivCtr);
        CryptoRandom.INSTANCE.nextBytes(ivCfb);

        // --- crypto-gost: создание и инициализация объектов режимов ---
        gostCtr = new Ctr(new Kuznyechik());
        gostCtr.init(true, new org.rssys.gost.cipher.ParametersWithIV(gostKey, ivCtr));

        gostCfb = new Cfb(new Kuznyechik());
        gostCfb.init(true, new org.rssys.gost.cipher.ParametersWithIV(gostKey, ivCfb));

        // --- BouncyCastle: те же ключ и IV ---
        bcKey    = gostKey.getKey();
        bcIvCtr  = new byte[16];
        System.arraycopy(ivCtr, 0, bcIvCtr, 0, 8); // BC CTR (SIC) требует 16-байтный IV
        bcIvCfb  = ivCfb.clone();

        // --- BouncyCastle: создание и инициализация объектов режимов ---
        bcCtrCipher = new SICBlockCipher(new GOST3412_2015Engine());
        bcCtrCipher.init(true, new ParametersWithIV(new KeyParameter(bcKey), bcIvCtr));

        bcCfbCipher = new CFBBlockCipher(new GOST3412_2015Engine(), 128);
        bcCfbCipher.init(true, new ParametersWithIV(new KeyParameter(bcKey), bcIvCfb));
    }

    // -----------------------------------------------------------------------
    // crypto-gost: CTR
    // Переинициализация (reinit) перед каждым вызовом processBytes.
    // IV инкрементируется на последнем байте — новый IV для каждого замера,
    // исключает оптимизацию JIT на константных входных данных.
    // -----------------------------------------------------------------------
    @Benchmark
    public byte[] ctrGost() {
        ivCtr[7]++;  // инкремент IV — новый nonce на каждый вызов
        gostCtr.init(true, new org.rssys.gost.cipher.ParametersWithIV(gostKey, ivCtr));
        gostCtr.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // crypto-gost: CFB
    // -----------------------------------------------------------------------
    @Benchmark
    public byte[] cfbGost() {
        ivCfb[15]++;
        gostCfb.init(true, new org.rssys.gost.cipher.ParametersWithIV(gostKey, ivCfb));
        gostCfb.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // BouncyCastle: CTR (SICBlockCipher)
    // -----------------------------------------------------------------------
    @Benchmark
    public byte[] ctrBc() {
        bcIvCtr[15]++;
        bcCtrCipher.init(true, new ParametersWithIV(new KeyParameter(bcKey), bcIvCtr));
        bcCtrCipher.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    // -----------------------------------------------------------------------
    // BouncyCastle: CFB (CFBBlockCipher, 128-bit feedback)
    // -----------------------------------------------------------------------
    @Benchmark
    public byte[] cfbBc() {
        bcIvCfb[15]++;
        bcCfbCipher.init(true, new ParametersWithIV(new KeyParameter(bcKey), bcIvCfb));
        bcCfbCipher.processBytes(data, 0, data.length, out, 0);
        return out;
    }
}
