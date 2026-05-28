package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк стоимости аллокаций Hmac+Streebog в HkdfStreebog.
 * <p>
 * Измеряет разницу между текущим кодом (newHmac на каждый вызов) и
 * гипотетической оптимизацией (переиспользование Hmac с clear()+init()).
 * Запускать с {@code -prof gc} для получения allocation rate.
 * <p>
 * Пары {@code *_new} / {@code *_reuse}: в {@code *_reuse} Hmac создаётся
 * один раз в {@code @Setup} и переиспользуется через clear()+init().
 * Разница = чистая стоимость аллокации Hmac+Streebog.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
public class HkdfAllocationBench {

    @Param({"32", "64"})
    private int hashLen;

    private byte[] ikm;
    private byte[] salt;
    private byte[] prk;
    private byte[] info;
    private byte[] transcript;
    private byte[] trafficSecret;

    // Переиспользуемые Hmac для *_reuse вариантов
    private Hmac hmacExtract;
    private Hmac hmacExpand;
    private Hmac hmacLabel;
    private Hmac hmacVerify;
    private Hmac hmacPlain;

    @Setup(Level.Trial)
    public void setup() {
        ikm = new byte[hashLen];
        salt = new byte[hashLen];
        prk = new byte[hashLen];
        info = new byte[hashLen];
        transcript = new byte[hashLen];
        trafficSecret = new byte[hashLen];
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        rnd.nextBytes(ikm);
        rnd.nextBytes(salt);
        rnd.nextBytes(prk);
        rnd.nextBytes(info);
        rnd.nextBytes(transcript);
        rnd.nextBytes(trafficSecret);

        hmacExtract = newHmac();
        hmacExpand  = newHmac();
        hmacLabel   = newHmac();
        hmacVerify  = newHmac();
        hmacPlain   = newHmac();
    }

    private Hmac newHmac() {
        return hashLen == 32 ? new Hmac(new Streebog256()) : new Hmac(new Streebog512());
    }

    // ========================================================================
    // extract
    // ========================================================================

    @Benchmark
    public byte[] extract_new() {
        return HkdfStreebog.extract(salt, ikm, hashLen);
    }

    @Benchmark
    public byte[] extract_reuse() {
        hmacExtract.clear();
        hmacExtract.init(salt);
        hmacExtract.update(ikm, 0, ikm.length);
        byte[] out = new byte[hashLen];
        hmacExtract.doFinal(out, 0);
        return out;
    }

    // ========================================================================
    // expand — уже использует 1 Hmac на весь цикл
    // _reuse переиспользует Hmac из @State вместо newHmac
    // ========================================================================

    @Benchmark
    public byte[] expand_new() {
        return HkdfStreebog.expand(prk, info, hashLen, hashLen);
    }

    @Benchmark
    public byte[] expand_reuse() {
        hmacExpand.clear();
        hmacExpand.init(prk);
        hmacExpand.update(info, 0, info.length);
        hmacExpand.update((byte) 1);
        byte[] out = new byte[hashLen];
        hmacExpand.doFinal(out, 0);
        return out;
    }

    // ========================================================================
    // finishedKey = expandLabel(secret, "finished", "", hashLen)
    // Это первая половина computeVerifyData.
    // ========================================================================

    @Benchmark
    public byte[] finishedKey_new() {
        return HkdfStreebog.expandLabel(
                trafficSecret, HkdfStreebog.PREFIXED_FINISHED,
                HkdfStreebog.EMPTY_CONTEXT, hashLen, hashLen);
    }

    @Benchmark
    public byte[] finishedKey_reuse() {
        byte[] prefixed = HkdfStreebog.PREFIXED_FINISHED;
        byte[] hkdfLabel = new byte[2 + 1 + prefixed.length + 1];
        hkdfLabel[0] = (byte) (hashLen >>> 8);
        hkdfLabel[1] = (byte) hashLen;
        hkdfLabel[2] = (byte) prefixed.length;
        System.arraycopy(prefixed, 0, hkdfLabel, 3, prefixed.length);
        hkdfLabel[3 + prefixed.length] = 0;

        hmacLabel.clear();
        hmacLabel.init(trafficSecret);
        hmacLabel.update(hkdfLabel, 0, hkdfLabel.length);
        byte[] out = new byte[hashLen];
        hmacLabel.doFinal(out, 0);
        return out;
    }

    // ========================================================================
    // HMAC verify_data (вторая половина computeVerifyData):
    //   finishedKey = expandLabel(...finished...)
    //   verifyData = HMAC(finishedKey, transcript)
    //
    // _new: newHmac() внутри computeVerifyData
    // _reuse: переиспользует Hmac из @State
    // ========================================================================

    @Benchmark
    public byte[] hmacVerify_new() {
        byte[] key = HkdfStreebog.expandLabel(
                trafficSecret, HkdfStreebog.PREFIXED_FINISHED,
                HkdfStreebog.EMPTY_CONTEXT, hashLen, hashLen);
        Hmac hmac = HkdfStreebog.newHmac(hashLen);
        hmac.init(key);
        hmac.update(transcript, 0, transcript.length);
        byte[] out = new byte[hashLen];
        hmac.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] hmacVerify_reuse() {
        byte[] key = HkdfStreebog.expandLabel(
                trafficSecret, HkdfStreebog.PREFIXED_FINISHED,
                HkdfStreebog.EMPTY_CONTEXT, hashLen, hashLen);
        hmacVerify.clear();
        hmacVerify.init(key);
        hmacVerify.update(transcript, 0, transcript.length);
        byte[] out = new byte[hashLen];
        hmacVerify.doFinal(out, 0);
        return out;
    }

    // ========================================================================
    // Чистая аллокация: newHmac() + clear() без криптоопераций
    // Показывает, сколько стоит сам объект без вычислений.
    // ========================================================================

    @Benchmark
    public Hmac newHmac_only() {
        Hmac hmac = HkdfStreebog.newHmac(hashLen);
        hmac.clear();
        return hmac;
    }

    // ========================================================================
    // Чистый init(): clear() + init(ikm) — сколько стоит переинициализация
    // без аллокации. Разница с newHmac_only = стоимость аллокации Hmac+Streebog
    // ========================================================================

    @Benchmark
    public void hmacInit_only(Blackhole bh) {
        hmacPlain.clear();
        hmacPlain.init(ikm);
        bh.consume(hmacPlain);
    }
}
