package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.util.CryptoRandom;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк отдельных компонентов handshake.
 * <p>
 * Зачем: понять, какая именно операция доминирует в полном handshake.
 * Позволяет фокусировать оптимизации на узком месте (bottleneck).
 * Каждый benchmark изолирован — без аллокаций TlsSession/транспорта.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class HandshakeComponentsBench {

    private ECParameters params;
    private byte[] ecdhePoint;
    private byte[] hash32;
    private PrivateKeyParameters signKey;
    private PublicKeyParameters verifyKey;
    private TlsKeySchedule ks;
    private byte[] sharedSecret;
    private TlsCiphersuite cs;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        params = ECParameters.tc26a256();
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // ECDHE keypair
        org.rssys.gost.api.KeyPair ecdhe = KeyGenerator.generateKeyPair(params);
        ecdhePoint = BenchHelper.encodePoint(ecdhe.getPublic());
        sharedSecret = new byte[32];
        java.security.SecureRandom.getInstanceStrong().nextBytes(sharedSecret);

        // Signature keypair (как сертификатный ключ)
        org.rssys.gost.api.KeyPair sigKp = KeyGenerator.generateKeyPair(params);
        signKey = sigKp.getPrivate();
        verifyKey = sigKp.getPublic();

        // Хеш для подписи
        hash32 = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash32);

        // Key schedule (без PSK)
        ks = new TlsKeySchedule(cs);
        ks.deriveHandshakeSecret(sharedSecret);
        ks.deriveMasterSecret();
    }

    @Benchmark
    public org.rssys.gost.api.KeyPair ecdheKeygen() {
        return KeyGenerator.generateKeyPair(params);
    }

    @Benchmark
    public byte[] ecdhePointEncoding() {
        return BenchHelper.encodePoint(verifyKey);
    }

    @Benchmark
    public byte[] hash256() {
        Digest d = new Streebog256();
        d.update(hash32, 0, hash32.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] sign() {
        return Signature.signHash(hash32, signKey);
    }

    @Benchmark
    public boolean verify() {
        byte[] sig = Signature.signHash(hash32, signKey);
        return Signature.verifyHash(hash32, sig, verifyKey);
    }

    @Benchmark
    public byte[] hkdfExtract() {
        byte[] zero = new byte[32];
        return HkdfStreebog.extract(zero, sharedSecret, 32);
    }

    @Benchmark
    public byte[] hkdfExpand() {
        return HkdfStreebog.expandLabel(sharedSecret, "test label", new byte[0], 32, 32);
    }

    @Benchmark
    public TlsTrafficKeys deriveTrafficKeys() {
        return ks.deriveTrafficKeys(sharedSecret);
    }

    @Benchmark
    public byte[] certVerifyHash() throws Exception {
        byte[] sigContent = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(sigContent);
        Digest d = new Streebog256();
        d.update(sigContent, 0, sigContent.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }
}
