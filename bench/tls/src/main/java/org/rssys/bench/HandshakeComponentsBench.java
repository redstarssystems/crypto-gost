package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import java.math.BigInteger;
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
 * Позволяет фокусировать оптимизации на узком месте.
 * Каждый benchmark изолирован — без аллокаций TlsSession/транспорта.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class HandshakeComponentsBench {

    private ECParameters params;
    private byte[] hash32;
    private PrivateKeyParameters signKey;
    private PublicKeyParameters verifyKey;
    private byte[] precomputedSig;
    private TlsKeySchedule ks;
    private byte[] sharedSecret;
    private TlsCiphersuite cs;
    private PrivateKeyParameters ecdheClientPriv;
    private PublicKeyParameters ecdheServerPub;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        params = ECParameters.tc26a256();
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // ECDHE keypairs для shared secret bench (client + server)
        org.rssys.gost.api.KeyPair ecdheClient = KeyGenerator.generateKeyPair(params);
        org.rssys.gost.api.KeyPair ecdheServer = KeyGenerator.generateKeyPair(params);
        ecdheClientPriv = ecdheClient.getPrivate();
        ecdheServerPub = ecdheServer.getPublic();
        sharedSecret = new byte[32];
        java.security.SecureRandom.getInstanceStrong().nextBytes(sharedSecret);

        // Signature keypair (как сертификатный ключ)
        org.rssys.gost.api.KeyPair sigKp = KeyGenerator.generateKeyPair(params);
        signKey = sigKp.getPrivate();
        verifyKey = sigKp.getPublic();

        // Хеш для подписи
        hash32 = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash32);
        // Подпись для verify — вынесена из @Benchmark, чтобы мерить только verify
        precomputedSig = Signature.signHash(hash32, signKey);

        // Key schedule (без PSK)
        ks = new TlsKeySchedule(cs);
        ks.deriveHandshakeSecret(sharedSecret);
        ks.deriveMasterSecret();
    }

    @Benchmark
    public void ecdheKeygen(Blackhole bh) {
        bh.consume(KeyGenerator.generateKeyPair(params));
    }

    @Benchmark
    public void ecdheShared(Blackhole bh) {
        ECPoint shared = ecdheServerPub.getQ().multiply(
                ecdheClientPriv.getD().multiply(BigInteger.ONE));
        shared = shared.normalize();
        bh.consume(shared.getX());
    }

    @Benchmark
    public void sign(Blackhole bh) {
        bh.consume(Signature.signHash(hash32, signKey));
    }

    @Benchmark
    public void verify(Blackhole bh) {
        bh.consume(Signature.verifyHash(hash32, precomputedSig, verifyKey));
    }

    @Benchmark
    public void hkdfExtract(Blackhole bh) {
        byte[] zero = new byte[32];
        bh.consume(HkdfStreebog.extract(zero, sharedSecret, 32));
    }

    @Benchmark
    public void hkdfExpand(Blackhole bh) {
        bh.consume(HkdfStreebog.expandLabel(sharedSecret, "test label", new byte[0], 32, 32));
    }

    @Benchmark
    public void deriveTrafficKeys(Blackhole bh) {
        bh.consume(ks.deriveTrafficKeys(sharedSecret));
    }
}
