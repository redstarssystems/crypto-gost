package org.rssys.bench;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.math.ec.ECCurve;
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
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * JMH-бенчмарк: пропускная способность электронной подписи ГОСТ Р 34.10-2012.
 *
 * <p>Сравнение: crypto-gost (низкоуровневый API) vs BouncyCastle 1.83.
 * Тестируются 256-бит (CryptoPro-A) и 512-бит (TC26-A-512) кривые.
 *
 * <p>Методика:
 * <ul>
 *   <li>Объекты подписи и их инициализация вынесены в {@code @Setup} —
 *       измеряется только операция подписи/верификации.</li>
 *   <li>Сообщения перебираются циклически из пула 1024 штук —
 *       исключает кеширование одного сообщения JIT.</li>
 *   <li>BC: {@link ECGOST3410_2012Signer} переиспользуется через {@code init()}
 *       — симметрично с crypto-gost.</li>
 *   <li>5 итераций по 2 с прогрева + 5 итераций по 2 с замера + 3 форка JVM.</li>
 * </ul>
 *
 *
 * <p>Примечание: crypto-gost использует детерминированный нонс k (RFC 6979),
 * BouncyCastle — случайный {@link SecureRandom}. Это влияет на подписание,
 * но не на верификацию.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(3)
public class SignatureBench {

    /** Кривая: 256-bit (CryptoPro-A) или 512-bit (TC26-A-512). */
    @Param({"256", "512"})
    public String bits;

    private static final int NUM_MESSAGES = 1024;
    private static final int MSG_SIZE     = 1024;

    private byte[][] messages;
    private int      index;

    // --- crypto-gost ---
    private ECDSASigner        gostSigner;
    private PrivateKeyParameters gostPriv;
    private PublicKeyParameters  gostPub;
    private byte[][]             gostSignatures; // предвычисленные для verifyGost

    // --- BouncyCastle ---
    private ECGOST3410_2012Signer bcSigner;
    private ECPrivateKeyParameters bcPriv;
    private ECPublicKeyParameters  bcPub;
    private BigInteger[][]         bcSignatures;  // предвычисленные для verifyBc

    // Размер компоненты подписи в байтах: 32 (256-bit) или 64 (512-bit)
    private int rolen;

    @Setup
    public void setup() {
        boolean is256 = "256".equals(bits);
        ECParameters params = is256 ? ECParameters.cryptoProA() : ECParameters.tc26a512();
        rolen = is256 ? 32 : 64;

        // --- crypto-gost: генерация ключей ---
        // KeyGenerator.generateKeyPair() — безопасная генерация с проверкой кривой
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        gostPriv = pair.getPrivate();
        gostPub  = pair.getPublic();

        // --- crypto-gost: создание и инициализация signer ---
        // передаём фабрику дайджеста — ECDSASigner создаёт свежий экземпляр
        // для каждой генерации k (RFC 6979), изолируя состояние хэша.
        Supplier<org.rssys.gost.digest.Digest> digestFactory =
                is256 ? Streebog256::new : Streebog512::new;
        gostSigner = new ECDSASigner(digestFactory);
        // init(true) = режим подписи; reinit() в benchmark методах — смена состояния не нужна,
        // т.к. RFC 6979 детерминирован по (d, hash) — каждое сообщение даёт уникальный k.
        gostSigner.init(true, gostPriv);

        // --- BouncyCastle: те же ключи ---
        BigInteger d  = gostPriv.getD();
        BigInteger qx = gostPub.getQ().normalize().getX();
        BigInteger qy = gostPub.getQ().normalize().getY();

        ECCurve curve = new ECCurve.Fp(params.p, params.a, params.b);
        org.bouncycastle.math.ec.ECPoint g = curve.createPoint(params.gx, params.gy);
        ECDomainParameters bcDomain = new ECDomainParameters(curve, g, params.n);

        bcPriv = new ECPrivateKeyParameters(d, bcDomain);
        org.bouncycastle.math.ec.ECPoint bcQ = curve.createPoint(qx, qy);
        bcPub  = new ECPublicKeyParameters(bcQ, bcDomain);

        // --- BouncyCastle: создание signer (переиспользуется через init()) ---
        bcSigner = new ECGOST3410_2012Signer();
        bcSigner.init(true, bcPriv);

        // --- Тестовые сообщения ---
        SecureRandom rnd = new SecureRandom();
        messages = new byte[NUM_MESSAGES][MSG_SIZE];
        for (int i = 0; i < NUM_MESSAGES; i++) {
            rnd.nextBytes(messages[i]);
        }

        // --- Предвычисляем подписи для verify-бенчмарков ---
        gostSignatures = new byte[NUM_MESSAGES][];
        bcSignatures   = new BigInteger[NUM_MESSAGES][];

        org.rssys.gost.digest.Digest gostDigest =
                is256 ? new Streebog256() : new Streebog512();

        org.bouncycastle.crypto.Digest bcDigestPrecompute =
                is256 ? new org.bouncycastle.crypto.digests.GOST3411_2012_256Digest()
                      : new org.bouncycastle.crypto.digests.GOST3411_2012_512Digest();

        for (int i = 0; i < NUM_MESSAGES; i++) {
            // crypto-gost sign
            gostDigest.reset();
            gostDigest.update(messages[i], 0, messages[i].length);
            byte[] gostHash = new byte[gostDigest.getDigestSize()];
            gostDigest.doFinal(gostHash, 0);
            gostSigner.init(true, gostPriv);
            BigInteger[] rs = gostSigner.generateSignature(gostHash);
            gostSignatures[i] = encodeSig(rs[0], rs[1], rolen);

            // BC sign
            bcDigestPrecompute.reset();
            bcDigestPrecompute.update(messages[i], 0, messages[i].length);
            byte[] bcHash = new byte[bcDigestPrecompute.getDigestSize()];
            bcDigestPrecompute.doFinal(bcHash, 0);
            bcSigner.init(true, bcPriv);
            bcSignatures[i] = bcSigner.generateSignature(bcHash);
        }

        // Восстанавливаем signer в нужный режим для бенчмарков
        gostSigner.init(true, gostPriv);
        bcSigner.init(true, bcPriv);

        index = 0;
    }

    private int nextIdx() {
        int i = index;
        index = (i + 1) & (NUM_MESSAGES - 1);
        return i;
    }

    // -----------------------------------------------------------------------
    // crypto-gost: подписание
    // Идиома: Signature.sign() — высокоуровневый API, hash-then-sign за один вызов.
    // -----------------------------------------------------------------------
    @Benchmark
    public byte[] signGost() {
        int i = nextIdx();
        return Signature.sign(messages[i], gostPriv);
    }

    // -----------------------------------------------------------------------
    // crypto-gost: верификация
    // -----------------------------------------------------------------------
    @Benchmark
    public boolean verifyGost() {
        int i = nextIdx();
        return Signature.verify(messages[i], gostSignatures[i], gostPub);
    }

    // -----------------------------------------------------------------------
    // BouncyCastle: подписание
    // Объекты digest и signer создаются в @Setup и переиспользуются через init().
    // Это справедливое сравнение: измеряется только hash + sign, без аллокаций.
    // -----------------------------------------------------------------------
    @Benchmark
    public byte[] signBc() {
        int i = nextIdx();
        // Хэш сообщения — создаём digest внутри для изоляции состояния между итерациями
        // (BC Digest — stateful, reset() недостаточно безопасен между вызовами в бенчмарке)
        org.bouncycastle.crypto.Digest digest =
                "256".equals(bits)
                ? new org.bouncycastle.crypto.digests.GOST3411_2012_256Digest()
                : new org.bouncycastle.crypto.digests.GOST3411_2012_512Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(messages[i], 0, messages[i].length);
        digest.doFinal(hash, 0);

        // Переиспользуем bcSigner через reinit — без аллокации нового объекта
        bcSigner.init(true, bcPriv);
        BigInteger[] sig = bcSigner.generateSignature(hash);
        return encodeSig(sig[0], sig[1], rolen);
    }

    // -----------------------------------------------------------------------
    // BouncyCastle: верификация
    // -----------------------------------------------------------------------
    @Benchmark
    public boolean verifyBc() {
        int i = nextIdx();
        org.bouncycastle.crypto.Digest digest =
                "256".equals(bits)
                ? new org.bouncycastle.crypto.digests.GOST3411_2012_256Digest()
                : new org.bouncycastle.crypto.digests.GOST3411_2012_512Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(messages[i], 0, messages[i].length);
        digest.doFinal(hash, 0);

        bcSigner.init(false, bcPub);
        return bcSigner.verifySignature(hash, bcSignatures[i][0], bcSignatures[i][1]);
    }

    // -----------------------------------------------------------------------
    // Утилита: кодирование BigInteger r,s -> byte[] r||s (big-endian, фиксированная длина)
    // -----------------------------------------------------------------------
    private static byte[] encodeSig(BigInteger r, BigInteger s, int rolen) {
        byte[] result = new byte[2 * rolen];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        // BigInteger.toByteArray() добавляет ведущий 0x00 если старший бит установлен — пропускаем его.
        int rStart = (rBytes[0] == 0) ? 1 : 0;
        int sStart = (sBytes[0] == 0) ? 1 : 0;
        int rLen = rBytes.length - rStart;
        int sLen = sBytes.length - sStart;
        // Для валидных ГОСТ-подписей r, s < n, поэтому rLen/sLen <= rolen.
        // Если это не так — данные некорректны; бросаем исключение вместо молчаливой порчи.
        if (rLen > rolen || sLen > rolen) {
            throw new IllegalStateException(
                "r or s exceeds rolen: rLen=" + rLen + " sLen=" + sLen + " rolen=" + rolen);
        }
        System.arraycopy(rBytes, rStart, result, rolen - rLen, rLen);
        System.arraycopy(sBytes, sStart, result, 2 * rolen - sLen, sLen);
        return result;
    }
}
