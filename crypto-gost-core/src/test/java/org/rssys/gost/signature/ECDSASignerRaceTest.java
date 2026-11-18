package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.Pack;

/**
 * Гонка между подписью (проверкой) и {@code init} / {@code destroy} подписанта.
 *
 * <p>Если {@code destroy()} или {@code init()} затирают ключ между двумя его чтениями при подписи,
 * {@code k} оказывается посчитанным от настоящего {@code d}, а {@code s} - от нулевого или чужого:
 * {@code s = k·e}. Из такой подписи и обычной подписи того же хэша вычисляется закрытый ключ.
 * Если снимок попал на середину затирания, подпись верна под усечённым ключом и выдаёт его
 * младшие байты. Поэтому при любом изменении состояния во время операции подпись обязана не
 * выдаваться.
 *
 * <p>Детерминированные тесты вызывают {@code destroy()} / {@code init()} из дайджеста, который
 * подписант получает от фабрики, ровно после того, как ключ уже скопирован: повторный вход в том
 * же потоке без ожиданий и потоков. Стресс-тесты ловят то, что хук воспроизвести не может: рваный
 * снимок посередине копирования. Они могут пройти, не попав в гонку, но ложно не падают.
 */
@DisplayName("ECDSASigner: гонка подписи и проверки с init/destroy")
class ECDSASignerRaceTest {

    private static final String MODIFIED_MESSAGE =
            "ECDSASigner state was modified concurrently during the operation";

    private static final long WAIT_SECONDS = 30;

    /** Допустимые тексты отказа подписи: изменение состояния, уничтожение, отсутствие init. */
    private static final List<String> KNOWN_REFUSALS =
            List.of(
                    MODIFIED_MESSAGE,
                    "ECDSASigner has been destroyed",
                    "ECDSASigner is not initialized");

    /** Пары кривых одной длины хэша: фабрика дайджеста одна, ключ меняется на другую кривую. */
    private static Stream<Arguments> curvePairs() {
        return Stream.of(
                Arguments.of(ECParameters.tc26a256(), ECParameters.cryptoProA()),
                Arguments.of(ECParameters.cryptoProB(), ECParameters.tc26a256()),
                Arguments.of(ECParameters.cryptoProC(), ECParameters.cryptoProB()),
                Arguments.of(ECParameters.tc26a512(), ECParameters.tc26b512()),
                Arguments.of(ECParameters.tc26b512(), ECParameters.tc26c512()),
                Arguments.of(ECParameters.tc26c512(), ECParameters.tc26a512()));
    }

    private static Digest newDigest(ECParameters params) {
        return params.hlen == Streebog256.DIGEST_SIZE ? new Streebog256() : new Streebog512();
    }

    private static byte[] hashFor(ECParameters params) {
        byte[] hash = new byte[params.hlen];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = (byte) (i * 11 + 5);
        }
        return hash;
    }

    private static BigInteger eOf(byte[] hash, ECParameters params) {
        BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(params.n);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    /**
     * Дайджест, который при первом {@code doFinal} выполняет хук. Первый {@code doFinal} внутри
     * выработки нонса - внутренний хэш HMAC, он идёт после копирования ключа и до вычисления
     * {@code s}, то есть именно там, где прежний код читал ключ второй раз. Остальные вызовы и
     * {@code destroy} передаются дальше: {@code Hmac.clear()} вызывает {@code destroy}, иначе тест
     * оставил бы незатёртое состояние Стрибога.
     */
    private static final class HookDigest implements Digest {
        private final Digest delegate;
        private final Runnable hook;
        private boolean fired;

        HookDigest(Digest delegate, Runnable hook) {
            this.delegate = delegate;
            this.hook = hook;
        }

        @Override
        public String getAlgorithmName() {
            return delegate.getAlgorithmName();
        }

        @Override
        public int getDigestSize() {
            return delegate.getDigestSize();
        }

        @Override
        public int getByteLength() {
            return delegate.getByteLength();
        }

        @Override
        public void update(byte in) {
            delegate.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len) {
            delegate.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff) {
            if (!fired) {
                fired = true;
                hook.run();
            }
            return delegate.doFinal(out, outOff);
        }

        @Override
        public void reset() {
            delegate.reset();
        }

        @Override
        public void destroy() {
            delegate.destroy();
        }
    }

    /**
     * Старое поведение: подпись выдана при изменении подписанта посреди подписи. Показывает, чем
     * это грозит: по такой подписи и обычной подписи того же хэша вычисляется закрытый ключ.
     */
    private static void failBecauseSignatureWasIssued(
            ECParameters params, PrivateKeyParameters key, byte[] hash, BigInteger[] issued) {
        BigInteger n = params.n;
        BigInteger e = eOf(hash, params);
        // s = k·e: нулевой d во втором чтении
        BigInteger k = issued[1].multiply(e.modInverse(n)).mod(n);

        ECDSASigner honest = new ECDSASigner(() -> newDigest(params));
        honest.init(true, key);
        BigInteger[] good = honest.generateSignature(hash);
        honest.destroy();

        BigInteger recovered =
                good[1].subtract(k.multiply(e)).mod(n).multiply(good[0].modInverse(n)).mod(n);
        fail(
                "Подпись выдана при изменении подписанта посреди подписи; закрытый ключ "
                        + (recovered.equals(key.getD()) ? "ВОССТАНАВЛИВАЕТСЯ" : "не восстановлен")
                        + " по этой подписи и обычной подписи того же хэша");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curvePairs")
    @DisplayName("destroy() посреди подписи: подпись не выдаётся")
    void destroyDuringSigningRefusesSignature(ECParameters params, ECParameters ignored) {
        PrivateKeyParameters key = KeyGenerator.generateKeyPair(params).getPrivate();
        byte[] hash = hashFor(params);
        ECDSASigner[] holder = new ECDSASigner[1];
        holder[0] =
                new ECDSASigner(() -> new HookDigest(newDigest(params), () -> holder[0].destroy()));
        holder[0].init(true, key);

        BigInteger[] issued;
        try {
            issued = holder[0].generateSignature(hash);
        } catch (IllegalStateException expected) {
            assertEquals(
                    MODIFIED_MESSAGE,
                    expected.getMessage(),
                    "отказ обязан быть из-за изменения состояния, а не по другой причине");
            assertTrue(holder[0].isDestroyed(), "подписант обязан остаться уничтоженным");
            return;
        }
        failBecauseSignatureWasIssued(params, key, hash, issued);
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @MethodSource("curvePairs")
    @DisplayName("init() с ключом другой кривой посреди подписи: подпись не выдаётся")
    void initWithOtherCurveDuringSigningRefusesSignature(
            ECParameters params, ECParameters otherParams) {
        PrivateKeyParameters key = KeyGenerator.generateKeyPair(params).getPrivate();
        PrivateKeyParameters otherKey = KeyGenerator.generateKeyPair(otherParams).getPrivate();
        byte[] hash = hashFor(params);
        ECDSASigner[] holder = new ECDSASigner[1];
        holder[0] =
                new ECDSASigner(
                        () ->
                                new HookDigest(
                                        newDigest(params), () -> holder[0].init(true, otherKey)));
        holder[0].init(true, key);

        BigInteger[] issued;
        try {
            issued = holder[0].generateSignature(hash);
        } catch (IllegalStateException expected) {
            assertEquals(
                    MODIFIED_MESSAGE,
                    expected.getMessage(),
                    "отказ обязан быть из-за изменения состояния, а не по другой причине");
            return;
        }
        // Подпись под смесью двух ключей и двух кривых не проверяется ни тем, ни другим ключом
        failBecauseSignatureWasIssued(params, key, hash, issued);
    }

    @Test
    @DisplayName("Неудачный init оставляет подписанта непригодным, следующий init работает")
    void failedInitLeavesSignerUnusableAndNextInitWorks() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keys = KeyGenerator.generateKeyPair(params);
        byte[] hash = hashFor(params);
        ECDSASigner signer = new ECDSASigner(Streebog256::new);
        signer.init(true, keys.getPrivate());

        // Открытый ключ вместо закрытого для режима подписи
        assertThrows(
                IllegalArgumentException.class,
                () -> signer.init(true, keys.getPublic()),
                "неверный тип параметров обязан отвергаться");

        // Прежний ключ не должен остаться пригодным после неудачной повторной инициализации
        IllegalStateException refused =
                assertThrows(
                        IllegalStateException.class,
                        () -> signer.generateSignature(hash),
                        "после неудачного init подпись прежним ключом недопустима");
        assertEquals("ECDSASigner is not initialized", refused.getMessage());

        // Следующий init выполняется в daemon-потоке с ожиданием через Future: writeLock не
        // прерывается, и без разблокировки в finally обычный таймаут оставил бы висеть поток
        ExecutorService executor = daemonExecutor();
        try {
            Future<?> reinit = executor.submit(() -> signer.init(true, keys.getPrivate()));
            try {
                reinit.get(WAIT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException hung) {
                fail("init после неудачного init завис: блокировка записи не освобождена");
            }
        } finally {
            executor.shutdownNow();
        }

        BigInteger[] signature = signer.generateSignature(hash);
        ECDSASigner verifier = new ECDSASigner(Streebog256::new);
        verifier.init(false, keys.getPublic());
        assertTrue(
                verifier.verifySignature(hash, signature[0], signature[1]),
                "после повторной инициализации подпись обязана проверяться");
    }

    @Test
    @DisplayName("init() после destroy() отвергается, подписант остаётся уничтоженным")
    void initAfterDestroyIsRejected() {
        ECParameters params = ECParameters.tc26a256();
        PrivateKeyParameters key = KeyGenerator.generateKeyPair(params).getPrivate();
        ECDSASigner signer = new ECDSASigner(Streebog256::new);
        signer.init(true, key);
        signer.destroy();

        IllegalStateException refused =
                assertThrows(
                        IllegalStateException.class,
                        () -> signer.init(true, key),
                        "уничтоженный подписант не должен инициализироваться заново");
        assertEquals("ECDSASigner has been destroyed", refused.getMessage());
        assertTrue(signer.isDestroyed(), "уничтожение необратимо");
    }

    // ---- Стресс: рваный снимок и повторные init посреди копирования ключа ----

    /** Что делает второй поток, пока первый подписывает. */
    private enum Disturbance {
        DESTROY,
        REINIT_SAME_KEY,
        REINIT_OTHER_CURVE
    }

    private static Stream<Arguments> stressCases() {
        List<Arguments> cases = new ArrayList<>();
        // Узкая кривая и широкая: у широкой ключ 64 байта, окно затирания длиннее
        ECParameters[][] pairs = {
            {ECParameters.tc26a256(), ECParameters.cryptoProA()},
            {ECParameters.tc26a512(), ECParameters.tc26b512()}
        };
        for (ECParameters[] pair : pairs) {
            for (Disturbance disturbance : Disturbance.values()) {
                cases.add(Arguments.of(pair[0], pair[1], disturbance));
            }
        }
        return cases.stream();
    }

    private static ExecutorService daemonExecutor() {
        return Executors.newCachedThreadPool(
                task -> {
                    Thread thread = new Thread(task, "ecdsa-race-test");
                    thread.setDaemon(true);
                    return thread;
                });
    }

    private static boolean verifies(
            ECParameters params, PublicKeyParameters pub, byte[] hash, BigInteger[] signature) {
        ECDSASigner verifier = new ECDSASigner(() -> newDigest(params));
        verifier.init(false, pub);
        return verifier.verifySignature(hash, signature[0], signature[1]);
    }

    @ParameterizedTest(name = "{0}, {2}")
    @MethodSource("stressCases")
    @Timeout(120)
    @DisplayName("Стресс: подпись во время destroy/init не выдаёт подпись под рваным ключом")
    void signingUnderConcurrentChangesNeverIssuesBrokenSignature(
            ECParameters params, ECParameters otherParams, Disturbance disturbance)
            throws Exception {
        final int iterations = 80;
        final int signaturesPerIteration = 25;
        byte[] hash = hashFor(params);

        ExecutorService executor = daemonExecutor();
        try {
            for (int iteration = 0; iteration < iterations; iteration++) {
                KeyPair keys = KeyGenerator.generateKeyPair(params);
                KeyPair otherKeys = KeyGenerator.generateKeyPair(otherParams);
                ECDSASigner signer = new ECDSASigner(() -> newDigest(params));
                signer.init(true, keys.getPrivate());

                CyclicBarrier start = new CyclicBarrier(2);
                Future<List<BigInteger[]>> signing =
                        executor.submit(
                                () -> {
                                    start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                                    List<BigInteger[]> issued = new ArrayList<>();
                                    for (int i = 0; i < signaturesPerIteration; i++) {
                                        try {
                                            issued.add(signer.generateSignature(hash));
                                        } catch (IllegalStateException refused) {
                                            // Отказ допустим, но только с известным текстом: без
                                            // ключевого материала и без посторонних причин
                                            assertTrue(
                                                    KNOWN_REFUSALS.contains(refused.getMessage()),
                                                    "неожиданный текст отказа: "
                                                            + refused.getMessage());
                                            break;
                                        }
                                    }
                                    return issued;
                                });
                Future<?> disturbing =
                        executor.submit(
                                () -> {
                                    start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                                    LockSupport.parkNanos(CryptoRandom.INSTANCE.nextInt(300_000));
                                    switch (disturbance) {
                                        case DESTROY -> signer.destroy();
                                        case REINIT_SAME_KEY -> {
                                            for (int i = 0; i < 6; i++) {
                                                signer.init(true, keys.getPrivate());
                                            }
                                        }
                                        case REINIT_OTHER_CURVE ->
                                                signer.init(true, otherKeys.getPrivate());
                                    }
                                    return null;
                                });

                List<BigInteger[]> issued;
                try {
                    issued = signing.get(WAIT_SECONDS, TimeUnit.SECONDS);
                    disturbing.get(WAIT_SECONDS, TimeUnit.SECONDS);
                } catch (TimeoutException | ExecutionException failure) {
                    throw new AssertionError(
                            "поток подписи или помехи не завершился штатно", failure);
                }

                for (BigInteger[] signature : issued) {
                    boolean underOld = verifies(params, keys.getPublic(), hash, signature);
                    if (disturbance == Disturbance.REINIT_OTHER_CURVE) {
                        // Допустима подпись под старым или под новым ключом, но не под смесью
                        boolean underNew =
                                verifies(otherParams, otherKeys.getPublic(), hash, signature);
                        assertTrue(
                                underOld || underNew,
                                "выданная подпись обязана проверяться старым или новым ключом");
                        assertFalse(
                                underOld && underNew,
                                "подпись не может проверяться обоими ключами");
                    } else {
                        assertTrue(
                                underOld,
                                "выданная подпись обязана проверяться ключом подписанта, а не"
                                        + " усечённым или нулевым");
                    }
                }
            }
        } finally {
            executor.shutdownNow();
        }
    }

    /** Кривая и число попыток подписи: у широкой кривой подпись дороже, попыток меньше. */
    private static Stream<Arguments> continuousReinitCases() {
        return Stream.of(
                Arguments.of(ECParameters.tc26a256(), 1500),
                Arguments.of(ECParameters.tc26a512(), 500));
    }

    /**
     * Рваный снимок: копия ключа снимается посередине затирания старого массива. Окно - время
     * {@code clone()} на 32-64 байта, поэтому помеха крутит {@code init} тем же ключом в цикле,
     * пока идут попытки подписи, а подпись на отказе не останавливается. Выданная подпись под
     * усечённым ключом проверку открытым ключом не пройдёт: именно её тест и ищет. Если подпись не
     * выдана, это допустимый отказ.
     */
    @ParameterizedTest(name = "{0}, попыток {1}")
    @MethodSource("continuousReinitCases")
    @Timeout(120)
    @DisplayName("Стресс: непрерывный init тем же ключом не даёт подпись под рваным ключом")
    void signingUnderContinuousReinitNeverIssuesTornSignature(ECParameters params, int attempts)
            throws Exception {
        KeyPair keys = KeyGenerator.generateKeyPair(params);
        ECDSASigner signer = new ECDSASigner(() -> newDigest(params));
        signer.init(true, keys.getPrivate());
        byte[] hash = hashFor(params);

        AtomicBoolean stop = new AtomicBoolean();
        ExecutorService executor = daemonExecutor();
        try {
            Future<?> reinitializing =
                    executor.submit(
                            () -> {
                                while (!stop.get()) {
                                    signer.init(true, keys.getPrivate());
                                }
                                return null;
                            });

            List<BigInteger[]> issued = new ArrayList<>();
            List<byte[]> issuedHashes = new ArrayList<>();
            int refusals = 0;
            for (int attempt = 0; attempt < attempts; attempt++) {
                byte[] attemptHash = hash.clone();
                attemptHash[0] = (byte) attempt;
                try {
                    issued.add(signer.generateSignature(attemptHash));
                    issuedHashes.add(attemptHash);
                } catch (IllegalStateException refused) {
                    refusals++;
                    assertTrue(
                            KNOWN_REFUSALS.contains(refused.getMessage()),
                            "неожиданный текст отказа: " + refused.getMessage());
                }
            }
            stop.set(true);
            // При работающей защите каждое попадание помехи в подпись даёт отказ: без отказов тест
            // не проверил ничего, потому что поток помехи не пересёкся с подписью
            assertTrue(refusals > 0, "помеха не пересеклась с подписью, тест ничего не проверил");
            try {
                reinitializing.get(WAIT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException | ExecutionException failure) {
                throw new AssertionError("поток init не завершился штатно", failure);
            }

            for (int i = 0; i < issued.size(); i++) {
                assertTrue(
                        verifies(params, keys.getPublic(), issuedHashes.get(i), issued.get(i)),
                        "выданная подпись обязана проверяться ключом подписанта, а не усечённым");
            }
        } finally {
            stop.set(true);
            executor.shutdownNow();
        }
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("verifyDisturbances")
    @Timeout(120)
    @DisplayName("Стресс: проверка во время init/destroy даёт верный вердикт или отказ")
    void verificationUnderConcurrentChangesNeverGivesWrongVerdict(
            ECParameters params, Disturbance disturbance) throws Exception {
        final int iterations = 60;
        final int verificationsPerIteration = 15;
        byte[] hash = hashFor(params);

        ExecutorService executor = daemonExecutor();
        try {
            for (int iteration = 0; iteration < iterations; iteration++) {
                KeyPair keys = KeyGenerator.generateKeyPair(params);
                ECDSASigner signing = new ECDSASigner(() -> newDigest(params));
                signing.init(true, keys.getPrivate());
                BigInteger[] valid = signing.generateSignature(hash);
                signing.destroy();

                ECDSASigner verifier = new ECDSASigner(() -> newDigest(params));
                verifier.init(false, keys.getPublic());

                CyclicBarrier start = new CyclicBarrier(2);
                Future<List<Boolean>> verifying =
                        executor.submit(
                                () -> {
                                    start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                                    List<Boolean> verdicts = new ArrayList<>();
                                    for (int i = 0; i < verificationsPerIteration; i++) {
                                        try {
                                            verdicts.add(
                                                    verifier.verifySignature(
                                                            hash, valid[0], valid[1]));
                                        } catch (IllegalStateException refused) {
                                            break;
                                        }
                                    }
                                    return verdicts;
                                });
                Future<?> disturbing =
                        executor.submit(
                                () -> {
                                    start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                                    LockSupport.parkNanos(CryptoRandom.INSTANCE.nextInt(300_000));
                                    if (disturbance == Disturbance.DESTROY) {
                                        verifier.destroy();
                                    } else {
                                        // Тот же ключ: состояние при каждом init равно исходному,
                                        // поэтому ложный отказ верной подписи недопустим
                                        for (int i = 0; i < 4; i++) {
                                            verifier.init(false, keys.getPublic());
                                        }
                                    }
                                    return null;
                                });

                List<Boolean> verdicts;
                try {
                    verdicts = verifying.get(WAIT_SECONDS, TimeUnit.SECONDS);
                    disturbing.get(WAIT_SECONDS, TimeUnit.SECONDS);
                } catch (TimeoutException | ExecutionException failure) {
                    throw new AssertionError(
                            "поток проверки или помехи не завершился штатно", failure);
                }
                for (Boolean verdict : verdicts) {
                    assertTrue(verdict, "верная подпись не может получить вердикт false");
                }
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static Stream<Arguments> verifyDisturbances() {
        return Stream.of(
                Arguments.of(ECParameters.tc26a256(), Disturbance.DESTROY),
                Arguments.of(ECParameters.tc26a256(), Disturbance.REINIT_SAME_KEY),
                Arguments.of(ECParameters.tc26a512(), Disturbance.REINIT_SAME_KEY));
    }
}
