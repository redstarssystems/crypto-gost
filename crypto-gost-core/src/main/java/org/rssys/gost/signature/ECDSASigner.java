package org.rssys.gost.signature;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.locks.StampedLock;
import java.util.function.Supplier;
import javax.security.auth.Destroyable;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.Pack;

/**
 * Реализация алгоритма электронной подписи ГОСТ Р 34.10-2012 (RFC 7091).
 * <p>
 * Хэш-значение H интерпретируется как целое число e по правилу RFC 7091 §5.3:
 * байты хэша переводятся в число с младшим байтом сначала (little-endian LSB first).
 * Это означает, что перед вызовом {@code new BigInteger(1, hash)} байты должны быть
 * реверсированы относительно того, как их возвращает Streebog.
 * <p>
 * Нонс k вырабатывается по схеме RFC 6979 (HMAC-DRBG на Стрибоге) с двумя поправками для ГОСТ:
 * затравкой служит число e из уравнения подписи, а не байты хэша, и во вход добавлен
 * идентификатор кривой (по образцу RFC 6979 §3.6). Есть два режима, см. {@link NonceMode}:
 * детерминированный и гибридный (дополнительно подмешиваются свежие случайные байты). По
 * умолчанию, то есть у конструктора без режима, гибридный ({@link NonceMode#DEFAULT}):
 * подпись одного хэша каждый раз другая. Воспроизводимость даёт явный
 * {@link NonceMode#DETERMINISTIC}.
 * Подробности - в описании {@code generateK}.
 *
 * <p>Класс не предназначен для общего использования несколькими потоками. Нельзя вызывать
 * {@link #init} и {@link #destroy} из другого потока, пока идёт подпись или проверка, и нельзя
 * делать это повторным входом из того же потока (например, из дайджеста, подставленного
 * фабрикой). Для параллельной работы создавайте подписанта на поток или на вызов: так делают
 * {@code Signature}, TLS и JCA. Если состояние всё же изменилось во время операции, подпись или
 * вердикт проверки не выдаются, вместо них бросается {@link IllegalStateException}. Если
 * {@link #destroy} начался уже после последней внутренней проверки, выданная подпись валидна под
 * копией прежнего ключа, снятой в начале операции.
 *
 * Ссылки:
 * <ul>
 *   <li>ГОСТ Р 34.10-2012 / RFC 7091: https://www.rfc-editor.org/rfc/rfc7091</li>
 *   <li>RFC 6979: https://www.rfc-editor.org/rfc/rfc6979</li>
 * </ul>
 */
public final class ECDSASigner implements Destroyable {
    private byte[] dBytes; // закрытый ключ хранится как byte[] для возможности обнуления
    private ECPoint q;
    private ECParameters params;
    private boolean forSigning;
    private final Supplier<Digest> digestFactory;

    /**
     * Режим нонса и источник случайной добавки задаются при создании и не меняются: так
     * состояние под {@code stateLock} не расширяется. {@code noiseSource} равен {@code null} в
     * детерминированном режиме, где датчик не вызывается вообще.
     */
    private final NonceMode nonceMode;

    private final NoiseSource noiseSource;

    /**
     * Нулевые байты для дополнения до границы блока в гибридном режиме. Длина покрывает блок
     * Стрибога (64 байта); дополнение всегда меньше блока.
     */
    private static final byte[] ZEROS = new byte[64];

    /** Разделители шагов d и f RFC 6979 §3.2: константы, а не массив на каждый вызов. */
    private static final byte[] SEPARATOR_D = {0x00};

    private static final byte[] SEPARATOR_F = {0x01};

    /**
     * Защита от гонки между подписью (проверкой) и {@link #init} / {@link #destroy}. Состояние
     * подписанта меняют только они, под {@code writeLock}. Подпись и проверка берут оптимистичную
     * метку, копируют нужное состояние в локальные переменные и сверяют метку до и после
     * вычисления: без сверки подпись, посчитанная по наполовину затёртому ключу, оказалась бы
     * верной под усечённым ключом и выдавала бы его младшие байты.
     */
    private final StampedLock stateLock = new StampedLock();

    /**
     * {@code volatile}: {@link #isDestroyed()} читает флаг вне окна оптимистичной метки. Запись -
     * только под {@code writeLock}.
     */
    private volatile boolean destroyed = false;

    /**
     * true только после успешного {@link #init}; сбрасывается при повторной инициализации и в
     * {@link #destroy}. Запись - только под {@code writeLock}, чтение - только между оптимистичной
     * меткой и её сверкой.
     */
    private boolean initialized = false;

    /**
     * Кешированная базовая точка G, инициализируется в {@link #init}.
     * При подписи служит основанием лестницы {@link ECPoint#multiply}, при проверке -
     * исходной точкой для построения wNAF-таблицы.
     */
    private ECPoint cachedG;

    /**
     * Предвычисленная wNAF-таблица для базовой точки G: {@code cachedGTable[i] = (2i+1)·G}.
     * Берётся в {@link #init} из {@code ECParameters.gWnafTable} (там строится один раз на кривую
     * и общая для всех проверяющих) только в режиме проверки подписи, в режиме подписи равна
     * {@code null}.
     * Используется только в {@link #verifySignature} для ускорения умножения {@code z1·G}
     * — заменяет лестницу Монтгомери на wNAF.
     */
    private ECPoint[] cachedGTable;

    /**
     * Предвычисленная wNAF-таблица для публичного ключа Q: {@code cachedQTable[i] = (2i+1)·Q}.
     * Строится один раз в {@link #init} при инициализации для верификации.
     * Переиспользуется во всех вызовах {@link #verifySignature}, устраняя повторное
     * построение таблицы (1 twice() + 3 add() при w=4) на каждый вызов.
     * {@code null} в signing-режиме — Q недоступен.
     */
    private ECPoint[] cachedQTable;

    private int wnafW;

    /** Размер окна wNAF для G и Q. Значение 4 оптимально для 256-бит; для 512-бит рассмотреть 5. */
    private static final int WNAF_W_256 = 4;

    private static final int WNAF_W_512 = 5;

    /**
     * Создаёт signer с фабрикой дайджестов.
     * <p>
     * Фабрика вызывается один раз при каждом вызове {@link #generateSignature(byte[])}
     * для получения свежего экземпляра {@link Digest} внутри алгоритма RFC 6979.
     * Это исключает конфликт состояний между хэшированием сообщения во внешнем коде
     * и внутренним использованием дайджеста для выработки k.
     *
     * <p>Режим нонса - {@link NonceMode#DEFAULT} (гибридный), источник случайности -
     * {@code CryptoRandom.INSTANCE}. Раньше умолчание было детерминированным: подпись одного хэша
     * тем же ключом теперь каждый раз другая. Прежнее поведение задаётся явно:
     * {@code new ECDSASigner(factory, NonceMode.DETERMINISTIC, null)}.
     *
     * @param digestFactory фабрика, создающая новый экземпляр дайджеста (Streebog256 или Streebog512)
     */
    public ECDSASigner(Supplier<Digest> digestFactory) {
        this(digestFactory, NonceMode.DEFAULT, noiseSourceOf(NonceMode.DEFAULT, null));
    }

    /**
     * Создаёт signer с явным режимом нонса.
     *
     * <p>В детерминированном режиме источник случайности не используется и игнорируется. В
     * гибридном режиме на каждую подпись берутся {@code rolen} случайных байт; исключение
     * источника означает отказ подписи без отката на детерминизм. Слабый или повторяющийся
     * источник исключения не даёт: подпись при этом не хуже детерминированной, даже если
     * источник известен противнику, потому что закрытый ключ и число {@code e} остаются во
     * входе HMAC.
     *
     * @param digestFactory фабрика дайджестов, как в {@link #ECDSASigner(Supplier)}
     * @param mode          режим нонса
     * @param random        источник случайности для гибридного режима; {@code null} означает
     *                      {@link CryptoRandom#INSTANCE}
     * @throws IllegalArgumentException если фабрика или режим равны {@code null}
     */
    public ECDSASigner(Supplier<Digest> digestFactory, NonceMode mode, SecureRandom random) {
        this(digestFactory, mode, noiseSourceOf(mode, random));
    }

    private ECDSASigner(Supplier<Digest> digestFactory, NonceMode mode, NoiseSource noiseSource) {
        if (digestFactory == null)
            throw new IllegalArgumentException("digestFactory must not be null");
        if (mode == null) throw new IllegalArgumentException("mode must not be null");
        this.digestFactory = digestFactory;
        this.nonceMode = mode;
        this.noiseSource = mode == NonceMode.HEDGED ? noiseSource : null;
        if (mode == NonceMode.HEDGED && noiseSource == null)
            throw new IllegalArgumentException("noise source must not be null in hedged mode");
    }

    /** Только для тестов этого пакета: подписант с заданным источником добавки {@code Z}. */
    static ECDSASigner withNoiseSource(
            Supplier<Digest> digestFactory, NonceMode mode, NoiseSource noiseSource) {
        return new ECDSASigner(digestFactory, mode, noiseSource);
    }

    private static NoiseSource noiseSourceOf(NonceMode mode, SecureRandom random) {
        if (mode != NonceMode.HEDGED) {
            return null;
        }
        SecureRandom source = random != null ? random : CryptoRandom.INSTANCE;
        return source::nextBytes;
    }

    /**
     * Инициализирует подписанта ключом: закрытым для подписи или открытым для проверки.
     * Повторная инициализация затирает прежний ключ.
     *
     * @param forSigning {@code true} - подпись ({@link PrivateKeyParameters}), {@code false} -
     *                   проверка ({@link PublicKeyParameters})
     * @param params     параметры ключа; тип должен соответствовать режиму
     * @throws IllegalArgumentException если тип параметров не соответствует режиму
     * @throws IllegalStateException    если подписант уничтожен
     */
    public void init(boolean forSigning, CipherParameters params) {
        long stamp = stateLock.writeLock();
        try {
            // Проверка внутри блокировки: снаружи destroy() мог бы проскочить между проверкой и
            // захватом, и уничтоженный подписант был бы инициализирован заново
            if (destroyed) throw new IllegalStateException("ECDSASigner has been destroyed");
            // Объект считается не инициализированным, пока init не завершится успешно: при
            // отказе ниже старое состояние не должно остаться пригодным и тем более смешаться с
            // новым
            this.initialized = false;
            // Затираем старый ключ перед перезаписью — защита от переинициализации без destroy()
            if (this.dBytes != null) {
                Arrays.fill(this.dBytes, (byte) 0);
                this.dBytes = null;
            }
            // Тип параметров проверяется до присвоения режима и полей, чтобы неудачный init не
            // менял forSigning
            if (forSigning) {
                if (!(params instanceof PrivateKeyParameters)) {
                    throw new IllegalArgumentException(
                            "for signing, expected PrivateKeyParameters");
                }
                PrivateKeyParameters priv = (PrivateKeyParameters) params;
                this.forSigning = true;
                this.params = priv.getParams();
                this.q = null;
                // диапазон 0 < d < n гарантирует конструктор PrivateKeyParameters (класс final,
                // dBytes наружу отдаётся копией); повторная проверка через BigInteger оставляла
                // бы ещё одну неочищаемую копию d на каждую подпись, так как signHash
                // инициализирует подписанта заново
                this.dBytes = priv.getDBytes();
            } else {
                if (!(params instanceof PublicKeyParameters)) {
                    throw new IllegalArgumentException(
                            "for verification, expected PublicKeyParameters");
                }
                PublicKeyParameters pub = (PublicKeyParameters) params;
                this.forSigning = false;
                this.q = pub.getQ();
                this.params = pub.getParams();
                this.dBytes = null;
            }
            // Кешируем G (нужен лестнице при подписи); wNAF-таблицы строим только для проверки
            this.wnafW = (this.params.n.bitLength() > 256) ? WNAF_W_512 : WNAF_W_256;
            this.cachedG = ECPoint.affine(this.params.gx, this.params.gy, this.params);
            // Таблицы нужны только при проверке подписи (Shamir wNAF). Подпись идёт через
            // лестницу и cachedG, поэтому построение таблиц при подписи было бы лишней работой
            // на каждый вызов: Signature.sign создаёт подписанта заново.
            this.cachedGTable = forSigning ? null : this.params.gWnafTable(this.wnafW);
            this.cachedQTable = forSigning ? null : q.buildWNafTable(this.wnafW);
            this.initialized = true;
        } finally {
            // Без разблокировки в finally неудачный init заблокировал бы подписанта навсегда
            stateLock.unlockWrite(stamp);
        }
    }

    /**
     * Проверяет по локальной копии состояния, что подписант инициализирован именно для нужной
     * операции. До {@code init}, после {@code destroy()} и в неверном режиме нужен понятный отказ
     * вместо {@link NullPointerException} из недоинициализированных полей.
     */
    private static void requireReady(
            boolean snapDestroyed,
            boolean snapInitialized,
            boolean snapForSigning,
            boolean expectedForSigning) {
        if (snapDestroyed) throw new IllegalStateException("ECDSASigner has been destroyed");
        if (!snapInitialized) throw new IllegalStateException("ECDSASigner is not initialized");
        if (snapForSigning != expectedForSigning) {
            throw new IllegalStateException(
                    expectedForSigning
                            ? "ECDSASigner is initialized for verification, not for signing"
                            : "ECDSASigner is initialized for signing, not for verification");
        }
    }

    /**
     * Исключение для состояния, изменённого во время операции. Текст без ключевого материала:
     * только факт гонки.
     */
    private static IllegalStateException modifiedConcurrently() {
        return new IllegalStateException(
                "ECDSASigner state was modified concurrently during the operation");
    }

    /**
     * Вырабатывает подпись ГОСТ Р 34.10-2012 под готовым хэшем. В детерминированном режиме нонс k
     * зависит только от закрытого ключа, числа e из уравнения подписи и кривой, поэтому равному e
     * на той же кривой соответствует побайтно равная подпись. В гибридном режиме (умолчание) к
     * ним добавляется свежая случайная добавка Z, и подписи одного и того же хэша различаются.
     *
     * <p>Закрытый ключ, кривая и базовая точка копируются в локальные переменные один раз в начале
     * и затем сверяются с состоянием подписанта: если {@link #init} или {@link #destroy} изменили
     * его во время подписи, подпись не выдаётся. Если {@link #destroy} начался позже последней
     * сверки, выданная подпись валидна под копией прежнего ключа.
     *
     * <p>Нулевые {@code r} или {@code s} приводят к исключению, а не к повтору с новым {@code k},
     * как предписывает RFC 6979: вероятность события ≈2/n (от 2⁻²⁵⁵ до 2⁻²⁵³ на 256-битных и от
     * 2⁻⁵¹¹ до 2⁻⁵⁰⁹ на 512-битных кривых), отказ безопаснее тихого повтора.
     *
     * @param hash хэш сообщения длиной {@code ECParameters.hlen} кривой ключа (вывод Стрибога)
     * @return пара {@code [r, s]}
     * @throws IllegalArgumentException если хэш {@code null}, его длина не равна {@code hlen}
     *                                  кривой или размер дайджеста фабрики не совпадает с кривой
     *                                  (пара кривая-хэш должна соответствовать ГОСТ Р 34.10-2012)
     * @throws IllegalStateException    если подписант не инициализирован для подписи, уничтожен
     *                                  или его состояние изменено во время подписи
     */
    public BigInteger[] generateSignature(byte[] hash) {
        long stamp = stateLock.tryOptimisticRead();
        // Нулевая метка: прямо сейчас идёт init или destroy
        if (stamp == 0L) throw modifiedConcurrently();

        boolean snapDestroyed;
        boolean snapInitialized;
        boolean snapForSigning;
        ECParameters snapParams;
        ECPoint snapG;
        byte[] d = null;
        try {
            snapDestroyed = destroyed;
            snapInitialized = initialized;
            snapForSigning = forSigning;
            snapParams = params;
            snapG = cachedG;
            byte[] source = dBytes;
            // Ключ копируется только в режиме подписи: в остальных состояниях его нет, и
            // отсутствие должно дать понятный отказ ниже, а не ложную «гонку»
            if (snapForSigning && source != null) {
                d = source.clone();
            }
        } catch (RuntimeException e) {
            // Копия могла быть уже снята: затираем и здесь, чтобы порядок операций внутри снимка
            // не влиял на то, останется ли ключ незатёртым
            if (d != null) {
                Arrays.fill(d, (byte) 0);
            }
            throw modifiedConcurrently();
        }

        // Копия d затирается при любом выходе, в том числе при отказе из-за гонки
        try {
            // До сверки метки снимок мог быть рваным: ничего по нему не проверяем и не считаем,
            // иначе вызывающий получил бы ложное «не инициализирован» вместо отказа из-за гонки
            if (!stateLock.validate(stamp)) throw modifiedConcurrently();

            requireReady(snapDestroyed, snapInitialized, snapForSigning, true);
            if (d == null || snapParams == null || snapG == null) {
                throw new IllegalStateException("ECDSASigner is not initialized");
            }
            requireHashLength(hash, snapParams);
            requireNonZeroKey(d);
            BigInteger n = snapParams.n;

            BigInteger e = hashToE(hash, n);

            // k вырабатывается HMAC-DRBG по RFC 6979 (в гибридном режиме со свежей добавкой Z) и
            // является секретным эфемерным ключом.
            // Его компрометация раскрывает долговременный d, поэтому k·G считается лестницей
            // Монтгомери (без ветвлений по биту в арифметике точек), а не wNAF. Чтение бит k и
            // вычисление s идут через BigInteger и постоянного времени не дают, см. adr-01.
            // Вход генератора - именно число e из уравнения подписи, а не байты хэша: два хэша
            // с одинаковым k и разными e давали бы s1 - s2 = k·(e1 - e2) и раскрывали бы d.
            // Ключ и кривая для k и для s берутся из одной копии: k от одного ключа, а s от
            // другого дали бы пару «верная и неверная подпись с общим k», то есть раскрытие d.
            BigInteger k = generateK(e, d, snapParams);

            // Лестница Монтгомери без предвычисленных таблиц
            ECPoint rPoint = snapG.multiply(k);
            BigInteger r = rPoint.getX().mod(n);

            // см. crypto-gost-core/doc/adr/adr-01.md
            BigInteger dVal = new BigInteger(1, d);
            BigInteger s = r.multiply(dVal).add(k.multiply(e)).mod(n);

            if (r.signum() == 0 || s.signum() == 0) {
                throw new IllegalStateException("signature produced zero r or s");
            }

            // Если за время вычисления init или destroy изменили подписант, подпись не уходит
            if (!stateLock.validate(stamp)) throw modifiedConcurrently();
            return new BigInteger[] {r, s};
        } finally {
            if (d != null) {
                Arrays.fill(d, (byte) 0);
            }
        }
    }

    /**
     * Проверяет подпись ГОСТ Р 34.10-2012 под готовым хэшем.
     *
     * <p>Кривая и таблицы копируются в локальные переменные один раз в начале и затем
     * сверяются с состоянием подписанта. Если {@link #init} или {@link #destroy} изменили его во
     * время проверки, вердикт не выдаётся: бросается {@link IllegalStateException}, а не
     * {@code false}. Раньше в этом случае возвращался вердикт, посчитанный по смеси двух
     * состояний (например, таблицы одной кривой и модуль другой), и он мог быть неверным.
     *
     * @param hash хэш сообщения длиной {@code ECParameters.hlen} кривой ключа
     * @param r    компонента r подписи
     * @param s    компонента s подписи
     * @return {@code true}, если подпись верна; {@code false}, если r или s вне диапазона
     *         {@code 0 < x < n} либо подпись не сходится
     * @throws IllegalArgumentException если хэш {@code null} или его длина не равна {@code hlen}
     *                                  кривой
     * @throws IllegalStateException    если подписант не инициализирован для проверки,
     *                                  уничтожен или его состояние изменено во время проверки
     */
    public boolean verifySignature(byte[] hash, BigInteger r, BigInteger s) {
        long stamp = stateLock.tryOptimisticRead();
        if (stamp == 0L) throw modifiedConcurrently();

        boolean snapDestroyed;
        boolean snapInitialized;
        boolean snapForSigning;
        ECParameters snapParams;
        ECPoint[] snapGTable;
        ECPoint[] snapQTable;
        int snapWnafW;
        try {
            snapDestroyed = destroyed;
            snapInitialized = initialized;
            snapForSigning = forSigning;
            snapParams = params;
            snapGTable = cachedGTable;
            snapQTable = cachedQTable;
            snapWnafW = wnafW;
        } catch (RuntimeException e) {
            throw modifiedConcurrently();
        }

        // Утечки ключа здесь нет (таблицы заменяются целиком, а не затираются), но смесь двух
        // состояний (например, таблицы одной кривой и модуль другой) дала бы неверный вердикт
        if (!stateLock.validate(stamp)) throw modifiedConcurrently();

        requireReady(snapDestroyed, snapInitialized, snapForSigning, false);
        if (snapParams == null || snapGTable == null || snapQTable == null) {
            throw new IllegalStateException("ECDSASigner is not initialized");
        }
        requireHashLength(hash, snapParams);

        boolean verdict = checkSignature(hash, r, s, snapParams, snapGTable, snapQTable, snapWnafW);

        if (!stateLock.validate(stamp)) throw modifiedConcurrently();
        return verdict;
    }

    /** Вычисляет вердикт проверки по локальной копии состояния (RFC 7091 §6.2). */
    private static boolean checkSignature(
            byte[] hash,
            BigInteger r,
            BigInteger s,
            ECParameters params,
            ECPoint[] gTable,
            ECPoint[] qTable,
            int wnafW) {
        BigInteger n = params.n;
        // RFC 7091 §6.2, Step 1: проверить 0 < r < q, 0 < s < q
        if (r.signum() < 1 || r.compareTo(n) >= 0) return false;
        if (s.signum() < 1 || s.compareTo(n) >= 0) return false;

        BigInteger e = hashToE(hash, n);

        BigInteger v = e.modInverse(n);
        BigInteger z1 = s.multiply(v).mod(n);
        BigInteger z2 = n.subtract(r).multiply(v).mod(n);

        ECPoint rPoint = ECPoint.shamirMultiply(z1, gTable, z2, qTable, wnafW, params);

        if (rPoint.isInfinity()) return false;

        BigInteger R = rPoint.getX().mod(n);
        return R.equals(r);
    }

    /**
     * Валидный закрытый ключ нулевым быть не может (0 &lt; d &lt; n). Нулевая копия означает, что
     * ключ затёрт во время подписи. Сложение по всем байтам без раннего выхода: это ключевой
     * материал, и время проверки не должно зависеть от позиции первого ненулевого байта.
     */
    private static void requireNonZeroKey(byte[] d) {
        int accumulated = 0;
        for (byte b : d) {
            accumulated |= b;
        }
        if (accumulated == 0) {
            throw new IllegalStateException("ECDSASigner private key is zeroed");
        }
    }

    /**
     * Число e по RFC 7091 §5.3: хэш читается как целое с младшим байтом первым (little-endian),
     * приводится по модулю n; нулевое значение заменяется единицей.
     */
    private static BigInteger hashToE(byte[] hash, BigInteger n) {
        BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(n);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    /**
     * Хэш обязан иметь длину, заданную кривой: иначе число e и затравка нонса считаются от
     * усечённых или избыточных данных, а вызывающий получает подпись под не тем значением.
     */
    private static void requireHashLength(byte[] hash, ECParameters params) {
        if (hash == null || hash.length != params.hlen) {
            throw new IllegalArgumentException(
                    "Hash length must be "
                            + params.hlen
                            + " bytes for this curve, got "
                            + (hash == null ? "null" : hash.length));
        }
    }

    /**
     * Генерация нонса k по RFC 6979 §3.2, адаптированная под ГОСТ Р 34.10-2012, в одном из двух
     * режимов ({@link NonceMode}); по умолчанию гибридный.
     *
     * <p>Вместо {@code bits2octets(H)} на вход HMAC-DRBG подаётся {@code int2octets(e)}, где
     * {@code e} - то самое число, которое входит в уравнение подписи {@code s = r·d + k·e}.
     * В RFC 6979 оба значения выводятся из одного {@code bits2int(H)}, поэтому равная затравка
     * означает равное {@code e}. В ГОСТ число {@code e} читается из хэша младшим байтом вперёд,
     * и затравка из прямого порядка байт этого свойства не сохраняет: у двух хэшей затравка могла
     * бы совпасть при разных {@code e}, а из двух подписей с общим {@code k} вычисляется закрытый
     * ключ. С затравкой {@code int2octets(e)} равный {@code k} возможен только при равном
     * {@code e} (в гибридном режиме ещё и при равном {@code Z}); тогда подпись побайтно равна.
     *
     * <p>После {@code int2octets(e)} во вход HMAC добавлен идентификатор кривой: хэш канонической
     * записи её параметров (по образцу RFC 6979 §3.6, данные {@code k'} в конце входа). В
     * детерминированном режиме нонс поэтому зависит от тройки {@code (d, e, кривая)}, в
     * гибридном ещё от {@code Z}: один закрытый ключ на двух кривых одной длины при равном
     * {@code e} не даёт общий нонс. Использовать один ключ на разных кривых не следует, защита
     * лишь закрывает последствие такой ошибки.
     *
     * <p>Гибридный режим по образцу черновика draft-irtf-cfrg-det-sigs-with-noise-05 (истёк, RFC
     * не стал) добавляет свежие случайные байты {@code Z} длиной {@code rolen}, один и тот же
     * массив на шагах d и f: {@code V || 0x00/0x01 || Z || нули || int2octets(d) || нули ||
     * int2octets(e) || curveBinding}. Нули дополняют {@code V || 0x00 || Z} и {@code d} до
     * границы блока хэш-функции, поэтому {@code d} обрабатывается в новом блоке, после состояния,
     * зависящего от секретного {@code Z}. Отличия от черновика: {@code int2octets(e)} вместо
     * {@code bits2octets(h1)} и {@code curveBinding} последним. Вход гибридного режима длиннее
     * детерминированного (256 и 352 байта против 129 и 225), поэтому совпасть с ним не может.
     * Привязка к кривой остаётся в обоих режимах: при повторяющемся {@code Z} нонс определяется
     * только {@code (d, e, кривая)} и повторяется, как в детерминированном режиме (значения
     * {@code k} при этом с режимом {@link NonceMode#DETERMINISTIC} не совпадают из-за другого
     * входа HMAC), и без привязки один ключ на двух кривых дал бы общий нонс. Исключение
     * источника {@code Z}, в том числе посреди заполнения, означает отказ подписи; массив
     * {@code Z} затирается при любом исходе. Нулевые {@code r} или {@code s} - отказ, а не повтор
     * с новым нонсом: цикл с тем же {@code Z} давал бы тот же результат.
     *
     * <p>Ключ и кривая приходят аргументами из локальной копии, снятой в начале подписи, а не
     * читаются из полей: иначе {@link #init} или {@link #destroy} посреди подписи дали бы нонс от
     * одного ключа, а {@code s} - от другого. Переданный массив {@code d} метод не затирает: им
     * владеет вызывающий.
     *
     * @param e     число из уравнения подписи, 0 &lt; e &lt; n (нуль уже заменён на единицу)
     * @param d     закрытый ключ, big-endian ровно {@code rolen} байт; это гарантирует
     *              {@code PrivateKeyParameters}, поэтому лишний {@link BigInteger} со значением
     *              {@code d} не создаётся (длина здесь не проверяется)
     * @param curve параметры кривой из той же копии состояния, что и {@code d}
     * @return нонс {@code k}, 0 &lt; k &lt; n
     * @throws IllegalArgumentException если размер дайджеста фабрики не равен {@code hlen} кривой
     * @throws IllegalStateException    если источник {@code Z} бросил исключение времени выполнения
     *                                  или блок хэш-функции больше 64 байт (для Стрибога
     *                                  недостижимо)
     */
    private BigInteger generateK(BigInteger e, byte[] d, ECParameters curve) {
        BigInteger n = curve.n;
        Digest freshDigest = digestFactory.get();
        int hlen = freshDigest.getDigestSize();
        int rolen = (n.bitLength() + 7) / 8;

        // Кандидат k берётся из одного блока V длиной hlen, цикла наращивания RFC 6979 §3.2 h.2
        // здесь нет. Поэтому дайджест обязан быть ровно длины кривой: при коротком дайджесте k
        // был бы меньше порядка кривой с известными старшими битами, и ключ восстанавливается
        // решёточной атакой. Длинный дайджест не опасен, но не соответствует паре кривая-хэш
        // ГОСТ Р 34.10-2012 (длина хэша в байтах равна длине поля и порядка в байтах, см.
        // ECParameters.requireConsistentHlen; в битах длина порядка может быть меньше, у tc26a256
        // хэш и поле по 256 бит, порядок 255), поэтому отвергается так же. Проверка стоит здесь, а
        // не в init: фабрика уже вызвана, лишний объект Стрибога на каждую подпись не создаётся, а
        // режим проверки подписи фабрику не использует.
        if (hlen != curve.hlen) {
            throw new IllegalArgumentException(
                    "Digest size " + hlen + " does not match curve hash length " + curve.hlen);
        }

        // int2octets(e): 0 < e < n, поэтому число помещается ровно в rolen байт
        byte[] b1 = Pack.toFixedLengthBigEndian(e, rolen);
        // Публичный идентификатор кривой стоит последним: так RFC 6979 §3.6 добавляет данные
        // k'. Без него один d на двух кривых одной длины при равном e давал бы общий k
        byte[] curveBinding = curve.curveBinding();

        // Состояние V и K HMAC-DRBG живёт в этих двух массивах всё вычисление: каждый
        // HMAC пишет результат прямо в них (HMAC уже поглотил прежнее значение при init и
        // update), поэтому на каждый шаг не создаётся новый массив, а старое значение не
        // остаётся в куче. Оба затираются в finally.
        byte[] v = new byte[hlen];
        Arrays.fill(v, (byte) 0x01);

        byte[] k = new byte[hlen];

        // Длина блока нужна для дополнения нулями в гибридном режиме. Hmac её наружу не отдаёт, а
        // после передачи дайджест принадлежит Hmac (clear() его уничтожает), поэтому берём заранее
        int blockSize = freshDigest.getByteLength();
        Hmac hmac = new Hmac(freshDigest);
        // Случайная добавка Z: только в гибридном режиме, один и тот же массив на шагах d и f
        byte[] z = null;

        try {
            if (nonceMode == NonceMode.HEDGED) {
                // Массив присваивается до заполнения: при исключении источника посреди заполнения
                // finally затрёт уже записанную часть. Подпись при отказе источника не выдаётся
                // и на детерминизм не откатывается
                z = new byte[rolen];
                try {
                    noiseSource.fill(z);
                } catch (RuntimeException failure) {
                    throw new IllegalStateException("Nonce randomness source failed", failure);
                }
            }

            // Детерминированный режим (x в RFC 6979 и в черновике - это наш d):
            // K = HMAC(K, V || 0x00 || int2octets(d) || int2octets(e) || curveBinding), в RFC 6979
            // вместо int2octets(e) стоит bits2octets(h1), а curveBinding - данные по образцу k'
            // из §3.6. Гибридный режим по образцу черновика draft-irtf-cfrg-det-sigs-with-noise-05:
            // V || 0x00 || Z || нули || int2octets(d) || нули || int2octets(e) || curveBinding
            hmac.init(k);
            hmac.update(v, 0, v.length);
            hmac.update(SEPARATOR_D, 0, 1);
            absorbProvidedData(hmac, z, d, b1, curveBinding, hlen, blockSize);
            hmac.doFinal(k, 0);

            hmac.init(k);
            hmac.update(v, 0, v.length);
            hmac.doFinal(v, 0);

            // То же с разделителем 0x01 (шаг f), Z тот же, что на шаге d
            hmac.init(k);
            hmac.update(v, 0, v.length);
            hmac.update(SEPARATOR_F, 0, 1);
            absorbProvidedData(hmac, z, d, b1, curveBinding, hlen, blockSize);
            hmac.doFinal(k, 0);

            hmac.init(k);
            hmac.update(v, 0, v.length);
            hmac.doFinal(v, 0);

            while (true) {
                hmac.init(k);
                hmac.update(v, 0, v.length);
                hmac.doFinal(v, 0);

                BigInteger ki = bits2int(v, n.bitLength());
                if (ki.signum() > 0 && ki.compareTo(n) < 0) {
                    return ki;
                }

                // Кандидат вне [1, n-1]: обычный рабочий путь, а не редкий случай. Если n заметно
                // меньше 2^qlen, кандидат отбрасывается в половине подписей (cryptoProB, tc26a256,
                // tc26b512) или в 39% (cryptoProC); на cryptoProA, tc26a512 и tc26c512 почти
                // никогда.
                // Отброшенный кандидат не связан с итоговым k, поэтому число итераций (его можно
                // наблюдать по времени) итоговый k не раскрывает; остальные временные утечки через
                // BigInteger описаны в ADR 01. Повторная итерация RFC 6979 §3.2 h.3:
                // K = HMAC(K, V || 0x00)
                hmac.init(k);
                hmac.update(v, 0, v.length);
                hmac.update(SEPARATOR_D, 0, 1);
                hmac.doFinal(k, 0);

                hmac.init(k);
                hmac.update(v, 0, v.length);
                hmac.doFinal(v, 0);
            }
        } finally {
            Arrays.fill(k, (byte) 0);
            Arrays.fill(v, (byte) 0);
            Arrays.fill(b1, (byte) 0);
            if (z != null) {
                Arrays.fill(z, (byte) 0);
            }
            hmac.clear();
        }
    }

    /**
     * Подаёт в HMAC часть входа шагов d и f после разделителя. Детерминированный режим:
     * {@code int2octets(d) || int2octets(e) || curveBinding}. Гибридный: перед ними {@code Z} и
     * нули, дополняющие {@code V || 0x00 || Z} до границы блока хэш-функции, затем {@code d}
     * (занимает новый блок, поэтому обрабатывается после состояния, зависящего от секретного
     * {@code Z}) и нули до границы блока.
     */
    private static void absorbProvidedData(
            Hmac hmac,
            byte[] z,
            byte[] d,
            byte[] b1,
            byte[] curveBinding,
            int hlen,
            int blockSize) {
        if (z != null) {
            hmac.update(z, 0, z.length);
            // V (hlen байт), разделитель (1 байт) и Z уже поданы: дополнить до границы блока
            int zeroCount = zeroCountToBlockBoundary(hlen + 1 + z.length, blockSize);
            hmac.update(ZEROS, 0, zeroCount);
        }
        hmac.update(d, 0, d.length);
        if (z != null) {
            hmac.update(ZEROS, 0, zeroCountToBlockBoundary(d.length, blockSize));
        }
        hmac.update(b1, 0, b1.length);
        hmac.update(curveBinding, 0, curveBinding.length);
    }

    /** Наименьшее неотрицательное число нулей, дополняющее длину до кратной блоку. */
    private static int zeroCountToBlockBoundary(int length, int blockSize) {
        if (blockSize > ZEROS.length) {
            throw new IllegalStateException("Digest block size " + blockSize + " is too large");
        }
        return (blockSize - length % blockSize) % blockSize;
    }

    /** Кандидат в k из блока V по RFC 6979 §2.3.2: старшие qBitLength бит, прямой порядок байт. */
    private static BigInteger bits2int(byte[] block, int qBitLength) {
        BigInteger result = new BigInteger(1, block);
        int blockBits = block.length * 8;
        if (blockBits > qBitLength) {
            result = result.shiftRight(blockBits - qBitLength);
        }
        return result;
    }

    /**
     * Обнуляет ключевой материал (dBytes) в памяти.
     * После вызова объект непригоден для использования.
     */
    @Override
    public void destroy() {
        long stamp = stateLock.writeLock();
        try {
            if (!destroyed) {
                // Флаг ставится до затирания: подпись, начавшая читать ключ, увидит смену метки
                // в любом случае, а флаг делает отказ понятным
                destroyed = true;
                // Вторая линия защиты: при будущей ошибке в проверках подпись не должна
                // считаться с нулевым ключом
                initialized = false;
                if (dBytes != null) {
                    Arrays.fill(dBytes, (byte) 0);
                }
            }
        } finally {
            stateLock.unlockWrite(stamp);
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
