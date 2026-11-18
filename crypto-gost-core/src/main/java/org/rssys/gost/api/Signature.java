package org.rssys.gost.api;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.DigestSigner;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.signature.SignatureCodec;

/**
 * API для электронной подписи ГОСТ Р 34.10-2012 (RFC 7091).
 *
 * <p>Алгоритм подписи:
 * <ul>
 *   <li>Для 256-битных кривых (hlen=32): хэш-функция Стрибог-256</li>
 *   <li>Для 512-битных кривых (hlen=64): хэш-функция Стрибог-512</li>
 * </ul>
 * Выбор дайджеста выполняется автоматически по параметрам кривой.
 *
 * <p>Нонс k вырабатывается через HMAC-Стрибог по схеме RFC 6979 §3.2 с поправками для ГОСТ:
 * затравкой служит число e из уравнения подписи, а в конец входа добавлен идентификатор кривой
 * (по образцу §3.6). По умолчанию режим гибридный ({@link NonceMode#DEFAULT}): во вход
 * подмешиваются свежие случайные байты, поэтому подпись одного и того же сообщения каждый раз
 * другая и все они верны. Это закрывает атаку сбоем по разности двух подписей одного сообщения
 * и усреднение тайминга по одному k; одиночный сбойный нонс и сбой в вычислении k·G не
 * закрываются (ADR 07). Воспроизводимость даёт явный {@link NonceMode#DETERMINISTIC}: перегрузки
 * {@code sign} и {@code signHash} с режимом. Один закрытый ключ на разных кривых не даёт общий
 * нонс в обоих режимах.
 *
 * <h3>Формат подписи:</h3>
 * X.509-формат: конкатенация s ∥ r в big-endian, каждая компонента длиной {@code ceil(n.bitLength()/8)} байт.
 * Итоговая длина: 64 байта для 256-битных кривых, 128 байт для 512-битных.
 *
 * <p>Без DER/ASN.1 кодирования — чистый бинарный формат.
 *
 * <h3>Thread-safety:</h3>
 * Все методы класса статические и потокобезопасны. Это не распространяется на уничтожение ключа:
 * {@code priv.destroy()} не должен пересекаться с операциями, которые используют этот ключ.
 *
 * <h3>Пример использования:</h3>
 * <pre>{@code
 * // Генерация ключевой пары
 * KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
 *
 * // Подпись
 * byte[] signature = Signature.sign(data, pair.getPrivate());
 *
 * // Верификация
 * boolean valid = Signature.verify(data, signature, pair.getPublic());
 *
 * // Очистка закрытого ключа после использования
 * pair.getPrivate().destroy();
 * }</pre>
 *
 * <p><b>Внимание!</b> Закрытый ключ не уничтожается автоматически.
 * После завершения работы с подписью вызывайте {@code priv.destroy()} явно,
 * предпочтительно в блоке {@code finally}.
 */
public final class Signature {

    private Signature() {}

    /**
     * Подписывает данные закрытым ключом ГОСТ Р 34.10-2012.
     *
     * <p>Хэш-функция выбирается автоматически по кривой:
     * Стрибог-256 для 256-бит кривых, Стрибог-512 для 512-бит кривых.
     *
     * <p>Выработанная подпись не проверяется открытым ключом: защиты от атак сбоем в ядре нет
     * (см. ADR 07). Если ключ хранится на устройстве, доступном атакующему физически, проверьте
     * результат вызовом {@link #verify(byte[], byte[], PublicKeyParameters)}.
     *
     * @param data данные для подписи (произвольная длина)
     * @param priv закрытый ключ
     * @return подпись s ∥ r (64 или 128 байт)
     * @throws IllegalStateException если закрытый ключ уничтожен
     */
    public static byte[] sign(byte[] data, PrivateKeyParameters priv) {
        return sign(data, priv, NonceMode.DEFAULT, null);
    }

    /**
     * Подписывает данные с явно заданным режимом нонса, см. {@link #sign(byte[],
     * PrivateKeyParameters)} и {@link NonceMode}.
     *
     * @param data данные для подписи (произвольная длина)
     * @param priv закрытый ключ
     * @param mode режим нонса
     * @return подпись s ∥ r (64 или 128 байт)
     * @throws IllegalArgumentException если режим равен {@code null}
     * @throws IllegalStateException    если закрытый ключ уничтожен
     */
    public static byte[] sign(byte[] data, PrivateKeyParameters priv, NonceMode mode) {
        return sign(data, priv, mode, null);
    }

    /**
     * Подписывает данные с явно заданными режимом нонса и источником случайности.
     *
     * <p>Источник нужен только гибридному режиму ({@link NonceMode#HEDGED}): из него берутся
     * свежие случайные байты, например, из аппаратного датчика. Он равноправен
     * {@code Signature.initSign(key, random)} в JCA. В детерминированном режиме источник
     * игнорируется и не вызывается. Слабый, повторяющийся или известный противнику источник
     * не раскрывает ключ: подпись при этом не хуже детерминированной. Отказ источника
     * (исключение) означает отказ подписи без отката на детерминизм.
     *
     * @param data   данные для подписи (произвольная длина)
     * @param priv   закрытый ключ
     * @param mode   режим нонса
     * @param random источник случайности для гибридного режима; {@code null} означает
     *               {@code CryptoRandom.INSTANCE}
     * @return подпись s ∥ r (64 или 128 байт)
     * @throws IllegalArgumentException если режим равен {@code null}
     * @throws IllegalStateException    если закрытый ключ уничтожен
     */
    public static byte[] sign(
            byte[] data, PrivateKeyParameters priv, NonceMode mode, SecureRandom random) {
        ECParameters params = priv.getParams();
        Supplier<Digest> factory = digestFactory(params);

        ECDSASigner rawSigner = new ECDSASigner(factory, mode, random);
        DigestSigner signer = new DigestSigner(rawSigner, factory.get());

        try {
            // init снимает копию закрытого ключа: любой отказ после него (например, data == null в
            // update) обязан пройти через destroy, иначе копия останется в куче
            signer.init(true, priv);
            signer.update(data, 0, data.length);
            return signer.sign();
        } finally {
            signer.destroy(); // обнуляет временную копию dBytes внутри ECDSASigner и хвост данных
        }
    }

    /**
     * Проверяет подпись открытым ключом ГОСТ Р 34.10-2012.
     *
     * <p>Хэш-функция выбирается автоматически по кривой.
     *
     * @param data      данные, для которых проверяется подпись
     * @param signature подпись s ∥ r (64 или 128 байт)
     * @param pub       открытый ключ
     * @return {@code true} если подпись верна; {@code false}, если она неверна или её длина не
     *         соответствует кривой
     * @throws IllegalArgumentException если открытый ключ не является корректной точкой кривой
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKeyParameters pub) {
        ECParameters params = pub.getParams();
        Supplier<Digest> factory = digestFactory(params);

        ECDSASigner rawSigner = new ECDSASigner(factory);
        DigestSigner signer = new DigestSigner(rawSigner, factory.get());

        try {
            signer.init(false, pub);
            signer.update(data, 0, data.length);
            return signer.verify(signature);
        } finally {
            signer.destroy(); // в дайджесте остаётся хвост проверяемого сообщения
        }
    }

    /**
     * Подписывает готовый хэш закрытым ключом ГОСТ Р 34.10-2012.
     *
     * <p>Используется когда хэш вычислен внешней системой (HSM, TSP, CMS)
     * и повторное хэширование нежелательно или невозможно.
     *
     * <p>Хэш должен соответствовать кривой:
     * <ul>
     *   <li>256-битные кривые (hlen=32): Стрибог-256, хэш 32 байта</li>
     *   <li>512-битные кривые (hlen=64): Стрибог-512, хэш 64 байта</li>
     * </ul>
     *
     * <p>Нонс k вырабатывается так же, как в {@link #sign(byte[], PrivateKeyParameters)}: через
     * HMAC-Стрибог по схеме RFC 6979 §3.2, затравкой служат число e из уравнения подписи и
     * идентификатор кривой; режим по умолчанию гибридный ({@link NonceMode#DEFAULT}), то есть
     * подпись одного хэша каждый раз другая. Из-за этого {@code signHash(digest(data))} и
     * {@code sign(data)} по умолчанию дают разные байты (обе подписи верны); совпадают они только
     * в детерминированном режиме.
     *
     * <p>Метод подписывает любой переданный хэш, то есть служит оракулом подписи: его нельзя
     * отдавать недоверенной стороне без авторизации и проверки того, что именно подписывается.
     *
     * <p>Выработанная подпись не проверяется открытым ключом: защиты от атак сбоем в ядре нет
     * (см. ADR 07). Для критичных подписей проверьте результат вызовом
     * {@link #verifyHash(byte[], byte[], PublicKeyParameters)}; в pkix так делает
     * {@code GostSignatureHelper.signHashChecked}.
     *
     * @param hash готовый хэш (длина должна быть равна hlen кривой)
     * @param priv закрытый ключ
     * @return подпись s ∥ r (64 или 128 байт)
     * @throws IllegalArgumentException если длина хэша не соответствует кривой
     * @throws IllegalStateException    если закрытый ключ уничтожен
     */
    public static byte[] signHash(byte[] hash, PrivateKeyParameters priv) {
        return signHash(hash, priv, NonceMode.DEFAULT, null);
    }

    /**
     * Подписывает готовый хэш с явно заданным режимом нонса, см.
     * {@link #signHash(byte[], PrivateKeyParameters)} и {@link NonceMode}.
     *
     * @param hash готовый хэш (длина должна быть равна hlen кривой)
     * @param priv закрытый ключ
     * @param mode режим нонса
     * @return подпись s ∥ r (64 или 128 байт)
     * @throws IllegalArgumentException если длина хэша не соответствует кривой или режим равен
     *                                  {@code null}
     * @throws IllegalStateException    если закрытый ключ уничтожен
     */
    public static byte[] signHash(byte[] hash, PrivateKeyParameters priv, NonceMode mode) {
        return signHash(hash, priv, mode, null);
    }

    /**
     * Подписывает готовый хэш с явно заданными режимом нонса и источником случайности.
     *
     * <p>Источник нужен только гибридному режиму ({@link NonceMode#HEDGED}): из него берутся
     * свежие случайные байты, например, из аппаратного датчика. Он равноправен
     * {@code Signature.initSign(key, random)} в JCA, через который его передаёт и провайдер. В
     * детерминированном режиме источник игнорируется и не вызывается. Длина хэша проверяется до
     * обращения к источнику. Слабый, повторяющийся или известный противнику источник не
     * раскрывает ключ: подпись при этом не хуже детерминированной. Отказ источника (исключение)
     * означает отказ подписи без отката на детерминизм.
     *
     * @param hash   готовый хэш (длина должна быть равна hlen кривой)
     * @param priv   закрытый ключ
     * @param mode   режим нонса
     * @param random источник случайности для гибридного режима; {@code null} означает
     *               {@code CryptoRandom.INSTANCE}
     * @return подпись s ∥ r (64 или 128 байт)
     * @throws IllegalArgumentException если длина хэша не соответствует кривой или режим равен
     *                                  {@code null}
     * @throws IllegalStateException    если закрытый ключ уничтожен
     */
    public static byte[] signHash(
            byte[] hash, PrivateKeyParameters priv, NonceMode mode, SecureRandom random) {
        ECParameters params = priv.getParams();
        validateHashLength(hash, params);

        Supplier<Digest> factory = digestFactory(params);
        ECDSASigner rawSigner = new ECDSASigner(factory, mode, random);
        try {
            rawSigner.init(true, priv);
            BigInteger[] sig = rawSigner.generateSignature(hash);
            return SignatureCodec.encode(sig[0], sig[1], params);
        } finally {
            rawSigner.destroy(); // обнуляет временную копию dBytes внутри ECDSASigner
        }
    }

    /**
     * Проверяет подпись готового хэша открытым ключом ГОСТ Р 34.10-2012.
     *
     * <p>Используется когда хэш вычислен внешней системой.
     * Хэш должен соответствовать кривой — см. {@link #signHash}.
     *
     * @param hash      готовый хэш (длина должна быть равна hlen кривой)
     * @param signature подпись s ∥ r (64 или 128 байт)
     * @param pub       открытый ключ
     * @return {@code true} если подпись верна; {@code false}, если она неверна или её длина не
     *         соответствует кривой
     * @throws IllegalArgumentException если длина хэша не соответствует кривой
     */
    public static boolean verifyHash(byte[] hash, byte[] signature, PublicKeyParameters pub) {
        ECParameters params = pub.getParams();
        validateHashLength(hash, params);

        Supplier<Digest> factory = digestFactory(params);
        ECDSASigner rawSigner = new ECDSASigner(factory);
        rawSigner.init(false, pub);

        if (!SignatureCodec.hasValidLength(signature, params)) {
            return false;
        }
        BigInteger[] sig = SignatureCodec.decode(signature, params);
        return rawSigner.verifySignature(hash, sig[0], sig[1]);
    }

    /**
     * Получает открытый ключ из закрытого: Q = d·G.
     *
     * <p>Используется когда есть только закрытый ключ и нужно восстановить
     * или проверить соответствующий открытый ключ.
     *
     * @param priv закрытый ключ
     * @return соответствующий открытый ключ
     * @throws IllegalStateException если закрытый ключ уничтожен
     */
    public static PublicKeyParameters derivePublicKey(PrivateKeyParameters priv) {
        return priv.derivePublicKey();
    }

    // -----------------------------------------------------------------------
    // Внутренние вспомогательные методы
    // -----------------------------------------------------------------------

    /**
     * Проверяет что длина хэша соответствует hlen кривой.
     *
     * @throws IllegalArgumentException если {@code hash} null или длина не совпадает с hlen
     */
    private static void validateHashLength(byte[] hash, ECParameters params) {
        if (hash == null || hash.length != params.hlen) {
            throw new IllegalArgumentException(
                    "Hash length must be "
                            + params.hlen
                            + " bytes for this curve, got "
                            + (hash == null ? "null" : hash.length));
        }
    }

    /**
     * Возвращает фабрику дайджестов по параметрам кривой:
     * hlen=32 -> Стрибог-256, hlen=64 -> Стрибог-512.
     * <p>
     * Используется в двух ролях:
     * <ul>
     *   <li>{@code factory.get()} — создаёт экземпляр дайджеста для {@link DigestSigner}
     *       (хэширование сообщения перед подписью)</li>
     *   <li>Сама фабрика передаётся в {@link ECDSASigner} для выработки нонса k (HMAC-DRBG по
     *       RFC 6979 §3.2, по умолчанию с подмешиванием случайных байт)</li>
     * </ul>
     * Каждый вызов фабрики создаёт новый экземпляр — изоляция состояния гарантирована.
     * Соответствует требованию ГОСТ Р 34.10-2012 §5.
     */
    private static Supplier<Digest> digestFactory(ECParameters params) {
        return (params.hlen == Streebog256.DIGEST_SIZE) ? Streebog256::new : Streebog512::new;
    }
}
