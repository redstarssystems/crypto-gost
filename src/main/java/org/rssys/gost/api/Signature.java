package org.rssys.gost.api;

import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.DigestSigner;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.util.function.Supplier;

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
 * <p>Нонс k вырабатывается детерминированно по RFC 6979 §3.2 с HMAC-Стрибог,
 * что исключает атаки на случайный нонс.
 *
 * <h3>Формат подписи:</h3>
 * Конкатенация r ∥ s в big-endian, каждая компонента длиной {@code ceil(n.bitLength()/8)} байт.
 * Итоговая длина: 64 байта для 256-битных кривых, 128 байт для 512-битных.
 *
 * <p>Без DER/ASN.1 кодирования — чистый бинарный формат.
 *
 * <h3>Thread-safety:</h3>
 * Все методы класса статические и потокобезопасны.
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
     * @param data данные для подписи (произвольная длина)
     * @param priv закрытый ключ
     * @return подпись r ∥ s (64 или 128 байт)
     * @throws IllegalStateException если закрытый ключ уничтожен
     */
    public static byte[] sign(byte[] data, PrivateKeyParameters priv) {
        ECParameters params = priv.getParams();
        Supplier<Digest> factory = digestFactory(params);

        ECDSASigner rawSigner = new ECDSASigner(factory);
        DigestSigner signer   = new DigestSigner(rawSigner, factory.get());

        signer.init(true, priv);
        signer.update(data, 0, data.length);
        return signer.sign();
    }


    /**
     * Проверяет подпись открытым ключом ГОСТ Р 34.10-2012.
     *
     * <p>Хэш-функция выбирается автоматически по кривой.
     *
     * @param data      данные, для которых проверяется подпись
     * @param signature подпись r ∥ s (64 или 128 байт)
     * @param pub       открытый ключ
     * @return {@code true} если подпись верна
     * @throws IllegalArgumentException если длина подписи не соответствует кривой
     *         или открытый ключ не является корректной точкой кривой
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKeyParameters pub) {
        ECParameters params = pub.getParams();
        Supplier<Digest> factory = digestFactory(params);

        ECDSASigner rawSigner = new ECDSASigner(factory);
        DigestSigner signer   = new DigestSigner(rawSigner, factory.get());

        signer.init(false, pub);
        signer.update(data, 0, data.length);
        return signer.verify(signature);
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
        ECParameters params = priv.getParams();
        // Q = d·G — скалярное умножение базовой точки на закрытый ключ
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint q = g.multiply(priv.getD()).normalize();
        return new PublicKeyParameters(q, params);
    }

    // -----------------------------------------------------------------------
    // Внутренние вспомогательные методы
    // -----------------------------------------------------------------------

    /**
     * Возвращает фабрику дайджестов по параметрам кривой:
     * hlen=32 → Стрибог-256, hlen=64 → Стрибог-512.
     * <p>
     * Используется в двух ролях:
     * <ul>
     *   <li>{@code factory.get()} — создаёт экземпляр дайджеста для {@link DigestSigner}
     *       (хэширование сообщения перед подписью)</li>
     *   <li>Сама фабрика передаётся в {@link ECDSASigner} для детерминированной
     *       генерации нонса k по RFC 6979 §3.2</li>
     * </ul>
     * Каждый вызов фабрики создаёт новый экземпляр — изоляция состояния гарантирована.
     * Соответствует требованию ГОСТ Р 34.10-2012 §5.
     */
    private static Supplier<Digest> digestFactory(ECParameters params) {
        return (params.hlen == 32) ? Streebog256::new : Streebog512::new;
    }
}
