package org.rssys.gost.pkix.cert;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.SignatureCodec;
import org.rssys.gost.util.DerCodec;

/**
 * Вспомогательные методы для построения ГОСТ-подписей в X.509-объектах.
 * Используется builder'ами пакета {@code pkix.cert} и структурами CAdES-C/X в
 * {@code pkix.cms} (форматирование времени).
 *
 * <p>Не имеет зависимостей от tls13. Выбор длины хэша —
 * через {@link GostOids#STREEBOG_256_HASH_LEN} (32) и {@link GostOids#STREEBOG_512_HASH_LEN} (64).
 * Паттерн идентичен {@code GostCertificate.verifySignature()} и {@code CrlVerifier}.</p>
 */
public final class GostSignatureHelper {

    private GostSignatureHelper() {}

    /** GeneralizedTime: YYYYMMDDHHMMSSZ (RFC 5280 §4.1.2.5.2). */
    private static final DateTimeFormatter GEN_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    /** UTCTime: YYMMDDHHMMSSZ (RFC 5280 §4.1.2.5.1). */
    static final DateTimeFormatter UTC_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyMMddHHmmssX").withZone(ZoneOffset.UTC);

    /** Текущее время в UTC как GeneralizedTime строка ("yyyyMMddHHmmssZ"). */
    public static String nowGeneralizedTime() {
        return ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME);
    }

    /** {@link Instant} в UTC как GeneralizedTime строка ("yyyyMMddHHmmssZ"). */
    public static String formatGeneralizedTime(Instant instant) {
        return instant.atZone(ZoneOffset.UTC).format(GEN_TIME);
    }

    /** {@link Instant} в UTC как UTCTime строка ("yyMMddHHmmssZ"). */
    public static String formatUtcTime(Instant instant) {
        return instant.atZone(ZoneOffset.UTC).format(UTC_TIME_FORMATTER);
    }

    /** Текущее время + n лет в UTC как GeneralizedTime строка. */
    static String nowPlusYears(int years) {
        return ZonedDateTime.now(ZoneOffset.UTC).plusYears(years).format(GEN_TIME);
    }

    /**
     * Парсит строку ASN.1 TIME в {@link Instant}.
     * Принимает оба формата: UTCTime (13 символов: YYMMDDHHMMSSZ) и
     * GeneralizedTime (15 символов: YYYYMMDDHHMMSSZ). RFC 5280 §4.1.2.5.
     *
     * @param timeStr строка времени (UTCTime или GeneralizedTime, с суффиксом 'Z')
     * @return Instant времени в UTC
     * @throws IllegalArgumentException если формат неверен
     */
    public static Instant parseAsn1Time(String timeStr) {
        if (timeStr == null || !timeStr.endsWith("Z")) {
            throw new IllegalArgumentException("Time string must end with 'Z': " + timeStr);
        }
        int len = timeStr.length();
        DateTimeFormatter fmt;
        if (len == 13) {
            fmt = UTC_TIME_FORMATTER;
        } else if (len == 15) {
            fmt = GEN_TIME;
        } else {
            throw new IllegalArgumentException(
                    "Time string must be 13 or 15 chars (UTCTime or GeneralizedTime): " + timeStr);
        }
        try {
            return Instant.from(fmt.parse(timeStr));
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("Invalid time string: " + timeStr, e);
        }
    }

    /**
     * Хэширование данных: Streebog-256 или Streebog-512.
     * Выбор — по {@code hlen} (32 -> 256, 64 -> 512). Fail-closed: неизвестная длина -> исключение
     * (консистентно с {@link #digestAlgByHlen(int)}; без молчаливого дефолта на 256-бит).
     */
    static byte[] doHash(byte[] data, int hlen) {
        if (hlen == GostOids.STREEBOG_512_HASH_LEN) {
            return Digest.digest512(data);
        }
        if (hlen == GostOids.STREEBOG_256_HASH_LEN) {
            return Digest.digest256(data);
        }
        throw new IllegalArgumentException("Unsupported Streebog hash length: " + hlen);
    }

    /**
     * Хэширование фрагмента данных с offset/length.
     * Используется для хэширования TBS-части в пределах DER-массива без копирования при вызове.
     */
    static byte[] doHash(byte[] data, int off, int len, int hlen) {
        byte[] slice = new byte[len];
        System.arraycopy(data, off, slice, 0, len);
        return doHash(slice, hlen);
    }

    /**
     * Возвращает OID дайджеста Стрибог по размеру ключа ГОСТ Р 34.10-2012.
     *
     * <p>Единая точка сопоставления «размер ключа -> OID дайджеста»: убирает разрозненные
     * тернарные развилки {@code keySize == 512 ? ... : ...} в {@code pkix.cms}. Fail-closed:
     * критичный параметр берётся из явного размера ключа, неизвестное значение — исключение,
     * а не молчаливый дефолт.
     *
     * <p><b>Контракт исключений (общий для {@link #digestByOid} и {@link #digestAlgByHlen}):</b>
     * метод бросает unchecked {@link IllegalArgumentException}. На локально контролируемых параметрах
     * (размер ключа разобранного сертификата, явно заданный OID) это сигнал программистской ошибки —
     * fail-fast уместен. На недоверенном входе (OID/длина из чужого SignerInfo) вызывающий обязан
     * поймать его и транслировать в {@code PkixException} согласно контракту своего метода.
     *
     * @param keySize размер ключа в битах (256 или 512)
     * @return {@link GostOids#DIGEST_256} или {@link GostOids#DIGEST_512}
     * @throws IllegalArgumentException если размер ключа не поддерживается
     */
    public static String keySizeToDigestOid(int keySize) {
        if (keySize == 512) {
            return GostOids.DIGEST_512;
        }
        if (keySize == 256) {
            return GostOids.DIGEST_256;
        }
        throw new IllegalArgumentException("Unsupported GOST key size: " + keySize);
    }

    /**
     * Хэширует данные дайджестом, заданным OID (Стрибог-256/512).
     *
     * <p>Единая точка диспетчеризации по OID дайджеста. Fail-closed: неизвестный OID —
     * исключение, а не молчаливое приведение к 256-бит.
     *
     * @param digestOid OID дайджеста ({@link GostOids#DIGEST_256} или {@link GostOids#DIGEST_512})
     * @param data      данные для хэширования
     * @return хэш (32 или 64 байта)
     * @throws IllegalArgumentException если OID дайджеста не поддерживается
     */
    public static byte[] digestByOid(String digestOid, byte[] data) {
        if (GostOids.DIGEST_512.equals(digestOid)) {
            return Digest.digest512(data);
        }
        if (GostOids.DIGEST_256.equals(digestOid)) {
            return Digest.digest256(data);
        }
        throw new IllegalArgumentException("Unsupported digest algorithm OID: " + digestOid);
    }

    /**
     * Возвращает алгоритм Стрибог для инкрементального ({@link Digest}) хэширования по длине хэша.
     *
     * <p>Единая точка диспетчеризации по {@code hlen} для случаев потокового хэширования среза
     * DER без копирования. Fail-closed: неизвестная длина — исключение.
     *
     * @param hlen длина хэша в байтах (32 или 64)
     * @return {@link Digest.Algorithm#STREEBOG_256} или {@link Digest.Algorithm#STREEBOG_512}
     * @throws IllegalArgumentException если длина хэша не поддерживается
     */
    public static Digest.Algorithm digestAlgByHlen(int hlen) {
        if (hlen == GostOids.STREEBOG_512_HASH_LEN) {
            return Digest.Algorithm.STREEBOG_512;
        }
        if (hlen == GostOids.STREEBOG_256_HASH_LEN) {
            return Digest.Algorithm.STREEBOG_256;
        }
        throw new IllegalArgumentException("Unsupported Streebog hash length: " + hlen);
    }

    /**
     * AlgorithmIdentifier для ГОСТ-подписи X.509 (RFC 9215 §2,§4).
     * Использует id-tc26-gost3410-2012-256/512 (без digest в алгоритме —
     * хеш-функция определяется параметрами ключа неявно):
     * {@code SEQUENCE { signOid }}.
     */
    static byte[] buildAlgId(ECParameters params) {
        int hlen = params.hlen;
        String signOid =
                (hlen == GostOids.STREEBOG_512_HASH_LEN)
                        ? GostOids.SIGN_WITH_DIGEST_512
                        : GostOids.SIGN_WITH_DIGEST_256;
        return DerCodec.encodeSequence(DerCodec.encodeOid(signOid));
    }

    /**
     * Подписывает готовый хэш через {@link GostSigner} с обязательной fail-closed проверкой
     * результата: (1) длина подписи должна соответствовать кривой подписанта; (2) подпись
     * должна проверяться открытым ключом подписанта (self-verify).
     *
     * <p>Ловит неисправный внешний подписант (HSM-адаптер), вернувший усечённый буфер или
     * подпись не тем ключом, чем заявлено — иначе УЦ молча выпустил бы объект с мусорной
     * подписью, что обнаружилось бы только у relying party постфактум.
     *
     * @param hash   готовый хэш TBS-структуры
     * @param signer подписант
     * @return проверенная подпись в X.509-формате {@code s ∥ r}
     * @throws IllegalStateException если подпись неверной длины или не прошла self-verify
     */
    public static byte[] signHashChecked(byte[] hash, GostSigner signer) {
        byte[] sig = signer.signHash(hash);
        // Длину проверяем тем же кодеком, что задаёт формат в контракте GostSigner.signHash,
        // чтобы формула rolen не дублировалась и не разошлась при будущих правках.
        try {
            SignatureCodec.decode(sig, signer.getParams());
        } catch (IllegalArgumentException e) {
            // Перевыброс как IllegalStateException: это дефект внешнего подписанта
            // (вернул подпись неверной формы), а не ошибка аргумента вызывающего билдер.
            throw new IllegalStateException(
                    "GostSigner returned malformed signature: " + e.getMessage(), e);
        }
        if (!Signature.verifyHash(hash, sig, signer.getPublicKey())) {
            throw new IllegalStateException(
                    "GostSigner self-verification failed: signature does not match signer's"
                            + " declared public key");
        }
        return sig;
    }
}
