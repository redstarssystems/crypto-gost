package org.rssys.gost.pkix.cert;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Вспомогательные методы для построения ГОСТ-подписей в X.509-объектах.
 * Используется всеми builder'ами пакета {@code pkix.cert}.
 *
 * <p>Не имеет зависимостей от tls13. Выбор длины хэша —
 * через {@link GostOids#STREEBOG_256_HASH_LEN} (32) и {@link GostOids#STREEBOG_512_HASH_LEN} (64).
 * Паттерн идентичен {@code GostCertificate.verifySignature()} и {@code CrlVerifier}.</p>
 */
final class GostSignatureHelper {

    private GostSignatureHelper() {}

    private static final DateTimeFormatter GEN_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");

    /** Текущее время в UTC как GeneralizedTime строка ("yyyyMMddHHmmssZ"). */
    public static String nowGeneralizedTime() {
        return ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME);
    }

    /** {@link Instant} в UTC как GeneralizedTime строка ("yyyyMMddHHmmssZ"). */
    public static String formatGeneralizedTime(Instant instant) {
        return instant.atZone(ZoneOffset.UTC).format(GEN_TIME);
    }

    /** Текущее время + n лет в UTC как GeneralizedTime строка. */
    static String nowPlusYears(int years) {
        return ZonedDateTime.now(ZoneOffset.UTC).plusYears(years).format(GEN_TIME);
    }

    /**
     * Хэширование данных: Streebog-256 или Streebog-512.
     * Выбор — по {@code hlen} (32 -> 256, 64 -> 512).
     */
    static byte[] doHash(byte[] data, int hlen) {
        if (hlen == GostOids.STREEBOG_512_HASH_LEN) return Digest.digest512(data);
        return Digest.digest256(data);
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
     * AlgorithmIdentifier для ГОСТ-подписи X.509 (RFC 9215 §2,§4).
     * Использует id-tc26-gost3410-2012-256/512 (без digest в алгоритме —
     * хеш-функция определяется параметрами ключа неявно):
     * {@code SEQUENCE { signOid }}.
     */
    static byte[] buildAlgId(ECParameters params) {
        int hlen = params.hlen;
        String signOid =
                (hlen == GostOids.STREEBOG_512_HASH_LEN)
                        ? GostOids.SIGN_ALG_512
                        : GostOids.SIGN_ALG_256;
        return DerCodec.encodeSequence(DerCodec.encodeOid(signOid));
    }
}
