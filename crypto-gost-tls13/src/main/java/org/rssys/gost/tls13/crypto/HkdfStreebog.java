package org.rssys.gost.tls13.crypto;

import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.TlsConstants;
import java.nio.charset.StandardCharsets;

/**
 * HKDF на основе HMAC-Streebog (RFC 5869) для TLS 1.3 (RFC 8446 §7.1).
 * <p>
 * В отличие от KDF_GOST_R_3411_2012_256 (RFC 7836, используется только в TLSTREE),
 * TLS 1.3 key schedule использует стандартный HKDF-Extract/Expand с HMAC-Streebog:
 * <pre>
 *   PRK = HMAC-Streebog(salt, IKM)
 *   OKM = T(1) || T(2) || ... || T(n)
 *   T(i) = HMAC-Streebog(PRK, T(i-1) || info || i)
 * </pre>
 * Поддержка Streebog-256 (32-байтный хеш) и Streebog-512 (64-байтный).
 *
 * @see KdfGostR3411_2012_256 TLSTREE-специфичный KDF
 */
public final class HkdfStreebog {

    private HkdfStreebog() {}

    // ========================================================================
    // Precomputed "tls13 " + label (RFC 8446 §7.1) — одна аллокация при
    // class loading, избегает конкатенации строк и кодирования на каждый вызов.
    // ========================================================================
    public static final byte[] PREFIXED_DERIVED          = "tls13 derived".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_S_HS_TRAFFIC     = "tls13 s hs traffic".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_C_HS_TRAFFIC     = "tls13 c hs traffic".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_S_AP_TRAFFIC     = "tls13 s ap traffic".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_C_AP_TRAFFIC     = "tls13 c ap traffic".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_KEY              = "tls13 key".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_IV               = "tls13 iv".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_FINISHED         = "tls13 finished".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_RES_BINDER       = "tls13 res binder".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_RES_MASTER       = "tls13 res master".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_RESUMPTION       = "tls13 resumption".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PREFIXED_TRAFFIC_UPD      = "tls13 traffic upd".getBytes(StandardCharsets.US_ASCII);
    /** Пустой контекст — заменяет new byte[0] в caller'ах. Длина 0 — System.arraycopy no-op. */
    public static final byte[] EMPTY_CONTEXT             = new byte[0];
    /** ZERO_SALT для HKDF-Extract, когда salt не передан — одна аллокация при class loading. */
    private static final byte[] ZERO_SALT_256            = new byte[32];
    private static final byte[] ZERO_SALT_512            = new byte[64];

    /**
     * HKDF-Extract: PRK = HMAC-Streebog(salt, IKM)
     *
     * @param salt    опциональная соль (null или пусто -> hashLen нулевых байт)
     * @param ikm     входной ключевой материал
     * @param hashLen 32 для Streebog-256, 64 для Streebog-512
     * @return псевдослучайный ключ длиной hashLen байт
     */
    public static byte[] extract(byte[] salt, byte[] ikm, int hashLen) {
        if (ikm == null) {
            throw new IllegalArgumentException("IKM must not be null");
        }
        if (hashLen != TlsConstants.STREEBOG_256_HASH_LEN && hashLen != TlsConstants.STREEBOG_512_HASH_LEN) {
            throw new IllegalArgumentException("hashLen must be 32 or 64");
        }
        if (salt == null || salt.length == 0) {
            salt = (hashLen == 64) ? ZERO_SALT_512 : ZERO_SALT_256;
        }
        Hmac hmac = newHmac(hashLen);
        hmac.init(salt);
        hmac.update(ikm, 0, ikm.length);
        byte[] prk = new byte[hashLen];
        hmac.doFinal(prk, 0);
        hmac.clear();
        return prk;
    }

    /**
     * HKDF-Expand (RFC 5869 §2.3): раунды T(i) до достижения нужной длины.
     * <pre>
     *   T(0) = empty
     *   T(i) = HMAC-Streebog(PRK, T(i-1) || info || i)
     *   OKM  = T(1) || T(2) || ... || T(n)
     * </pre>
     *
     * @param prk     псевдослучайный ключ (из HKDF-Extract)
     * @param info    опциональный контекст (может быть пустым)
     * @param length  желаемая длина выходных данных в байтах
     * @param hashLen 32 для Streebog-256, 64 для Streebog-512
     * @return выходной ключевой материал запрошенной длины
     */
    public static byte[] expand(byte[] prk, byte[] info, int length, int hashLen) {
        if (prk == null) {
            throw new IllegalArgumentException("PRK must not be null");
        }
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative");
        }
        if (hashLen != TlsConstants.STREEBOG_256_HASH_LEN && hashLen != TlsConstants.STREEBOG_512_HASH_LEN) {
            throw new IllegalArgumentException("hashLen must be 32 or 64");
        }
        if (length == 0) {
            return EMPTY_CONTEXT;
        }
        int n = (length + hashLen - 1) / hashLen;
        if (n > 255) {
            throw new IllegalArgumentException("Output length too large for given hashLen");
        }
        if (info == null) {
            info = EMPTY_CONTEXT;
        }
        byte[] result = new byte[length];
        // T(0) = empty для первой итерации (i == 1: hmac.update не вызывается).
        // t = new byte[hashLen] сразу: переиспользуемый буфер, аллокация одна,
        // а не n × new byte[hashLen] как было.
        byte[] t = new byte[hashLen];

        // Hmac один на весь цикл. doFinal() в конце сам сбрасывает digest и
        // подмешивает inputPad — следующий update() начинает новую HMAC-операцию
        // без init(). hmac.clear() только после цикла: inputPad/outputPad — это
        // производные от prk, который сам производный от ECDHE shared secret
        // (уже затёрт). Время жизни в heap ограничено expand().
        Hmac hmac = newHmac(hashLen);
        hmac.init(prk);

        for (int i = 1; i <= n; i++) {
            if (i > 1) {
                hmac.update(t, 0, hashLen);   // T(i-1) для i >= 2
            }
            hmac.update(info, 0, info.length);
            hmac.update((byte) i);

            hmac.doFinal(t, 0);                // перезаписывает t = T(i)

            int copyLen = Math.min(hashLen, length - (i - 1) * hashLen);
            System.arraycopy(t, 0, result, (i - 1) * hashLen, copyLen);
        }

        hmac.clear();
        // t не зануляем: на каждой итерации цикла doFinal перезаписывает его целиком.
        // После выхода из метода t — локальная переменная, становится unreachable.
        return result;
    }

    /**
     * TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
     * <p>
     * Оборачивает {@link #expand} в структуру HkdfLabel:
     * <pre>
     *   HkdfLabel =
     *     length(2) || label_len(1) || prefixedLabel || context_len(1) || context
     * </pre>
     * Принимает готовый prefixed label (с префиксом "tls13 ") — избегает
     * конкатенации строк и кодирования в ASCII на каждый вызов.
     *
     * @param secret         секретный ключ (PRK)
     * @param prefixedLabel  метка с префиксом "tls13 " (напр. {@link #PREFIXED_DERIVED})
     * @param context        контекст (транскрипт-хэш для Derive-Secret, null = пусто)
     * @param length         желаемая длина выхода
     * @param hashLen        32 для Streebog-256, 64 для Streebog-512
     * @return выходной ключевой материал
     */
    public static byte[] expandLabel(byte[] secret, byte[] prefixedLabel, byte[] context,
                                     int length, int hashLen) {
        if (secret == null) {
            throw new IllegalArgumentException("secret must not be null");
        }
        if (prefixedLabel == null) {
            throw new IllegalArgumentException("prefixedLabel must not be null");
        }
        byte[] ctx = (context != null) ? context : EMPTY_CONTEXT;

        // HkdfLabel: длина(2) + длина_метки(1) + метка + длина_контекста(1) + контекст
        byte[] hkdfLabel = new byte[2 + 1 + prefixedLabel.length + 1 + ctx.length];

        hkdfLabel[0] = (byte) (length >>> 8);
        hkdfLabel[1] = (byte) (length);

        hkdfLabel[2] = (byte) prefixedLabel.length;
        System.arraycopy(prefixedLabel, 0, hkdfLabel, 3, prefixedLabel.length);

        int off = 3 + prefixedLabel.length;
        hkdfLabel[off] = (byte) ctx.length;
        if (ctx.length > 0) {
            System.arraycopy(ctx, 0, hkdfLabel, off + 1, ctx.length);
        }

        return expand(secret, hkdfLabel, length, hashLen);
    }

    /**
     * TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1), версия со строковой меткой.
     * <p>
     * Делегирует {@link #expandLabel(byte[], byte[], byte[], int, int)} предварительно
     * сформировав "tls13 " + label. Сохранён для обратной совместимости (тесты, бенчмарки).
     * Для production-кода используйте перегрузку с готовым {@code byte[] prefixedLabel}.
     *
     * @param secret   секретный ключ (PRK)
     * @param label    метка без префикса (напр. "derived", "c ap traffic")
     * @param context  контекст (транскрипт-хэш для Derive-Secret, null = пусто)
     * @param length   желаемая длина выхода
     * @param hashLen  32 для Streebog-256, 64 для Streebog-512
     * @return выходной ключевой материал
     */
    public static byte[] expandLabel(byte[] secret, String label, byte[] context,
                                     int length, int hashLen) {
        if (secret == null) {
            throw new IllegalArgumentException("secret must not be null");
        }
        if (label == null) {
            throw new IllegalArgumentException("label must not be null");
        }
        byte[] prefixedLabel = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        return expandLabel(secret, prefixedLabel, context, length, hashLen);
    }

    /**
     * TLS 1.3 Derive-Secret (RFC 8446 §7.1).
     * <pre>
     *   Derive-Secret(Secret, Label, Messages) =
     *       HKDF-Expand-Label(Secret, Label, Transcript-Hash, Hash.length)
     * </pre>
     * Принимает готовый prefixed label (с префиксом "tls13 ").
     *
     * @param secret        секрет (Early, Handshake, Master)
     * @param prefixedLabel метка с префиксом "tls13 " (напр. {@link #PREFIXED_DERIVED})
     * @param transcriptHash Transcript-Hash рукопожатия
     * @param hashLen       32 для Streebog-256, 64 для Streebog-512
     * @return производный ключ длиной hashLen
     */
    public static byte[] deriveSecret(byte[] secret, byte[] prefixedLabel,
                                      byte[] transcriptHash, int hashLen) {
        return expandLabel(secret, prefixedLabel, transcriptHash, hashLen, hashLen);
    }

    /**
     * TLS 1.3 Derive-Secret (RFC 8446 §7.1), версия со строковой меткой.
     * <p>
     * Делегирует {@link #deriveSecret(byte[], byte[], byte[], int)}. Сохранён
     * для обратной совместимости (тесты, бенчмарки).
     *
     * @param secret        секрет (Early, Handshake, Master)
     * @param label         метка без префикса (напр. "c hs traffic")
     * @param transcriptHash Transcript-Hash рукопожатия
     * @param hashLen       32 для Streebog-256, 64 для Streebog-512
     * @return производный ключ длиной hashLen
     */
    public static byte[] deriveSecret(byte[] secret, String label,
                                      byte[] transcriptHash, int hashLen) {
        return deriveSecret(secret, ("tls13 " + label).getBytes(StandardCharsets.US_ASCII),
                            transcriptHash, hashLen);
    }

    /**
     * Создаёт HMAC-Streebog по длине хеша.
     * hashLen=32 → Streebog-256, hashLen=64 → Streebog-512.
     *
     * @param hashLen длина хеша (32 или 64)
     * @return HMAC-Streebog
     */
    public static Hmac newHmac(int hashLen) {
        if (hashLen == TlsConstants.STREEBOG_256_HASH_LEN) {
            return new Hmac(new Streebog256());
        }
        return new Hmac(new Streebog512());
    }
}
