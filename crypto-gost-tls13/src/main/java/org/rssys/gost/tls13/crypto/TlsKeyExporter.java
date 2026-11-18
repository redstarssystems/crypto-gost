package org.rssys.gost.tls13.crypto;

import java.nio.charset.StandardCharsets;
import org.rssys.gost.api.Digest;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Экспорт ключевого материала TLS 1.3 (RFC 8446 §7.5).
 *
 * <pre>
 *   TLS-Exporter(label, context, length) =
 *       HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""),
 *                         "exporter", Hash(context), length)
 * </pre>
 *
 * Класс не хранит состояния: ключевое расписание к моменту вызова уже уничтожено, поэтому расчёт
 * идёт по одному только {@code exporter_master_secret}. Для ГОСТ-наборов RFC 9367 экспорт не
 * определяет; схема и хэш (Стрибог) взяты из RFC 8446 по аналогии с остальным ключевым
 * расписанием.
 */
public final class TlsKeyExporter {

    private TlsKeyExporter() {}

    /**
     * Вычисляет экспортируемое значение.
     *
     * @param exporterMasterSecret секрет экспорта (не затирается)
     * @param label метка назначения, не null и не пуста; в UTF-8 не длиннее
     *     {@link TlsConstants#EXPORTER_LABEL_MAX_LENGTH} байт; для привязки к каналу метки берутся
     *     из реестра IANA «TLS Exporter Labels»
     * @param context контекст; {@code null} и пустой массив дают одно значение (RFC 8446 §7.5);
     *     не длиннее {@link TlsConstants#EXPORTER_CONTEXT_MAX_LENGTH} байт
     * @param length длина результата от 1 до {@code 255 * hashLen}
     * @param hashLen длина хэша набора шифров
     * @return секретное значение; вызывающий обязан затереть его, когда оно больше не нужно
     * @throws IllegalArgumentException если аргументы выходят за допустимые пределы
     */
    public static byte[] export(
            byte[] exporterMasterSecret, String label, byte[] context, int length, int hashLen) {
        if (exporterMasterSecret == null) {
            throw new IllegalArgumentException("exporterMasterSecret must not be null");
        }
        if (label == null) {
            throw new IllegalArgumentException("label must not be null");
        }
        byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
        if (labelBytes.length == 0 || labelBytes.length > TlsConstants.EXPORTER_LABEL_MAX_LENGTH) {
            throw new IllegalArgumentException("label length outside range");
        }
        byte[] contextBytes = context != null ? context : HkdfStreebog.EMPTY_CONTEXT;
        if (contextBytes.length > TlsConstants.EXPORTER_CONTEXT_MAX_LENGTH) {
            throw new IllegalArgumentException("context length outside range");
        }
        if (length < 1 || length > TlsConstants.HKDF_EXPAND_MAX_BLOCKS * hashLen) {
            throw new IllegalArgumentException("length outside range");
        }

        // Метку строим сами: строковая перегрузка HkdfStreebog кодирует в US_ASCII и молча
        // подменила бы не-ASCII символы, а контракт JSSE требует UTF-8.
        byte[] prefixedLabel = new byte[HkdfStreebog.LABEL_PREFIX.length + labelBytes.length];
        System.arraycopy(
                HkdfStreebog.LABEL_PREFIX, 0, prefixedLabel, 0, HkdfStreebog.LABEL_PREFIX.length);
        System.arraycopy(
                labelBytes, 0, prefixedLabel, HkdfStreebog.LABEL_PREFIX.length, labelBytes.length);

        // Третий аргумент Derive-Secret здесь Hash(""), а не пустой массив; при пустом контексте
        // Hash(context) равен тому же значению.
        byte[] emptyHash = hash(HkdfStreebog.EMPTY_CONTEXT, hashLen);
        byte[] contextHash = hash(contextBytes, hashLen);
        byte[] labelSecret =
                HkdfStreebog.deriveSecret(exporterMasterSecret, prefixedLabel, emptyHash, hashLen);
        try {
            return HkdfStreebog.expandLabel(
                    labelSecret, HkdfStreebog.PREFIXED_EXPORTER, contextHash, length, hashLen);
        } finally {
            TlsUtils.wipeArray(labelSecret);
        }
    }

    /** Хэш Стрибог по длине хэша набора шифров; другие длины отвергает HKDF ниже по вызову. */
    private static byte[] hash(byte[] data, int hashLen) {
        return hashLen == TlsConstants.STREEBOG_512_HASH_LEN
                ? Digest.digest512(data)
                : Digest.digest256(data);
    }
}
