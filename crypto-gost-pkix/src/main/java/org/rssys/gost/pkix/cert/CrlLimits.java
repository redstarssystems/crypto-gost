package org.rssys.gost.pkix.cert;

/**
 * Пределы размера и числа записей CRL, общие для всех путей проверки.
 *
 * <p>Пределы защищают от CRL, который разорвёт память: разобранный список отозванных занимает
 * заметно больше места, чем его DER (замер на CRL ФНС даёт кучу порядка 825 МБ). Объект
 * неизменяемый и один для всех путей: прямой {@link CrlVerifier}, {@link ChainValidator}, CMS и
 * CAdES, JSSE. Значения по умолчанию - {@value GostCrl#DEFAULT_MAX_REVOKED_ENTRIES} записей и
 * {@value GostCrl#DEFAULT_MAX_CRL_SIZE} байт.</p>
 *
 * <p><b>Что настраивать крупному УЦ.</b> CRL ФНС содержит 829 548 записей (83% предела записей) и
 * занимает 38,9 МиБ (61% предела размера), поэтому первым упрётся счётчик записей. Предел записей
 * поднимают вместе с пределом размера: 5 млн записей занимают около 245 МБ DER и в 64 МиБ не
 * поместятся. Превышение любого предела - отказ для всех сертификатов этого УЦ при любой
 * политике, а не «адрес недоступен»: проверка отзыва не пропускается, ошибка имеет причину
 * {@link PkixException.Reason#CRL_LIMIT_EXCEEDED}. Значения по умолчанию не менялись; повышать их
 * нужно осознанно, с запасом кучи под разбор.</p>
 *
 * <p>Встроенные в CMS и CAdES-X Long CRL, кроме этих пределов, ограничены 8 штуками и суммой
 * 32 МиБ: это отдельный предел на недоверенный вход, и {@code CrlLimits} его не меняет.</p>
 *
 * @param maxSize           наибольший размер CRL в DER, байт (больше нуля)
 * @param maxRevokedEntries наибольшее число отозванных записей (больше нуля)
 */
public record CrlLimits(int maxSize, int maxRevokedEntries) {

    /** Пределы по умолчанию. */
    public static final CrlLimits DEFAULT =
            new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);

    /**
     * @throws IllegalArgumentException если любое значение не больше нуля: такой предел отвергал
     *     бы любой непустой CRL, а ошибка проявилась бы только на первом соединении
     */
    public CrlLimits {
        if (maxSize <= 0) {
            throw new IllegalArgumentException("maxSize must be positive, got " + maxSize);
        }
        if (maxRevokedEntries <= 0) {
            throw new IllegalArgumentException(
                    "maxRevokedEntries must be positive, got " + maxRevokedEntries);
        }
    }

    /**
     * @param newMaxSize новый предел размера в байтах
     * @return копия с другим пределом размера
     */
    public CrlLimits withMaxSize(int newMaxSize) {
        return new CrlLimits(newMaxSize, maxRevokedEntries);
    }

    /**
     * @param newMaxRevokedEntries новый предел числа записей
     * @return копия с другим пределом числа записей
     */
    public CrlLimits withMaxRevokedEntries(int newMaxRevokedEntries) {
        return new CrlLimits(maxSize, newMaxRevokedEntries);
    }

    /**
     * Проверяет размер CRL до создания {@link GostCrl}.
     *
     * <p>Одна проверка для всех путей проверки: конструктор {@code GostCrl} остаётся
     * низкоуровневым и бросает {@code IllegalArgumentException}, текст которой разбирать нельзя,
     * поэтому причина {@link PkixException.Reason#CRL_LIMIT_EXCEEDED} выставляется здесь.</p>
     *
     * @param crlDer DER CRL; {@code null} - нечего проверять, отказ на пустой ввод остаётся за
     *               вызывающим кодом
     * @throws PkixException с причиной {@code CRL_LIMIT_EXCEEDED}, если размер больше
     *                       {@link #maxSize()}
     */
    public void requireSize(byte[] crlDer) throws PkixException {
        if (crlDer != null && crlDer.length > maxSize) {
            throw new PkixException(
                    PkixException.Reason.CRL_LIMIT_EXCEEDED,
                    "CRL size exceeds the configured limit: size is "
                            + crlDer.length
                            + " bytes, limit is "
                            + maxSize
                            + " bytes");
        }
    }
}
