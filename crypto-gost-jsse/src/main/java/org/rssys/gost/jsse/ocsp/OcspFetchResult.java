package org.rssys.gost.jsse.ocsp;

import org.rssys.gost.pkix.util.FetchFailure;

/**
 * Результат OCSP-запроса с опциональным nonce (RFC 8954) и причиной отказа.
 *
 * <p>Причина нужна вызывающему, который знает сертификат: загрузчик сам в журнал не пишет, а
 * менеджер доверия записывает один раз серийный номер, очищенный адрес и причину. Причина это
 * перечисление, а не текст: текст исключения HTTP-клиента недоверен.
 *
 * @param response DER-encoded OCSPResponse (null при ошибке)
 * @param nonce    nonce из запроса (null если nonce не использовался)
 * @param failure  причина отказа или null, если ответ получен либо загрузчик причину не сообщает
 */
public record OcspFetchResult(byte[] response, byte[] nonce, FetchFailure failure) {

    /**
     * Результат без причины отказа: успешный ответ либо «ответа нет» от загрузчика, не
     * сообщающего причину.
     */
    public OcspFetchResult(byte[] response, byte[] nonce) {
        this(response, nonce, null);
    }

    /** Отказ с известной причиной: ответа и nonce нет. */
    public static OcspFetchResult failed(FetchFailure failure) {
        return new OcspFetchResult(null, null, failure);
    }
}
