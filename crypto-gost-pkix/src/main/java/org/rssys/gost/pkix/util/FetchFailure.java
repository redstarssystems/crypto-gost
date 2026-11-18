package org.rssys.gost.pkix.util;

import java.net.SocketTimeoutException;

/**
 * Причина отказа сетевой загрузки (CRL, OCSP): перечисление, а не текст.
 *
 * <p>Текст исключения HTTP-клиента или сервера недоверен и может нести адрес с учётными данными,
 * поэтому в журнал и в результаты загрузчиков идёт только эта причина. Вызывающий, который знает
 * сертификат и адрес, записывает одну запись на поглощённый отказ: серийный номер, очищенный адрес
 * и причина.
 */
public enum FetchFailure {
    /** Схема адреса не поддерживается загрузчиком (ошибка настройки). */
    UNSUPPORTED_SCHEME,
    /** Адрес не разбирается как URI. */
    BAD_ADDRESS,
    /** Адрес отвергнут проверкой допустимых адресов (внутренние сети, петля). */
    ADDRESS_BLOCKED,
    /** Перенаправление не разрешено или их слишком много. */
    REDIRECT_REJECTED,
    /** Ответ с кодом не 200. */
    HTTP_STATUS,
    /** Тип содержимого ответа не тот, что ожидался. */
    CONTENT_TYPE,
    /** Тело ответа больше допустимого предела. */
    TOO_LARGE,
    /** Вышел срок загрузки. */
    TIMEOUT,
    /** Сетевой сбой: обрыв, отказ в соединении, ошибка TLS. */
    NETWORK,
    /** Непредвиденный сбой самой библиотеки. */
    INTERNAL;

    /**
     * Причина по исключению загрузки. Тип исключения решает, текст не читается.
     *
     * @param failure исключение загрузчика
     * @return причина; сетевая ошибка, если тип не опознан
     */
    public static FetchFailure of(Throwable failure) {
        if (failure instanceof DeadlineExceededException
                || failure instanceof SocketTimeoutException) {
            return TIMEOUT;
        }
        if (failure instanceof BodyTooLargeException) {
            return TOO_LARGE;
        }
        if (failure instanceof java.io.IOException) {
            return NETWORK;
        }
        return INTERNAL;
    }
}
