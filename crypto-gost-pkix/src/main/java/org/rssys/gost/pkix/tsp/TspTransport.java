package org.rssys.gost.pkix.tsp;

import java.io.IOException;

/**
 * Транспорт для отправки TimeStampReq на TSA (RFC 3161).
 *
 * <p>Интерфейс абстрагирует HTTP-взаимодействие, позволяя подменять
 * реализацию для тестирования (mock) или кастомной аутентификации
 * (прокси, mTLS к TSA).
 *
 * <p>Реализация по умолчанию: {@link JdkHttpTspTransport}.
 */
public interface TspTransport {

    /**
     * Отправляет TimeStampReq DER на TSA и возвращает TimeStampResp DER.
     *
     * @param tspRequestDer DER-байты TimeStampReq
     * @param tsaUrl        URL службы штампов времени
     * @return DER-байты TimeStampResp
     * @throws IOException              при сетевой ошибке
     * @throws IllegalArgumentException при некорректном URL
     */
    byte[] send(byte[] tspRequestDer, String tsaUrl) throws IOException;
}
