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
     * <p>Ошибки вызывающего ({@link IllegalArgumentException}) отличаются от ошибок удалённой
     * стороны ({@link IOException}): всё, что пришло от сервера, включая заголовок
     * {@code Location} перенаправления и тип содержимого ответа, даёт {@link IOException}, а не
     * непроверяемое исключение.
     *
     * @param tspRequestDer DER-байты TimeStampReq, не {@code null} и не пустые
     * @param tsaUrl        URL службы штампов времени, не {@code null} и не пустой
     * @return DER-байты TimeStampResp
     * @throws IOException              при сетевой ошибке, истечении срока, отказе сервера,
     *                                  неподдерживаемой схеме или внутреннем адресе
     * @throws IllegalArgumentException если аргумент пуст или адрес синтаксически некорректен
     */
    byte[] send(byte[] tspRequestDer, String tsaUrl) throws IOException;
}
