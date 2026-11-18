package org.rssys.gost.pkix.internal.net;

import java.io.IOException;

/**
 * Транспорт загрузки: выполняет запрос и возвращает исход ({@link FetchOutcome}). Для
 * {@code HttpClient} это экземпляр {@link JdkHttpFetch}, для {@code HttpURLConnection} подставляется
 * ссылка на статический метод {@link UrlConnectionFetch#execute(FetchRequest)}. Внутренний тип, не
 * часть публичного API библиотеки.
 */
@FunctionalInterface
public interface FetchTransport {

    /**
     * Выполняет запрос.
     *
     * @param request запрос
     * @return исход загрузки: тело, «не изменилось» или причина отказа
     * @throws IOException при сетевой ошибке, превышении срока или размера
     */
    FetchOutcome execute(FetchRequest request) throws IOException;
}
