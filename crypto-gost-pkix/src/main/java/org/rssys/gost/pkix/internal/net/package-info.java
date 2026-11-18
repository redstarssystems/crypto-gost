/**
 * Внутренняя реализация HTTP-загрузки для загрузчиков OCSP и CRL и транспортов TSP: общий срок на
 * запрос, предел размера, перенаправления с проверкой схемы и SSRF на каждом переходе, безопасный
 * вывод адресов и текста от сервера (через {@code org.rssys.gost.util.SafeText}), движки на {@code HttpClient} и {@code HttpURLConnection}.
 *
 * <p><b>Это не публичный API.</b> Классы публичны только потому, что их используют пакеты
 * {@code org.rssys.gost.jsse.ocsp} и {@code org.rssys.gost.jsse.crl} (модуль jsse) и
 * {@code org.rssys.gost.pkix.tsp}, лежащие в других пакетах и модулях. Они могут меняться или
 * исчезнуть в любой версии без предупреждения и без записи в CHANGELOG; не используйте их в своём
 * коде. Публичные контракты - интерфейсы {@code OcspFetcher}, {@code CrlFetcher} и
 * {@code TspTransport} и их штатные реализации.
 */
package org.rssys.gost.pkix.internal.net;
