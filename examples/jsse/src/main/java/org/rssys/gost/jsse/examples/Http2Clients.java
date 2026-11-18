package org.rssys.gost.jsse.examples;

import java.util.List;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.TlsVersion;

/**
 * Клиент OkHttp для HTTP/2 поверх ГОСТ TLS.
 * <p>
 * OkHttp предлагает {@code h2} через ALPN и сам разбирает кадры HTTP/2, то есть это независимая
 * от Netty и Jetty реализация протокола: на ней проверяются серверы примеров.
 */
public final class Http2Clients {

    private Http2Clients() {}

    /**
     * Создаёт клиент OkHttp, который предлагает HTTP/2 и доверяет УЦ примеров.
     *
     * @param helper сертификаты и менеджеры примеров
     * @return клиент OkHttp
     */
    public static OkHttpClient okHttp(ExamplesCertHelper helper) {
        return new OkHttpClient.Builder()
                .sslSocketFactory(
                        helper.getSslContext().getSocketFactory(), helper.createTrustManager())
                // ConnectionSpec без фильтрации наборов шифров: по умолчанию OkHttp пропускает
                // только JDK-наборы и отсёк бы ГОСТ
                .connectionSpecs(
                        List.of(
                                new ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                                        .allEnabledCipherSuites()
                                        .tlsVersions(TlsVersion.TLS_1_3)
                                        .build()))
                // Имя узла сверяет GostX509TrustManager внутри рукопожатия; верификатор OkHttp
                // не знает ГОСТ-сертификаты
                .hostnameVerifier((host, session) -> true)
                // OkHttp требует http/1.1 в списке при ALPN; сервер без h2 уйдёт на HTTP/1.1, и
                // тесты проверяют Response.protocol() == HTTP_2, а не успех запроса
                .protocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .build();
    }
}
