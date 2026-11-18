package org.rssys.gost.jsse.examples.netty;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.jsse.examples.Http2Clients;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;

/**
 * HTTP/2 в Netty поверх ГОСТ TLS: независимый клиент OkHttp (своя реализация HTTP/2) против
 * сервера на {@code Http2FrameCodec}. TLS на обеих сторонах библиотеки.
 */
@DisplayName("Netty: HTTP/2 поверх ГОСТ TLS (OkHttp <-> Netty)")
class NettyHttp2OkHttpTest {

    @Test
    @DisplayName("OkHttp получает ответ сервера Netty по HTTP/2")
    void okHttpTalksHttp2ToNetty() throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();
        GostSslContext serverContext =
                GostSslContextBuilder.forServer(helper.createKeyManager())
                        .applicationProtocols("h2", "http/1.1")
                        .build();

        try (Http2EchoServer server = Http2EchoServer.start(serverContext)) {
            assertPing(Http2Clients.okHttp(helper), server.port());
        }
    }

    private static void assertPing(OkHttpClient client, int port) throws IOException {
        Request request = new Request.Builder().url("https://localhost:" + port + "/ping").build();
        try (Response response = client.newCall(request).execute()) {
            assertEquals(Protocol.HTTP_2, response.protocol(), "должен быть согласован HTTP/2");
            assertEquals(200, response.code(), "код ответа");
            assertEquals("PONG /ping", response.body().string(), "тело ответа по потоку HTTP/2");
        }
    }
}
