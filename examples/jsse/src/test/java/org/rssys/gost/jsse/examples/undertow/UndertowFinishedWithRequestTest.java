package org.rssys.gost.jsse.examples.undertow;

import io.undertow.Undertow;
import io.undertow.util.Headers;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.Security;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.examples.AbstractFinishedWithRequestTest;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

/** Undertow: запрос, склеенный с Finished клиента, доставлен. */
@DisplayName("Undertow: запрос, склеенный с Finished клиента, доставлен")
class UndertowFinishedWithRequestTest extends AbstractFinishedWithRequestTest {

    private static Undertow server;
    private static int port;
    private static ExamplesCertHelper helper;

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        helper = new ExamplesCertHelper();
        server =
                Undertow.builder()
                        .addHttpsListener(0, "127.0.0.1", helper.getSslContext())
                        .setHandler(
                                exchange ->
                                        exchange.getRequestReceiver()
                                                .receiveFullBytes(
                                                        (ex, bytes) -> {
                                                            ex.getResponseHeaders()
                                                                    .put(
                                                                            Headers.CONTENT_LENGTH,
                                                                            bytes.length);
                                                            ex.getResponseSender()
                                                                    .send(ByteBuffer.wrap(bytes));
                                                        }))
                        .build();
        server.start();
        port = ((InetSocketAddress) server.getListenerInfo().get(0).getAddress()).getPort();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) server.stop();
    }

    @Override
    protected int serverPort() {
        return port;
    }

    @Override
    protected ExamplesCertHelper certHelper() {
        return helper;
    }
}
