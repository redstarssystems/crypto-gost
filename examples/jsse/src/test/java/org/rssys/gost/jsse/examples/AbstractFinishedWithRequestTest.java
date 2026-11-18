package org.rssys.gost.jsse.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLEngine;

/**
 * Finished клиента и первый запрос одной записью в сокет. Сервер получает их одним чтением, когда
 * билет сессии ещё стоит в очереди на отправку; ответ должен прийти и при полном рукопожатии, и при
 * возобновлении. Клиент ведёт движок вручную поверх обычного сокета: стандартный сокет отправляет
 * Finished отдельной записью, и склейка была бы делом случая.
 *
 * <p>Наследник поднимает сервер, который отвечает телом запроса.
 */
public abstract class AbstractFinishedWithRequestTest {

    /** Повторов на вид рукопожатия: склейку в одно чтение на сервере даёт TCP, а не тест. */
    private static final int ATTEMPTS = 5;

    /** Ответ на loopback приходит за миллисекунды; потерянный запрос ждали бы бесконечно. */
    private static final int RESPONSE_TIMEOUT_MS = 3000;

    /** Тело запроса; сервер наследника возвращает его в ответе. */
    protected static final String BODY = "finished-and-request";

    /** Порт запущенного сервера. */
    protected abstract int serverPort();

    /** Сертификаты, которыми запущен сервер: клиент доверяет их корню. */
    protected abstract ExamplesCertHelper certHelper();

    /** Свой контекст — свой кэш билетов: соединения разных контекстов друг друга не возобновляют. */
    private SSLContext newClientContext() throws Exception {
        SSLContext context =
                SSLContext.getInstance(
                        GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        context.init(null, new TrustManager[] {certHelper().createTrustManager()}, null);
        return context;
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Ответ приходит на каждый запрос, склеенный с Finished")
    protected void responseArrivesWhenRequestFollowsFinished(boolean resumed) throws Exception {
        // Для возобновления контекст общий на серию, иначе у каждой попытки свой
        SSLContext shared = newClientContext();
        if (resumed) {
            // Клиенту нужен билет: одно соединение до серии, дальше каждое выдаёт следующий
            assertEquals(
                    BODY,
                    new Connection(shared).requestAfterFinished(),
                    "подготовительное соединение");
        }
        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            Connection connection = new Connection(resumed ? shared : newClientContext());
            String context = "попытка " + attempt + ", возобновление " + resumed;
            String response;
            try {
                response = connection.requestWithFinished();
            } catch (SocketTimeoutException e) {
                fail("ответа нет за " + RESPONSE_TIMEOUT_MS + " мс: " + context);
                return;
            }
            assertEquals(BODY, response, context);
            assertEquals(resumed, connection.wasResumed(), "вид рукопожатия: " + context);
        }
    }

    private static byte[] request() {
        return ("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                        + BODY.length()
                        + "\r\n\r\n"
                        + BODY)
                .getBytes(StandardCharsets.US_ASCII);
    }

    /** Клиентский движок поверх обычного сокета. */
    private final class Connection {
        private final SSLEngine engine;
        private final ByteBuffer netIn;
        private final ByteBuffer netOut;
        private final ByteBuffer appIn;
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();

        Connection(SSLContext context) {
            engine = context.createSSLEngine("localhost", serverPort());
            engine.setUseClientMode(true);
            int packet = engine.getSession().getPacketBufferSize();
            netIn = ByteBuffer.allocate(packet * 2);
            netOut = ByteBuffer.allocate(packet * 2);
            appIn = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() * 2);
        }

        boolean wasResumed() {
            return ((GostSSLEngine) engine).wasResumed();
        }

        String requestWithFinished() throws Exception {
            return run(true);
        }

        /** Обычное соединение: запрос отдельно от Finished. Даёт клиенту билет. */
        String requestAfterFinished() throws Exception {
            return run(false);
        }

        private String run(boolean coalesce) throws Exception {
            try (Socket socket = new Socket()) {
                socket.setTcpNoDelay(true);
                socket.connect(new InetSocketAddress("127.0.0.1", serverPort()));
                socket.setSoTimeout(RESPONSE_TIMEOUT_MS);
                InputStream in = socket.getInputStream();
                OutputStream out = socket.getOutputStream();
                handshake(in, out, coalesce);
                if (!coalesce) {
                    out.write(wrap(request()));
                    out.flush();
                }
                return readResponse(in);
            }
        }

        private void handshake(InputStream in, OutputStream out, boolean coalesce)
                throws Exception {
            engine.beginHandshake();
            while (true) {
                SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
                switch (status) {
                    case NEED_WRAP -> {
                        netOut.clear();
                        SSLEngineResult result = engine.wrap(ByteBuffer.allocate(0), netOut);
                        ByteArrayOutputStream wire = new ByteArrayOutputStream();
                        wire.write(netOut.array(), 0, result.bytesProduced());
                        boolean finished =
                                result.getHandshakeStatus()
                                        == SSLEngineResult.HandshakeStatus.FINISHED;
                        if (finished && coalesce) {
                            // Finished и запрос уходят одним write: на loopback это один сегмент
                            wire.write(wrap(request()));
                        }
                        out.write(wire.toByteArray());
                        out.flush();
                        if (finished) {
                            return;
                        }
                    }
                    case NEED_UNWRAP -> unwrapFromSocket(in);
                    case NEED_TASK -> {
                        Runnable task;
                        while ((task = engine.getDelegatedTask()) != null) task.run();
                    }
                    default -> throw new IllegalStateException("рукопожатие: " + status);
                }
            }
        }

        private byte[] wrap(byte[] data) throws Exception {
            netOut.clear();
            SSLEngineResult result = engine.wrap(ByteBuffer.wrap(data), netOut);
            assertEquals(SSLEngineResult.Status.OK, result.getStatus(), "запись запроса");
            assertEquals(data.length, result.bytesConsumed(), "запрос целиком в одной записи");
            byte[] record = new byte[result.bytesProduced()];
            System.arraycopy(netOut.array(), 0, record, 0, record.length);
            return record;
        }

        /** Одна обработка входящих байт; при неполной записи дочитывает сокет. */
        private void unwrapFromSocket(InputStream in) throws IOException {
            netIn.flip();
            SSLEngineResult result = engine.unwrap(netIn, appIn);
            netIn.compact();
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW
                    || (result.bytesConsumed() == 0 && result.bytesProduced() == 0)) {
                readSocket(in);
            }
            collectApp();
        }

        private void readSocket(InputStream in) throws IOException {
            byte[] chunk = new byte[netIn.remaining()];
            int n = in.read(chunk);
            if (n < 0) throw new IOException("сервер закрыл соединение");
            netIn.put(chunk, 0, n);
        }

        private void collectApp() {
            appIn.flip();
            received.write(appIn.array(), appIn.position(), appIn.remaining());
            appIn.clear();
        }

        /** Читает ответ до тела целиком; потерянный запрос даёт SocketTimeoutException. */
        private String readResponse(InputStream in) throws IOException {
            while (true) {
                String text = received.toString(StandardCharsets.US_ASCII);
                int headerEnd = text.indexOf("\r\n\r\n");
                if (headerEnd >= 0 && text.length() - headerEnd - 4 >= BODY.length()) {
                    assertTrue(text.startsWith("HTTP/1.1 200"), "статус ответа: " + text);
                    return text.substring(headerEnd + 4);
                }
                unwrapFromSocket(in);
            }
        }
    }
}
