package org.rssys.gost.jsse.testkit;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.function.Consumer;
import javax.net.ssl.SSLEngineResult;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.tls13.TlsConstants;

/**
 * {@link GostSSLEngine} поверх TCP в роли пира для тестов сокета: тест сам решает, что и когда
 * уходит в провод (переложенный полёт, половина записи), а сокет проверяется как есть.
 */
public final class EngineSocketPeer {

    private static final int MAX_STEPS = 100_000;
    private static final int NET_BUFFER = 64 * TlsConstants.MAX_CIPHERTEXT_LENGTH;

    private EngineSocketPeer() {}

    /** Рукопожатие без вмешательства в полёт. */
    public static void handshake(GostSSLEngine engine, Socket socket) throws Exception {
        handshake(engine, socket, 0, ignored -> {});
    }

    /**
     * Рукопожатие поверх сокета. Перед отправкой первого полёта, в очереди которого не меньше
     * {@code flightFrames} сообщений, один раз вызывается {@code beforeFlight}.
     */
    public static void handshake(
            GostSSLEngine engine,
            Socket socket,
            int flightFrames,
            Consumer<GostSSLEngine> beforeFlight)
            throws Exception {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        boolean shaped = flightFrames == 0;
        engine.beginHandshake();
        for (int step = 0; step < MAX_STEPS; step++) {
            switch (engine.getHandshakeStatus()) {
                case FINISHED, NOT_HANDSHAKING -> {
                    return;
                }
                case NEED_WRAP -> {
                    if (!shaped && HandshakeFlightShaper.queuedFrames(engine) >= flightFrames) {
                        beforeFlight.accept(engine);
                        shaped = true;
                    }
                    ByteBuffer net = ByteBuffer.allocate(NET_BUFFER);
                    while (engine.getHandshakeStatus()
                            == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                        engine.wrap(ByteBuffer.allocate(0), net);
                    }
                    net.flip();
                    send(out, net);
                }
                case NEED_UNWRAP -> {
                    byte[] record = readRecord(in);
                    if (record == null) {
                        throw new IOException("пир закрыл соединение во время рукопожатия");
                    }
                    app.clear();
                    engine.unwrap(ByteBuffer.wrap(record), app);
                }
                case NEED_TASK -> {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                }
                default -> throw new IllegalStateException("неожиданный статус");
            }
        }
        throw new IllegalStateException("рукопожатие не завершено");
    }

    /** Шифрует данные; служебные сообщения из очереди (тикеты) уходят перед ними. */
    public static byte[] wrapData(GostSSLEngine engine, byte[] data) throws Exception {
        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer net = ByteBuffer.allocate(NET_BUFFER);
        while (src.hasRemaining()) {
            engine.wrap(src, net);
        }
        net.flip();
        byte[] out = new byte[net.remaining()];
        net.get(out);
        return out;
    }

    /** Читает записи, пока не придут данные приложения; служебные записи пропускаются. */
    public static byte[] readData(GostSSLEngine engine, Socket socket) throws Exception {
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        for (int i = 0; i < MAX_STEPS && app.position() == 0; i++) {
            byte[] record = readRecord(socket.getInputStream());
            if (record == null) {
                throw new IOException("пир закрыл соединение до данных");
            }
            engine.unwrap(ByteBuffer.wrap(record), app);
        }
        app.flip();
        byte[] data = new byte[app.remaining()];
        app.get(data);
        return data;
    }

    public static void send(OutputStream out, ByteBuffer net) throws IOException {
        byte[] data = new byte[net.remaining()];
        net.get(data);
        out.write(data);
        out.flush();
    }

    /** Читает одну TLS-запись целиком; null при закрытии соединения. */
    public static byte[] readRecord(InputStream in) throws IOException {
        byte[] header = in.readNBytes(TlsConstants.RECORD_HEADER_SIZE);
        if (header.length < TlsConstants.RECORD_HEADER_SIZE) {
            return null;
        }
        int bodyLength = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);
        byte[] body = in.readNBytes(bodyLength);
        byte[] record = new byte[header.length + body.length];
        System.arraycopy(header, 0, record, 0, header.length);
        System.arraycopy(body, 0, record, header.length, body.length);
        return record;
    }
}
