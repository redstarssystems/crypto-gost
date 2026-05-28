package org.rssys.gost.jsse.socket;

import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;

import org.rssys.gost.tls13.TlsConstants;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;

/**
 * SSLSocket для ГОСТ TLS 1.3 (RFC 8446 + RFC 9367).
 * <p>
 * Реализация через wrapping: реальный TCP-сокет хранится в поле {@code socket},
 * все Socket-методы делегируют ему. Криптография — через {@link GostSSLEngine}.
 * <p>
 * Lock discipline: три независимых ReentrantLock (handshake, read, write).
 * После handshake чтение и запись могут выполняться из разных потоков.
 * <p>
 * Идемпотентность: getInputStream()/getOutputStream() возвращают один и тот же
 * объект при повторных вызовах.
 */
public final class GostSSLSocket extends SSLSocket {

    private static final int MAX_PLAINTEXT = TlsConstants.MAX_PLAINTEXT_LENGTH;
    private static final int MAX_PACKET = TlsConstants.MAX_CIPHERTEXT_LENGTH + 64;
    private static final int RECORD_HEADER = TlsConstants.RECORD_HEADER_SIZE;
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    // ========================================================================
    // Transport
    // ========================================================================

    private final Socket socket;                          // реальный TCP-сокет
    private final InputStream socketIn;                   // socket.getInputStream()
    private final OutputStream socketOut;                 // socket.getOutputStream()
    private final boolean autoCloseUnderlying;

    // ========================================================================
    // SSL
    // ========================================================================

    private final GostSSLEngine engine;
    private final GostX509KeyManager keyManager;
    private final GostX509TrustManager trustManager;
    private final GostSSLSessionContext sessionContext;
    private final boolean clientMode;

    // ========================================================================
    // Состояние сокета
    // ========================================================================

    private volatile boolean closed;
    private volatile boolean handshakeDone;

    // ========================================================================
    // I/O streams (кэшированы, идемпотентны)
    // ========================================================================

    private final AppInputStream appIn;
    private final AppOutputStream appOut;

    // ========================================================================
    // Handshake
    // ========================================================================

    private final CopyOnWriteArrayList<HandshakeCompletedListener> handshakeListeners =
            new CopyOnWriteArrayList<>();

    // ========================================================================
    // Locks
    // ========================================================================

    private final ReentrantLock handshakeLock = new ReentrantLock();
    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();

    // ========================================================================
    // Буферы
    // ========================================================================

    private final ByteBuffer readDst = ByteBuffer.allocate(MAX_PLAINTEXT + 64);
    private final ByteBuffer writeDst = ByteBuffer.allocate(MAX_PACKET);

    // ========================================================================
    // Конструкторы
    // ========================================================================

    // (1) Client: новый TCP-сокет + connect
    public GostSSLSocket(String host, int port,
                         GostX509KeyManager km, GostX509TrustManager tm,
                         GostSSLSessionContext sessionContext) throws IOException {
        this(new Socket(host, port), host, port, true, km, tm, sessionContext, true);
    }

    // (2) Client: с локальным адресом
    public GostSSLSocket(String host, int port, InetAddress localAddr, int localPort,
                         GostX509KeyManager km, GostX509TrustManager tm,
                         GostSSLSessionContext sessionContext) throws IOException {
        this(new Socket(host, port, localAddr, localPort), host, port, true,
                km, tm, sessionContext, true);
    }

    // (3) Client: InetAddress
    public GostSSLSocket(InetAddress addr, int port,
                         GostX509KeyManager km, GostX509TrustManager tm,
                         GostSSLSessionContext sessionContext) throws IOException {
        this(new Socket(addr, port), addr.getHostName(), port, true,
                km, tm, sessionContext, true);
    }

    // (4) Client: InetAddress + local
    public GostSSLSocket(InetAddress addr, int port, InetAddress localAddr, int localPort,
                         GostX509KeyManager km, GostX509TrustManager tm,
                         GostSSLSessionContext sessionContext) throws IOException {
        this(new Socket(addr, port, localAddr, localPort), addr.getHostName(), port, true,
                km, tm, sessionContext, true);
    }

    // (5) Server: wrap accepted socket (package-private, вызывается из GostSSLServerSocket)
    GostSSLSocket(Socket socket,
                  GostX509KeyManager km, GostX509TrustManager tm,
                  GostSSLSessionContext sessionContext) throws IOException {
        this(socket, socket.getInetAddress().getHostName(), socket.getPort(), true,
                km, tm, sessionContext, false);
    }

    // (6) Layered (HttpsURLConnection прокси) — публичный
    public GostSSLSocket(Socket underlying, String host, int port, boolean autoClose,
                         GostX509KeyManager km, GostX509TrustManager tm,
                         GostSSLSessionContext sessionContext) throws IOException {
        this(underlying, host, port, autoClose, km, tm, sessionContext, true);
    }

    // Единый private конструктор
    private GostSSLSocket(Socket socket, String host, int port, boolean autoClose,
                          GostX509KeyManager km, GostX509TrustManager tm,
                          GostSSLSessionContext sessionContext,
                          boolean clientMode) throws IOException {
        this.socket = socket;
        this.autoCloseUnderlying = autoClose;
        this.keyManager = km;
        this.trustManager = tm;
        this.sessionContext = sessionContext;
        this.clientMode = clientMode;

        this.engine = clientMode
                ? GostSSLEngine.createForClient(km, tm, host, port, sessionContext)
                : GostSSLEngine.createForServer(km, tm, host, port, sessionContext);

        // handshakeLock реентрабельный: когда read()/write() триггерят startHandshake()
        // до его завершения, вызывающий тред уже держит readLock/writeLock, затем
        // захватывает handshakeLock — это design decision.
        this.socketIn = socket.getInputStream();
        this.socketOut = socket.getOutputStream();

        this.appIn = new AppInputStream();
        this.appOut = new AppOutputStream();
    }

    // ========================================================================
    // startHandshake
    // ========================================================================

    @Override
    public void startHandshake() throws IOException {
        if (handshakeDone) return;
        handshakeLock.lock();
        try {
            if (handshakeDone) return;

            engine.beginHandshake();

            while (true) {
                switch (engine.getHandshakeStatus()) {
                    case NEED_WRAP:
                        writeDst.clear();
                        engine.wrap(EMPTY, writeDst);
                        writeDst.flip();
                        // WHY: прямой write из backing array (HeapByteBuffer) — zero-alloc
                        socketOut.write(writeDst.array(),
                                writeDst.arrayOffset() + writeDst.position(),
                                writeDst.remaining());
                        socketOut.flush();
                        break;
                    case NEED_UNWRAP: {
                        ByteBuffer record = readTlsRecord();
                        if (record == null) {
                            throw new IOException("Connection closed by peer during handshake");
                        }
                        readDst.clear();
                        engine.unwrap(record, readDst);
                        readDst.flip();
                        break;
                    }
                    case NEED_TASK: {
                        Runnable task = engine.getDelegatedTask();
                        if (task != null) task.run();
                        break;
                    }
                    case FINISHED:
                    case NOT_HANDSHAKING:
                        handshakeDone = true;
                        fireHandshakeCompleted();
                        return;
                }
            }
        } finally {
            handshakeLock.unlock();
        }
    }

    // ========================================================================
    // I/O: getInputStream / getOutputStream
    // ========================================================================

    @Override
    public InputStream getInputStream() {
        return appIn;
    }

    @Override
    public OutputStream getOutputStream() {
        return appOut;
    }

    // ========================================================================
    // AppInputStream
    // ========================================================================

    private class AppInputStream extends InputStream {
        private boolean closed;
        private byte[] leftover;
        private int leftoverOff;
        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n == -1 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (closed) throw new IOException("Stream closed");
            readLock.lock();
            try {
                if (len == 0) return 0;
                if (!handshakeDone) startHandshake();

                // Есть буферизованный остаток с прошлого read() — отдаём
                if (leftover != null) {
                    int toRead = Math.min(len, leftover.length - leftoverOff);
                    System.arraycopy(leftover, leftoverOff, b, off, toRead);
                    leftoverOff += toRead;
                    if (leftoverOff >= leftover.length) {
                        TlsUtils.wipeArray(leftover);
                        leftover = null;
                        leftoverOff = 0;
                    }
                    return toRead;
                }

                // Цикл: читаем TLS-записи, пока не получим app data
                while (true) {
                    ByteBuffer record = readTlsRecord();
                    if (record == null) return -1;

                    readDst.clear();
                    SSLEngineResult unwrapResult = engine.unwrap(record, readDst);
                    readDst.flip();

                    switch (unwrapResult.getStatus()) {
                        case BUFFER_UNDERFLOW:
                            throw new IOException("TLS buffer underflow");
                        case BUFFER_OVERFLOW:
                            throw new IOException("TLS buffer overflow");
                    }

                    if (readDst.hasRemaining()) {
                        int toRead = Math.min(len, readDst.remaining());
                        readDst.get(b, off, toRead);
                        if (readDst.hasRemaining()) {
                            leftover = new byte[readDst.remaining()];
                            readDst.get(leftover);
                            TlsUtils.wipeArray(readDst.array());
                            leftoverOff = 0;
                        }
                        return toRead;
                    }

                    // Post-handshake (NST, KU) — engine обработал, данных нет
                    if (engine.isInboundDone()) return -1;
                }
            } finally {
                readLock.unlock();
            }
        }

        @Override
        public int available() {
            if (leftover != null) return leftover.length - leftoverOff;
            return 0;
        }

        @Override
        public void close() {
            closed = true;
            TlsUtils.wipeArray(leftover);
            leftover = null;
            leftoverOff = 0;
            TlsUtils.wipeArray(readDst.array());
        }
    }

    // ========================================================================
    // AppOutputStream
    // ========================================================================

    private class AppOutputStream extends OutputStream {
        private boolean closed;
        private final byte[] one = new byte[1];

        @Override
        public void write(int b) throws IOException {
            one[0] = (byte) b;
            write(one, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (closed) throw new IOException("Stream closed");
            writeLock.lock();
            try {
                if (len == 0) return;
                if (!handshakeDone) startHandshake();

                ByteBuffer src = ByteBuffer.wrap(b, off, len);

                while (src.hasRemaining()) {
                    writeDst.clear();
                    SSLEngineResult result = engine.wrap(src, writeDst);
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        throw new IOException("TLS buffer overflow");
                    }
                    writeDst.flip();
                    int toWrite = writeDst.remaining();
                    // WHY: прямой write из backing array (HeapByteBuffer) — zero-alloc
                    socketOut.write(writeDst.array(),
                            writeDst.arrayOffset() + writeDst.position(),
                            writeDst.remaining());

                    // Дренирование outgoing queue (auto-KeyUpdate):
                    // после wrap мог появиться KU-фрейм — вычитываем все
                    while (true) {
                        writeDst.clear();
                        SSLEngineResult drainResult = engine.wrap(EMPTY, writeDst);
                        if (drainResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                            throw new IOException("TLS buffer overflow during drain");
                        }
                        if (writeDst.position() == 0) break;
                        writeDst.flip();
                        socketOut.write(writeDst.array(),
                                writeDst.arrayOffset() + writeDst.position(),
                                writeDst.remaining());
                    }
                }
                socketOut.flush();
            } finally {
                writeLock.unlock();
            }
        }

        @Override
        public void flush() throws IOException {
            socketOut.flush();
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    // ========================================================================
    // Close
    // ========================================================================

    @Override
    public void close() throws IOException {
        if (isClosed()) return;
        closed = true;

        if (!engine.isOutboundDone()) {
            try {
                engine.closeOutbound();
                byte[] alertRecord = engine.pollOutboundRecord();
                if (alertRecord != null) {
                    socketOut.write(alertRecord);
                    socketOut.flush();
                }
            } catch (IOException ignored) { }
        }

        if (autoCloseUnderlying) {
            socket.close();
        }
    }

    // ========================================================================
    // HandshakeCompletedListener
    // ========================================================================

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeListeners.add(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeListeners.remove(listener);
    }

    private void fireHandshakeCompleted() {
        HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, engine.getSession());
        for (HandshakeCompletedListener l : handshakeListeners) {
            try {
                l.handshakeCompleted(event);
            } catch (RuntimeException ignored) { }
        }
    }

    // ========================================================================
    // SSLSocket abstract methods — делегирование в engine
    // ========================================================================

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return engine.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        engine.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return GostJsseConstants.SUPPORTED_PROTOCOLS.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        return engine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        engine.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return engine.getSession();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return engine.getHandshakeSession();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        engine.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return engine.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        engine.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return engine.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        engine.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return engine.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        engine.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return engine.getEnableSessionCreation();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return engine.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        engine.setSSLParameters(params);
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return engine.getApplicationProtocol();
    }

    private java.util.function.BiFunction<SSLSocket, java.util.List<String>, String> socketSelector;

    @Override
    public void setHandshakeApplicationProtocolSelector(
            java.util.function.BiFunction<SSLSocket, java.util.List<String>, String> selector) {
        this.socketSelector = selector;
        if (selector != null) {
            java.util.function.BiFunction<SSLEngine, java.util.List<String>, String> wrapped =
                    (eng, list) -> selector.apply(this, list);
            engine.setHandshakeApplicationProtocolSelector(wrapped);
        } else {
            engine.setHandshakeApplicationProtocolSelector(null);
        }
    }

    @Override
    public java.util.function.BiFunction<SSLSocket, java.util.List<String>, String>
            getHandshakeApplicationProtocolSelector() {
        return socketSelector;
    }

    // ========================================================================
    // String representation
    // ========================================================================
    // Socket methods — делегирование в this.socket
    // ========================================================================

    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    @Override
    public int getPort() {
        return socket.getPort();
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return socket.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return socket.getLocalSocketAddress();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return socket.getSoTimeout();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        socket.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        socket.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return socket.getKeepAlive();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        socket.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return socket.getReuseAddress();
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        socket.bind(bindpoint);
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        socket.connect(endpoint);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        socket.connect(endpoint, timeout);
    }

    @Override
    public boolean isConnected() {
        return socket.isConnected();
    }

    @Override
    public boolean isClosed() {
        return closed || socket.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return socket.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return socket.isOutputShutdown();
    }

    @Override
    public void shutdownInput() {
        throw new UnsupportedOperationException("SSL does not support half-close (shutdownInput)");
    }

    @Override
    public void shutdownOutput() {
        throw new UnsupportedOperationException("SSL does not support half-close (shutdownOutput)");
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        socket.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return socket.getOOBInline();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return socket.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        socket.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return socket.getReceiveBufferSize();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        socket.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return socket.getTrafficClass();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        socket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /**
     * Читает полную TLS-запись из socketIn.
     * <p>
     * Предусловие: socketIn доступен под handshakeLock (handshake) или readLock (app data).
     * Эти локи никогда не пересекаются на одном thread — нет конкурентного доступа.
     * <p>
     * EOF между записями (clean close): возвращает null.
     * EOF внутри записи (truncation): IOException.
     *
     * @return ByteBuffer записи (header + body), или null при чистом EOF
     * @throws IOException при ошибке ввода-вывода или truncation
     */
    private ByteBuffer readTlsRecord() throws IOException {
        byte[] hdr = new byte[RECORD_HEADER];
        int off = 0;
        while (off < RECORD_HEADER) {
            int n = socketIn.read(hdr, off, RECORD_HEADER - off);
            if (n == -1) {
                if (off == 0) return null;
                throw new EOFException("Truncated TLS record header: "
                        + off + " of " + RECORD_HEADER + " bytes");
            }
            off += n;
        }
        int bodyLen = ((hdr[3] & 0xFF) << 8) | (hdr[4] & 0xFF);
        if (bodyLen > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new IOException("TLS record too large: " + bodyLen);
        }
        byte[] record = new byte[RECORD_HEADER + bodyLen];
        System.arraycopy(hdr, 0, record, 0, RECORD_HEADER);
        readFully(socketIn, record, RECORD_HEADER, bodyLen);
        return ByteBuffer.wrap(record, 0, RECORD_HEADER + bodyLen);
    }

    /**
     * Читает ровно {@code len} байт из {@code in} в {@code buf}.
     * EOF до чтения всех байт: {@link EOFException}.
     */
    private static void readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(buf, off, len);
            if (n == -1) throw new EOFException("Unexpected EOF");
            off += n;
            len -= n;
        }
    }

    @Override
    public String toString() {
        return "GostSSLSocket[" + (clientMode ? "CLIENT" : "SERVER") + ", "
                + (handshakeDone ? "HANDSHAKED" : "NOT_HANDSHAKED") + "]";
    }

    /** Для тестов: закрывает TCP-сокет без close_notify. */
    void closeUnderlyingForTest() throws IOException {
        socket.close();
    }
}
