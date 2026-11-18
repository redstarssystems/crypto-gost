package org.rssys.gost.jsse.socket;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

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
    private static final int RECORD_HEADER = TlsConstants.RECORD_HEADER_SIZE;
    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.socket.GostSSLSocket");
    private static final String MSG_TLS_BUFFER_OVERFLOW = "TLS buffer overflow";
    private static final String MSG_STREAM_CLOSED = "Stream closed";
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    // ========================================================================
    // Transport
    // ========================================================================

    private final Socket socket; // реальный TCP-сокет
    private final InputStream socketIn; // socket.getInputStream()
    private final OutputStream socketOut; // socket.getOutputStream()
    private final boolean autoCloseUnderlying;

    // ========================================================================
    // SSL
    // ========================================================================

    private final GostSSLEngine engine;
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

    // Замки вкладываются: read()/write() берут readLock/writeLock и, если рукопожатие ещё не
    // завершено, внутри startHandshake() берут handshakeLock (порядок всегда такой, поэтому
    // взаимной блокировки нет; handshakeLock реентрабелен).
    private final ReentrantLock handshakeLock = new ReentrantLock();
    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();

    // ========================================================================
    // Буферы
    // ========================================================================

    private final ByteBuffer readDst =
            ByteBuffer.allocate(MAX_PLAINTEXT + TlsConstants.RECORD_BUFFER_HEADROOM);
    // Заголовок читаемой записи; чтение сокета сериализовано замками, поэтому массив общий
    private final byte[] recordHeader = new byte[TlsConstants.RECORD_HEADER_SIZE];
    // Частично прочитанная запись: SocketTimeoutException посреди записи не должен терять уже
    // прочитанные байты, иначе следующее чтение приняло бы середину записи за заголовок. Доступ
    // под тем же замком, что и чтение сокета (handshakeLock или readLock).
    private int recordHeaderRead;
    // Движок начал рукопожатие (под handshakeLock): тайм-аут не должен приводить к повторному
    // beginHandshake()
    private boolean handshakeBegun;
    private byte[] partialRecord;
    private int partialRecordRead;
    private final ByteBuffer writeDst =
            ByteBuffer.allocate(GostJsseConstants.DEFAULT_PACKET_BUFFER_SIZE);

    // ========================================================================
    // Конструкторы
    // ========================================================================

    /**
     * Клиентский сокет: новое TCP-соединение к {@code host:port}.
     *
     * @param host           имя сервера (используется для SNI и проверки имени в сертификате)
     * @param port           порт сервера
     * @param km             менеджер ключей (собственный сертификат для mTLS), может быть пустым
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий (возобновление по PSK), может быть null
     * @throws IOException при ошибке соединения
     */
    public GostSSLSocket(
            String host,
            int port,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(new Socket(host, port), host, port, true, km, tm, sessionContext, true);
    }

    /**
     * Клиентский сокет: новое TCP-соединение с привязкой к локальному адресу.
     *
     * @param host           имя сервера
     * @param port           порт сервера
     * @param localAddr      локальный адрес привязки
     * @param localPort      локальный порт привязки
     * @param km             менеджер ключей
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий, может быть null
     * @throws IOException при ошибке соединения
     */
    public GostSSLSocket(
            String host,
            int port,
            InetAddress localAddr,
            int localPort,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(
                new Socket(host, port, localAddr, localPort),
                host,
                port,
                true,
                km,
                tm,
                sessionContext,
                true);
    }

    /**
     * Клиентский сокет: новое TCP-соединение по адресу. Имя для проверки сертификата берётся из
     * адреса без обратного DNS-запроса: исходное имя, если адрес создан по имени, иначе литерал.
     *
     * @param addr           адрес сервера
     * @param port           порт сервера
     * @param km             менеджер ключей
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий, может быть null
     * @throws IOException при ошибке соединения
     */
    public GostSSLSocket(
            InetAddress addr,
            int port,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(
                new Socket(addr, port),
                hostWithoutLookup(addr, port),
                port,
                true,
                km,
                tm,
                sessionContext,
                true);
    }

    /**
     * Клиентский сокет: новое TCP-соединение по адресу с привязкой к локальному адресу.
     *
     * @param addr           адрес сервера
     * @param port           порт сервера
     * @param localAddr      локальный адрес привязки
     * @param localPort      локальный порт привязки
     * @param km             менеджер ключей
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий, может быть null
     * @throws IOException при ошибке соединения
     */
    public GostSSLSocket(
            InetAddress addr,
            int port,
            InetAddress localAddr,
            int localPort,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(
                new Socket(addr, port, localAddr, localPort),
                hostWithoutLookup(addr, port),
                port,
                true,
                km,
                tm,
                sessionContext,
                true);
    }

    // Серверный сокет поверх принятого соединения; вызывается из GostSSLServerSocket.accept().
    // Имя пира берётся без обратного DNS-запроса: на сервере оно нужно только журналу и привязке
    // возобновления, а запрос блокировал бы accept().
    GostSSLSocket(
            Socket socket,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(
                socket,
                hostWithoutLookup(socket.getInetAddress(), socket.getPort()),
                socket.getPort(),
                true,
                km,
                tm,
                sessionContext,
                false);
    }

    /**
     * Клиентский сокет поверх существующего соединения (например, туннель прокси для
     * {@code HttpsURLConnection}).
     *
     * @param underlying     готовое TCP-соединение
     * @param host           имя сервера
     * @param port           порт сервера
     * @param autoClose      закрывать ли нижележащий сокет при закрытии этого
     * @param km             менеджер ключей
     * @param tm             менеджер доверия
     * @param sessionContext контекст сессий, может быть null
     * @throws IOException при ошибке ввода-вывода
     */
    public GostSSLSocket(
            Socket underlying,
            String host,
            int port,
            boolean autoClose,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext)
            throws IOException {
        this(underlying, host, port, autoClose, km, tm, sessionContext, true);
    }

    /**
     * Имя пира без обратного DNS-запроса: исходное имя, если адрес создан по имени, иначе литерал
     * адреса. {@code InetAddress.getHostName()} при литерале ходит в PTR-запись, а по этому имени
     * потом сверяется сертификат.
     */
    private static String hostWithoutLookup(InetAddress address, int port) {
        return new InetSocketAddress(address, port).getHostString();
    }

    // Единый private конструктор
    private GostSSLSocket(
            Socket socket,
            String host,
            int port,
            boolean autoClose,
            GostX509KeyManager km,
            GostX509TrustManager tm,
            GostSSLSessionContext sessionContext,
            boolean clientMode)
            throws IOException {
        this.socket = socket;
        this.autoCloseUnderlying = autoClose;
        this.clientMode = clientMode;

        this.engine =
                clientMode
                        ? GostSSLEngine.createForClient(km, tm, host, port, sessionContext)
                        : GostSSLEngine.createForServer(km, tm, host, port, sessionContext);

        this.socketIn = socket.getInputStream();
        this.socketOut = socket.getOutputStream();

        this.appIn = new AppInputStream();
        this.appOut = new AppOutputStream();
    }

    // ========================================================================
    // max_fragment_length
    // ========================================================================

    /**
     * Запрашивает уменьшение максимального размера фрагмента (RFC 6066 §4).
     * Должно быть вызвано ДО startHandshake().
     *
     * @param maxFragLenCode 0 = дефолт (16384), 1=512, 2=1024, 3=2048, 4=4096
     */
    public void setMaxFragmentLengthRequest(int maxFragLenCode) {
        engine.setClientMaxFragLenRequest(maxFragLenCode);
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

            // Рукопожатие, прерванное тайм-аутом чтения, продолжается с того же места: движок уже
            // начат, повторный beginHandshake() отверг бы вызов
            if (!handshakeBegun) {
                engine.beginHandshake();
                handshakeBegun = true;
            }

            while (true) {
                switch (engine.getHandshakeStatus()) {
                    case NEED_WRAP:
                        writeDst.clear();
                        engine.wrap(EMPTY, writeDst);
                        writeDst.flip();
                        writeDstToSocket();
                        socketOut.flush();
                        break;
                    case NEED_UNWRAP:
                        {
                            ByteBuffer record = readTlsRecord();
                            if (record == null) {
                                throw new IOException("Connection closed by peer during handshake");
                            }
                            readDst.clear();
                            engine.unwrap(record, readDst);
                            readDst.flip();
                            break;
                        }
                    case NEED_TASK:
                        {
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
        } catch (SSLException e) {
            sendPendingFatalAlert();
            // Контракт SSLSocket: при отказе рукопожатия сокет закрывается, дальнейший обмен
            // невозможен. Ключи и буферы затираются сразу, а не при закрытии приложением
            closeQuietly();
            throw e;
        } catch (InterruptedIOException e) {
            // Тайм-аут чтения (setSoTimeout) не роковой, как в JDK: недочитанная запись сохранена,
            // и повторный вызов продолжает рукопожатие
            throw e;
        } catch (IOException e) {
            // Обрыв или иная ошибка ввода-вывода: рукопожатие продолжить нельзя
            closeQuietly();
            throw e;
        } catch (RuntimeException e) {
            // Как в JDK (SSLSocketImpl.handleException): непредвиденный сбой рукопожатия роковой и
            // отдаётся как SSLException, поэтому getSession() не выпускает его в приложение
            sendPendingFatalAlert();
            closeQuietly();
            throw new SSLException("Handshake failed", e);
        } finally {
            handshakeLock.unlock();
        }
    }

    private void closeQuietly() {
        try {
            close();
        } catch (IOException ignored) {
            // закрытие после отказа best-effort: причину отказа приложение получает исключением
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
        // volatile: close() вызывают из другого потока, чтобы разбудить читателя
        private volatile boolean closed;
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
            if (closed) throw new IOException(MSG_STREAM_CLOSED);
            readLock.lock();
            try {
                // Поток закрыли, пока читатель ждал замок
                if (closed) throw new IOException(MSG_STREAM_CLOSED);
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
                            throw new IOException(MSG_TLS_BUFFER_OVERFLOW);
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
            } catch (SSLException e) {
                sendPendingFatalAlert();
                throw e;
            } finally {
                readLock.unlock();
                // close() мог не получить замок и оставил затирание читателю. Проверка после
                // unlock: флаг записан до неудачного tryLock закрывающего потока, поэтому здесь
                // он виден, а затирание под замком не пересекается с чужим чтением.
                if (closed) {
                    wipeBuffersIfIdle();
                }
            }
        }

        @Override
        public int available() {
            byte[] pending = leftover;
            return pending != null ? pending.length - leftoverOff : 0;
        }

        @Override
        public void close() {
            closed = true;
            wipeBuffersIfIdle();
        }

        /**
         * Затирает буфер расшифровки и остаток открытого текста, только если читатель не работает
         * с ними: затирание под чужим чтением отдало бы приложению нули, обнулило бы остаток между
         * проверкой и копированием либо оставило бы новый остаток в памяти. Занятый замок значит,
         * что затрёт сам читатель по завершении чтения.
         */
        private void wipeBuffersIfIdle() {
            if (!readLock.tryLock()) {
                return;
            }
            try {
                TlsUtils.wipeArray(leftover);
                leftover = null;
                leftoverOff = 0;
                TlsUtils.wipeArray(readDst.array());
                discardPartialRecordIfIdle();
            } finally {
                readLock.unlock();
            }
        }
    }

    // ========================================================================
    // AppOutputStream
    // ========================================================================

    private class AppOutputStream extends OutputStream {
        private volatile boolean closed;
        private final byte[] one = new byte[1];

        @Override
        public void write(int b) throws IOException {
            one[0] = (byte) b;
            write(one, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (closed) throw new IOException(MSG_STREAM_CLOSED);
            writeLock.lock();
            try {
                if (len == 0) return;
                if (!handshakeDone) startHandshake();

                ByteBuffer src = ByteBuffer.wrap(b, off, len);

                while (src.hasRemaining()) {
                    writeDst.clear();
                    SSLEngineResult result = engine.wrap(src, writeDst);
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        throw new IOException(MSG_TLS_BUFFER_OVERFLOW);
                    }
                    writeDst.flip();
                    writeDstToSocket();

                    // Дренирование outgoing queue (auto-KeyUpdate):
                    // после wrap мог появиться KU-фрейм — вычитываем все
                    while (true) {
                        writeDst.clear();
                        SSLEngineResult drainResult = engine.wrap(EMPTY, writeDst);
                        if (drainResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                            throw new IOException(MSG_TLS_BUFFER_OVERFLOW + " during drain");
                        }
                        if (writeDst.position() == 0) break;
                        writeDst.flip();
                        writeDstToSocket();
                    }
                }
                socketOut.flush();
            } catch (SSLException e) {
                sendPendingFatalAlert();
                throw e;
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
            } catch (IOException ignored) {
                // close_notify best-effort: закрытие продолжается и при обрыве соединения
            }
        }

        // Закрываем inbound после отправки close_notify — единая точка
        // destroyAll() зачищает record-ключи во всех сценариях close
        // (штатная ветка closeOutbound() не разрушает engine до получения close_notify пира).
        // Порядок строгий: pollOutboundRecord() выше уже забрал pendingCloseRecord,
        // иначе destroyAll() обнулил бы его и close_notify потерялся.
        try {
            engine.closeInbound();
        } catch (SSLException ignored) {
            // closeInbound без close_notify пира легален (RFC 8446 §6.1)
        }

        try {
            if (autoCloseUnderlying) {
                socket.close();
            }
        } finally {
            // Закрытие сокета, а не только потока чтения, обязано затереть открытый текст
            // приложения (буфер расшифровки и непрочитанный остаток). Затирание после закрытия
            // нижележащего сокета: заблокированный читатель уже разбужен и не пишет в буфер.
            appIn.close();
            appOut.close();
        }
    }

    /**
     * Сообщает, завершилось ли рукопожатие возобновлением по PSK (без обмена сертификатами).
     * <p>Значение фиксируется при завершении рукопожатия и не меняется после закрытия сокета.</p>
     *
     * @return true, если рукопожатие возобновлено; false, если оно было полным
     * @throws IllegalStateException если рукопожатие ещё не завершено
     */
    public boolean wasResumed() {
        return engine.wasResumed();
    }

    /** Только для тестов пакета: доступ к engine без рефлексии. Не часть публичного API SSLSocket. */
    GostSSLEngine engine() {
        return engine;
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
            } catch (RuntimeException ignored) {
                // ошибка слушателя не должна сорвать остальных слушателей и соединение
            }
        }
    }

    // ========================================================================
    // SSLSocket abstract methods — делегирование в engine
    // ========================================================================

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.supportedCipherSuites();
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
        return GostJsseConstants.supportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return engine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        engine.setEnabledProtocols(protocols);
    }

    /**
     * {@inheritDoc}
     * <p>
     * По контракту {@code SSLSocket} запускает рукопожатие, если оно не завершено, и ждёт его. Если
     * рукопожатие уже идёт в текущем потоке (вызов из обратного вызова рукопожатия, например
     * селектора ALPN), возвращается текущая сессия без повторного запуска: замок рукопожатия
     * реентерабельный, и повторный запуск ушёл бы в рекурсию. У неподключённого сокета и при отказе
     * рукопожатия возвращается пустая сессия ({@code SSL_NULL_WITH_NULL_NULL}), исключения нет;
     * после отказа сокет закрыт.
     */
    @Override
    public SSLSession getSession() {
        if (!handshakeDone
                && isConnected()
                && !isClosed()
                && !handshakeLock.isHeldByCurrentThread()) {
            try {
                startHandshake();
            } catch (IOException e) {
                // Причину приложение узнаёт из startHandshake()/чтения; здесь контракт — пустая
                // сессия без исключения. Исключение смешанного происхождения (движок, сокет JDK),
                // поэтому текст не пишется, только тип
                String label = engine.getConnectionLabel();
                GostLogger logger = label != null ? LOG.withContext(label) : LOG;
                logger.log(
                        Level.DEBUG,
                        "Handshake for getSession() failed: {0}",
                        e.getClass().getSimpleName());
            }
        }
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
    public String getApplicationProtocol() {
        return engine.getApplicationProtocol();
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return engine.getHandshakeApplicationProtocol();
    }

    private BiFunction<SSLSocket, List<String>, String> socketSelector;

    @Override
    public void setHandshakeApplicationProtocolSelector(
            BiFunction<SSLSocket, List<String>, String> selector) {
        this.socketSelector = selector;
        if (selector != null) {
            BiFunction<SSLEngine, List<String>, String> wrapped =
                    (eng, list) -> selector.apply(this, list);
            engine.setHandshakeApplicationProtocolSelector(wrapped);
        } else {
            engine.setHandshakeApplicationProtocolSelector(null);
        }
    }

    @Override
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return socketSelector;
    }

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
     * Отправляет пиру fatal alert, который движок поставил при сбое рукопожатия, приёма или записи.
     * <p>
     * Пир должен узнать о причине обрыва сразу (RFC 8446 §6), а не при закрытии сокета: приложение
     * вправе поймать исключение и не закрывать сокет, тогда пир висел бы до таймаута. Запись в сокет
     * идёт под {@code writeLock}, чтобы не перемешаться с данными другого потока. Блокировку берём
     * без ожидания: читающий поток может держать {@code readLock} и {@code handshakeLock}, а писатель
     * в это время ждать их под {@code writeLock}, и ожидание привело бы к взаимной блокировке. Если
     * писатель занят, alert остаётся в движке и уходит при {@link #close()}. Повторной отправки нет:
     * {@code pollOutboundRecord} отдаёт запись один раз и закрывает выходную сторону движка.
     * Сбой отправки не скрывает исходную ошибку (best-effort).
     */
    private void sendPendingFatalAlert() {
        if (!writeLock.tryLock()) {
            return;
        }
        try {
            byte[] alertRecord = engine.pollOutboundRecord();
            if (alertRecord != null) {
                socketOut.write(alertRecord);
                socketOut.flush();
            }
        } catch (IOException ignored) {
            // alert best-effort: пир увидит обрыв соединения
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Пишет в сокет готовую запись из {@code writeDst} (после {@code flip()}). Запись идёт прямо
     * из массива HeapByteBuffer без промежуточной копии.
     */
    private void writeDstToSocket() throws IOException {
        socketOut.write(
                writeDst.array(),
                writeDst.arrayOffset() + writeDst.position(),
                writeDst.remaining());
    }

    /**
     * Читает полную TLS-запись из socketIn.
     * <p>
     * Предусловие: socketIn доступен под handshakeLock (handshake) или readLock (app data).
     * Замки вкладываются (read() берёт readLock, а неявный startHandshake() внутри — ещё и
     * handshakeLock), поэтому два потока не читают сокет одновременно.
     * <p>
     * EOF между записями (clean close): возвращает null.
     * EOF внутри записи (truncation): IOException.
     *
     * @return ByteBuffer записи (header + body), или null при чистом EOF
     * @throws IOException при ошибке ввода-вывода или truncation
     */
    private ByteBuffer readTlsRecord() throws IOException {
        // Состояние чтения живёт в полях: тайм-аут сокета (SocketTimeoutException) прерывает
        // чтение в любой точке, и повторный вызов продолжает с того же байта
        while (recordHeaderRead < RECORD_HEADER) {
            int n = socketIn.read(recordHeader, recordHeaderRead, RECORD_HEADER - recordHeaderRead);
            if (n == -1) {
                if (recordHeaderRead == 0) return null;
                throw new EOFException(
                        "Truncated TLS record header: "
                                + recordHeaderRead
                                + " of "
                                + RECORD_HEADER
                                + " bytes");
            }
            recordHeaderRead += n;
        }
        if (partialRecord == null) {
            int bodyLen = ((recordHeader[3] & 0xFF) << 8) | (recordHeader[4] & 0xFF);
            if (bodyLen > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
                throw new IOException("TLS record too large: " + bodyLen);
            }
            // Размер по согласованному max_fragment_length здесь не проверяется: дополнение
            // TLSInnerPlaintext не ограничено сверху ничем, кроме общего предела записи (RFC 8446
            // §5.4), а длину открытого текста после расшифровки сверяет TlsRecord (record_overflow)
            partialRecord = new byte[RECORD_HEADER + bodyLen];
            System.arraycopy(recordHeader, 0, partialRecord, 0, RECORD_HEADER);
            partialRecordRead = RECORD_HEADER;
        }
        while (partialRecordRead < partialRecord.length) {
            int n =
                    socketIn.read(
                            partialRecord,
                            partialRecordRead,
                            partialRecord.length - partialRecordRead);
            if (n == -1) throw new EOFException("Unexpected EOF");
            partialRecordRead += n;
        }
        byte[] record = partialRecord;
        partialRecord = null;
        partialRecordRead = 0;
        recordHeaderRead = 0;
        return ByteBuffer.wrap(record);
    }

    /**
     * Затирает недочитанную запись, если сокет сейчас никто не читает (оба замка чтения свободны):
     * затирание под чужим чтением испортило бы его. Иначе затрёт сам читатель при закрытии.
     */
    private void discardPartialRecordIfIdle() {
        if (!handshakeLock.tryLock()) {
            return;
        }
        try {
            TlsUtils.wipeArray(partialRecord);
            partialRecord = null;
            partialRecordRead = 0;
            TlsUtils.wipeArray(recordHeader);
            recordHeaderRead = 0;
        } finally {
            handshakeLock.unlock();
        }
    }

    // ========================================================================
    // String representation
    // ========================================================================

    @Override
    public String toString() {
        return "GostSSLSocket["
                + (clientMode ? "CLIENT" : "SERVER")
                + ", "
                + (handshakeDone ? "HANDSHAKED" : "NOT_HANDSHAKED")
                + "]";
    }

    /** Для тестов: закрывает TCP-сокет без close_notify. */
    void closeUnderlyingForTest() throws IOException {
        socket.close();
    }
}
