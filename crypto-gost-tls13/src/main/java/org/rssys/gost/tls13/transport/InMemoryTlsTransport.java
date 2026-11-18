package org.rssys.gost.tls13.transport;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.rssys.gost.tls13.TlsTransport;

/**
 * Транспорт TLS 1.3 в памяти — однонаправленный или парный.
 *
 * <p>Используется для тестов и для связи сессий в одном JVM-процессе.
 * Поддерживает два режима:
 * <ul>
 *   <li><b>Однонаправленный</b> — создать {@code new InMemoryTlsTransport()},
 *       запись через {@link #inject(byte[])} или {@link #sendRecord(byte[])}
 *       (обе кладут запись во входящую очередь самого транспорта).</li>
 *   <li><b>Парный (двунаправленный)</b> — создать через
 *       {@link #newPair()}, получить {@code clientTransport} и
 *       {@code serverTransport}.</li>
 * </ul>
 *
 * <p><b>Закрытие.</b> Транспорт одноразовый (single-use). {@link #close()} закрывает
 * соединение целиком: у пары обе стороны разделяют одну метку закрытия, поэтому закрытие
 * любой стороны видит и вторая. Полузакрытия на уровне транспорта нет: полузакрытие
 * RFC 8446 §6.1 выражается на уровне TLS через {@code close_notify}, а не через
 * {@code transport.close()}.
 * <ul>
 *   <li>{@link #receiveRecord()} сначала отдаёт всё, что уже стоит в очереди, затем
 *       бросает {@link IOException}. Ждущий вызов просыпается не позже одного кванта
 *       опроса после закрытия.</li>
 *   <li>{@link #sendRecord(byte[])} после закрытия бросает {@link IOException}.</li>
 *   <li>{@link #inject(byte[])} — тестовый вход; его использование после закрытия считается
 *       ошибкой программиста и бросает {@link IllegalStateException}. На парном транспорте
 *       с общей меткой он бросает и после закрытия пира; на парах он не используется.</li>
 * </ul>
 *
 * <p>Таймаут чтения — 10 секунд. Потокобезопасно: очереди —
 * {@link LinkedBlockingQueue}, метка закрытия — {@link AtomicBoolean}.
 */
public class InMemoryTlsTransport implements TlsTransport {

    /** Текст ошибки операции над закрытым соединением. */
    static final String MSG_TRANSPORT_CLOSED = "Transport closed";

    /** Текст ошибки истёкшего срока ожидания записи. */
    static final String MSG_RECEIVE_TIMEOUT = "Receive timeout";

    /** Общий срок ожидания записи в {@link #receiveRecord()}. */
    static final Duration DEFAULT_RECEIVE_TIMEOUT = Duration.ofSeconds(10);

    /**
     * Квант опроса: ждущий {@link #receiveRecord()} перечитывает метку закрытия не реже
     * одного раза за квант. Запись, пришедшая раньше, возвращается сразу, без ожидания кванта.
     */
    private static final long POLL_QUANTUM_NANOS = TimeUnit.MILLISECONDS.toNanos(50);

    private final LinkedBlockingQueue<byte[]> inbound;
    private final LinkedBlockingQueue<byte[]> outbound;
    private final AtomicBoolean connectionClosed;
    private final long receiveTimeoutNanos;

    /** Создаёт транспорт с собственной входящей очередью. */
    public InMemoryTlsTransport() {
        this(new LinkedBlockingQueue<>());
    }

    /**
     * Создаёт транспорт с готовой входящей очередью (для ручной сборки пар). Исходящие записи
     * кладутся в ту же очередь, метка закрытия у транспорта своя.
     *
     * @param inbound готовая входящая очередь
     */
    public InMemoryTlsTransport(LinkedBlockingQueue<byte[]> inbound) {
        this(inbound, DEFAULT_RECEIVE_TIMEOUT);
    }

    /**
     * То же, что {@link #InMemoryTlsTransport(LinkedBlockingQueue)}, но с заданным сроком
     * ожидания записи (для теста истечения срока).
     */
    InMemoryTlsTransport(LinkedBlockingQueue<byte[]> inbound, Duration timeout) {
        this(inbound, inbound, new AtomicBoolean(), timeout);
    }

    /** Общий конструктор: им же {@link #newPair()} собирает пару с общей меткой закрытия. */
    InMemoryTlsTransport(
            LinkedBlockingQueue<byte[]> inbound,
            LinkedBlockingQueue<byte[]> outbound,
            AtomicBoolean connectionClosed,
            Duration timeout) {
        this.inbound = Objects.requireNonNull(inbound, "inbound");
        this.outbound = Objects.requireNonNull(outbound, "outbound");
        this.connectionClosed = Objects.requireNonNull(connectionClosed, "connectionClosed");
        Objects.requireNonNull(timeout, "timeout");
        // нулевой срок молча превратил бы транспорт в «всегда Receive timeout»
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("Receive timeout must be positive");
        }
        this.receiveTimeoutNanos = timeout.toNanos();
    }

    /**
     * Внедряет запись напрямую во входящую очередь (для тестов и канала обратной связи).
     * Для однонаправленного режима.
     *
     * @param record TLS-запись для внедрения
     * @throws IllegalStateException если соединение закрыто (ошибка использования)
     */
    public void inject(byte[] record) {
        if (connectionClosed.get()) throw new IllegalStateException(MSG_TRANSPORT_CLOSED);
        inbound.add(record.clone());
    }

    /**
     * Отправляет запись в исходящую очередь: у пары это входящая очередь пира, у
     * однонаправленного транспорта — его собственная.
     *
     * <p>Записи, чей {@code add} произошёл раньше {@link #close()}, получатель увидит по
     * порядку до исключения. Между проверкой метки и {@code add} пир может закрыться, и такая
     * запись останется в очереди, которую уже не прочитают: проверка метки доставки не
     * гарантирует.
     *
     * @param record TLS-запись для отправки
     * @throws IOException если соединение закрыто
     */
    @Override
    public void sendRecord(byte[] record) throws IOException {
        if (connectionClosed.get()) throw new IOException(MSG_TRANSPORT_CLOSED);
        outbound.add(record.clone());
    }

    /**
     * Принимает следующую TLS-запись из входящей очереди.
     *
     * <p>Ожидание ограничено общим сроком и идёт квантами. Метка закрытия читается ДО опроса
     * очереди: всё, что пир поставил в очередь до своего {@link #close()}, отдаётся раньше
     * исключения. Если очередь пуста и соединение закрыто — {@link IOException}.
     *
     * @return сырая TLS-запись (с заголовком)
     * @throws IOException при истечении срока, закрытии соединения или прерывании
     */
    @Override
    public byte[] receiveRecord() throws IOException {
        // Срок вычисляется один раз: пересчёт на каждой итерации дал бы бесконечное ожидание
        long deadline = System.nanoTime() + receiveTimeoutNanos;
        try {
            while (true) {
                boolean closedSeen = connectionClosed.get();
                long remaining = deadline - System.nanoTime();
                if (!closedSeen && remaining <= 0) {
                    throw new IOException(MSG_RECEIVE_TIMEOUT);
                }
                long waitNanos = closedSeen ? 0 : Math.min(remaining, POLL_QUANTUM_NANOS);
                byte[] record = inbound.poll(waitNanos, TimeUnit.NANOSECONDS);
                if (record != null) return record;
                if (closedSeen) throw new IOException(MSG_TRANSPORT_CLOSED);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }

    /**
     * Закрывает соединение целиком: ставит общую метку закрытия. Идемпотентно.
     *
     * <p>Уже поставленные в очередь записи не теряются — {@link #receiveRecord()} отдаст их
     * до выброса {@link IOException}.
     */
    @Override
    public void close() {
        connectionClosed.set(true);
    }

    /**
     * Создаёт пару связанных транспортов для двунаправленной связи.
     *
     * <p>Использование:
     * <pre>{@code
     * InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
     * TlsSession server = TlsSession.createServer(
     *         pair.getServerTransport(), cs, cert, priv);
     * TlsSession client = TlsSession.createClientWithoutServerAuth(
     *         pair.getClientTransport(), cs, null, null);
     * }</pre>
     *
     * <p>Закрытие любой стороны закрывает соединение целиком (см. описание класса).
     */
    public static Pair newPair() {
        return newPair(DEFAULT_RECEIVE_TIMEOUT);
    }

    /** То же, но с заданным сроком ожидания записи (для тестов). */
    static Pair newPair(Duration timeout) {
        LinkedBlockingQueue<byte[]> c2s = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> s2c = new LinkedBlockingQueue<>();
        AtomicBoolean connectionClosed = new AtomicBoolean();

        InMemoryTlsTransport clientTransport =
                new InMemoryTlsTransport(s2c, c2s, connectionClosed, timeout);
        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s, s2c, connectionClosed, timeout);

        return new Pair(clientTransport, serverTransport, c2s, s2c);
    }

    /**
     * Пара связанных транспортов (клиент + сервер).
     */
    public static final class Pair {
        private final InMemoryTlsTransport clientTransport;
        private final InMemoryTlsTransport serverTransport;
        private final LinkedBlockingQueue<byte[]> c2s;
        private final LinkedBlockingQueue<byte[]> s2c;

        Pair(
                InMemoryTlsTransport clientTransport,
                InMemoryTlsTransport serverTransport,
                LinkedBlockingQueue<byte[]> c2s,
                LinkedBlockingQueue<byte[]> s2c) {
            this.clientTransport = clientTransport;
            this.serverTransport = serverTransport;
            this.c2s = c2s;
            this.s2c = s2c;
        }

        /** @return транспорт со стороны клиента */
        public InMemoryTlsTransport getClientTransport() {
            return clientTransport;
        }

        /** @return транспорт со стороны сервера */
        public InMemoryTlsTransport getServerTransport() {
            return serverTransport;
        }

        /** @return очередь клиент->сервер (для тестов) */
        public LinkedBlockingQueue<byte[]> getClientToServerQueue() {
            return c2s;
        }

        /** @return очередь сервер->клиент (для тестов) */
        public LinkedBlockingQueue<byte[]> getServerToClientQueue() {
            return s2c;
        }
    }
}
