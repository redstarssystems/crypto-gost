package org.rssys.gost.tls13.transport;

import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.rssys.gost.tls13.TlsTransport;

/**
 * Транспорт TLS 1.3 в памяти — однонаправленный или парный.
 *
 * <p>Используется для тестов и для связи сессий в одном JVM-процессе.
 * Поддерживает два режима:
 * <ul>
 *   <li><b>Однонаправленный</b> — создать {@code new InMemoryTlsTransport()},
 *       запись через {@link #inject(byte[])}.</li>
 *   <li><b>Парный (двунаправленный)</b> — создать через
 *       {@link #newPair()}, получить {@code clientTransport} и
 *       {@code serverTransport}.</li>
 * </ul>
 *
 * <p><b>Важно:</b> Транспорт одноразовый (single-use). После {@link #close()}
 * экземпляр не подлежит переиспользованию — все операции проверяют
 * флаг {@code closed} и вызовут {@link IllegalStateException}.
 * Уже поставленные в очередь записи при этом не теряются —
 * {@link #receiveRecord()} отдаст их до выброса исключения.
 *
 * <p>Таймаут чтения — 10 секунд.
 * Потокобезопасно: каждая очередь — {@link LinkedBlockingQueue}.
 */
public class InMemoryTlsTransport implements TlsTransport {

    private final LinkedBlockingQueue<byte[]> inbound;
    volatile boolean closed;

    /** Создаёт транспорт с собственной входящей очередью. */
    public InMemoryTlsTransport() {
        this.inbound = new LinkedBlockingQueue<>();
    }

    /** @param inbound готовая входящая очередь (для Pair). */
    public InMemoryTlsTransport(LinkedBlockingQueue<byte[]> inbound) {
        this.inbound = inbound;
    }

    /**
     * Внедряет запись напрямую (для тестов и канала обратной связи).
     * Для однонаправленного режима.
     *
     * @param record TLS-запись для внедрения
     */
    public void inject(byte[] record) {
        if (closed) throw new IllegalStateException("Transport closed");
        inbound.add(record.clone());
    }

    /**
     * Отправляет запись через {@link #inject(byte[])}.
     * <p>
     * Для парного режима переопределяется в анонимном классе
     * ({@link #newPair()}) — перенаправляет в очередь пира.
     *
     * @param record TLS-запись для отправки
     * @throws IOException при ошибке отправки
     */
    @Override
    public void sendRecord(byte[] record) throws IOException {
        inject(record);
    }

    /**
     * Принимает следующую TLS-запись из входящей очереди.
     * <p>
     * Двухфазный poll: сначала без блокировки (для немедленного drain-а
     * после close), затем с таймаутом 10 секунд (для нормального ожидания).
     * Если очередь пуста и транспорт закрыт — {@link IOException}.
     *
     * @return сырая TLS-запись (с заголовком)
     * @throws IOException при ошибке получения записи
     */
    @Override
    public byte[] receiveRecord() throws IOException {
        try {
            byte[] record = inbound.poll();
            if (record != null) return record;
            if (closed) throw new IOException("Transport closed");
            record = inbound.poll(10, TimeUnit.SECONDS);
            if (record != null) return record;
            throw new IOException("Receive timeout");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }

    /**
     * Закрывает транспорт: устанавливает флаг {@code closed}.
     * <p>
     * Уже поставленные в очередь записи не теряются —
     * {@link #receiveRecord()} отдаст их до выброса {@link IOException}.
     */
    @Override
    public void close() {
        closed = true;
    }

    /**
     * Создаёт пару связанных транспортов для двунаправленной связи.
     *
     * <p>Использование:
     * <pre>{@code
     * InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
     * TlsSession server = TlsSession.createServer(
     *         pair.getServerTransport(), cs, cert, priv);
     * TlsSession client = TlsSession.createClient(
     *         pair.getClientTransport(), cs, null, null);
     * }</pre>
     */
    public static Pair newPair() {
        LinkedBlockingQueue<byte[]> c2s = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> s2c = new LinkedBlockingQueue<>();

        InMemoryTlsTransport clientTransport =
                new InMemoryTlsTransport(s2c) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        if (closed) throw new IOException("Transport closed");
                        c2s.add(record.clone());
                    }
                };
        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        if (closed) throw new IOException("Transport closed");
                        s2c.add(record.clone());
                    }
                };

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
