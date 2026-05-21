package org.rssys.gost.jsse.engine;

import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.TlsPskHelper;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Контекст сессии для ГОСТ TLS 1.3 по JSSE-контракту.
 * <p>
 * Держит два хранилища:
 * <ul>
 *   <li>{@link InMemoryPskStore} — PSK-тикеты для session resumption</li>
 *   <li>{@code ConcurrentHashMap<sessionId, GostSSLSession>} — для JSSE API
 *       ({@link #getSession(byte[])}, {@link #getIds()})</li>
 *   <li>{@code ConcurrentHashMap<HostPort, byte[]>} — привязка (host,port)→идентификатор
 *       тикета для безопасного клиентского lookup</li>
 * </ul>
 * <p>
 * Предусловия:
 * <ul>
 *   <li>maxSize >= 1 (передаётся в InMemoryPskStore)</li>
 *   <li>sessionTimeout == 0 означает «без ограничения» (JSSE-контракт)</li>
 * </ul>
 */
public final class GostSSLSessionContext implements SSLSessionContext {

    /** RFC 8446 §4.6.1: ticket_lifetime MUST NOT exceed 604800 seconds (7 days) */
    private static final long RFC_MAX_TICKET_LIFETIME = 604800L;
    private static final int DEFAULT_MAX_PSK = 1000;
    private static Logger LOG = System.getLogger("org.rssys.gost.jsse.GostSSLSessionContext");

    private int maxIdentityEntries = 1000;

    /** setter для тестов (eviction limit) */
    void setMaxIdentityEntries(int n) {
        this.maxIdentityEntries = n;
    }

    private InMemoryPskStore pskStore;
    private final ReentrantLock sessionsLock = new ReentrantLock();
    private final Map<ByteBuffer, GostSSLSession> sessions;
    private Map<HostPort, byte[]> identityByHost;
    private final TlsCiphersuite ciphersuite;
    private final int hashLen;
    private volatile int sessionTimeout = 86400;
    private volatile int sessionCacheSize;

    /**
     * @param ciphersuite cipher suite для PSK-деривации
     * @param hashLen     длина хэша (32 для Streebog-256)
     */
    public GostSSLSessionContext(TlsCiphersuite ciphersuite, int hashLen) {
        this.pskStore = new InMemoryPskStore(DEFAULT_MAX_PSK);
        this.sessions = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<ByteBuffer, GostSSLSession> eldest) {
                return sessionCacheSize > 0 && size() > sessionCacheSize;
            }
        };
        this.identityByHost = new ConcurrentHashMap<>();
        this.ciphersuite = ciphersuite;
        this.hashLen = hashLen;
    }

    // ========================================================================
    // SSLSessionContext API
    // ========================================================================

    @Override
    public SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) return null;
        sessionsLock.lock();
        try {
            return sessions.get(ByteBuffer.wrap(sessionId));
        } finally {
            sessionsLock.unlock();
        }
    }

    @Override
    public Enumeration<byte[]> getIds() {
        List<ByteBuffer> keys;
        sessionsLock.lock();
        try {
            keys = List.copyOf(sessions.keySet());
        } finally {
            sessionsLock.unlock();
        }
        return new Enumeration<>() {
            private final Iterator<ByteBuffer> it = keys.iterator();

            @Override
            public boolean hasMoreElements() {
                return it.hasNext();
            }

            @Override
            public byte[] nextElement() {
                ByteBuffer buf = it.next();
                byte[] id = new byte[buf.remaining()];
                buf.duplicate().get(id);
                return id;
            }
        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * Предусловие: timeout ≥ 0 (JSSE-контракт).
     */
    @Override
    public void setSessionTimeout(int seconds) {
        if (seconds < 0) throw new IllegalArgumentException("Timeout must be non-negative");
        this.sessionTimeout = seconds;
    }

    @Override
    public int getSessionTimeout() {
        return sessionTimeout;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Предусловие: size ≥ 0 (JSSE-контракт).
     */
    @Override
    public void setSessionCacheSize(int size) {
        if (size < 0) throw new IllegalArgumentException("Cache size must be non-negative");
        this.sessionCacheSize = size;
    }

    @Override
    public int getSessionCacheSize() {
        return sessionCacheSize;
    }

    // ========================================================================
    // Внутренние методы (package-private, для GostSSLSession и GostSSLEngine)
    // ========================================================================

    /**
     * Сохраняет сессию в кэш sessionId→GostSSLSession и устанавливает
     * обратную ссылку session→context.
     */
    void putSession(GostSSLSession session) {
        sessionsLock.lock();
        try {
            session.setSessionContext(this);
            sessions.put(ByteBuffer.wrap(session.getId()), session);
        } finally {
            sessionsLock.unlock();
        }
    }

    /**
     * Удаляет сессию из кэша.
     */
    void removeSession(GostSSLSession session) {
        sessionsLock.lock();
        try {
            sessions.remove(ByteBuffer.wrap(session.getId()));
        } finally {
            sessionsLock.unlock();
        }
    }

    /** @return PskStore для прямого доступа (серверный lookup, тесты) */
    public InMemoryPskStore getPskStore() {
        return pskStore;
    }

    /**
     * Сохраняет NewSessionTicket в PskStore и в карту host:port→identity.
     * <p>
     * Постусловие: PSK доступен для последующего resumption через
     * {@link #getForClientResumption(String, int)}.
     *
     * @param peerHost   DNS-имя пира
     * @param peerPort   порт пира
     * @param rms        Resumption Master Secret
     * @param nstBody    тело NewSessionTicket (парсится внутри)
     * @throws TlsException при ошибке парсинга NST
     */
    void saveNewSessionTicket(String peerHost, int peerPort,
                               byte[] rms, byte[] nstBody) throws TlsException {
        TlsMessageParser.ParsedNewSessionTicket parsed =
                TlsMessageParser.parseNewSessionTicket(nstBody);
        byte[] psk = TlsPskHelper.derivePsk(rms, parsed.ticketNonce, hashLen);
        if (psk == null) {
            LOG.log(Level.WARNING, "PSK derivation failed for {0}:{1}, NST not saved",
                    peerHost, peerPort);
            return;
        }
        long effectiveLifetime = effectiveTtl(parsed.ticketLifetime);
        PskEntry entry = new PskEntry(parsed.ticket, effectiveLifetime,
                parsed.ticketAgeAdd, parsed.ticketNonce, psk,
                System.currentTimeMillis());
        pskStore.onTicketReceived(entry);
        // ConcurrentHashMap без LRU — при превышении лимита вытесняем случайный entry
        if (identityByHost.size() >= maxIdentityEntries) {
            identityByHost.entrySet().stream().findAny().ifPresent(
                    e -> identityByHost.remove(e.getKey()));
        }
        identityByHost.put(new HostPort(peerHost, peerPort), parsed.ticket);
        LOG.log(Level.DEBUG, "NST saved for {0}:{1}, lifetime={2}s",
                peerHost, peerPort, effectiveLifetime);
    }

    /** Тестовый хелпер: подменить logger для перехвата сообщений. Возвращает предыдущий для restore в tearDown. */
    static System.Logger setLoggerForTest(System.Logger testLogger) {
        System.Logger prev = LOG;
        LOG = testLogger;
        return prev;
    }

    /**
     * Ищет PSK для клиентского resumption по (host, port).
     * <p>
     * Безопасность: lookup идёт в два этапа — сначала host:port→identity,
     * затем identity→PskEntry. Это исключает использование PSK от другого
     * сервера (императив #1).
     *
     * @param host DNS-имя сервера
     * @param port порт сервера
     * @return PskEntry или null если нет подходящего
     */
    PskEntry getForClientResumption(String host, int port) {
        byte[] identity = identityByHost.get(new HostPort(host, port));
        if (identity == null) return null;
        return pskStore.get(identity);
    }

    /**
     * Ищет PSK по идентификатору тикета (серверный lookup).
     *
     * @param identity opaque ticket identity
     * @return PskEntry или null
     */
    PskEntry getByIdentity(byte[] identity) {
        return pskStore.get(identity);
    }

    // ========================================================================
    // Внутренние хелперы
    // ========================================================================

    /**
     * Вычисляет effective TTL по трём ограничениям:
     * <ol>
     *   <li>ticketLifetime из NST (RFC 8446: ≤ 604800)</li>
     *   <li>sessionTimeout от приложения (0 = без ограничения)</li>
     *   <li>RFC_MAX_TICKET_LIFETIME (604800)</li>
     * </ol>
     */
    private long effectiveTtl(long ticketLifetime) {
        long st = sessionTimeout;
        long capped = (st == 0) ? RFC_MAX_TICKET_LIFETIME : Math.min(st, RFC_MAX_TICKET_LIFETIME);
        return Math.min(ticketLifetime, capped);
    }

    /**
     * Переключает pskStore и identityByHost на shared-объекты из другого контекста.
     * <p>
     * После вызова оба экземпляра читают и пишут в одни и те же хранилища —
     * PSK, сохранённые через любой из них, видны обоим (необходимо для
     * разделения сессионного контекста между клиентом и сервером в тестах
     * PSK resumption через Netty).
     * <p>
     * Предусловие: вызывается в однопоточном контексте строителя
     * {@code GostSslContextBuilder.build()} до начала handshake.
     * После начала handshake — неопределённое поведение.
     *
     * @param shared контекст, чьи pskStore и identityByHost становятся общими
     */
    public void redirectToSharedState(GostSSLSessionContext shared) {
        this.pskStore = shared.pskStore;
        this.identityByHost = shared.identityByHost;
    }

    /**
     * Value-based ключ для карты host:port→identity.
     * equals/hashCode по (host, port).
     */
    private static final class HostPort {
        private final String host;
        private final int port;

        HostPort(String host, int port) {
            this.host = host != null ? host : "";
            this.port = port;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof HostPort)) return false;
            HostPort hp = (HostPort) o;
            return port == hp.port && host.equals(hp.host);
        }

        @Override
        public int hashCode() {
            return Objects.hash(host, port);
        }
    }
}
