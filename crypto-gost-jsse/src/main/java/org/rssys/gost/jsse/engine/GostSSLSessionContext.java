package org.rssys.gost.jsse.engine;

import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.cert.PeerTrustBoundary;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.psk.TlsTicketHelper;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Контекст сессии для ГОСТ TLS 1.3 по JSSE-контракту.
 * <p>
 * Держит три хранилища:
 * <ul>
 *   <li>{@link InMemoryPskStore} — PSK-тикеты для session resumption</li>
 *   <li>{@code LinkedHashMap<sessionId, GostSSLSession>} с порядком по обращению под
 *       {@link ReentrantLock} — для JSSE API ({@link #getSession(byte[])}, {@link #getIds()})</li>
 *   <li>{@code ConcurrentHashMap<HostPort, byte[]>} — привязка (host,port)->идентификатор
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
    static final long RFC_MAX_TICKET_LIFETIME = 604800L;

    // Один предел для хранилища тикетов и для привязки (host, port)->тикет: каждая привязка
    // указывает на тикет, и держать их больше, чем тикетов, незачем.
    private static final int DEFAULT_MAX_ENTRIES = 1000;
    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.engine.GostSSLSessionContext");

    private int maxIdentityEntries = DEFAULT_MAX_ENTRIES;

    /** Предел привязок (host, port)->тикет; для проверки вытеснения в тестах. */
    void setMaxIdentityEntries(int n) {
        if (n < 1) {
            throw new IllegalArgumentException("maxIdentityEntries must be positive");
        }
        this.maxIdentityEntries = n;
    }

    /**
     * Предел кэша сессий по умолчанию, одинаковый для клиента и сервера (как в JDK). Без предела
     * каждое полное рукопожатие оставляло бы в серверном кэше сессию до истечения её срока, и
     * поток соединений занимал бы память без границы. {@code setSessionCacheSize(0)} по контракту
     * {@code SSLSessionContext} снимает предел.
     */
    public static final int DEFAULT_SESSION_CACHE_SIZE = 20_480;

    private InMemoryPskStore pskStore;
    private final ReentrantLock sessionsLock = new ReentrantLock();
    private final Map<ByteBuffer, GostSSLSession> sessions;
    private Map<HostPort, byte[]> identityByHost;
    private final int hashLen;
    private volatile int sessionTimeout = TlsConstants.DEFAULT_SESSION_TIMEOUT;
    private volatile int sessionCacheSize = DEFAULT_SESSION_CACHE_SIZE;
    private boolean interopAcceptGostBaseSigScheme;

    private volatile EndpointIdentificationMode endpointIdentificationMode =
            EndpointIdentificationMode.DEFAULT;

    /**
     * Задаёт режим проверки имени узла для клиентских engine, создаваемых после вызова.
     *
     * <p>Решение уровня контекста: уже созданные engine не меняются. Служебный метод адаптеров
     * (например, Netty), которые не задают проверку имени сами; прикладному коду нужен
     * {@code GostSslBuilder}. Вызывать до начала рукопожатий через контекст. Включение
     * {@link EndpointIdentificationMode#DISABLED} пишет в журнал одно предупреждение на
     * контекст.</p>
     *
     * @param mode режим проверки имени (не null)
     * @throws IllegalArgumentException если mode равен null
     * @see EndpointIdentificationMode
     */
    public void setEndpointIdentificationMode(EndpointIdentificationMode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("endpointIdentificationMode must not be null");
        }
        if (mode == EndpointIdentificationMode.DISABLED
                && endpointIdentificationMode != EndpointIdentificationMode.DISABLED) {
            LOG.log(
                    Level.WARNING,
                    "Hostname verification is DISABLED for this session context: client engines"
                            + " accept a certificate of any trusted CA for any host."
                            + " Disable it only for development or closed networks.");
        }
        this.endpointIdentificationMode = mode;
    }

    /** @return режим проверки имени узла для клиентских engine контекста (не null) */
    public EndpointIdentificationMode getEndpointIdentificationMode() {
        return endpointIdentificationMode;
    }

    /**
     * Включает приём базовых signature scheme от серверов openssl-gost-provider: сервер шлёт
     * 0x0709 или 0x070D независимо от реальной кривой сертификата.
     *
     * @param enabled true - принимать
     */
    public void setInteropAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
    }

    /** @return true, если приём базовых signature scheme включён */
    public boolean isInteropAcceptGostBaseSigScheme() {
        return interopAcceptGostBaseSigScheme;
    }

    private boolean needClientAuth;
    private boolean wantClientAuth;

    private volatile ClientOcspPolicy clientOcspPolicy = ClientOcspPolicy.OFF;

    /**
     * Задаёт политику сервера в отношении OCSP-staple клиентского сертификата
     * (RFC 8446 §4.4.2.1). Применяется ко всем engine, созданным через этот контекст;
     * действует при аутентификации клиента ({@code need} или {@code want}).
     * Серверная настройка: для клиентского контекста игнорируется.
     * Значение по умолчанию - {@link ClientOcspPolicy#OFF}.
     *
     * @param policy политика (не null)
     * @throws IllegalArgumentException если policy равен null
     */
    public void setClientOcspPolicy(ClientOcspPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("clientOcspPolicy must not be null");
        }
        this.clientOcspPolicy = policy;
    }

    /** @return политика в отношении клиентского OCSP-staple (не null) */
    public ClientOcspPolicy getClientOcspPolicy() {
        return clientOcspPolicy;
    }

    /**
     * Включает обязательную аутентификацию клиента (mTLS). Аналог
     * {@code SSLServerSocket.setNeedClientAuth(true)}. Флаг хранится на контексте сессий и
     * применяется ко всем серверным engine, созданным через этот контекст.
     *
     * @param need true - клиентский сертификат обязателен
     */
    public void setNeedClientAuth(boolean need) {
        this.needClientAuth = need;
    }

    /** @return true, если клиентский сертификат обязателен */
    public boolean isNeedClientAuth() {
        return needClientAuth;
    }

    /**
     * Включает необязательную аутентификацию клиента: сертификат запрашивается, но клиент
     * вправе его не предъявлять. Аналог {@code SSLServerSocket.setWantClientAuth(true)}.
     * Если одновременно включён {@link #setNeedClientAuth(boolean)}, действует обязательный
     * режим. Флаг применяется ко всем engine, созданным через этот контекст.
     */
    public void setWantClientAuth(boolean want) {
        this.wantClientAuth = want;
    }

    /** @return true, если клиентский сертификат запрашивается, но не обязателен */
    public boolean isWantClientAuth() {
        return wantClientAuth;
    }

    /**
     * Создаёт контекст сессий.
     *
     * @param ciphersuite набор шифров, от которого берётся длина хэша для PSK-деривации
     *                    (у наборов L и S она одинакова: 32 байта, Streebog-256)
     */
    public GostSSLSessionContext(TlsCiphersuite ciphersuite) {
        this.pskStore = new InMemoryPskStore(DEFAULT_MAX_ENTRIES);
        this.sessions =
                new LinkedHashMap<>(16, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(
                            Map.Entry<ByteBuffer, GostSSLSession> eldest) {
                        if (sessionCacheSize > 0 && size() > sessionCacheSize) return true;
                        return !eldest.getValue().isValid();
                    }
                };
        this.identityByHost = new ConcurrentHashMap<>();
        this.hashLen = ciphersuite.getHashLen();
    }

    // ========================================================================
    // SSLSessionContext API
    // ========================================================================

    @Override
    public SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) return null;
        sessionsLock.lock();
        try {
            ByteBuffer key = ByteBuffer.wrap(sessionId);
            GostSSLSession session = sessions.get(key);
            if (session != null && !session.isValid()) {
                sessions.remove(key);
                return null;
            }
            return session;
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
     * Сохраняет сессию в кэш sessionId->GostSSLSession и устанавливает
     * обратную ссылку session->context.
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
     * Сохраняет NewSessionTicket в PskStore и в карту host:port->identity.
     * <p>
     * Постусловие: PSK доступен для последующего resumption через
     * {@link #getForClientResumption(String, int, PskBinding)}.
     *
     * @param peerHost   DNS-имя пира; для {@code null} и blank тикет не сохраняется
     * @param peerPort   порт пира
     * @param rms        Resumption Master Secret
     * @param parsed     разобранный NewSessionTicket (структуру проверил движок)
     * @param binding    привязка к серверу и модели доверия, по которой сервер был принят
     * @param validUntil граница доверия: наименьший {@code notAfter} среди сертификатов сервера
     *                   (миллисекунды эпохи); срок тикета ограничивается остатком до неё
     */
    void saveNewSessionTicket(
            String peerHost,
            int peerPort,
            byte[] rms,
            TlsMessageParser.ParsedNewSessionTicket parsed,
            PskBinding binding,
            long validUntil) {
        // Тикет привязан к имени сервера (host:port). Без имени узла привязывать не к чему, а
        // поиск при пустом host всё равно не выполняется: запись только занимала бы кэш.
        if (peerHost == null || peerHost.isBlank()) {
            return;
        }
        // Тикет, который не поместится в расширение pre_shared_key, предъявить нельзя: ClientHello
        // вышел бы с переполненными длинами. Не сохраняем, соединение пойдёт полным рукопожатием.
        if (parsed.ticket.length > TlsPskHelper.maxIdentityLength(hashLen)) {
            LOG.log(Level.WARNING, "NewSessionTicket for {0} is too long to be offered", peerHost);
            return;
        }
        // Тикет не должен пережить сертификаты сервера: при возобновлении клиент их не видит.
        // Граница уже наступила - тикет не сохраняем, PSK не выводим.
        long now = System.currentTimeMillis();
        long effectiveLifetime =
                PeerTrustBoundary.clampLifetimeSeconds(
                        effectiveTtl(parsed.ticketLifetime), validUntil, now);
        if (effectiveLifetime <= 0) {
            return;
        }
        // Сбой хранилища или вывода PSK: тикет не сохранён, идентификатор для поиска не запоминаем
        if (!TlsTicketHelper.storeReceived(
                pskStore,
                rms,
                parsed.ticket,
                parsed.ticketNonce,
                parsed.ticketAgeAdd,
                effectiveLifetime,
                now,
                binding,
                validUntil,
                hashLen)) {
            LOG.log(Level.DEBUG, "NST not saved for {0}:{1}", peerHost, peerPort);
            return;
        }
        // ConcurrentHashMap без порядка вытеснения: при превышении предела уходит произвольная
        // запись
        if (identityByHost.size() >= maxIdentityEntries) {
            identityByHost.entrySet().stream()
                    .findAny()
                    .ifPresent(e -> identityByHost.remove(e.getKey()));
        }
        identityByHost.put(new HostPort(peerHost, peerPort), parsed.ticket);
        LOG.log(
                Level.DEBUG,
                "NST saved for {0}:{1}, lifetime={2}s",
                peerHost,
                peerPort,
                effectiveLifetime);
    }

    /**
     * Удаляет привязку host:port->identity из identityByHost.
     * Вызывается из GostSSLEngine при успешном возобновлении по PSK и при снятии
     * устаревшего тикета, который клиент больше не предлагает.
     */
    void removeIdentity(String host, int port) {
        identityByHost.remove(new HostPort(host, port));
    }

    /**
     * Ищет PSK для клиентского resumption по (host, port).
     * <p>
     * Безопасность: lookup идёт в два этапа — сначала host:port->identity,
     * затем identity->PskEntry. Это исключает использование PSK от другого
     * сервера.
     *
     * @param host     DNS-имя сервера
     * @param port     порт сервера
     * @param expected привязка, которую клиент ожидает от записи: сервер и модель доверия
     * @return PskEntry с равной привязкой или null если нет подходящего
     */
    PskEntry getForClientResumption(String host, int port, PskBinding expected) {
        byte[] identity = identityByHost.get(new HostPort(host, port));
        if (identity == null) return null;
        PskEntry entry = pskStore.peek(identity);
        // Хранилище отдаёт запись по байтам тикета без привязки: сверяем сами. Запись с чужой
        // привязкой (другой режим проверки имени или другой менеджер доверия) при
        // возобновлении пропустила бы проверку сервера.
        if (entry == null || !expected.equals(entry.getBinding())) {
            return null;
        }
        return entry;
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
        return Math.min(ticketLifetime, maxTicketLifetimeSeconds());
    }

    /**
     * Предел срока жизни тикета в секундах: тайм-аут сессии приложения, но не более предела
     * RFC 8446 §4.6.1. Нулевой тайм-аут означает «без ограничения», то есть предел RFC.
     */
    long maxTicketLifetimeSeconds() {
        long timeout = sessionTimeout;
        return timeout == 0 ? RFC_MAX_TICKET_LIFETIME : Math.min(timeout, RFC_MAX_TICKET_LIFETIME);
    }

    /**
     * Переключает pskStore и identityByHost на shared-объекты из другого контекста.
     * <p>
     * После вызова оба экземпляра читают и пишут в одни и те же хранилища.
     * <p>
     * Ограничения:
     * <ul>
     *   <li>общее состояние допустимо между контекстами одной роли; для клиента и сервера
     *       его использовать нельзя: клиентская и серверная записи с одним тикетом имеют
     *       разные привязки, а ключ хранилища - байты тикета, поэтому они затирают друг друга
     *       и возобновление молча отключается (движок такую ошибку не обнаруживает);</li>
     *   <li>общее состояние между клиентскими контекстами с разными менеджерами доверия не
     *       даёт возобновления: тикет привязан к экземпляру менеджера доверия, это
     *       намеренно.</li>
     * </ul>
     * <p>
     * Служебный метод адаптеров (например, {@code GostSslContextBuilder} модуля Netty).
     * Общими становятся только хранилище PSK-тикетов и привязки host:port; тайм-аут сессий,
     * размер кэша JSSE-сессий, режим проверки имени, политика OCSP и interop-флаги остаются
     * у каждого контекста свои. Срок жизни тикета вычисляется один раз, при его сохранении, по
     * тайм-ауту контекста, который тикет получил или выдал; контекст, читающий тот же тикет из
     * общего хранилища, свой тайм-аут к нему не применяет. Предел хранилища тикетов фиксирован
     * (1000 записей) и от размера кэша сессий не зависит.
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
     * Value-based ключ для карты host:port->identity.
     * equals/hashCode по (host, port).
     */
    private static final class HostPort {
        private final String host;
        private final int port;

        HostPort(String host, int port) {
            // DNS-имена регистронезависимы: Bank.Example и bank.example - один сервер
            this.host = host != null ? host.toLowerCase(Locale.ROOT) : "";
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
