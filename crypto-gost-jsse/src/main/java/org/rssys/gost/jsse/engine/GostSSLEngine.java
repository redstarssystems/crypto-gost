package org.rssys.gost.jsse.engine;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.rssys.gost.api.Digest;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jsse.EndpointIdentification;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.SslParameterNames;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostDnsName;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.SingleOcspResponse;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsAlerts;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.cert.PeerTrustBoundary;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientCredentials;
import org.rssys.gost.tls13.config.TlsServerCredentials;
import org.rssys.gost.tls13.engine.HandshakeOutput;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.HandshakeMessageAssembler;
import org.rssys.gost.tls13.message.ServerNameCheck;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskBindingProfile;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.TlsTicketHelper;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.record.UnprotectResult;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.SafeText;

/**
 * SSLEngine для ГОСТ TLS 1.3 (RFC 8446 + RFC 9367).
 * <p>
 * Реализует клиентский и серверный handshake, wrap/unwrap данных.
 * Управляет TlsHandshakeEngine для handshake и TlsRecord для protect/unwrap.
 * <p>
 * Потокобезопасность: один {@code ReentrantLock} на движок, как в {@code SSLEngineImpl} JDK. Вызовы
 * {@code wrap}, {@code unwrap}, {@code beginHandshake}, {@code closeInbound}, {@code closeOutbound},
 * {@code pollOutboundRecord}, {@code initiateKeyUpdate}, {@code getHandshakeStatus},
 * {@code setOcspResponse} сериализуются: javadoc {@code SSLEngine} разрешает параллельные
 * {@code wrap} и {@code unwrap}, но не требует их. Под замком только обработка одной записи без
 * ввода-вывода. Проверка цепочки сертификатов ({@code NEED_TASK}, может ходить в сеть за OCSP и CRL)
 * выполняется вне замка; замок задача берёт на короткое время, чтобы записать результат. Прочие
 * настройки ({@code setUseClientMode}, {@code setEnabledProtocols}, {@code setSSLParameters} и
 * подобные) и их геттеры тоже берут замок: {@code beginHandshake()} снимает параметры под ним и
 * видит либо все значения одного вызова {@code setSSLParameters}, либо ни одного.
 * <p>
 * Порядок замков: замки {@code GostSSLSocket} (рукопожатие, чтение, запись) берутся раньше замка
 * движка, никогда наоборот; движок замков сокета не берёт. Селектор ALPN приложения вызывается
 * под замком движка в потоке, который у сокета уже держит реентерабельный замок рукопожатия,
 * поэтому обратного порядка нет и при вызове методов сокета из селектора.
 * <p>
 * Данные приложения рядом с {@code NEED_WRAP}: сервер их не выдаёт — пока NewSessionTicket не
 * отправлен, {@code unwrap} ничего не потребляет. Клиент, приняв Finished сервера, сразу читает
 * записи сервера ключами приложения (эпохи ключей, RFC 8446 §4.4.4) и может выдать их до отправки
 * своего Finished, то есть вместе с {@code NEED_WRAP}. Netty это учитывает; собственный потребитель
 * должен учитывать {@code bytesProduced()} при любом статусе рукопожатия.
 */
public final class GostSSLEngine extends SSLEngine {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.engine.GostSSLEngine");

    /**
     * Логгер соединения. Не final: движок создаётся лениво в initHandshake, и метка
     * {@code conn#N} появляется только вместе с ним. volatile: записи делает и поток задачи
     * проверки сертификата.
     */
    private volatile GostLogger log = LOG;

    /** Метка соединения для журнала; null до initHandshake. Не session ID и не секрет. */
    private volatile String connectionLabel;

    /** Глубина обхода цепочки причин: защита от циклической цепочки. */
    private static final int MAX_CAUSE_DEPTH = 16;

    /**
     * Признак от handleEncryptedRecord: запись приложения не помещается в буферы приёмника, она не
     * потреблена, состояние читателя не изменилось. Отрицательное значение не пересекается с числом
     * потреблённых байт.
     */
    private static final int RECORD_NEEDS_SPACE = -1;

    // ========================================================================
    // Состояние
    // ========================================================================

    private enum EngineState {
        INITIAL,
        HANDSHAKE,
        DATA,
        CLOSED
    }

    // ========================================================================
    // Поля
    // ========================================================================

    private TlsHandshakeEngine handshakeEngine;
    private TlsMessageBuilder messageBuilder;
    private volatile TlsRecord readerRecord;
    private volatile TlsRecord writerRecord;

    private final GostX509KeyManager keyManager;
    private final GostX509TrustManager trustManager;
    private boolean clientMode;
    private final String peerHost;
    private final int peerPort;
    private volatile TlsCiphersuite ciphersuite;

    /** ECDHE-группа для key_share (клиент, RFC 8446 §4.2.8). 0 = GC256B по умолчанию. */
    private int clientNamedGroup;

    // Сборка сообщений рукопожатия: общий с TlsSession разбор, пределы по типу сообщения и граница
    // записи при смене ключей
    private final HandshakeMessageAssembler handshakeAssembler = new HandshakeMessageAssembler();
    // Выходной поток рукопожатия в порядке отправки: сообщения и метки смены ключа записи. Эпоха
    // кадра задаётся местом метки, а не моментом wrap(), поэтому смена ключа не может обогнать
    // кадр, стоящий перед ней. Инвариант: после любого вызова первым стоит сообщение — метки в
    // голове очереди применяются сразу (applyLeadingWriteKeyChanges).
    private final ConcurrentLinkedDeque<HandshakeOutput> outgoingQueue =
            new ConcurrentLinkedDeque<>();

    private volatile EngineState engineState = EngineState.INITIAL;
    private boolean handshakeStarted;
    private volatile boolean handshakeDone;

    /**
     * Состоялся ли обмен ClientHello: сервер принял первую handshake-запись, клиент записал
     * ClientHello в выходной буфер. До этого change_cipher_spec недопустим (RFC 8446 §5).
     * Флаг ставится по первой handshake-записи, а не по полному ClientHello: это чуть мягче
     * формулировки RFC, но совпадает с TlsSession, а незащищённый CCS всё равно отбрасывается.
     */
    private volatile boolean helloExchanged;

    /**
     * Принята ли от пира хотя бы одна успешно расшифрованная запись. Окно открытого alert есть
     * только у сервера: клиент включает ключ записи рукопожатия лишь после Finished сервера и до
     * этого вправе слать alert открытым (RFC 8446 приложение A.1), а сервер включает его на
     * ServerHello, и открытый alert от сервера после ServerHello это нарушение. Пока флаг не
     * стоит, сервер принимает открытый alert и при включённом ключе чтения рукопожатия.
     * Выставляется после любого успешного {@code unprotect}, включая alert, и не сбрасывается:
     * смена эпохи ключей окно не открывает. Читается и пишется только под замком движка.
     */
    private boolean peerRecordDecrypted;

    // FINISHED ещё не отдан наружу; нужен, когда сервер завершил handshake без NST.
    private volatile boolean finishStatusPending;
    private volatile boolean closeSent;
    private volatile boolean closeReceived;
    // Готовый зашифрованный close_notify — отдельно от outgoingQueue,
    // чтобы wrap() не перешифровал его второй раз.
    // Очищается только в точке отдачи (wrap, pollOutboundRecord) либо явным решением. volatile:
    // сигнальные поля (closeSent, closeReceived, fatalAlertPending) читают геттеры без замка.
    private volatile byte[] pendingCloseRecord;

    // Fatal alert собран, но ещё не отдан пиру. volatile: читают геттеры без замков
    // (getHandshakeStatus). Пока флаг стоит, isOutboundDone() ложно: alert ещё не ушёл.
    private volatile boolean fatalAlertPending;

    // Код alert, которым закрыто соединение (-1: отказа не было). Нужен, чтобы вызовы после отказа
    // бросали исключение с настоящим кодом, а не безликое «Engine is closed».
    private volatile int failureAlertCode = -1;

    // Отказ, обнаруженный в задаче проверки сертификата: задача исключение бросить не может, его
    // бросает ближайший wrap() или unwrap() (как JDK), ровно один раз. Следующий wrap() отдаёт
    // alert.
    // Без этого контейнер увидел бы NOT_HANDSHAKING после отказа и принял его за успех.
    private final AtomicReference<SSLException> taskFailure = new AtomicReference<>();

    // Один замок на движок, как в JDK (SSLEngineImpl.engineLock): javadoc SSLEngine разрешает
    // параллельные wrap() и unwrap(), но не требует их. Вызовы сериализуются, под замком только
    // обработка одной записи без ввода-вывода. Задача проверки сертификата выполняется вне замка
    // (проверка цепочки может ходить в сеть); замок она берёт на короткое время для записи
    // результата. ReentrantLock не закрепляет виртуальный поток.
    private final ReentrantLock engineLock = new ReentrantLock();

    private final AtomicBoolean taskInProgress = new AtomicBoolean(false);
    // переиспользуемый буфер — каждый unwrap() аллоцирует 16 КБ на горячем пути
    private final ByteBuffer plaintextBuf =
            ByteBuffer.allocate(
                    TlsConstants.MAX_PLAINTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    private final AtomicReference<Runnable> pendingTask = new AtomicReference<>();

    // Сессия и OCSP
    private volatile GostSSLSession session;

    /** null-сессия до handshake (кэш для getSession(), RFC JSSE spec) */
    private final GostSSLSession preHandshakeSession;

    // Сессия идущего рукопожатия (контракт SSLEngine.getHandshakeSession): создаётся при его
    // начале, видна только до завершения
    private volatile GostSSLSession handshakeSession;

    /** peer-сертификаты, сохранённые до создания session (immutable pattern) */
    private volatile X509Certificate[] peerCertificates;

    // OCSP-ответ собственного сертификата (приватный канал от сессии к trust manager)
    private byte[] ocspResponse;

    // Клиент: ответы OCSP, присланные сервером, по порядку его цепочки. Снимается в потоке
    // задачи валидации, читается в finishHandshake - отсюда volatile.
    private volatile List<byte[]> peerStatusResponses = List.of();

    // Политика сервера в отношении клиентского staple (снимок контекста на момент handshake)
    private ClientOcspPolicy clientOcspPolicy = ClientOcspPolicy.OFF;

    // SSLParameters
    private String[] enabledCipherSuites = GostJsseConstants.supportedCipherSuites();
    private String[] enabledProtocols = GostJsseConstants.supportedProtocols();
    private boolean needClientAuth;
    private boolean wantClientAuth;
    private boolean enableSessionCreation = true;
    private String endpointIdentificationAlgorithm;

    // Алгоритм проверки имени, зафиксированный при beginHandshake() под замком: поздний
    // setSSLParameters не должен отключить сверку имени у рукопожатия, которое уже идёт. Задача
    // проверки сертификата получает его локальной переменной при создании (под замком), а
    // публикацию задачи обеспечивает AtomicReference pendingTask
    private String handshakeEndpointIdAlgorithm;

    // true только для движка из createForClientNoHostnameCheck — осознанный opt-out через
    // публичный API. Влияет ТОЛЬКО на частоту WARNING (намерение уже залогировано при создании),
    // но не на решение о проверке hostname (оно определяется endpointIdentificationAlgorithm).
    private boolean explicitNoHostnameCheck;

    // max_fragment_length (RFC 6066 §4): 0 = default (16384)
    private int maxFragmentLength;
    // Снимок mTLS-флага: сессия не должна выдавать PSK-тикет при запросе клиентского сертификата.
    private boolean clientAuthRequested;
    // Запрос клиента (1..4): 0 = не запрашивать. Устанавливается до beginHandshake.
    private int clientMaxFragLenRequest;
    // Промежуточный буфер для фрагментации handshake-сообщений
    private byte[] pendingHsFragment;
    private int pendingHsOffset;

    /** @return код max_fragment_length, согласованный при handshake (0 = default) */
    public int getMaxFragmentLength() {
        return maxFragmentLength;
    }

    /** Максимальный размер данных (без inner_type) для одного TLS-рекорда при handshake */
    private int hsChunkSize() {
        return TlsUtils.maxFragmentLength(currentMaxFragmentLengthCode()) - 1;
    }

    /**
     * Устанавливает запрос max_fragment_length для ClientHello (RFC 6066 §4).
     *
     * @param code 0 = не запрашивать, 1=512, 2=1024, 3=2048, 4=4096 байт
     * @throws IllegalArgumentException если код не из допустимых: иначе расширение молча не было
     *     бы запрошено
     * @throws IllegalStateException если рукопожатие уже начато
     */
    public void setClientMaxFragLenRequest(int code) {
        if (code != 0 && !TlsUtils.isMaxFragmentLengthCode(code)) {
            throw new IllegalArgumentException("Invalid max_fragment_length code: " + code);
        }
        withLock(
                () -> {
                    if (engineState != EngineState.INITIAL) {
                        throw new IllegalStateException(
                                "Cannot set max_fragment_length request after handshake started");
                    }
                    this.clientMaxFragLenRequest = code;
                });
    }

    // ALPN: протоколы прикладного уровня (RFC 7301)
    private String[] applicationProtocols;
    private volatile String selectedAlpnProtocol;

    // Переиспользуемый массив позиций dst-буферов в unwrap: на каждый вызов не аллоцируем новый
    private int[] dstPosBefore = new int[1];

    // Подмена селектора клиентского сертификата, только для тестов
    private ClientCertificateSelector selectorOverrideForTest;

    // Локальная цепочка сертификатов для сервера — сохраняется в сессию
    private X509Certificate[] localCertChain;
    // DNS-имя, запрошенное клиентом через SNI (для тестов и GostSSLContextSpi)
    private String requestedServerName;
    // Имя для SNI, заданное через SSLParameters.setServerNames: null — берётся из peerHost,
    // пустая строка — SNI не отправляется. Сверка сертификата и привязка тикета остаются по
    // peerHost: SNI выбирает виртуальный сервер, а не того, кому доверяет клиент
    private String sniOverride;

    /** Тикет текущего PSK resumption — для remove после подтверждения сервером */
    private byte[] currentPskTicketIdentity;

    /** Рукопожатие завершилось возобновлением по PSK; фиксируется до уничтожения движка. */
    private volatile boolean resumed;

    /** Итог рукопожатия зафиксирован: {@link #resumed} имеет смысл только после этого. */
    private volatile boolean resumptionKnown;

    /** Привязка клиентских тикетов; null до начала рукопожатия, см. {@link #clientPskBinding()}. */
    private PskBinding clientPskBinding;

    /**
     * Граница доверия к серверу по сроку его сертификатов (миллисекунды эпохи), полученная при
     * полном рукопожатии клиента. Задаётся задачей проверки цепочки, которая может идти в другом
     * потоке; {@link #BOUND_UNKNOWN}, пока сервер не проверен.
     */
    private volatile long peerTrustValidUntil = BOUND_UNKNOWN;

    /**
     * Граница использованной для возобновления записи: при PSK-возобновлении сертификата нет, и
     * новые тикеты наследуют границу прежнего, иначе доверие продлевалось бы бесконечно.
     */
    private long resumedValidUntil = BOUND_UNKNOWN;

    /** Граница срока собственной цепочки сервера (миллисекунды эпохи) для выдачи тикетов. */
    private long ownChainValidUntil = BOUND_UNKNOWN;

    /** Граница не определена: тикет с такой границей ни выдавать, ни сохранять нельзя. */
    private static final long BOUND_UNKNOWN = Long.MIN_VALUE;

    /** Алгоритм хэша KDF набора шифров, предложенного клиентом (для привязки тикета). */
    private Digest.Algorithm offeredKdfHash;

    // Клиентский контекст сессий из конструктора: нужен, чтобы setUseClientMode переключал
    // контекст в обе стороны (sessionContext указывает на действующий для текущей роли)
    private final GostSSLSessionContext clientSessionContext;

    // Контекст сессии (PSK resumption)
    private GostSSLSessionContext sessionContext;
    // Серверный контекст — передаётся из SSLContextSpi при createSSLEngine,
    // sessionContext переключается между клиентским и серверным в setUseClientMode
    private GostSSLSessionContext serverSessionContext;

    // ========================================================================
    // Конструкторы
    // ========================================================================

    GostSSLEngine(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            boolean clientMode,
            GostSSLSessionContext clientSessionContext,
            GostSSLSessionContext serverSessionContext) {
        super(host, port);
        this.keyManager = keyManager;
        this.trustManager = trustManager;
        this.peerHost = host;
        this.peerPort = port;
        this.clientMode = clientMode;
        this.ciphersuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        this.clientSessionContext = clientSessionContext;
        this.sessionContext = clientSessionContext;
        this.serverSessionContext = serverSessionContext;
        this.preHandshakeSession =
                new GostSSLSession(
                        GostJsseConstants.SSL_NULL_CIPHER,
                        this.peerHost,
                        this.peerPort,
                        null,
                        null);
    }

    /**
     * Создаёт клиентский GostSSLEngine с контекстом сессии и проверкой hostname по RFC 6125
     * (HTTPS), если флаг отключения проверки в контексте не стоит.
     */
    public static GostSSLEngine createForClient(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            GostSSLSessionContext sessionContext) {
        GostSSLEngine engine =
                new GostSSLEngine(keyManager, trustManager, host, port, true, sessionContext, null);
        applyEndpointIdentification(engine, sessionContext);
        return engine;
    }

    /**
     * Включает проверку hostname (HTTPS) либо, если режим контекста сессий её отключает
     * ({@link EndpointIdentificationMode#DISABLED}), фиксирует осознанный отказ. Предупреждение
     * об отказе пишет сам контекст один раз при включении режима, поэтому здесь только DEBUG.
     */
    private static void applyEndpointIdentification(
            GostSSLEngine engine, GostSSLSessionContext context) {
        if (context != null
                && context.getEndpointIdentificationMode() == EndpointIdentificationMode.DISABLED) {
            LOG.log(Level.DEBUG, "Client SSLEngine created without hostname verification");
            engine.explicitNoHostnameCheck = true;
        } else {
            engine.endpointIdentificationAlgorithm = GostJsseConstants.ENDPOINT_ID_HTTPS;
        }
    }

    /**
     * Создаёт клиентский GostSSLEngine для пути SSLContext.createSSLEngine(host, port).
     * <p>
     * Включает hostname verification (endpointIdentificationAlgorithm = "HTTPS") при
     * непустом и не blank host — так engine-путь даёт те же гарантии, что socket-путь
     * (устранение confused-deputy). serverSessionContext сохраняется, т.к. engine
     * может быть переключён в серверный режим через setUseClientMode(false)
     * (сценарий Tomcat/Spring Boot: createSSLEngine() без явного режима).
     * <p>
     * В режиме {@link EndpointIdentificationMode#DEFAULT} при пустом host endpoint
     * identification не включается: без ожидаемого имени проверять нечего (peerHost неизменяем
     * после конструктора). В режиме {@link EndpointIdentificationMode#STRICT} HTTPS ставится и
     * без host, а отказ происходит в {@code beginHandshake()}; в режиме
     * {@link EndpointIdentificationMode#DISABLED} HTTPS не ставится никогда.
     */
    static GostSSLEngine createForContextClient(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            GostSSLSessionContext clientSessionContext,
            GostSSLSessionContext serverSessionContext) {
        GostSSLEngine engine =
                new GostSSLEngine(
                        keyManager,
                        trustManager,
                        host,
                        port,
                        true,
                        clientSessionContext,
                        serverSessionContext);
        // В режиме DEFAULT без узла проверять нечего. Строгий режим и отключение проверки
        // фиксируются всегда: первый обязан отказать без узла, второй не должен
        // предупреждать на каждом рукопожатии
        boolean modeIsExplicit =
                clientSessionContext != null
                        && clientSessionContext.getEndpointIdentificationMode()
                                != EndpointIdentificationMode.DEFAULT;
        if (modeIsExplicit || (host != null && !host.isBlank())) {
            applyEndpointIdentification(engine, clientSessionContext);
        }
        return engine;
    }

    /**
     * Создаёт клиентский GostSSLEngine БЕЗ проверки hostname.
     * Только для тестов и изолированных сетей: имя сервера не проверяется.
     */
    public static GostSSLEngine createForClientNoHostnameCheck(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            GostSSLSessionContext sessionContext) {
        LOG.log(
                Level.WARNING,
                "Client SSLEngine created WITHOUT hostname verification. "
                        + "Use createForClient() for production.");
        GostSSLEngine engine =
                new GostSSLEngine(keyManager, trustManager, host, port, true, sessionContext, null);
        engine.explicitNoHostnameCheck = true;
        return engine;
    }

    /**
     * Создаёт серверный GostSSLEngine с контекстом сессии.
     * <p>
     * Контекст передаётся в оба слота конструктора, поэтому последующий
     * {@code setUseClientMode(false)} читает тот же серверный контекст.
     */
    public static GostSSLEngine createForServer(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            GostSSLSessionContext sessionContext) {
        return new GostSSLEngine(
                keyManager, trustManager, host, port, false, sessionContext, sessionContext);
    }

    /**
     * Создаёт engine без контекстов сессий (возобновление по PSK недоступно).
     *
     * @param keyManager   менеджер ключей
     * @param trustManager менеджер доверия
     * @param host         имя пира (SNI и проверка имени); может быть пустым
     * @param port         порт пира; -1, если неизвестен
     * @param clientMode   true - клиентский режим, false - серверный
     */
    public GostSSLEngine(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            boolean clientMode) {
        this(keyManager, trustManager, host, port, clientMode, null, null);
    }

    // ========================================================================
    // Внутренняя инициализация handshake
    // ========================================================================

    /**
     * Идентификаторы наборов шифров для рукопожатия из включённых наборов, в порядке включения.
     * Включённые наборы снимаются при начале рукопожатия. Если TLS 1.3 выключен или не осталось ни
     * одного набора, рукопожатие отвергается: как в JDK, это ошибка рукопожатия, а не настройки.
     *
     * @throws TlsException если включённых параметров недостаточно для рукопожатия
     */
    private List<Integer> offeredCipherSuiteIds() throws TlsException {
        if (!Arrays.asList(enabledProtocols).contains(GostJsseConstants.PROTOCOL_TLS_1_3)) {
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "No appropriate protocol: "
                            + GostJsseConstants.PROTOCOL_TLS_1_3
                            + " is disabled");
        }
        List<Integer> ids = new ArrayList<>();
        for (String name : enabledCipherSuites) {
            TlsCiphersuite suite = TlsCiphersuite.byIanaName(name);
            if (suite != null && !ids.contains(suite.getId())) {
                ids.add(suite.getId());
            }
        }
        if (ids.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "No appropriate cipher suite: all cipher suites are disabled");
        }
        return ids;
    }

    /**
     * Имя для SNI из {@code SSLParameters.getServerNames()}: первое имя типа host_name, остальные
     * типы игнорируются, как в JDK (RFC 6066 §3 определяет только host_name). Имя проверяется
     * сразу, а не в рукопожатии, вдали от места ошибки.
     *
     * @return ASCII-имя; пустая строка, если имени типа host_name в списке нет (SNI отключён)
     * @throws IllegalArgumentException если имя нельзя отправить в SNI
     */
    private static String sniFromServerNames(List<SNIServerName> serverNames) {
        for (SNIServerName name : serverNames) {
            if (name instanceof SNIHostName hostName) {
                String ascii = hostName.getAsciiName();
                ServerNameCheck.requireValidForSni(ascii);
                return ascii;
            }
        }
        return "";
    }

    /**
     * Приводит peerHost к ASCII-имени для SNI.
     * <p>
     * SNI передаётся только в ASCII, поэтому кириллический peerHost преобразуется в A-label,
     * иначе расширение молча не уйдёт. Blank host равен отсутствию host
     * ({@code toAsciiHostname} отвергает пустое имя): тогда возвращается null.
     *
     * @return ASCII-имя или null, если имени нет
     * @throws SSLException если peerHost не является допустимым именем узла
     */
    private String toSniHostname() throws SSLException {
        if (sniOverride != null) {
            return sniOverride.isEmpty() ? null : sniOverride;
        }
        if (peerHost == null || peerHost.isBlank()) {
            return null;
        }
        try {
            String ascii = GostDnsName.toAsciiHostname(peerHost);
            // Длина и пустые метки: тот же отказ, что и у сервера, но сразу как SSLException, а не
            // исключение из setServerHostname внутри рукопожатия
            ServerNameCheck.requireValidForSni(ascii);
            return ascii;
        } catch (IllegalArgumentException e) {
            // Имя пира не включаем: оно приходит извне и может содержать управляющие символы.
            throw new SSLException("Peer host is not a valid host name", e);
        }
    }

    /**
     * Инициализирует TlsHandshakeEngine для клиента или сервера.
     * <p>
     * Предусловие: engineState == INITIAL, handshakeStarted == false,
     * handshakeEngine == null.
     * Постусловие: handshakeEngine создан, engineState == HANDSHAKE,
     * handshakeStarted == true.
     * Для клиента: первый исходящий фрейм (ClientHello) уже в outgoingQueue.
     * Для сервера: ожидает ClientHello от пира.
     */
    private void initHandshake() throws SSLException, TlsException {
        // Имя для SNI вычисляется до создания состояния рукопожатия: при некорректном
        // peerHost не должно остаться полуинициализированных messageBuilder/handshakeEngine.
        String sniHostname = clientMode ? toSniHostname() : null;
        helloExchanged = false;
        peerRecordDecrypted = false;
        // RFC 9367: cipher suites L и S используют 256-бит кривую и Streebog-256,
        // различаются только в TLSTREE-константах (C1/C2/C3, SNMAX).
        // 256-битные константы корректны для обеих suite.
        int effectiveNamedGroup =
                clientNamedGroup != 0 ? clientNamedGroup : TlsConstants.GRP_GC256B;
        ECParameters ecParams = TlsCiphersuite.namedGroupToParams(effectiveNamedGroup);
        int sigScheme = TlsConstants.SIG_GOST_CRYPTOPRO_A;
        // Предлагаются и принимаются только включённые наборы; первый из них - предпочтительный
        List<Integer> offeredSuiteIds = offeredCipherSuiteIds();
        this.ciphersuite = TlsCiphersuite.byId(offeredSuiteIds.get(0));
        int hashLen = ciphersuite.getHashLen();

        List<GostCertificate> certChain = null;
        PrivateKeyParameters privateKey = null;

        if (clientMode) {
            // Сертификат клиента здесь не выбирается: до CertificateRequest неизвестны ни схемы
            // подписи сервера, ни его список CA, поэтому выбор (и схема подписи) делает селектор
            // на основе keyManager при получении запроса.
            this.messageBuilder =
                    new TlsMessageBuilder(
                            ciphersuite,
                            offeredSuiteIds,
                            effectiveNamedGroup,
                            sigScheme,
                            null,
                            null,
                            hashLen);

            this.handshakeEngine =
                    new TlsHandshakeEngine(
                            TlsHandshakeEngine.Role.CLIENT,
                            ciphersuite,
                            messageBuilder,
                            ecParams,
                            effectiveNamedGroup,
                            sigScheme,
                            hashLen,
                            // staple собственного сертификата: уходит только по запросу сервера
                            ocspResponse,
                            false,
                            null);

            if (keyManager != null) {
                handshakeEngine.setClientCertificateSelector(clientCertificateSelector());
            }
            // blank host равен отсутствию host: SNI и поиск PSK без имени узла бессмысленны.
            if (sniHostname != null) {
                handshakeEngine.setServerHostname(sniHostname);
            }
            if (applicationProtocols != null && applicationProtocols.length > 0) {
                handshakeEngine.setClientAlpnProtocols(Arrays.asList(applicationProtocols));
            }
            if (clientMaxFragLenRequest != 0) {
                messageBuilder.setClientMaxFragLen(clientMaxFragLenRequest);
                handshakeEngine.setClientMaxFragLenRequest(clientMaxFragLenRequest);
            }
            if (sessionContext != null && sessionContext.isInteropAcceptGostBaseSigScheme()) {
                handshakeEngine.setInteropAcceptGostBaseSigScheme(true);
            }

            // PSK resumption: ищем тикет для этого сервера
            if (sessionContext != null && peerHost != null && !peerHost.isBlank()) {
                PskBinding binding = clientPskBinding();
                PskEntry entry =
                        binding != null
                                ? sessionContext.getForClientResumption(peerHost, peerPort, binding)
                                : null;
                if (entry != null) {
                    byte[] psk = entry.getPsk();
                    if (psk != null) {
                        resumedValidUntil = entry.getValidUntil();
                        currentPskTicketIdentity = entry.getTicket();
                        // RFC 8446 §4.2.11: возраст тикета в миллисекундах; сервер сверяет его
                        // в миллисекундах же (TlsHandshakeEngine.validatePskTicketAge)
                        long ticketAgeMs =
                                (System.currentTimeMillis() - entry.getIssueTime()) & 0xFFFFFFFFL;
                        long obfuscatedAge = (ticketAgeMs + entry.getTicketAgeAdd()) & 0xFFFFFFFFL;
                        handshakeEngine.setPsk(psk, entry.getTicket(), obfuscatedAge);
                    }
                }
            }

            // engine.start() возвращает ClientHello
            byte[] firstOutgoing = handshakeEngine.start();
            if (firstOutgoing != null) {
                outgoingQueue.addLast(new HandshakeOutput.Message(firstOutgoing));
            }
            // Тикет не поместился в ClientHello: рукопожатие идёт полным, а тикет убираем из кэша,
            // иначе то же самое повторялось бы на каждом соединении к этому серверу
            if (handshakeEngine.isPskOfferWithdrawn() && currentPskTicketIdentity != null) {
                dropClientTicket();
            }
        } else {
            // Сервер: выбираем сертификат через keyManager
            if (keyManager != null) {
                String alias =
                        keyManager.chooseEngineServerAlias(
                                GostJsseConstants.KEY_TYPE_ECGOST_256, null, this);
                if (alias == null) {
                    alias =
                            keyManager.chooseEngineServerAlias(
                                    GostJsseConstants.KEY_TYPE_ECGOST_512, null, this);
                }
                if (alias != null) {
                    localCertChain = keyManager.getCertificateChain(alias);
                    if (localCertChain != null && localCertChain.length > 0) {
                        certChain = keyManager.getCertificateChainTls(alias);
                        ownChainValidUntil = PeerTrustBoundary.validUntil(certChain);
                    }
                    PrivateKey pk = keyManager.getPrivateKey(alias);
                    if (pk instanceof GostECPrivateKey gostKey) {
                        privateKey = gostKey.toPrivateKeyParameters();
                    }
                }
            }
            // Схема подписи определяется сертификатом, а не дефолтной ECDHE-группой
            if (privateKey != null) {
                int certNamedGroup = TlsCiphersuite.paramsToNamedGroup(privateKey.getParams());
                sigScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
            }

            this.messageBuilder =
                    new TlsMessageBuilder(
                            ciphersuite,
                            offeredSuiteIds,
                            effectiveNamedGroup,
                            sigScheme,
                            privateKey,
                            certChain,
                            hashLen);

            SniCertificateSelector sniSel =
                    withServerStaple(
                            keyManager != null ? keyManager.asSniSelector() : null, certChain);

            // mTLS: читаем needClientAuth из sessionContext (GostSslBuilder.needClientAuth /
            // ss.setNeedClientAuth)
            if (sessionContext != null && sessionContext.isNeedClientAuth()) {
                needClientAuth = true;
            }
            if (sessionContext != null && sessionContext.isWantClientAuth()) {
                wantClientAuth = true;
            }

            // Политика клиентского staple (RFC 8446 §4.4.2.1) берётся из контекста; без
            // аутентификации клиента запрашивать staple не у кого - отказываемся явно.
            this.clientOcspPolicy =
                    sessionContext != null
                            ? sessionContext.getClientOcspPolicy()
                            : ClientOcspPolicy.OFF;
            if (clientOcspPolicy != ClientOcspPolicy.OFF && !(needClientAuth || wantClientAuth)) {
                throw new TlsException(
                        TlsConstants.ALERT_INTERNAL_ERROR,
                        "clientOcspPolicy requires client authentication"
                                + " (needClientAuth or wantClientAuth)");
            }

            // requestClientAuth = need || want: в обоих случаях CR отправляется.
            // optionalClientAuth = !needClientAuth: если только want (без need),
            // пустой certificate_list не фатален. Флаг читается в tls13 engine
            // только при requestClientAuth=true.
            this.handshakeEngine =
                    new TlsHandshakeEngine(
                            TlsHandshakeEngine.Role.SERVER,
                            ciphersuite,
                            messageBuilder,
                            ecParams,
                            effectiveNamedGroup,
                            sigScheme,
                            hashLen,
                            // staple, заданный до beginHandshake, иначе терялся (в engine шёл null)
                            ocspResponse,
                            needClientAuth || wantClientAuth,
                            sniSel,
                            !needClientAuth);
            if (clientOcspPolicy != ClientOcspPolicy.OFF) {
                handshakeEngine.setRequestClientOcsp(true);
            }

            // serverPskStore — engine сам ищет PSK при получении ClientHello
            if (sessionContext != null) {
                handshakeEngine.setServerPskStore(sessionContext.getPskStore());
            }

            if (applicationProtocols != null && applicationProtocols.length > 0) {
                handshakeEngine.setServerAlpnProtocols(Arrays.asList(applicationProtocols));
            }
            if (sessionContext != null && sessionContext.isInteropAcceptGostBaseSigScheme()) {
                handshakeEngine.setInteropAcceptGostBaseSigScheme(true);
            }

            // Для сервера start() возвращает null
            handshakeEngine.start();
        }

        this.connectionLabel = handshakeEngine.getConnectionLabel();
        this.log = LOG.withContext(connectionLabel);

        engineState = EngineState.HANDSHAKE;
        handshakeStarted = true;
    }

    // ========================================================================
    // Session and close
    // ========================================================================

    /** Для тестов (package-private): установить порог rekey на writerRecord */
    void setRekeyThresholdForTest(long threshold) {
        if (writerRecord != null) {
            writerRecord.setRekeyThreshold(threshold);
        }
    }

    private int peerKeyUpdateCount;

    int getPeerKeyUpdateCountForTest() {
        return peerKeyUpdateCount;
    }

    /**
     * Для тестов (package-private): снять лимит исходящих записей, чтобы собрать запись, которую
     * соблюдающий согласованный max_fragment_length собеседник не отправил бы.
     */
    void disableSendFragmentLimitForTest() {
        maxFragmentLength = 0;
        if (writerRecord != null) {
            writerRecord.setMaxFragmentLength(0);
        }
    }

    /** Для тестов (package-private): writerRecord key epoch (null если не создан) */
    org.rssys.gost.tls13.record.TlsRecord getWriterRecordForTest() {
        return writerRecord;
    }

    /**
     * Для тестов (package-private): код alert, которым закрыто соединение (свой или полученный
     * от пира), либо -1, если соединение не закрывалось из-за ошибки.
     */
    int failureAlertCodeForTest() {
        return failureAlertCode;
    }

    /** Для тестов (package-private): есть ли неотправленный фрагмент handshake-фрейма. */
    boolean hasPendingHandshakeFragmentForTest() {
        return pendingHsFragment != null;
    }

    /** Для тестов (package-private): число handshake-фреймов, ожидающих wrap(). */
    int queuedHandshakeFramesForTest() {
        return outgoingQueue.size();
    }

    /** Для тестов (package-private): длина первого ожидающего handshake-фрейма. */
    int firstQueuedHandshakeFrameLengthForTest() {
        HandshakeOutput head = outgoingQueue.peekFirst();
        return head instanceof HandshakeOutput.Message message ? message.frame().length : -1;
    }

    /**
     * Устанавливает ECDHE-группу для key_share (RFC 8446 §4.2.8).
     * По умолчанию — GC256B. Должен быть вызван до {@link #beginHandshake()}.
     * <p>
     * Параметр действует в обеих ролях: клиент присылает key_share для этой группы
     * в ClientHello, сервер предпочитает её при выборе. Если стороны не совпали, сервер
     * вернёт HelloRetryRequest с желаемой группой (RFC 8446 §4.1.3).
     *
     * @param namedGroup идентификатор именованной группы (TlsConstants.GRP_*)
     * @throws IllegalArgumentException если группа не распознана
     */
    public void setClientNamedGroup(int namedGroup) {
        // Валидация на входе, а не в initHandshake() — ранняя диагностика
        TlsCiphersuite.namedGroupToParams(namedGroup);
        withLock(() -> this.clientNamedGroup = namedGroup);
    }

    @Override
    public void beginHandshake() throws SSLException {
        engineLock.lock();
        try {
            beginHandshakeLocked();
        } finally {
            engineLock.unlock();
        }
    }

    private void beginHandshakeLocked() throws SSLException {
        if (engineState == EngineState.CLOSED) throw new SSLException("Engine is closed");
        if (handshakeStarted) throw new SSLException("Handshake already started");

        // Неподдерживаемый алгоритм (например, LDAP) молча отключил бы проверку имени, а при
        // возобновлении по PSK сертификат не валидируется и trust manager не вызывается.
        // Поэтому отказ здесь, до ClientHello и после guard-ов состояния (не маскируем их).
        // Сервер имя клиента не сверяет.
        // Поле читается один раз: setSSLParameters не берёт замок движка, и повторное чтение
        // дало бы проверку по одному значению, а снимок по другому.
        String requestedAlgorithm = endpointIdentificationAlgorithm;
        if (clientMode && EndpointIdentification.isUnsupported(requestedAlgorithm)) {
            throw new SSLException(EndpointIdentification.unsupportedMessage(requestedAlgorithm));
        }
        // Строгий режим контекста (адаптеры вроде Netty): без узла проверять имя нечем, а
        // молчаливый пропуск принял бы сертификат любого доверенного УЦ для любого узла.
        // Отказ до ClientHello, поэтому алерт пиру не нужен. Явное отключение (пустая строка
        // в SSLParameters или режим DISABLED) алгоритм HTTPS не оставляет и отказа не вызывает
        if (clientMode
                && sessionContext != null
                && sessionContext.getEndpointIdentificationMode()
                        == EndpointIdentificationMode.STRICT
                && EndpointIdentification.isSupported(requestedAlgorithm)
                && (peerHost == null || peerHost.isBlank())) {
            throw new SSLException(
                    "Peer host is required for hostname verification: create the engine with"
                            + " a host or disable verification explicitly");
        }
        // С этого момента и привязка тикета, и задача проверки сертификата работают по снимку
        handshakeEndpointIdAlgorithm = requestedAlgorithm;

        handshakeSession =
                new GostSSLSession(
                        GostJsseConstants.SSL_NULL_CIPHER, peerHost, peerPort, null, null);
        try {
            initHandshake();
            installAlpnSelector();
        } catch (TlsException e) {
            throw AlertMapper.toException(e.getAlertCode(), e.getMessage(), e);
        }
        log.log(
                Level.DEBUG,
                "Handshake started: role={0}, host={1}, port={2}",
                clientMode ? "CLIENT" : "SERVER",
                peerHost,
                peerPort);
        if (clientMode && !isHostnameVerificationActive() && !explicitNoHostnameCheck) {
            // WARNING на каждом клиентском соединении без проверки hostname: случайная очистка
            // safe-default через setSSLParameters должна быть видна per-connection.
            // Осознанный opt-out (createForClientNoHostnameCheck, режим DISABLED контекста)
            // исключён: намерение уже залогировано разово, повтор сигнала не добавляет.
            log.log(
                    Level.WARNING,
                    "Client TLS handshake without hostname verification (host={0}). "
                            + "Set SSLParameters.setEndpointIdentificationAlgorithm(\"HTTPS\") "
                            + "and create the engine with a host, or disable verification "
                            + "explicitly for the engine or its context.",
                    peerHost);
        }
    }

    /**
     * @return true, если при валидации серверного сертификата будет выполнена
     *     проверка hostname. Зеркалит {@link GostX509TrustManager#requireHostnameForEndpointId}:
     *     алгоритм HTTPS/LDAPS (case-insensitive) и непустой, не blank peerHost.
     */
    private boolean isHostnameVerificationActive() {
        // До beginHandshake() действует текущая настройка (привязку тикета можно запросить
        // заранее), после него - снимок. Предусловие: замок движка у вызывающего
        String algorithm =
                handshakeStarted ? handshakeEndpointIdAlgorithm : endpointIdentificationAlgorithm;
        return EndpointIdentification.isSupported(algorithm)
                && peerHost != null
                && !peerHost.isBlank();
    }

    // ========================================================================
    // wrap
    // ========================================================================

    /**
     * Отдаёт готовый зашифрованный close_notify или fatal alert, если он есть. Запись собрана
     * заранее и не шифруется повторно. Под выходным замком.
     *
     * @return результат wrap() либо null, если отдавать нечего
     */
    private SSLEngineResult deliverPendingCloseRecord(ByteBuffer dst) {
        byte[] rec = pendingCloseRecord;
        if (rec == null) {
            return null;
        }
        if (dst.remaining() < rec.length) {
            // не хватает места: запись остаётся, повторим в следующем wrap()
            return new SSLEngineResult(
                    SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
        }
        pendingCloseRecord = null;
        dst.put(rec);
        markAlertDelivered();
        // Выходная сторона закрыта: как в JDK, после отдачи закрывающей записи статус CLOSED
        return new SSLEngineResult(
                SSLEngineResult.Status.CLOSED,
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                0,
                rec.length);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
            throws SSLException {
        engineLock.lock();
        try {
            // Готовый alert или close_notify отдаётся в любом состоянии, в том числе в CLOSED:
            // после отказа движок закрыт, но пир обязан получить причину
            throwTaskFailure();
            SSLEngineResult pendingResult = deliverPendingCloseRecord(dst);
            if (pendingResult != null) {
                return pendingResult;
            }
            if (engineState == EngineState.CLOSED && failureAlertCode >= 0 && !closeSent) {
                // Отказ, а alert пиру не отдан и не будет (собрать было не из чего): приложение
                // получает причину исключением, а не безликим CLOSED
                checkNotClosed();
            }
            if (engineState == EngineState.CLOSED || isOutboundDone()) {
                // Закрыто и всё отдано: как в JDK, CLOSED без байтов. Движок, закрытый
                // closeInbound(), писать уже не может: ключи записи разрушены
                return new SSLEngineResult(
                        SSLEngineResult.Status.CLOSED,
                        SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                        0,
                        0);
            }

            // симметричный implicit-start для клиента. JSSE-контракт
            // требует, чтобы первый wrap() без beginHandshake() сам начинал
            // handshake. Netty 4.2 зовёт beginHandshake() явно через
            // SslHandler.channelActive, но не-Netty consumer может не знать.
            // Сервер: wrap() в INITIAL — ошибка, возвращаем NEED_UNWRAP.
            // Безопасно: замок реентерабелен, beginHandshake() берёт его повторно,
            // handshakeStarted проверяется внутри.
            if (engineState == EngineState.INITIAL) {
                if (clientMode) {
                    beginHandshake();
                } else {
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                            0,
                            0);
                }
            }

            int bytesConsumed = 0;
            int bytesProduced = 0;

            if (engineState == EngineState.HANDSHAKE) {
                // Отправляем handshake-фреймы из очереди (с фрагментацией при
                // max_fragment_length). Фрейм только заглядываем (peek), но не
                // извлекаем: до проверки места состояние меняться не должно.
                byte[] frame;
                int frameOffset;
                if (pendingHsFragment != null) {
                    frame = pendingHsFragment;
                    frameOffset = pendingHsOffset;
                } else {
                    frame = peekQueuedMessage();
                    frameOffset = 0;
                }
                if (frame != null) {
                    int chunkSize = hsChunkSize();
                    int remaining = frame.length - frameOffset;
                    int sendLen = Math.min(remaining, chunkSize);

                    // Защита по текущей эпохе: пока ключа записи нет (ClientHello, HRR,
                    // ServerHello),
                    // сообщение уходит открытым. Эпоха сменится только меткой в очереди за ним.
                    boolean encrypted = writerRecord != null;
                    // RFC 8446 §D.4: dummy CCS идёт сразу после первого сообщения сервера (HRR
                    // или ServerHello), оба открытые. Фрагментации они не подвергаются: короче
                    // минимального max_fragment_length (512), поэтому sendLen == remaining -
                    // инвариант, а не ветка поведения.
                    boolean ccsAfter =
                            !clientMode
                                    && !encrypted
                                    && sendLen == remaining
                                    && handshakeEngine.isServerCompatCcsPending();
                    int recordLen =
                            TlsConstants.RECORD_HEADER_SIZE
                                    + sendLen
                                    + (encrypted ? 1 + ciphersuite.getTagLen() : 0)
                                    + (ccsAfter ? TlsConstants.CCS_RECORD_SIZE : 0);

                    // Проверка места до любых изменений состояния: повтор после BUFFER_OVERFLOW
                    // обязан отправить тот же кадр той же эпохой, а seqNum не должен сдвинуться.
                    if (dst.remaining() < recordLen) {
                        return new SSLEngineResult(
                                SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
                    }

                    if (pendingHsFragment == null) {
                        outgoingQueue.poll();
                    }

                    byte[] record;
                    if (encrypted) {
                        record =
                                writerRecord.protect(
                                        TlsConstants.CT_HANDSHAKE, frame, frameOffset, sendLen);
                    } else {
                        byte[] chunk = new byte[sendLen];
                        System.arraycopy(frame, frameOffset, chunk, 0, sendLen);
                        record = buildPlaintextRecord(TlsConstants.CT_HANDSHAKE, chunk);
                    }

                    dst.put(record);
                    bytesProduced = record.length;
                    if (ccsAfter && handshakeEngine.takeServerCompatCcs()) {
                        byte[] ccsRecord = TlsUtils.buildCompatibilityCcsRecord();
                        dst.put(ccsRecord);
                        bytesProduced += ccsRecord.length;
                    }
                    // Клиент: ClientHello реально записан в dst, CCS пира теперь допустим
                    // (helloExchanged). У сервера helloExchanged уже выставлен приёмом
                    // ClientHello, ответ (HRR/ServerHello) его не меняет.
                    if (clientMode) {
                        helloExchanged = true;
                    }

                    // Фрагментация: если не всё отправлено — буферизируем остаток. Метка эпохи за
                    // кадром применяется только после его последнего фрагмента
                    if (sendLen < remaining) {
                        pendingHsFragment = frame;
                        pendingHsOffset = frameOffset + sendLen;
                    } else {
                        pendingHsFragment = null;
                        pendingHsOffset = 0;
                        applyLeadingWriteKeyChanges();
                    }
                }

                // Рукопожатие завершено и всё отправлено: смены ключа записи за последним кадром
                // уже применены, дальше данные идут ключами приложения
                if (outgoingQueue.isEmpty() && pendingHsFragment == null && handshakeDone) {
                    engineState = EngineState.DATA;

                    // по JSSE-контракту SSLEngineResult, завершивший
                    // handshake, возвращает FINISHED. Tomcat полагается на
                    // это при проверке handshakeComplete.
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.FINISHED,
                            bytesConsumed,
                            bytesProduced);
                }

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        getHandshakeStatus(),
                        bytesConsumed,
                        bytesProduced);
            }

            if (engineState == EngineState.DATA) {
                // Post-handshake сообщения (KeyUpdate, NewSessionTicket) из очереди; смена ключа
                // за KeyUpdate стоит меткой и применяется сразу после его отправки. KeyUpdate
                // забирается из движка только здесь, в момент отправки
                byte[] postFrame = peekQueuedMessage();
                if (postFrame == null) {
                    drainHandshakeOutput();
                    postFrame = peekQueuedMessage();
                }
                if (postFrame != null) {
                    if (dst.remaining() < protectedRecordLength(postFrame.length)) {
                        return new SSLEngineResult(
                                SSLEngineResult.Status.BUFFER_OVERFLOW,
                                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                0,
                                0);
                    }
                    outgoingQueue.poll();
                    byte[] encrypted = writerRecord.protect(TlsConstants.CT_HANDSHAKE, postFrame);
                    dst.put(encrypted);
                    applyLeadingWriteKeyChanges();
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                            0,
                            encrypted.length);
                }

                // Прикладные данные
                int totalSrcRemaining = 0;
                for (int i = offset; i < offset + length && i < srcs.length; i++) {
                    if (srcs[i] != null && srcs[i].hasRemaining()) {
                        totalSrcRemaining += srcs[i].remaining();
                    }
                }
                if (totalSrcRemaining == 0) {
                    // После проверки post-handshake — авто-KeyUpdate если близки к SNMAX
                    tryAutoKeyUpdate();
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                            0,
                            0);
                }

                // Фрагментируем по согласованному max_fragment_length (RFC 6066 §4)
                int maxFragment = TlsUtils.maxFragmentLength(maxFragmentLength) - 1;

                for (int i = offset; i < offset + length && i < srcs.length; i++) {
                    ByteBuffer src = srcs[i];
                    if (src == null || !src.hasRemaining()) continue;

                    int srcLimit = src.limit();
                    int srcPos = src.position();
                    int available = srcLimit - srcPos;

                    int chunkLen = Math.min(available, maxFragment);
                    if (chunkLen == 0) continue;

                    // Ограничиваем буфер размером чанка — TlsRecord.protect() читает все
                    // src.remaining(), без limit возьмёт весь массив.
                    src.limit(srcPos + chunkLen);

                    if (dst.remaining() < protectedRecordLength(chunkLen)) {
                        src.limit(srcLimit);
                        return new SSLEngineResult(
                                SSLEngineResult.Status.BUFFER_OVERFLOW,
                                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                bytesConsumed,
                                bytesProduced);
                    }

                    int written = writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
                    src.limit(srcLimit);
                    bytesConsumed += chunkLen;
                    bytesProduced += written;
                }

                // Авто-KeyUpdate после отправки app data
                tryAutoKeyUpdate();

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                        bytesConsumed,
                        bytesProduced);
            }

            return new SSLEngineResult(
                    SSLEngineResult.Status.CLOSED,
                    getHandshakeStatus(),
                    bytesConsumed,
                    bytesProduced);
        } catch (IllegalStateException e) {
            // Ключи записи исчерпаны (SNMAX): этими же ключами alert не защитить, поэтому он не
            // ставится; соединение закрывается, ключи разрушаются, наружу SSLException.
            failureAlertCode = TlsConstants.ALERT_INTERNAL_ERROR & 0xFF;
            engineState = EngineState.CLOSED;
            destroyAll();
            throw new SSLException("Engine was closed during wrap", e);
        } finally {
            engineLock.unlock();
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return wrap(new ByteBuffer[] {src}, 0, 1, dst);
    }

    // ========================================================================
    // unwrap
    // ========================================================================

    /**
     * Привязка клиентских PSK-тикетов этого engine: сервер и модель доверия, по которой он
     * принят. Вычисляется один раз в начале рукопожатия: проверка имени задаётся на engine, а
     * тикет наследует именно ту проверку, что действовала при его получении.
     *
     * <p>Режим различает только проверку имени: факт и строгость проверки цепочки закодированы
     * идентификатором экземпляра менеджера доверия ({@code bindingId()}), в том числе у
     * trust-all менеджера.</p>
     *
     * @return привязка, или null, если менеджера доверия нет и PSK предлагать нельзя
     */
    PskBinding clientPskBinding() {
        engineLock.lock();
        try {
            return clientPskBindingLocked();
        } finally {
            engineLock.unlock();
        }
    }

    private PskBinding clientPskBindingLocked() {
        // Контекст без менеджера доверия допустим (сервер, либо клиент, которому сертификат
        // сервера всё равно будет отвергнут): модели доверия нет, привязывать тикет не к чему,
        // поэтому PSK не предлагается и тикет не сохраняется
        if (trustManager == null) {
            return null;
        }
        PskBinding binding = clientPskBinding;
        if (binding == null) {
            byte mode =
                    isHostnameVerificationActive()
                            ? TlsConstants.PSK_BINDING_MODE_CHAIN_AND_NAME
                            : TlsConstants.PSK_BINDING_MODE_CHAIN_ONLY;
            offeredKdfHash = ciphersuite.getKdfHashAlgorithm();
            String verificationId =
                    PskBindingProfile.verificationId(
                            mode,
                            trustManager.isRequireOcspStapling(),
                            sessionContext != null
                                    && sessionContext.isInteropAcceptGostBaseSigScheme(),
                            offeredKdfHash,
                            trustManager.bindingId());
            binding = new PskBinding(peerHost, verificationId);
            clientPskBinding = binding;
        }
        return binding;
    }

    /**
     * Сообщает, завершилось ли рукопожатие возобновлением по PSK (без обмена сертификатами).
     * <p>Значение фиксируется при завершении рукопожатия и не меняется после закрытия.</p>
     *
     * @return true, если рукопожатие возобновлено; false, если оно было полным
     * @throws IllegalStateException если рукопожатие ещё не завершено
     */
    public boolean wasResumed() {
        if (!resumptionKnown) {
            throw new IllegalStateException(
                    "wasResumed() called before handshake completion on this engine");
        }
        return resumed;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws SSLException {
        engineLock.lock();
        try {
            throwTaskFailure();
            if (engineState == EngineState.CLOSED || closeReceived) {
                // После отказа каждый вызов даёт исключение с кодом alert: иначе цикл
                // рукопожатия контейнера принял бы отказ за успех
                if (failureAlertCode >= 0) {
                    checkNotClosed();
                }
                // Штатное закрытие (в том числе close_notify пира: ключи чтения уничтожены, данные
                // после него не принимаются, RFC 8446 §6.1), при любом src. Данных, ожидающих
                // выдачи, нет: запись приложения, не поместившаяся в dsts, не потребляется (см.
                // handleEncryptedRecord), поэтому close_notify за ней не будет обработан раньше.
                finishStatusPending = false;
                // Статус рукопожатия настоящий: пока close_notify или alert не отданы, нужен wrap()
                return new SSLEngineResult(
                        SSLEngineResult.Status.CLOSED, getHandshakeStatus(), 0, 0);
            }

            // Контракт SSLEngine: IllegalArgumentException на пустые src и dsts,
            // IndexOutOfBoundsException на неверные границы - до любых действий над состоянием
            if (src == null || dsts == null) {
                throw new IllegalArgumentException("src and dsts must not be null");
            }
            if (offset < 0 || length < 0 || offset > dsts.length - length) {
                throw new IndexOutOfBoundsException(
                        "offset=" + offset + ", length=" + length + ", dsts=" + dsts.length);
            }
            // Контракт SSLEngine: ReadOnlyBufferException до потребления входа. После расшифровки
            // запись уже потреблена и номер записи сдвинут, повторить её было бы нельзя.
            requireWritable(dsts, offset, length);

            int srcRemaining = src.remaining();

            // проверка srcRemaining ДО implicit-start — пустой unwrap()
            // на сервере не должен преждевременно стартовать handshake.
            if (srcRemaining < TlsConstants.RECORD_HEADER_SIZE) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.BUFFER_UNDERFLOW, consumeFinishStatus(), 0, 0);
            }

            // RFC 8446 §5: change_cipher_spec до первого ClientHello - нарушение протокола.
            // Привязка к факту обмена ClientHello, а не к engineState: приложение вправе вызвать
            // beginHandshake() заранее, и тогда состояние уже HANDSHAKE. Проверка раньше ветки
            // INITIAL: иначе клиент вернул бы NEED_WRAP без потребления.
            if (!helloExchanged && src.get(src.position()) == TlsConstants.CT_CHANGE_CIPHER_SPEC) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "change_cipher_spec received before ClientHello");
            }

            // если unwrap() вызван на серверном engine в INITIAL, это
            // означает, что прибыл ClientHello. Автоматически начинаем handshake,
            // иначе SslHandler.decode интерпретирует consumption=0 как ошибку.
            // Безопасно: замок реентерабелен, beginHandshake() берёт его повторно,
            // handshakeStarted проверяется внутри и бросит осмысленную ошибку при race.
            if (engineState == EngineState.INITIAL) {
                if (!clientMode) {
                    beginHandshake();
                } else {
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                            0,
                            0);
                }
            }

            // Проверка сертификата пира идёт отдельной задачей (NEED_TASK), и записи после
            // Certificate разбирать рано: reader ещё на handshake-ключах, а законный пир шлёт
            // данные под ключами приложения, их расшифровка дала бы ложный decrypt_error. Как и
            // в JDK, до выполнения задачи ничего не потребляем. Фатальный alert пира в это
            // время тоже обрабатывается только после задачи: так задумано.
            if (taskInProgress.get()) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_TASK, 0, 0);
            }

            // Сервер завершил рукопожатие, но NST ещё не отправлен: записи данных за Finished
            // клиента остаются в src до wrap(), иначе их выдал бы результат с NEED_WRAP. Как и в
            // JDK, при неотправленном выводе рукопожатия ничего не потребляем, сколько бы раз ни
            // вызвали. Клиент сюда не попадает: данные сервера за его Finished он читает сразу,
            // до отправки своего Finished (эпохи ключей, RFC 8446 §4.4.4). HANDSHAKE после
            // завершения рукопожатия означает неотправленный вывод: wrap() при пустой очереди
            // переводит движок в DATA и отдаёт FINISHED, поэтому возврат здесь не зацикливается.
            // Условие совпадает с NEED_WRAP из getHandshakeStatus(): сужать его до непустой
            // очереди нельзя, иначе данные снова ушли бы рядом с NEED_WRAP.
            if (!clientMode && handshakeDone && engineState == EngineState.HANDSHAKE) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, 0);
            }

            int consumed;
            int produced = 0;

            if (readerRecord == null) {
                consumed = handlePlaintextRecord(src);
            } else {
                // сохраняем позиции dst до вызова, чтобы вычислить
                // bytesProduced — сколько байт было записано в dst.
                // Без этого SslHandler не увидит расшифрованные app data.
                int[] dstPosBefore = this.dstPosBefore;
                if (dstPosBefore.length < length) {
                    dstPosBefore = new int[length];
                    this.dstPosBefore = dstPosBefore;
                }
                for (int i = 0; i < length; i++) {
                    dstPosBefore[i] =
                            (dsts != null && dsts[offset + i] != null)
                                    ? dsts[offset + i].position()
                                    : -1;
                }
                consumed = handleEncryptedRecord(src, dsts, offset, length);
                if (consumed == RECORD_NEEDS_SPACE) {
                    // Контракт SSLEngine: при нехватке места в dsts ничего не потреблено и не
                    // выдано, потребитель увеличивает буфер и повторяет вызов. Статус FINISHED
                    // не расходуем: его получит вызов, который что-то обработает.
                    return new SSLEngineResult(
                            SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
                }
                for (int i = 0; i < length; i++) {
                    if (dstPosBefore[i] >= 0) {
                        // Math.max защищает от wrap-around: если буфер был сброшен или перемотан,
                        // позиция могла уменьшиться. В этом случае bytesProduced = 0 корректно.
                        produced += Math.max(0, dsts[offset + i].position() - dstPosBefore[i]);
                    }
                }

                // После Client Finished в том же src могут лежать AppData-записи. Без NST движок
                // уже в DATA и отдаёт FINISHED этим вызовом: записи добираем здесь, иначе Tomcat
                // выйдет из цикла рукопожатия и их не дочитает. С NST в очереди результат несёт
                // NEED_WRAP, а данные рядом с NEED_* потребитель вправе не учитывать (Undertow
                // возвращает читателю 0): записи остаются в src и выдаются после отправки NST.
                while (handshakeDone
                        && !closeReceived
                        && engineState != EngineState.CLOSED
                        && finishStatusPending
                        && src.hasRemaining()) {
                    // перезахватываем dstPosBefore перед каждой итерацией,
                    // иначе produced накапливает дельту от начальной позиции
                    // (до первого handleEncryptedRecord), а не от текущей.
                    for (int i = 0; i < length; i++) {
                        if (dstPosBefore[i] >= 0) {
                            dstPosBefore[i] = dsts[offset + i].position();
                        }
                    }
                    int addConsumed = handleEncryptedRecord(src, dsts, offset, length);
                    // Запись приложения, не поместившаяся в dsts, остаётся в src целиком: уже
                    // обработанный Finished отдаём сейчас, а запись - следующим вызовом
                    if (addConsumed == RECORD_NEEDS_SPACE || addConsumed == 0) break;
                    consumed += addConsumed;
                    for (int i = 0; i < length; i++) {
                        if (dstPosBefore[i] >= 0) {
                            produced += Math.max(0, dsts[offset + i].position() - dstPosBefore[i]);
                        }
                    }
                }
            }

            // при consumed=0 handleEncryptedRecord увидел неполную запись
            // (NEED_MORE_INPUT) и не потребил байты. Возвращаем BUFFER_UNDERFLOW,
            // чтобы Tomcat дочитал из сокета. Без этого unwrap() возвращает OK
            // с consumed=0, produced=0 — Tomcat не знает что нужно читать ещё.
            if (consumed == 0 && produced == 0) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.BUFFER_UNDERFLOW, consumeFinishStatus(), 0, 0);
            }

            SSLEngineResult.Status status =
                    closeReceived ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
            return new SSLEngineResult(status, consumeFinishStatus(), consumed, produced);
        } catch (TlsException e) {
            failConnection(e.getAlertCode(), e.isFromPeer());
            throw AlertMapper.toException(e.getAlertCode(), e.getMessage(), e);
        } catch (SSLException e) {
            // уже готовое исключение (alert пира, закрытый движок): сообщение не прячем за
            // «I/O error»; соединение закрывается, если ещё не закрыто
            failConnection(TlsConstants.ALERT_INTERNAL_ERROR, false);
            throw e;
        } catch (IOException e) {
            failConnection(TlsConstants.ALERT_INTERNAL_ERROR, false);
            throw new SSLException("I/O error during unwrap", e);
        } catch (IllegalStateException e) {
            // запись или движок уничтожены закрытием: наружу SSLException
            throw new SSLException("Engine was closed during unwrap", e);
        } finally {
            try {
                settleAfterUnwrap();
            } finally {
                engineLock.unlock();
            }
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return unwrap(src, new ByteBuffer[] {dst}, 0, 1);
    }

    /**
     * Обрабатывает plaintext TLS-запись (до установки handshake-ключей).
     */
    private int handlePlaintextRecord(ByteBuffer src) throws IOException, TlsException {
        // RFC 8446 §D.4: совместимый change_cipher_spec (после HelloRetryRequest сервер шлёт его
        // открытым, до второго ServerHello) молча отбрасывается; содержимое проверяет общая
        // функция. Неполная запись - ждём остаток.
        TlsUtils.CcsResult ccs = TlsUtils.consumeCompatibilityCcs(src);
        if (ccs.status() == TlsUtils.CcsStatus.CONSUMED) {
            return ccs.consumed();
        }
        if (ccs.status() == TlsUtils.CcsStatus.INCOMPLETE) {
            return 0;
        }

        int srcPos = src.position();

        byte contentType = src.get(srcPos);
        int payloadLen = recordPayloadLength(src, srcPos);
        int totalLen = TlsConstants.RECORD_HEADER_SIZE + payloadLen;

        // TLSPlaintext.length ≤ 2^14 (RFC 8446 §5.1). Проверка до аллокации и до ожидания
        // остатка: оверсайз-запись — нарушение протокола, реагируем немедленно, а не копим
        // до 65 КБ. Зеркалит раннюю проверку в TlsRecord.unprotect() для шифрованного пути.
        if (payloadLen > TlsConstants.MAX_PLAINTEXT_LENGTH) {
            throw new TlsException(
                    TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Plaintext record too large: " + payloadLen);
        }

        if (src.remaining() < totalLen) {
            return 0; // BUFFER_UNDERFLOW
        }

        byte[] recordData = new byte[totalLen];
        src.get(recordData);

        if (contentType == TlsConstants.CT_ALERT) {
            handleAlert(Arrays.copyOfRange(recordData, TlsConstants.RECORD_HEADER_SIZE, totalLen));
            return totalLen;
        }

        if (contentType != TlsConstants.CT_HANDSHAKE) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected handshake, got " + contentType);
        }

        // RFC 8446 §5.1: пустой фрагмент сборщик отвергает (unexpected_message)
        handshakeAssembler.append(recordData, TlsConstants.RECORD_HEADER_SIZE, payloadLen);
        helloExchanged = true;
        processHandshakeFrames();

        return totalLen;
    }

    /**
     * Один и тот же буфер в нескольких слотах dsts даёт место один раз: запись в него идёт общей
     * позицией, и двойной учёт завысил бы ёмкость. {@code length} мал, квадратичный просмотр дёшев.
     */
    private static boolean isListedEarlier(ByteBuffer[] dsts, int offset, int index) {
        for (int j = offset; j < index; j++) {
            if (dsts[j] == dsts[index]) {
                return true;
            }
        }
        return false;
    }

    private static void requireWritable(ByteBuffer[] dsts, int offset, int length) {
        if (dsts == null) {
            return;
        }
        for (int i = offset; i < offset + length; i++) {
            if (dsts[i] != null && dsts[i].isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
        }
    }

    /** Суммарное место в dsts под открытый текст записи, не больше Integer.MAX_VALUE. */
    private static int applicationCapacity(ByteBuffer[] dsts, int offset, int length) {
        if (dsts == null) {
            return 0;
        }
        long capacity = 0;
        for (int i = offset; i < offset + length; i++) {
            if (dsts[i] != null && !isListedEarlier(dsts, offset, i)) {
                capacity += dsts[i].remaining();
            }
        }
        return (int) Math.min(capacity, Integer.MAX_VALUE);
    }

    private int handleEncryptedRecord(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws IOException, TlsException {
        int srcPos = src.position();
        int remaining = src.remaining();

        // RFC 8446 §5, §D.4: совместимый change_cipher_spec молча отбрасывается до Finished
        // пира; после Finished (в том числе в фазе данных) он недопустим. Проверка стоит до
        // расшифровки: CCS не защищён, и unprotect() принял бы его за повреждённую запись.
        if (remaining >= TlsConstants.RECORD_HEADER_SIZE
                && src.get(srcPos) == TlsConstants.CT_CHANGE_CIPHER_SPEC) {
            if (handshakeDone) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "change_cipher_spec received after peer Finished");
            }
            TlsUtils.CcsResult ccs = TlsUtils.consumeCompatibilityCcs(src);
            if (ccs.status() == TlsUtils.CcsStatus.CONSUMED) {
                return ccs.consumed();
            }
            return 0;
        }

        // Окно открытого alert (только сервер, см. peerRecordDecrypted). Внешний тип 21 не бывает у
        // шифротекста (внешний тип зашифрованной
        // записи всегда 23), поэтому опознание однозначно; формат проверяет общий разбор. Порядок
        // важен: после ветки CCS, до unprotect; неполную запись не потребляем, как и везде.
        if (!clientMode
                && !handshakeDone
                && !peerRecordDecrypted
                && remaining >= TlsConstants.RECORD_HEADER_SIZE
                && src.get(srcPos) == TlsConstants.CT_ALERT) {
            int bodyLength = recordPayloadLength(src, srcPos);
            TlsUtils.requireAlertLength(bodyLength);
            int totalLength = TlsConstants.RECORD_HEADER_SIZE + bodyLength;
            if (remaining < totalLength) {
                return 0;
            }
            byte[] body =
                    new byte[] {
                        src.get(srcPos + TlsConstants.RECORD_HEADER_SIZE),
                        src.get(srcPos + TlsConstants.RECORD_HEADER_SIZE + 1)
                    };
            src.position(srcPos + totalLength);
            handleAlert(body);
            return totalLength;
        }

        plaintextBuf.clear();
        UnprotectResult r;
        try {
            // Предел на открытый текст действует только для application_data: рукопожатие и alert
            // принимаются при любых dsts. Запись приложения, не помещающаяся в dsts целиком,
            // читатель не потребляет и номер записи не сдвигает: движок не хранит открытый текст
            // между вызовами (контракт SSLEngine), потребитель увеличит буфер и повторит вызов.
            // До Finished пира данные приложения - нарушение протокола, а не вопрос места: предел
            // не задаём, иначе вместо fatal alert потребитель получил бы BUFFER_OVERFLOW.
            int applicationLimit =
                    handshakeDone ? applicationCapacity(dsts, offset, length) : Integer.MAX_VALUE;
            r = readerRecord.unprotect(src, plaintextBuf, applicationLimit);
        } catch (AuthenticationException e) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_RECORD_MAC, "Record authentication failed", e);
        }

        if (r.status == UnprotectResult.Status.OUTPUT_TOO_SMALL) {
            if (r.hint > plaintextBuf.capacity()) {
                // Внутренний буфер вмещает любую допустимую запись; иначе это ошибка движка, а
                // не нехватка места у потребителя: BUFFER_UNDERFLOW заставил бы его ждать вечно
                throw new TlsException(
                        TlsConstants.ALERT_INTERNAL_ERROR,
                        "Decrypt buffer is smaller than the record plaintext");
            }
            return RECORD_NEEDS_SPACE;
        }
        // NEED_MORE_INPUT: запись неполная, ничего не потреблено
        if (r.status != UnprotectResult.Status.OK) {
            return 0;
        }
        peerRecordDecrypted = true;

        int consumed = src.position() - srcPos;
        plaintextBuf.flip();
        byte contentType = r.contentType;
        int dataLen = plaintextBuf.remaining();
        byte[] rawArray = plaintextBuf.array();
        int rawOffset = plaintextBuf.arrayOffset() + plaintextBuf.position();

        if (contentType == TlsConstants.CT_ALERT) {
            byte[] alertData = new byte[dataLen];
            plaintextBuf.get(alertData);
            handleAlert(alertData);
            return consumed;
        }

        if (contentType == TlsConstants.CT_HANDSHAKE) {
            handshakeAssembler.append(rawArray, rawOffset, dataLen);
            processHandshakeFrames();
            return consumed;
        }

        if (contentType == TlsConstants.CT_APPLICATION_DATA) {
            // Инвариант: данные допустимы только после проверки Finished пира, а handshakeDone
            // выставляется именно там (finishHandshake). Пир уже знает handshake-ключи и может
            // зашифровать ими application_data до своей аутентификации (при needClientAuth - до
            // Certificate); без этой проверки такие данные уходили бы приложению. Проверка стоит
            // до копирования в dst: иначе приложение получило бы данные вдобавок к alert.
            if (!handshakeDone) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "Application data received before handshake completion");
            }
            // Место проверено читателем до расшифровки: вся запись помещается в dsts. Копируем
            // напрямую из backing array plaintextBuf
            int remainingData = dataLen;
            int dataOff = rawOffset;
            for (int dstIndex = offset;
                    remainingData > 0 && dstIndex < offset + length;
                    dstIndex++) {
                ByteBuffer dst = dsts[dstIndex];
                if (dst == null) {
                    continue;
                }
                int toWrite = Math.min(remainingData, dst.remaining());
                dst.put(rawArray, dataOff, toWrite);
                dataOff += toWrite;
                remainingData -= toWrite;
            }
            if (remainingData > 0) {
                // Инвариант: ёмкость проверена до расшифровки. Нарушиться он может, если один и
                // тот же буфер передан в нескольких слотах dsts (ёмкость посчиталась дважды).
                // Тихая потеря тела запроса хуже отказа: закрываем соединение.
                TlsUtils.wipeArray(plaintextBuf.array());
                throw new TlsException(
                        TlsConstants.ALERT_INTERNAL_ERROR,
                        "Application data does not fit the destination buffers");
            }
            return consumed;
        }

        throw new TlsException(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Unexpected content type: " + contentType);
    }

    /**
     * Разбирает собранные сообщения рукопожатия и передаёт их в TlsHandshakeEngine.
     * <p>
     * Предусловие: вызывается под engineLock. Постусловие: разобраны все целые сообщения, кроме
     * случая, когда понадобилась задача проверки сертификата: остаток ждёт её и разбирается в ней
     * же. При любой ошибке буфер сборки затирается.
     */
    private void processHandshakeFrames() throws IOException, TlsException {
        try {
            byte[] frame;
            int postHandshakeMessages = 0;
            while ((frame = handshakeAssembler.nextMessage(handshakeDone)) != null) {
                if (handshakeDone) {
                    // Тот же бюджет, что у TlsSession.read(): одна запись в 16 КБ вмещает сотни
                    // служебных сообщений, и каждое требовало бы HKDF или записи тикета
                    if (++postHandshakeMessages > TlsConstants.MAX_POST_HANDSHAKE) {
                        throw new TlsException(
                                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                                "Too many post-handshake messages in one record");
                    }
                    processPostHandshakeFrame(frame);
                } else if (!processHandshakeFrame(frame)) {
                    return;
                }
            }
        } catch (IOException | RuntimeException e) {
            handshakeAssembler.reset();
            throw e;
        }
    }

    /** Служебное сообщение после рукопожатия: KeyUpdate или NewSessionTicket. */
    private void processPostHandshakeFrame(byte[] frame) throws IOException, TlsException {
        TlsHandshakeEngine.PostHandshakeResult result = handshakeEngine.receivePostHandshake(frame);
        if (result.type == TlsHandshakeEngine.PostHandshakeResult.Type.KEY_UPDATE_HANDLED) {
            // RFC 8446 §5.1: KeyUpdate меняет ключ чтения и замыкает свою запись; остаток после
            // него пир отправил бы прежним ключом уже после смены
            handshakeAssembler.requireRecordBoundaryAtKeyChange();
            // Окно частоты чужих KeyUpdate держит сам TlsHandshakeEngine: он бросает
            // TlsException до обработки сообщения
            peerKeyUpdateCount++;
            log.log(Level.DEBUG, "KeyUpdate received");
            // Ключ чтения обновляется немедленно — пир сменил свой ключ записи
            handleEngineKeyChanges();
            // Ответный KeyUpdate (если пир его запросил) остаётся в потоке движка до wrap(): пока
            // он не отдан, следующий запрос пира не порождает второго ответа (RFC 8446 §4.6.3:
            // молчащая сторона отвечает на несколько запросов одним обновлением)
        }
        if (result.type == TlsHandshakeEngine.PostHandshakeResult.Type.NEW_SESSION_TICKET) {
            if (sessionContext != null) {
                byte[] rms = handshakeEngine.getResumptionMasterSecret();
                if (rms != null) {
                    try {
                        PskBinding binding = clientPskBinding();
                        // хэш KDF набора шифров не должен измениться относительно
                        // предложенного: иначе тикет нельзя возобновлять (RFC 8446
                        // §4.6.1)
                        // Граница: из проверенной цепочки полного рукопожатия или
                        // из использованной записи при возобновлении; не определена -
                        // тикет не сохраняется
                        long validUntil = resumed ? resumedValidUntil : peerTrustValidUntil;
                        if (binding != null
                                && validUntil != BOUND_UNKNOWN
                                && ciphersuite.getKdfHashAlgorithm() == offeredKdfHash) {
                            sessionContext.saveNewSessionTicket(
                                    peerHost, peerPort, rms, result.ticket, binding, validUntil);
                        }
                    } finally {
                        TlsUtils.wipeArray(rms);
                    }
                }
            }
        }
    }

    /**
     * Одно сообщение рукопожатия.
     *
     * @return {@code false}, если поставлена задача проверки сертификата и разбор надо прервать
     */
    private boolean processHandshakeFrame(byte[] frame) throws IOException, TlsException {
        try {
            handshakeEngine.receive(frame);
        } catch (IOException e) {
            if (handshakeEngine.isError()) {
                String err = handshakeEngine.getErrorMessage();
                // Текст отказа собирается и из сообщений разбора чужих данных, поэтому в журнал
                // идут только тип исключения и код alert; полный текст получает вызывающий
                // через исключение
                log.log(
                        Level.DEBUG,
                        "Handshake error: stage={0}, alert={1}, {2}",
                        failedHandshakeStage(),
                        e instanceof TlsException tls
                                ? TlsAlerts.forLog(tls.getAlertCode())
                                : "none",
                        e.getClass().getSimpleName());
                String message = (err != null) ? err : e.getMessage();
                // Код alert задаёт сам отказ (protocol_version, decode_error,
                // unrecognized_name и др.): подмена на handshake_failure скрывала бы причину и
                // от пира, и от приложения (RFC 8446 §6.2). Для прочих ошибок ввода-вывода
                // остаётся handshake_failure
                if (e instanceof TlsException tlsException) {
                    throw tlsException;
                }
                throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE, message);
            }
            throw e;
        }

        // Выходной поток сразу: смены ключа записи встают в очередь на свои места, а стоящие в
        // голове применяются. Так клиентский ключ записи после ServerHello включён до любой
        // проверки ниже, и alert при отказе уходит зашифрованным (RFC 8446, приложение A.1)
        drainHandshakeOutput();

        if (handleEngineKeyChanges()) {
            // RFC 8446 §5.1: сообщения не пересекают смену ключа чтения (после ClientHello,
            // ServerHello, Finished, KeyUpdate), поэтому остатка в буфере сборки быть не должно
            handshakeAssembler.requireRecordBoundaryAtKeyChange();
        }

        // PSK принят сервером — удаляем тикет из store (single-use, RFC 8446 §8.1)
        if (clientMode && handshakeEngine.isPskAccepted() && currentPskTicketIdentity != null) {
            dropClientTicket();
        }

        // SNI нужен GostSSLContextSpi для выбора сертификата и тестам для проверки
        if (!clientMode && requestedServerName == null) {
            String sni = handshakeEngine.getRequestedServerName();
            if (sni != null) {
                this.requestedServerName = sni;
            }
        }

        // setEnableSessionCreation(false) на сервере = не принимай full
        // handshake, только PSK resumption. Проверка после receive() —
        // PSK уже определён (isPskAccepted).
        if (!clientMode && !enableSessionCreation && !handshakeEngine.isPskAccepted()) {
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "Session creation disabled, PSK required");
        }

        // валидация сертификата асинхронна (NEED_TASK) — не блокируем handshake-поток
        if (handshakeEngine.needsCertificateValidation()) {
            List<GostCertificate> certs = handshakeEngine.getReceivedCertificates();
            pendingTask.set(createCertValidationTask(certs, handshakeEndpointIdAlgorithm));
            taskInProgress.set(true);
            return false;
        }

        if (handshakeEngine.isDone()) {
            finishHandshake();
        }
        if (handshakeEngine.isError()) {
            // Текст ошибки не пишем: он собирается из сообщений разбора чужих данных
            log.log(
                    Level.DEBUG,
                    "Handshake failed: stage={0}, alert={1}",
                    failedHandshakeStage(),
                    TlsAlerts.forLog(handshakeEngine.getErrorAlertCode()));
            throw new TlsException(handshakeEngine.getErrorAlertCode(), "Handshake failed");
        }
        return true;
    }

    /**
     * Применяет смену ключа чтения из движка рукопожатия и обновляет согласованный набор шифров.
     * Ключи записи сюда не приходят: их смены стоят метками в выходном потоке.
     * <p>
     * Предусловие: handshakeEngine не null. Постусловие: флаг смены ключа чтения сброшен.
     *
     * @return {@code true}, если сменился ключ чтения
     */
    private boolean handleEngineKeyChanges() {
        TlsCiphersuite negotiated = handshakeEngine.getNegotiatedCiphersuite();
        if (negotiated != null) this.ciphersuite = negotiated;
        if (!handshakeEngine.hasReadKeysChanged()) {
            return false;
        }
        TlsTrafficKeys newKeys = handshakeEngine.getReadKeys();
        if (readerRecord != null) readerRecord.destroy();
        readerRecord = newReaderRecord(newKeys.getKey(), newKeys.getIv(), ciphersuite.getTagLen());
        handshakeEngine.acknowledgeReadKeyChange();
        return true;
    }

    /**
     * Забывает клиентский тикет: удаляет его из хранилища и привязку к серверу. Тикет одноразовый
     * (RFC 8446 §8.1): после использования или отказа от предложения повторять его нельзя.
     */
    private void dropClientTicket() {
        if (sessionContext != null) {
            sessionContext.getPskStore().remove(currentPskTicketIdentity);
            sessionContext.removeIdentity(peerHost, peerPort);
        }
        currentPskTicketIdentity = null;
    }

    /**
     * Переносит выходной поток движка рукопожатия в очередь отправки как есть: сообщения и метки
     * смены ключа на своих местах. Метки в голове очереди (перед ними нечего отправлять, например
     * ключ записи клиента после ServerHello) применяются сразу.
     */
    private void drainHandshakeOutput() {
        HandshakeOutput item;
        while ((item = handshakeEngine.poll()) != null) {
            outgoingQueue.addLast(item);
        }
        applyLeadingWriteKeyChanges();
    }

    /**
     * Применяет метки смены ключа записи, стоящие в голове очереди: все кадры их эпохи уже
     * отправлены. Пока отправляется фрагментированный кадр, метка за ним ждёт его конца.
     */
    private void applyLeadingWriteKeyChanges() {
        if (pendingHsFragment != null) {
            return;
        }
        while (outgoingQueue.peekFirst() instanceof HandshakeOutput.WriteKeyChange change) {
            outgoingQueue.pollFirst();
            try {
                swapWriterRecord(change.keys(), change.ciphersuite());
            } finally {
                change.destroy();
            }
        }
    }

    /**
     * Очищает очередь отправки и затирает её содержимое: метки несут ключи записи следующих эпох,
     * сообщения — Finished и тикеты; при закрытии и отказе они не остаются в памяти.
     */
    private void clearOutgoingQueue() {
        HandshakeOutput item;
        while ((item = outgoingQueue.pollFirst()) != null) {
            if (item instanceof HandshakeOutput.WriteKeyChange change) {
                change.destroy();
            } else if (item instanceof HandshakeOutput.Message message) {
                // Неотправленные сообщения (Finished, тикеты) затираются, как в движке рукопожатия
                TlsUtils.wipeArray(message.frame());
            }
        }
        TlsUtils.wipeArray(pendingHsFragment);
    }

    /** Сообщение в голове очереди после применения меток перед ним, либо null. */
    private byte[] peekQueuedMessage() {
        applyLeadingWriteKeyChanges();
        HandshakeOutput head = outgoingQueue.peekFirst();
        return head instanceof HandshakeOutput.Message message ? message.frame() : null;
    }

    /** Своё обновление ключа ещё не отправлено: оно в потоке движка или его метка в очереди. */
    private boolean keyUpdateQueued() {
        return (handshakeEngine != null && handshakeEngine.isKeyUpdateQueued())
                || keyUpdateInSendQueue();
    }

    /** Метка смены ключа стоит в очереди отправки: KeyUpdate забран из движка, но не отправлен. */
    private boolean keyUpdateInSendQueue() {
        for (HandshakeOutput item : outgoingQueue) {
            if (item instanceof HandshakeOutput.WriteKeyChange) {
                return true;
            }
        }
        return false;
    }

    /** Авто-KeyUpdate при приближении к SNMAX (RFC 8446 §4.6.3). */
    private void tryAutoKeyUpdate() throws SSLException {
        if (writerRecord != null && writerRecord.isApproachingRekeyLimit() && !keyUpdateQueued()) {
            try {
                handshakeEngine.initiateKeyUpdate(false);
            } catch (TlsException e) {
                throw new SSLException("KeyUpdate initiation failed", e);
            }
        }
    }

    /**
     * Код max_fragment_length, действующий сейчас: до {@code beginHandshake()} движка рукопожатия
     * ещё нет и действует сохранённое поле, дальше значение хранит движок рукопожатия (ссылка на
     * него не обнуляется и после завершения).
     */
    private int currentMaxFragmentLengthCode() {
        return handshakeEngine != null ? handshakeEngine.getMaxFragmentLength() : maxFragmentLength;
    }

    /**
     * Единственное место создания записей: каждая новая запись (в том числе после KeyUpdate)
     * получает согласованный лимит открытого текста (RFC 6066 §4), иначе приёмный предел
     * молча пропадал бы при смене ключей, а запись без лимита принимала бы фрагменты до 16384 байт.
     * Пока лимит не согласован (клиент до EncryptedExtensions), действует значение по умолчанию.
     */
    private TlsRecord newRecordWithNegotiatedLimit(byte[] key, byte[] iv, int tagLen) {
        return newRecordWithNegotiatedLimit(key, iv, ciphersuite);
    }

    private TlsRecord newRecordWithNegotiatedLimit(byte[] key, byte[] iv, TlsCiphersuite suite) {
        TlsRecord record = new TlsRecord(key, iv, suite.getTagLen(), suite);
        record.setMaxFragmentLength(currentMaxFragmentLengthCode());
        return record;
    }

    /**
     * Запись приёма: лимит ставится только после рукопожатия. Сообщения рукопожатия (например,
     * Certificate при mTLS) собеседник мог отправлять без нарезки, и проверка их размера здесь
     * раньше не велась; при завершении рукопожатия лимит применяется к текущей записи отдельно.
     */
    private TlsRecord newReaderRecord(byte[] key, byte[] iv, int tagLen) {
        return handshakeDone
                ? newRecordWithNegotiatedLimit(key, iv, tagLen)
                : new TlsRecord(key, iv, tagLen, ciphersuite);
    }

    /**
     * Устанавливает новый writerRecord по ключам и набору шифров эпохи и сразу уничтожает старый
     * (под замком движка). Набор берётся из метки, а не из поля движка: у клиента метка после
     * ServerHello применяется раньше, чем поле узнает согласованный набор.
     */
    private void swapWriterRecord(TlsTrafficKeys newKeys, TlsCiphersuite suite) {
        TlsRecord previous = writerRecord;
        writerRecord = newRecordWithNegotiatedLimit(newKeys.getKey(), newKeys.getIv(), suite);
        if (previous != null) {
            previous.destroy();
        }
    }

    /**
     * Снимает OCSP-ответы, присланные пиром, по порядку его цепочки (контракт
     * {@code ExtendedSSLSession.getStatusResponses()}): запись нулевой длины означает «ответа нет»,
     * хвостовые пустые записи отбрасываются.
     */
    static List<byte[]> snapshotPeerStatusResponses(List<GostCertificate> certs) {
        List<byte[]> responses = new ArrayList<>(certs.size());
        for (GostCertificate cert : certs) {
            byte[] response = cert.getOcspResponse();
            responses.add(response != null ? response.clone() : new byte[0]);
        }
        int last = responses.size();
        while (last > 0 && responses.get(last - 1).length == 0) {
            last--;
        }
        return List.copyOf(responses.subList(0, last));
    }

    /**
     * Создаёт задачу валидации сертификата для NEED_TASK.
     * <p>
     * Валидирует напрямую через GostCertificate, минуя JCA-конверсию — так OCSP-ответы
     * из stapled CertificateEntry не теряются. JCA-конверсия делается только для
     * peerCertificates (JSSE-контракт).
     */
    private Runnable createCertValidationTask(
            List<GostCertificate> certs, String endpointIdAlgorithm) {
        return () -> {
            try {
                if (trustManager == null) {
                    log.log(
                            Level.WARNING,
                            "Peer certificate received but no GostX509TrustManager is configured"
                                    + " — rejecting certificate");
                    rejectByTask(
                            TlsConstants.ALERT_UNKNOWN_CA, "No trust manager configured", null);
                    return;
                }
                if (clientMode) {
                    // Снимок до валидации: при STAPLING_OR_FETCH trust manager кладёт в те же
                    // GostCertificate ответ, полученный клиентом по сети, а сессия обязана
                    // отражать только присланное сервером.
                    peerStatusResponses = snapshotPeerStatusResponses(certs);
                    // Алгоритм из снимка при beginHandshake(), переданный при создании задачи, а не
                    // из текущих SSLParameters
                    String hostname =
                            GostX509TrustManager.requireHostname(endpointIdAlgorithm, peerHost);
                    peerTrustValidUntil =
                            PeerTrustBoundary.validUntil(
                                    trustManager.validateChainWithOcsp(
                                            certs, hostname, trustManager.isRequireOcspStapling()));
                } else {
                    // mTLS: напрямую по GostCertificate, без конверсии через JCA - иначе
                    // присланный клиентом staple терялся бы. Обязательность staple задаёт
                    // политика контекста (по умолчанию OFF: staple не запрашивается).
                    trustManager.validateClientChain(certs, clientOcspPolicy);
                }
                // Проверка цепочки (сеть, OCSP, CRL) выполнена вне замка; под замком только
                // публикация результата и разбор остатка. Движок мог быть закрыт, пока шла
                // проверка: тогда публиковать и разбирать нечего.
                engineLock.lock();
                try {
                    if (engineState == EngineState.CLOSED) {
                        return;
                    }
                    handshakeEngine.acknowledgeCertificateValidation(true);
                    this.peerCertificates = CertificateBridge.toJca(certs);
                    processFramesAfterCertificateTask();
                } finally {
                    engineLock.unlock();
                }
            } catch (CertificateException e) {
                byte alertCode = alertCodeFor(e);
                // Отказ по сертификату собеседника: причина остаётся в исключении, а движок
                // пишет одну запись на DEBUG, чтобы клиент не мог заполнить журнал WARNING.
                // Отзыв уже записан менеджером доверия (WARNING с серийным номером).
                if (alertCode != TlsConstants.ALERT_CERTIFICATE_REVOKED) {
                    logPeerCertificateRejected(alertCode, e);
                }
                // Отказ обрабатывается здесь, без промежуточного состояния ERROR движка.
                // Поля результата проверки (peerStatusResponses, peerTrustValidUntil)
                // публикуются вместе с подтверждением под замком.
                // Вызов раньше taskInProgress.set(false): когда статус перестанет быть NEED_TASK,
                // неотданный alert уже виден (NEED_WRAP).
                rejectByTask(alertCode, e.getMessage(), e);
            } catch (RuntimeException e) {
                // Настоящий сбой библиотеки или стороннего загрузчика: одна WARNING,
                // только тип исключения (текст может содержать данные собеседника)
                log.log(
                        Level.WARNING,
                        "Certificate validation failed unexpectedly: {0}",
                        e.getClass().getName());
                rejectByTask(alertCodeFor(e), e.getMessage(), e);
            } finally {
                taskInProgress.set(false);
                pendingTask.set(null);
            }
        };
    }

    /**
     * Отказ по сертификату собеседника: одна запись на DEBUG, без исключения и стека.
     *
     * <p>Причина остаётся в {@link CertificateException}, которую получает приложение. Текст
     * исключения может содержать SAN и URI из сертификата, поэтому в журнал он идёт только
     * после {@link SafeText#printableAscii(CharSequence)} и только на DEBUG: WARNING включён
     * по умолчанию, и внешний узел не должен заполнять им журнал сервера.
     */
    private void logPeerCertificateRejected(byte alertCode, CertificateException failure) {
        if (!log.isLoggable(Level.DEBUG)) {
            return;
        }
        String detail = failure.getMessage();
        log.log(
                Level.DEBUG,
                "Peer certificate rejected: stage={0}, alert={1}, {2}",
                failedHandshakeStage(),
                TlsAlerts.forLog(alertCode),
                detail == null
                        ? "null"
                        : SafeText.printableAscii(detail, TlsConstants.LOG_PEER_STRING_LIMIT));
    }

    /**
     * Разбирает сообщения, пришедшие в той же записи после Certificate (CertificateVerify,
     * Finished). Как в JDK ({@code SSLEngineImpl.DelegatedTask.run()} разбирает под замком всю
     * очередь отложенных сообщений): иначе их никто бы не разобрал, а следующий {@code unwrap()}
     * без новых байт вернул бы BUFFER_UNDERFLOW, и рукопожатие повисло бы. Под замком здесь
     * проверка подписи CertificateVerify, Finished и создание сессии; сетевая проверка цепочки
     * идёт раньше, вне замка.
     * <p>
     * Предусловие: engineLock захвачен, проверка сертификата подтверждена. Ошибка разбора
     * закрывает соединение с настоящим кодом alert через {@link #rejectByTask}, а не исключением
     * из задачи.
     */
    private void processFramesAfterCertificateTask() {
        if (handshakeAssembler.isEmpty()) {
            return;
        }
        try {
            processHandshakeFrames();
        } catch (TlsException e) {
            rejectByTask(e.getAlertCode(), e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            rejectByTask(TlsConstants.ALERT_INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    /**
     * Код alert по цепочке причин отказа проверки сертификата: код {@code TlsException}, иначе
     * {@code certificate_revoked} для отзыва (проверка CRL бросает {@code PkixException} с
     * причиной REVOKED без {@code TlsException}), иначе {@code bad_certificate}.
     */
    /**
     * Стадия, на которой рукопожатие закончилось отказом. После отказа
     * {@link TlsHandshakeEngine#getState()} всегда {@code ERROR}, поэтому сначала берётся
     * зафиксированная стадия отказа, а при её отсутствии (отказ вне приёма сообщения) - текущая.
     */
    private TlsHandshakeEngine.State failedHandshakeStage() {
        TlsHandshakeEngine.State stage = handshakeEngine.getFailedStage();
        return stage != null ? stage : handshakeEngine.getState();
    }

    /**
     * Диагностическая метка соединения для журнала, {@code conn#N}.
     *
     * <p>Монотонный номер, а не идентификатор сессии: в протокол не попадает, ключей и
     * персональных данных не несёт. До {@code beginHandshake()} возвращает {@code null}.
     * Нужна сокету и другим обёрткам, чтобы писать записи с тем же префиксом.
     *
     * @return метка или {@code null} до создания движка рукопожатия
     */
    public String getConnectionLabel() {
        return connectionLabel;
    }

    private static byte alertCodeFor(Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < MAX_CAUSE_DEPTH; depth++) {
            if (current instanceof TlsException tls) {
                return tls.getAlertCode();
            }
            if (current instanceof PkixException pkix
                    && pkix.reason() == PkixException.Reason.REVOKED) {
                return TlsConstants.ALERT_CERTIFICATE_REVOKED;
            }
            current = current.getCause();
        }
        return TlsConstants.ALERT_BAD_CERTIFICATE;
    }

    /**
     * Срок жизни тикета по настройке контекста сессий, не более предела RFC 8446 §4.6.1;
     * нулевой тайм-аут контекста означает «без ограничения», то есть предел RFC.
     */
    private long sessionLifetimeForTicket() {
        return sessionContext == null ? 0 : sessionContext.maxTicketLifetimeSeconds();
    }

    /**
     * Завершает handshake: создаёт сессию с финальными данными.
     * <p>
     * Предусловие: handshakeDone == false
     * Постусловие: session создан, handshakeDone == true,
     *              writerRecord не тронут (эпоху меняют метки в очереди отправки).
     */
    private void finishHandshake() {
        if (handshakeDone) return;

        // Буфер сборки к этому моменту пуст (граница записи при смене ключа чтения проверена).
        // Сброс возвращает массив, выросший под цепочку сертификатов, к начальному размеру, как в
        // TlsSession: иначе он занимал бы память всё время жизни соединения
        handshakeAssembler.reset();

        // Ключ записи здесь не трогается: клиентский Finished ещё в очереди, а смена на ключи
        // приложения стоит меткой за ним и применится в wrap() после его отправки.

        // Сохраняем ALPN-протокол и mTLS-флаг в полях движка: состояние handshakeEngine
        // затирается при закрытии соединения.
        this.selectedAlpnProtocol = handshakeEngine.getSelectedAlpnProtocol();
        this.clientAuthRequested = handshakeEngine.isClientAuthRequested();
        this.resumed = handshakeEngine.isPskAccepted();
        if (clientMode) {
            this.localCertChain = sentClientCertificates();
        }
        this.resumptionKnown = true;

        // Сессия собирается целиком в локальной переменной и публикуется в volatile-поле
        // последним шагом: другой поток не должен увидеть её без ответов OCSP и контекста
        // (иначе isValid() не учёл бы срок жизни).
        GostSSLSession finishedSession =
                new GostSSLSession(
                        ciphersuite.getIanaName(),
                        peerHost,
                        peerPort,
                        peerCertificates,
                        localCertChain != null ? localCertChain : new X509Certificate[0],
                        selectedAlpnProtocol);
        finishedSession.setKeyingMaterialEngine(this);
        // Сервер: собственный staple. Клиент: ответы, присланные сервером; его собственный
        // staple (ocspResponse) в getStatusResponses() попадать не должен.
        if (clientMode) {
            finishedSession.setStatusResponses(peerStatusResponses);
        } else if (ocspResponse != null) {
            finishedSession.setOcspResponse(ocspResponse);
        }
        // putSession задаёт сессии контекст (обратную ссылку)
        if (sessionContext != null) {
            sessionContext.putSession(finishedSession);
        }
        this.session = finishedSession;

        // Сервер: генерируем NewSessionTicket для resumption.
        // При mTLS тикет не выдаём: PSK-возобновление обошло бы повторную
        // аутентификацию клиента. Это локальная политика, а не требование RFC.
        // Тикет не должен пережить собственный сертификат: клиент при возобновлении цепочки не
        // видит. Без цепочки или при остатке меньше секунды тикет не выдаётся
        // (ticket_lifetime = 0 означает «удалить немедленно», RFC 8446 §4.6.1).
        long issueTimeMillis = System.currentTimeMillis();
        long ticketLifetime =
                ownChainValidUntil == BOUND_UNKNOWN
                        ? 0
                        : PeerTrustBoundary.clampLifetimeSeconds(
                                sessionLifetimeForTicket(), ownChainValidUntil, issueTimeMillis);
        if (!clientMode && sessionContext != null && !clientAuthRequested && ticketLifetime > 0) {
            byte[] rms = handshakeEngine.getResumptionMasterSecret();
            if (rms != null) {
                TlsTicketHelper.IssuedTicket issued;
                try {
                    // Запись в хранилище делается до постановки тикета в очередь: тикет, которого
                    // сервер не знает, клиенту бесполезен. Сбой хранилища тикет не выдаёт и
                    // рукопожатие не прерывает (контракт PskStore)
                    issued =
                            TlsTicketHelper.issue(
                                    sessionContext.getPskStore(),
                                    rms,
                                    0,
                                    ciphersuite.getHashLen(),
                                    ticketLifetime,
                                    issueTimeMillis,
                                    PskBinding.forServer(requestedServerName),
                                    ownChainValidUntil);
                } finally {
                    // getResumptionMasterSecret() отдаёт копию: затираем и при сбое хранилища
                    TlsUtils.wipeArray(rms);
                }
                if (issued != null) {
                    try {
                        byte[] nstBody =
                                TlsMessageBuilder.buildNewSessionTicket(
                                        issued.lifetimeSeconds(),
                                        issued.ticketAgeAdd(),
                                        issued.ticketNonce(),
                                        issued.ticket());
                        byte[] nstFrame =
                                new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, nstBody)
                                        .encode();
                        outgoingQueue.addLast(new HandshakeOutput.Message(nstFrame));
                    } finally {
                        issued.wipe();
                    }
                }
            }
        }

        currentPskTicketIdentity = null;

        // Сохраняем согласованный max_fragment_length: состояние handshakeEngine затирается
        // при закрытии соединения
        this.maxFragmentLength = handshakeEngine.getMaxFragmentLength();

        handshakeDone = true;
        // Приёмный лимит включается с этого момента (RFC 6066 §4); запись приёма с app-ключами
        // создана раньше, в handleEngineKeyChanges, когда handshakeDone ещё не был выставлен
        if (readerRecord != null) {
            readerRecord.setMaxFragmentLength(maxFragmentLength);
        }

        if (log.isLoggable(Level.DEBUG)) {
            // SNI, ALPN и DN приходят от собеседника: в журнал только очищенными/усечёнными
            String sniInfo =
                    !clientMode && requestedServerName != null
                            ? TlsUtils.peerTextForLog(requestedServerName)
                            : "N/A";
            String peerInfo;
            try {
                peerInfo =
                        GostDnParser.truncateForLog(
                                finishedSession.getPeerPrincipal().getName(),
                                GostCertificate.DN_LOG_MAX_CHARS);
            } catch (SSLPeerUnverifiedException e) {
                peerInfo = "none";
            }
            log.log(
                    Level.DEBUG,
                    "Handshake completed: suite={0}, alpn={1}, sni={2}, peer={3}",
                    ciphersuite.forLog(),
                    TlsUtils.peerTextForLog(selectedAlpnProtocol),
                    sniInfo,
                    peerInfo);
        }

        // При mTLS без NewSessionTicket очередь пуста. Переходим в DATA сразу,
        // но FINISHED отдаём из завершающего unwrap(): этого ждёт Tomcat.
        if (!clientMode && outgoingQueue.isEmpty()) {
            handleEngineKeyChanges();
            engineState = EngineState.DATA;
            finishStatusPending = true;
        }
    }

    // ========================================================================
    // Alert handling
    // ========================================================================

    /**
     * Разбирает тело alert-записи пира. Формат проверяет общий разбор ({@link
     * TlsUtils#alertDescription}): нарушение даёт локальный {@code TlsException}, на который
     * {@code unwrap()} отвечает своим alert. Решение по описанию: {@code close_notify} это закрытие
     * пира, остальные alert - отказ соединения.
     */
    private void handleAlert(byte[] alertData) throws TlsException {
        byte description = TlsUtils.alertDescription(alertData);

        if (description == TlsConstants.CLOSE_NOTIFY) {
            closeReceived = true;
            log.log(
                    Level.DEBUG,
                    "Alert received: {0}",
                    TlsAlerts.forLog(TlsConstants.CLOSE_NOTIFY));
            // Разрушение не здесь: этот же unwrap ещё дочитывает запись и может обратиться к
            // ключам и движку. Входную сторону (и всё остальное, если свой close_notify уже
            // отправлен) разрушает settleAfterUnwrap() в конце вызова.
            return;
        }

        // Поле level не учитывается: в TLS 1.3 любой alert, кроме закрывающих, это ошибка (RFC 8446
        // §6). Ответного alert нет, соединение разрушается целиком в общем обработчике unwrap()
        // Код задаёт пир (в окне открытой записи он ещё и не аутентифицирован), приложение получает
        // его исключением: журнал только для отладки
        log.log(Level.DEBUG, "Fatal alert received: {0}", TlsAlerts.forLog(description));
        throw TlsException.fromPeer(
                description, "Received fatal alert " + (description & 0xFF) + " from peer");
    }

    /**
     * Отказ соединения (RFC 8446 §6.2): собирает fatal alert (если отказ локальный), разрушает ключи
     * и движок рукопожатия. Вызывается под замком движка или из потока без замка (задача проверки
     * сертификата): замок реентерабелен, берётся здесь же.
     *
     * <p>Идемпотентен: повторный вызов, а также вызов на уже закрытом движке не ставит второй alert
     * и не меняет код. Если свой {@code close_notify} уже собран, alert не ставится. Alert
     * собирается текущим {@code writerRecord}, до появления ключей открытой записью; разрушение
     * идёт строго после сборки.
     *
     * @param alertCode код alert: свой, либо полученный от пира
     * @param fromPeer  true, если отказ пришёл от пира (ответного alert нет)
     */
    private void failConnection(byte alertCode, boolean fromPeer) {
        engineLock.lock();
        try {
            // Fatal alert пира закрывает и его сторону: ответный close_notify уже не нужен
            if (fromPeer) {
                closeReceived = true;
            }
            if (engineState == EngineState.CLOSED) {
                return;
            }
            failureAlertCode = alertCode & 0xFF;
            // После СВОЕГО close_notify (closeSent, даже ещё не отданного) alert не ставится:
            // номер записи уже использован, откат запрещён (повтор nonce), следующий номер пир
            // не расшифрует (ждёт предыдущий), а RFC 8446 §6.1 игнорирует всё после закрывающего
            // alert. Уходит уже собранный close_notify, как есть. close_notify пира
            // (closeReceived) alert не отменяет.
            if (!fromPeer && !closeSent) {
                try {
                    pendingCloseRecord = buildAlertRecord(TlsConstants.ALERT_FATAL, alertCode);
                    fatalAlertPending = true;
                } catch (Exception e) {
                    // alert best-effort: ключи всё равно разрушаются, пир увидит обрыв
                    log.log(Level.DEBUG, "Fatal alert could not be built");
                    pendingCloseRecord = null;
                }
            }
            engineState = EngineState.CLOSED;
            finishStatusPending = false;
            destroyAll();
        } finally {
            engineLock.unlock();
        }
    }

    /**
     * Собирает запись alert: защищённую, если ключи записи уже есть, иначе открытую (как и все
     * записи до появления ключей).
     */
    private byte[] buildAlertRecord(byte level, byte description) {
        byte[] payload = new byte[] {level, description};
        return writerRecord != null
                ? writerRecord.protect(TlsConstants.CT_ALERT, payload)
                : buildPlaintextRecord(TlsConstants.CT_ALERT, payload);
    }

    /** Разрушает входную сторону: ключи чтения, буфер рукопожатия, идентичность PSK. */
    private void destroyInboundSide() {
        if (readerRecord != null) {
            readerRecord.destroy();
            readerRecord = null;
        }
        handshakeAssembler.reset();
        currentPskTicketIdentity = null;
    }

    /**
     * Экспорт ключевого материала для {@link GostSSLSession}. Берёт замок движка: уничтожение
     * секрета ({@link #destroyAll()}) идёт под тем же замком, поэтому экспорт не читает
     * наполовину затёртый секрет, а после закрытия соединения получает отказ.
     *
     * @throws IllegalStateException если рукопожатие не завершено или соединение закрыто
     * @throws IllegalArgumentException если аргументы выходят за допустимые пределы
     */
    byte[] exportKeyingMaterial(String label, byte[] context, int length) {
        engineLock.lock();
        try {
            if (handshakeEngine == null || !handshakeEngine.isExportAvailable()) {
                throw new IllegalStateException(GostSSLSession.MSG_EXPORTER_UNAVAILABLE);
            }
            // Контракт JSSE строже слоя tls13 (см. GostJsseConstants.EXPORT_CONTEXT_MAX_LENGTH)
            if (context != null && context.length > GostJsseConstants.EXPORT_CONTEXT_MAX_LENGTH) {
                throw new IllegalArgumentException("context length outside range");
            }
            return handshakeEngine.exportKeyingMaterial(label, context, length);
        } finally {
            engineLock.unlock();
        }
    }

    /**
     * Разрушает всё: ключи чтения и записи, ожидающие ключи, очередь рукопожатия, движок
     * рукопожатия (RMS, PSK, traffic secrets). Не трогает {@code pendingCloseRecord}: он очищается
     * только в точке отдачи. Вызывается под замком движка.
     */
    private void destroyAll() {
        destroyInboundSide();
        // Буфер расшифрованных записей переиспользуется между вызовами unwrap и хранит последний
        // открытый текст: после закрытия он не должен остаться в памяти
        TlsUtils.wipeArray(plaintextBuf.array());
        if (writerRecord != null) {
            writerRecord.destroy();
            writerRecord = null;
        }
        clearOutgoingQueue();
        pendingHsFragment = null;
        pendingHsOffset = 0;
        if (handshakeEngine != null) {
            handshakeEngine.destroy();
        }
    }

    /**
     * Завершение вызова {@code unwrap()} под замком: после {@code close_notify} пира разрушается
     * входная сторона; если свой {@code close_notify} уже отправлен, закрывается всё. Не раньше
     * конца вызова: тот же {@code unwrap()} ещё дочитывает запись и обращается к ключам.
     */
    private void settleAfterUnwrap() {
        if (closeReceived) {
            if (closeSent) {
                engineState = EngineState.CLOSED;
                finishStatusPending = false;
                destroyAll();
            } else {
                destroyInboundSide();
            }
        }
    }

    /**
     * Отказ задачи проверки сертификата: закрывает соединение и запоминает исключение для
     * приложения. Оба действия идут под одним захватом замка: иначе параллельный {@code wrap()}
     * между ними отдал бы alert и вернул {@code CLOSED}, не бросив исключения, и настоящий код
     * отказа мог бы не дойти до приложения. Исключение запоминается, только если соединение закрыл
     * именно этот вызов: при уже закрытом соединении приложение получило другую причину.
     */
    private void rejectByTask(byte alertCode, String message, Throwable cause) {
        engineLock.lock();
        try {
            boolean closedHere = engineState != EngineState.CLOSED;
            failConnection(alertCode, false);
            if (closedHere) {
                taskFailure.set(AlertMapper.toException(alertCode, message, cause));
            }
        } finally {
            engineLock.unlock();
        }
    }

    /** Бросает отказ задачи проверки сертификата, если он ещё не доставлен приложению. */
    private void throwTaskFailure() throws SSLException {
        SSLException failure = taskFailure.getAndSet(null);
        if (failure != null) {
            throw failure;
        }
    }

    /** Фиксирует отдачу fatal alert пиру: выходная сторона закрыта. */
    private void markAlertDelivered() {
        if (fatalAlertPending) {
            fatalAlertPending = false;
            closeSent = true;
        }
    }

    /**
     * Только для тестов: факт зануления ссылок на record-ключи после
     * разрушения. Возвращает лишь boolean, ключевой материал не раскрывает.
     */
    boolean recordsDestroyedForTest() {
        return readerRecord == null && writerRecord == null && !keyUpdateQueued();
    }

    // ========================================================================
    // Close
    // ========================================================================

    @Override
    public void closeOutbound() {
        engineLock.lock();
        try {
            // повторный вызов, либо fatal alert уже собран: close_notify его не заменяет
            if (closeSent || fatalAlertPending) return;
            // Отправляем close_notify (best-effort, RFC 8446 §6.1). Запись собирается сразу, до
            // возможного разрушения ключей записи, и уходит через wrap() или pollOutboundRecord().
            // Без ключей записи после закрытия пиром (closeInbound, fatal alert пира) отвечать
            // нечем: открытый alert после защищённого трафика недопустим. Иное дело, если пир
            // закрыл рукопожатие, пока ключей записи ещё нет (движок не закрыт): ответ уходит
            // открытым, как и все записи до ключей.
            if (canAnswerWithCloseNotify()) {
                try {
                    pendingCloseRecord =
                            buildAlertRecord(TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY);
                } catch (Exception e) {
                    // RFC 8446 §6.1: close_notify best-effort, не кидаем исключение
                    pendingCloseRecord = null;
                }
            }
            closeSent = true;
            // Журнал отражает факт: без собранной записи close_notify пир не получит
            if (pendingCloseRecord != null) {
                log.log(Level.DEBUG, "close_notify queued");
            } else {
                log.log(Level.DEBUG, "close_notify not sent: no write keys to protect it");
            }
            if (closeReceived) {
                // Пир закрыл первым: это ответный close_notify, после него закрывается всё
                // (входная сторона разрушена в unwrap).
                engineState = EngineState.CLOSED;
                finishStatusPending = false;
                destroyAll();
            }
        } finally {
            engineLock.unlock();
        }
    }

    /**
     * Есть ли чем отвечать на закрытие: ключи записи ещё живы, либо движок не закрыт. Закрытый
     * движок без ключей записи (после closeInbound, fatal alert пира) отвечать нечем, а открытый
     * alert после защищённого трафика недопустим. Пока движок открыт, а ключей записи нет, пир
     * закрыл рукопожатие до их появления, и ответ уходит открытым, как все записи до ключей.
     */
    private boolean canAnswerWithCloseNotify() {
        return writerRecord != null || !(closeReceived && engineState == EngineState.CLOSED);
    }

    @Override
    public void closeInbound() throws SSLException {
        engineLock.lock();
        try {
            if (closeReceived) {
                // Приложение отказалось читать дальше: в буфере расшифровки лежит открытый текст
                // последней записи, он не должен ждать сборщика мусора
                TlsUtils.wipeArray(plaintextBuf.array());
                return;
            }
            if (!closeSent) {
                // RFC 8446 §6.1 не требует closeSent перед closeInbound.
                // Netty SslHandler вызывает closeInbound() при channelInactive
                // (обрыв TCP, таймаут) — без close_notify.
                log.log(Level.DEBUG, "closeInbound without closeOutbound — close_notify not sent");
            }
            closeReceived = true;
            engineState = EngineState.CLOSED;
            finishStatusPending = false;
            // Не отданный close_notify при закрытии входной стороны отбрасывается, как и прежде;
            // fatal alert не трогаем: SslHandler Netty при отказе вызывает closeInbound() до
            // отправки alert, и пир обязан получить причину
            if (!fatalAlertPending) {
                pendingCloseRecord = null;
            }
            destroyAll();
        } finally {
            engineLock.unlock();
        }
    }

    /**
     * После closeOutbound() забирает уже собранный close_notify alert-record
     * для прямой записи в сокет. Хранится отдельно от outgoingQueue, чтобы
     * wrap() не перешифровал его второй раз.
     *
     * @return зашифрованный alert-record или null если записи нет
     */
    public byte[] pollOutboundRecord() {
        engineLock.lock();
        try {
            byte[] rec = pendingCloseRecord;
            pendingCloseRecord = null;
            if (rec != null) {
                markAlertDelivered();
            }
            return rec;
        } finally {
            engineLock.unlock();
        }
    }

    @Override
    public boolean isOutboundDone() {
        // Закрыто, когда закрывающая запись отдана: пока close_notify или alert ещё ждут
        // отдачи, приложение обязано вызвать wrap(). Если отдавать нечего (ответить было нечем
        // или сборка записи не удалась), закрытие завершено сразу. Инвариант: истинно ровно тогда,
        // когда wrap() больше нечего отдавать; иначе цикл «пока не isOutboundDone() - wrap()»
        // не завершился бы.
        return pendingCloseRecord == null
                && !fatalAlertPending
                && (closeSent || engineState == EngineState.CLOSED);
    }

    @Override
    public boolean isInboundDone() {
        // Расшифрованных, но не выданных данных движок не держит (запись приложения принимается
        // целиком или не принимается), поэтому приём завершён, как только пришло закрытие
        return closeReceived || engineState == EngineState.CLOSED;
    }

    // ========================================================================
    // Application protocol (ALPN)
    // ========================================================================

    /**
     * {@inheritDoc}
     * <p>
     * Контракт JDK: {@code null}, пока протокол не определён; имя протокола, как только он
     * согласован (в том числе до завершения рукопожатия); пустая строка после завершения
     * рукопожатия, если протокол не согласован (ALPN не использовался). Различие нужно
     * интеграциям (Netty): они читают результат без проверки на {@code null} и считают пустую
     * строку признаком «ALPN не согласован».
     */
    @Override
    public String getApplicationProtocol() {
        if (!handshakeDone) {
            return getHandshakeApplicationProtocol();
        }
        String negotiated = selectedAlpnProtocol;
        return negotiated != null ? negotiated : "";
    }

    /**
     * {@inheritDoc}
     * <p>
     * Значение доступно только пока рукопожатие идёт и сервер уже выбрал протокол; после его
     * завершения, как в JDK, возвращается {@code null}: итоговое значение отдаёт
     * {@link #getApplicationProtocol()}.
     */
    @Override
    public String getHandshakeApplicationProtocol() {
        return withLock(
                () -> {
                    if (handshakeDone || handshakeEngine == null) {
                        return null;
                    }
                    return handshakeEngine.getSelectedAlpnProtocol();
                });
    }

    /**
     * ALPN-селектор (BiFunction): вызывается на серверной стороне при получении
     * ClientHello с ALPN-расширением. Получает список протоколов от клиента и возвращает
     * выбранный протокол, пустую строку или null (контракт JDK).
     * <p>
     * Результат селектора:
     * <ul>
     *   <li>имя протокола из списка клиента - протокол согласован;</li>
     *   <li>пустая строка - протокол не выбран, рукопожатие продолжается без ALPN
     *       ({@code getApplicationProtocol()} вернёт пустую строку);</li>
     *   <li>null или протокол не из списка клиента - отказ: рукопожатие завершается
     *       фатальным алертом {@code no_application_protocol} (RFC 7301 §3.2).</li>
     * </ul>
     */
    private BiFunction<SSLEngine, List<String>, String> alpnSelector;

    @Override
    public void setHandshakeApplicationProtocolSelector(
            BiFunction<SSLEngine, List<String>, String> selector) {
        withLock(
                () -> {
                    this.alpnSelector = selector;
                    installAlpnSelector();
                });
    }

    @Override
    public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return withLock(() -> alpnSelector);
    }

    private void installAlpnSelector() {
        if (handshakeEngine != null) {
            if (alpnSelector != null) {
                Function<List<String>, String> fn =
                        clientList -> alpnSelector.apply(this, clientList);
                handshakeEngine.setAlpnSelector(fn);
            } else {
                handshakeEngine.setAlpnSelector(null);
            }
        }
    }

    /**
     * Возвращает DNS-имя, которое клиент указал в расширении server_name
     * ClientHello (RFC 6066 §3). Доступно только на стороне сервера после
     * получения ClientHello.
     * <p>
     * Используется для multi-tenant селекции сертификата и для тестов.
     *
     * @return запрошенное имя хоста, или null если SNI не было
     */
    public String getRequestedServerName() {
        return requestedServerName;
    }

    // ========================================================================
    // Handshake status
    // ========================================================================

    /**
     * Возвращает {@code FINISHED}, если завершённый handshake ещё не подтверждён
     * наружу, иначе обычный статус. Флаг сбрасывается при первом возврате,
     * чтобы {@code FINISHED} был отдан ровно один раз на сторону.
     */
    private SSLEngineResult.HandshakeStatus consumeFinishStatus() {
        if (finishStatusPending) {
            finishStatusPending = false;
            return SSLEngineResult.HandshakeStatus.FINISHED;
        }
        return getHandshakeStatus();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        // Читает несколько согласованных полей (очередь, фрагмент, признаки); как в JDK, под
        // замком,
        // иначе возможен неверный статус при параллельном wrap()
        engineLock.lock();
        try {
            return handshakeStatusLocked();
        } finally {
            engineLock.unlock();
        }
    }

    private SSLEngineResult.HandshakeStatus handshakeStatusLocked() {
        if (taskInProgress.get()) {
            return SSLEngineResult.HandshakeStatus.NEED_TASK;
        }
        // неотданный fatal alert требует wrap(); проверка раньше ветки CLOSED, иначе NEED_WRAP
        // не вернётся. Геттер ничего не меняет: только читает volatile-признак.
        if (fatalAlertPending || pendingCloseRecord != null) {
            return SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        // До вызова beginHandshake() (INITIAL) движок не handshaking. SslHandler в Netty
        // проверяет этот статус, чтобы решить, нужно ли инициировать handshake:
        // NOT_HANDSHAKING означает «ещё не начали», NEED_UNWRAP — «ждём входящие данные».
        // Возврат NEED_UNWRAP на INITIAL ломает SslHandler. В DATA и CLOSED рукопожатия нет.
        if (engineState != EngineState.HANDSHAKE) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        // FINISHED не отдаётся из getHandshakeStatus(): он возвращается
        // ровно один раз из завершающего wrap()/unwrap(). Пока handshake
        // завершён, но очередь или последний фрагмент не отправлены,
        // потребитель обязан вызвать wrap().
        if (handshakeDone || !outgoingQueue.isEmpty() || pendingHsFragment != null) {
            return SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
    }

    /**
     * Инициирует KeyUpdate (RFC 8446 §4.6.3).
     * <p>
     * Нестандартное расширение JSSE для ручного управления ре-кейингом.
     * После вызова следующий {@link #wrap(ByteBuffer, ByteBuffer)} отправит
     * KU-фрейм старыми ключами и переключится на новые.
     * <p>
     * Собственные обновления не ограничиваются (приложение доверенное), но не вызывайте метод в
     * цикле: пир принимает чужие обновления в пределах окна
     * ({@code TlsConstants.MAX_PEER_KEY_UPDATES_PER_WINDOW} за
     * {@code TlsConstants.KEY_UPDATE_RATE_WINDOW_NANOS}) и закрывает соединение при превышении.
     *
     * @param requestUpdate true = запросить ответный KU от пира
     * @throws SSLException если handshake не завершён
     */
    public void initiateKeyUpdate(boolean requestUpdate) throws SSLException {
        engineLock.lock();
        try {
            if (!handshakeDone) {
                throw new SSLException("Cannot initiate KeyUpdate before handshake complete");
            }
            // Неотправленное обновление объединяется с новым вызовом (как в движке рукопожатия):
            // запрос ответа повышает его, а не теряется. Обычно оно ждёт в потоке движка до wrap(),
            // после BUFFER_OVERFLOW может стоять и в очереди отправки
            if (keyUpdateInSendQueue()) {
                if (requestUpdate) {
                    TlsHandshakeEngine.requestUpdateInQueuedKeyUpdate(outgoingQueue);
                }
                return;
            }
            handshakeEngine.initiateKeyUpdate(requestUpdate);
            log.log(Level.DEBUG, "KeyUpdate queued: requestUpdate={0}", requestUpdate);
        } catch (TlsException e) {
            throw AlertMapper.toException(e.getAlertCode(), e.getMessage(), e);
        } finally {
            engineLock.unlock();
        }
    }

    @Override
    public Runnable getDelegatedTask() {
        // атомарное получение задачи — getAndSet гарантирует, что только
        // один поток получит non-null pendingTask, даже при конкурентном вызове
        // getDelegatedTask() из нескольких потоков. taskInProgress не сбрасывается
        // здесь — он остаётся true, пока задача не выполнится (сброс в finally
        // таска), чтобы getHandshakeStatus() продолжал возвращать NEED_TASK.
        if (!taskInProgress.get()) return null;
        return pendingTask.getAndSet(null);
    }

    // ========================================================================
    // Session
    // ========================================================================

    @Override
    public SSLSession getSession() {
        if (session != null) return session;
        return preHandshakeSession;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Пока рукопожатие идёт, отдаёт его сессию с адресом пира и протоколом; набор шифров и
     * сертификаты пира появляются в {@link #getSession()} после завершения. До начала и после
     * завершения рукопожатия — {@code null}, как в JDK.
     */
    @Override
    public SSLSession getHandshakeSession() {
        // Только volatile-поля: метод зовут и из других потоков
        GostSSLSession current = handshakeSession;
        return current != null && !handshakeDone && engineState != EngineState.CLOSED
                ? current
                : null;
    }

    // ========================================================================
    // Client/Server mode
    // ========================================================================

    /** Выполняет действие под замком движка (сеттеры параметров, см. javadoc класса). */
    private void withLock(Runnable action) {
        engineLock.lock();
        try {
            action.run();
        } finally {
            engineLock.unlock();
        }
    }

    /** Читает значение под замком движка (геттеры параметров, см. javadoc класса). */
    private <T> T withLock(Supplier<T> reader) {
        engineLock.lock();
        try {
            return reader.get();
        } finally {
            engineLock.unlock();
        }
    }

    @Override
    public void setUseClientMode(boolean mode) {
        withLock(
                () -> {
                    if (handshakeStarted) {
                        throw new IllegalArgumentException(
                                "Cannot change mode after handshake started");
                    }
                    // Если engine создан через SSLContextSpi, контекст сессий переключается
                    // вместе с ролью в обе стороны: без возврата клиентского контекста
                    // клиентский режим после серверного брал бы PSK из серверного хранилища
                    if (serverSessionContext != null) {
                        this.sessionContext = mode ? clientSessionContext : serverSessionContext;
                    }
                    this.clientMode = mode;
                });
    }

    @Override
    public boolean getUseClientMode() {
        return withLock(() -> clientMode);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        // Как в JDK: режим один (обязателен, запрашивается или нет), поэтому вызов заменяет
        // предыдущий выбор, в том числе сбрасывает запрашиваемый режим
        withLock(
                () -> {
                    this.needClientAuth = need;
                    this.wantClientAuth = false;
                });
    }

    @Override
    public boolean getNeedClientAuth() {
        return withLock(() -> needClientAuth);
    }

    /**
     * Запрашивает клиентский сертификат необязательно.
     * <p>
     * Как и {@link #setNeedClientAuth(boolean)}, отключает выдачу PSK-тикетов:
     * resumption обошёл бы повторную аутентификацию клиента.
     */
    @Override
    public void setWantClientAuth(boolean want) {
        // Как в JDK: вызов заменяет предыдущий выбор, в том числе сбрасывает обязательный режим
        withLock(
                () -> {
                    this.wantClientAuth = want;
                    this.needClientAuth = false;
                });
    }

    @Override
    public boolean getWantClientAuth() {
        return withLock(() -> wantClientAuth);
    }

    // ========================================================================
    // Cipher suites / Protocols
    // ========================================================================

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        String[] checked = SslParameterNames.checkedCipherSuites(suites);
        withLock(() -> this.enabledCipherSuites = checked);
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return withLock(() -> enabledCipherSuites.clone());
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.supportedCipherSuites();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        String[] checked = SslParameterNames.checkedProtocols(protocols);
        withLock(() -> this.enabledProtocols = checked);
    }

    @Override
    public String[] getEnabledProtocols() {
        return withLock(() -> enabledProtocols.clone());
    }

    @Override
    public String[] getSupportedProtocols() {
        return GostJsseConstants.supportedProtocols();
    }

    // ========================================================================
    // SSLParameters
    // ========================================================================

    /**
     * Параметры движка. Настройки (наборы шифров, протоколы, режим аутентификации клиента,
     * алгоритм проверки имени, протоколы ALPN) снимаются при {@link #beginHandshake()}: изменение
     * после начала рукопожатия видно через геттеры, но на текущее рукопожатие не влияет.
     */
    @Override
    public SSLParameters getSSLParameters() {
        return withLock(this::sslParametersLocked);
    }

    private SSLParameters sslParametersLocked() {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(enabledCipherSuites);
        params.setProtocols(enabledProtocols);
        // В SSLParameters режимы взаимоисключающие, и setWantClientAuth сбрасывает need: порядок
        // важен, иначе круговой setSSLParameters(getSSLParameters()) отключил бы обязательный режим
        if (needClientAuth) {
            params.setNeedClientAuth(true);
        } else {
            params.setWantClientAuth(wantClientAuth);
        }
        if (endpointIdentificationAlgorithm != null) {
            params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }
        if (applicationProtocols != null) {
            params.setApplicationProtocols(applicationProtocols);
        }
        // Действующее имя SNI возвращается, чтобы круговой setSSLParameters(getSSLParameters()) не
        // сбрасывал переопределение; пустой список — SNI отключён
        if (sniOverride != null) {
            params.setServerNames(
                    sniOverride.isEmpty() ? List.of() : List.of(new SNIHostName(sniOverride)));
        }
        return params;
    }

    /**
     * Применяет параметры. Значения действуют на рукопожатие, только если заданы до
     * {@link #beginHandshake()}; позднее изменение на уже идущее рукопожатие не влияет (так и в
     * JDK: сеттеры после начала рукопожатия исключений не бросают).
     * <p>
     * Режим аутентификации клиента задаётся полностью, как в JDK: {@code needClientAuth} включает
     * обязательный режим, иначе {@code wantClientAuth} включает запрашиваемый, иначе клиентский
     * сертификат не запрашивается. Непустой массив протоколов ALPN заменяет прежние, пустой
     * снимает их.
     */
    @Override
    public void setSSLParameters(SSLParameters params) {
        if (params == null) return;
        // Один захват на весь вызов: beginHandshake() видит либо все новые значения, либо ни одного
        withLock(() -> applySslParametersLocked(params));
    }

    private void applySslParametersLocked(SSLParameters params) {
        String[] suites = params.getCipherSuites();
        if (suites != null) setEnabledCipherSuites(suites);
        String[] protocols = params.getProtocols();
        if (protocols != null) setEnabledProtocols(protocols);
        // Как в JDK: need -> обязателен, иначе want -> запрашивается, иначе клиентский сертификат
        // не запрашивается; прежние значения сбрасываются, а не только включаются
        // Сеттеры заменяют друг друга, поэтому применяется один вызов
        if (params.getNeedClientAuth()) {
            setNeedClientAuth(true);
        } else {
            setWantClientAuth(params.getWantClientAuth());
        }
        // Контракт SSLParameters: endpoint id применяется всегда, включая null
        // (null = endpoint identification отключён). Иначе явный opt-out по спецификации
        // не сработал бы и safe-default стал бы ловушкой. Исключение - контекст в режиме
        // STRICT: там null означает «не задано» (так передаёт Netty), иначе он снял бы HTTPS,
        // выставленный при создании engine. Пустая строка -
        // явное отключение и присваивается как есть. Условий на host и opt-out не нужно: без
        // host или при opt-out текущее значение и так null, а у createForClient оно HTTPS даже
        // при пустом host: сохранение его не меняет, и рукопожатие осознанно падает на
        // «peer host is missing» (fail-closed), а не пропускает проверку.
        String requestedAlgorithm = params.getEndpointIdentificationAlgorithm();
        boolean keepCurrent =
                requestedAlgorithm == null
                        && sessionContext != null
                        && sessionContext.getEndpointIdentificationMode()
                                == EndpointIdentificationMode.STRICT;
        if (!keepCurrent) {
            this.endpointIdentificationAlgorithm = requestedAlgorithm;
        }
        String[] appProtocols = params.getApplicationProtocols();
        if (appProtocols != null) {
            // Плохое имя отвергаем сразу, а не из beginHandshake, далеко от места ошибки.
            // Пустой массив снимает ранее заданные протоколы.
            if (appProtocols.length > 0) {
                TlsUtils.validateAlpnProtocols(Arrays.asList(appProtocols));
            }
            this.applicationProtocols = appProtocols.clone();
        }
        List<SNIServerName> serverNames = params.getServerNames();
        if (serverNames != null) {
            this.sniOverride = sniFromServerNames(serverNames);
        }
        // SSLParameters.statusResponses (JDK 13+ стандартный JSSE-путь OCSP стэпплинга)
        // НЕ поддерживается. Для передачи stapled OCSP-ответа используйте
        // setOcspResponse(byte[]).
    }

    // ========================================================================
    // Enable session creation
    // ========================================================================

    @Override
    public void setEnableSessionCreation(boolean flag) {
        withLock(() -> this.enableSessionCreation = flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return withLock(() -> enableSessionCreation);
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private void checkNotClosed() throws SSLException {
        if (engineState == EngineState.CLOSED) {
            int alertCode = failureAlertCode;
            if (alertCode >= 0) {
                // соединение закрыто отказом: настоящий код, а не безликое «закрыто»
                throw AlertMapper.toException(
                        (byte) alertCode, "Connection failed with alert " + alertCode, null);
            }
            throw new SSLException("Engine is closed");
        }
    }

    /**
     * Селектор клиентского сертификата на основе KeyManager с учётом staple, заданного через
     * {@link #setOcspResponse}.
     * <p>
     * Селектор KeyManager возвращает учётные данные без staple, а движок рукопожатия заменяет
     * staple значением из учётных данных. Ответ из {@code setOcspResponse} прикладывается к
     * выбранному сертификату, только если относится к его листу (серийный номер в ответе), иначе
     * не отправляется.
     */
    private ClientCertificateSelector clientCertificateSelector() {
        ClientCertificateSelector selector =
                selectorOverrideForTest != null
                        ? selectorOverrideForTest
                        : keyManager.asClientCertificateSelector();
        return request -> {
            TlsClientCredentials selected = selector.select(request);
            byte[] staple = ocspResponse;
            if (selected != null && staple != null && selected.ocspResponse() == null) {
                // Выбор зависит от запроса сервера, и приложение заранее не знает, какой лист
                // уйдёт: чужой staple сервер отверг бы целиком (CertID не совпадёт), а без него
                // рукопожатие могло бы пройти. Поэтому прикладываем только staple этого листа.
                if (stapleBelongsTo(staple, selected.chain().get(0))) {
                    return new TlsClientCredentials(
                            selected.chain(), selected.privateKey(), staple);
                }
                log.log(
                        Level.WARNING,
                        "The OCSP response set via setOcspResponse does not belong to the"
                                + " selected client certificate, it is not sent");
            }
            return selected;
        };
    }

    /** Содержит ли OCSP-ответ статус сертификата с серийным номером этого листа. */
    private static boolean stapleBelongsTo(byte[] staple, GostCertificate leaf) {
        try {
            for (SingleOcspResponse single : GostOcspResponse.fromDer(staple).getResponses()) {
                if (Arrays.equals(single.certSerialNumber(), leaf.getSerialNumber())) {
                    return true;
                }
            }
        } catch (PkixException | RuntimeException e) {
            // неразбираемый ответ сервер отверг бы так же: считаем, что он листу не принадлежит
        }
        return false;
    }

    /**
     * Цепочка, фактически отправленная клиентом: определяется после сверки с CertificateRequest
     * (она могла быть заменена или обнулена). {@code null}, если сертификат не запрашивался или
     * Certificate пуст, как у JDK. Сбой конвертации соединение не роняет.
     */
    private X509Certificate[] sentClientCertificates() {
        List<GostCertificate> sent = handshakeEngine.getSentClientCertificateChain();
        if (sent == null || sent.isEmpty()) {
            return null;
        }
        try {
            return CertificateBridge.toJca(sent);
        } catch (CertificateException e) {
            log.log(Level.WARNING, "Cannot expose the sent client certificates in the session");
            return null;
        }
    }

    /**
     * Оборачивает SNI-селектор так, чтобы staple, заданный через {@link #setOcspResponse},
     * не терялся при выборе сертификата по SNI.
     * <p>
     * Селектор KeyManager возвращает учётные данные без staple, а engine заменяет серверный
     * staple значением из учётных данных. Staple относится к сертификату, выбранному по
     * умолчанию, поэтому подставляется только если SNI выбрал тот же leaf: чужой staple сервер
     * получил бы как отказ клиента.
     *
     * @param selector      селектор KeyManager (может быть null)
     * @param defaultChain  цепочка, выбранная по умолчанию (может быть null)
     * @return исходный селектор или обёртка, возвращающая staple для того же leaf
     */
    private SniCertificateSelector withServerStaple(
            SniCertificateSelector selector, List<GostCertificate> defaultChain) {
        if (selector == null
                || ocspResponse == null
                || defaultChain == null
                || defaultChain.isEmpty()) {
            return selector;
        }
        byte[] stapleResponse = ocspResponse;
        byte[] defaultLeaf = defaultChain.get(0).getEncoded();
        return serverName -> {
            TlsServerCredentials creds = selector.select(serverName);
            if (creds != null
                    && creds.getOcspResponse() == null
                    && Arrays.equals(
                            creds.getCertificateChain().get(0).getEncoded(), defaultLeaf)) {
                return new TlsServerCredentials(
                        creds.getCertificateChain(), creds.getPrivateKey(), stapleResponse);
            }
            return creds;
        };
    }

    /**
     * Устанавливает OCSP-ответ собственного сертификата (stapling), для обеих ролей.
     * Приложение загружает ответ заранее и передаёт в engine до {@link #beginHandshake()}.
     * <p>
     * Сервер прикладывает его к своему сертификату, если клиент запросил OCSP
     * ({@code status_request}). Клиент прикладывает его к своему сертификату только по запросу
     * сервера ({@code status_request} в CertificateRequest, см.
     * {@link ClientOcspPolicy}). Клиент выбирает сертификат по запросу сервера, поэтому ответ
     * прикладывается только если относится к выбранному листу (совпадает серийный номер); иначе
     * он не отправляется, и в журнал пишется предупреждение.
     *
     * @param response DER-кодированный OCSP-ответ, или null
     * @throws IllegalArgumentException если ответ пуст или длиннее допустимого предела
     */
    public void setOcspResponse(byte[] response) {
        TlsUtils.validateOcspResponse(response);
        engineLock.lock();
        try {
            this.ocspResponse = response;
            if (handshakeEngine != null) {
                handshakeEngine.setOcspResponse(response);
            }
        } finally {
            engineLock.unlock();
        }
    }

    /** Тестовый хелпер: подменить селектор клиентского сертификата (до начала рукопожатия). */
    void setClientCertificateSelectorForTest(ClientCertificateSelector selector) {
        this.selectorOverrideForTest = selector;
    }

    byte[] getOcspResponseForTest() {
        return ocspResponse;
    }

    /** Длина защищённой записи с данными {@code payloadLen}: заголовок, данные, inner type, тег. */
    private int protectedRecordLength(int payloadLen) {
        return TlsConstants.RECORD_HEADER_SIZE + payloadLen + 1 + ciphersuite.getTagLen();
    }

    /** Длина тела записи из её заголовка (байты 3-4), запись начинается с позиции {@code pos}. */
    private static int recordPayloadLength(ByteBuffer src, int pos) {
        return ((src.get(pos + 3) & 0xFF) << 8) | (src.get(pos + 4) & 0xFF);
    }

    static byte[] buildPlaintextRecord(byte contentType, byte[] body) {
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + body.length];
        record[0] = contentType;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (body.length >>> 8);
        record[4] = (byte) body.length;
        System.arraycopy(body, 0, record, TlsConstants.RECORD_HEADER_SIZE, body.length);
        return record;
    }

    @Override
    public String toString() {
        return "GostSSLEngine[" + (clientMode ? "CLIENT" : "SERVER") + ", " + engineState + "]";
    }
}
