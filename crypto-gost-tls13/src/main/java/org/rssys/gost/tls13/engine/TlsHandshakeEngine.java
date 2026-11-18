package org.rssys.gost.tls13.engine;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.stream.Collectors;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.cert.TlsCertUtils;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import org.rssys.gost.tls13.config.ClientCertificateRequest;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientCredentials;
import org.rssys.gost.tls13.config.TlsServerCredentials;
import org.rssys.gost.tls13.crypto.TlsKeyExporter;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;
import org.rssys.gost.tls13.message.ServerNameCheck;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.SafeText;

/**
 * Пошаговый state machine для handshake TLS 1.3.
 * <p>
 * Отвязан от I/O: принимает handshake-фреймы (уже дешифрованные, если требуется),
 * возвращает handshake-фреймы для отправки и сигналы о смене ключей.
 * <p>
 * Используется:
 * <ul>
 *   <li>{@link TlsSession} — как тонкая обёртка с I/O (читает запись -> engine.receive ->
 *       poll -> отправляет)</li>
 *   <li>Будущий JSSE-модуль (GostSSLEngine) — для управления handshake
 *       через wrap/unwrap</li>
 * </ul>
 * <p>
 * Состояния перечислены в {@link State}. Переходы:
 * <pre>
 *   CLIENT:
 *     CLIENT_START -> (send ClientHello) -> CLIENT_WAIT_SERVER_HELLO
 *       -> receive HRR (SH с HRR random) -> handleHelloRetryRequest
 *         -> (send CH2) -> stay CLIENT_WAIT_SERVER_HELLO
 *       -> receive SH -> CLIENT_WAIT_ENCRYPTED_EXTENSIONS
 *       -> receive EE -> CLIENT_WAIT_CERTIFICATE_OR_CR
 *       -> receive CR -> CLIENT_WAIT_CERTIFICATE
 *       -> receive Certificate -> CLIENT_WAIT_CERTIFICATE_VERIFY
 *       -> receive CV -> CLIENT_WAIT_FINISHED
 *       -> receive Finished -> CLIENT_SEND_FINISHED
 *       -> poll() -> POST_HANDSHAKE
 *
 *   SERVER:
 *     SERVER_WAIT_CLIENT_HELLO -> receive CH1 -> [HRR нужен?]
 *       -> send HRR -> stay SERVER_WAIT_CLIENT_HELLO (ждать CH2)
 *       -> receive CH2 -> [ECDHE, key schedule] -> SERVER_SEND_FLIGHT
 *         -> poll() -> (SH, EE, CR?, Cert, CV, Finished) ->
 *         SERVER_WAIT_CLIENT_FINISHED | SERVER_WAIT_CLIENT_CERTIFICATE
 *       -> receive Cert -> SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY
 *       -> receive CV -> SERVER_WAIT_CLIENT_FINISHED
 *       -> receive Finished -> POST_HANDSHAKE
 * </pre>
 * <p>
 * Не thread-safe. Каждый экземпляр — для одного handshake.
 */
public final class TlsHandshakeEngine {

    // ========================================================================
    // Роль и состояния
    // ========================================================================

    public enum Role {
        CLIENT,
        SERVER
    }

    /**
     * Результат post-handshake сообщения.
     * Заменяет схему "byte[] -> null=KU, non-null=NST",
     * которая была неочевидна для вызывающего кода.
     */
    public static final class PostHandshakeResult {
        public enum Type {
            KEY_UPDATE_HANDLED,
            NEW_SESSION_TICKET
        }

        public final Type type;

        /** Разобранный NewSessionTicket (null если тип не NEW_SESSION_TICKET) */
        public final TlsMessageParser.ParsedNewSessionTicket ticket;

        private static final PostHandshakeResult KEY_UPDATE_HANDLED_INSTANCE =
                new PostHandshakeResult(Type.KEY_UPDATE_HANDLED, null);

        private PostHandshakeResult(Type type, TlsMessageParser.ParsedNewSessionTicket ticket) {
            this.type = type;
            this.ticket = ticket;
        }

        static PostHandshakeResult keyUpdateHandled() {
            return KEY_UPDATE_HANDLED_INSTANCE;
        }

        static PostHandshakeResult newSessionTicket(
                TlsMessageParser.ParsedNewSessionTicket ticket) {
            return new PostHandshakeResult(Type.NEW_SESSION_TICKET, ticket);
        }
    }

    /**
     * Текущее состояние handshake.
     */
    public enum State {
        CLIENT_START,
        CLIENT_WAIT_SERVER_HELLO,
        CLIENT_WAIT_ENCRYPTED_EXTENSIONS,
        CLIENT_WAIT_CERTIFICATE_OR_CR,
        CLIENT_WAIT_CERTIFICATE,
        CLIENT_WAIT_CERTIFICATE_VERIFY,
        CLIENT_WAIT_FINISHED,
        CLIENT_SEND_FINISHED,

        SERVER_WAIT_CLIENT_HELLO,
        SERVER_SEND_FLIGHT,
        SERVER_WAIT_CLIENT_CERTIFICATE,
        SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY,
        SERVER_WAIT_CLIENT_FINISHED,

        /** Финальное состояние после handshake.
         *  Engine остаётся жив:
         *  ctx уничтожен (транскрипт не нужен), но app traffic secrets
         *  сохранены для KeyUpdate. receive() принимает только
         *  post-handshake сообщения (KeyUpdate, NewSessionTicket). */
        POST_HANDSHAKE,
        ERROR
    }

    // ========================================================================
    // Поля
    // ========================================================================

    private final Role role;
    private State state;

    /** Стадия, на которой приём сообщения закончился отказом; {@code null}, пока отказа не было. */
    private State failedStage;

    private State pendingNextState; // для SERVER_SEND_FLIGHT -> следующее состояние ожидания
    private TlsCiphersuite ciphersuite;
    private final int hashLen;
    private TlsMessageBuilder messageBuilder;
    private final ECParameters ecParams;
    private final int selectedNamedGroup;
    private final int selectedSigScheme;
    private byte[] ocspResponse;
    private final boolean requestClientAuth;

    /** true = wantClientAuth (пустой сертификат не фатален, только когда requestClientAuth=true) */
    private final boolean optionalClientAuth;

    // Упорядоченный выходной поток: сообщения и смены ключа записи на своих местах
    private final ArrayDeque<HandshakeOutput> outgoingQueue = new ArrayDeque<>();

    /** Клиентский Finished, добавленный в очередь, но ещё НЕ в transcript.
     *  Добавляется в transcript в finishHandshake() ПОСЛЕ выработки app traffic keys,
     *  чтобы transcript для SATS/CATS соответствовал RFC 8446 §4.4.1
     *  (ClientHello...server Finished, БЕЗ client Finished). */
    private byte[] pendingClientFinished;

    private HandshakeContext ctx;

    // Ключи
    private TlsTrafficKeys handshakeServerKeys;
    private TlsTrafficKeys handshakeClientKeys;
    // Ключи чтения меняются при приёме сообщения: вызывающий применяет их сразу и проверяет
    // границу записи. Ключи записи в поля не попадают: их смена стоит в выходном потоке
    // (HandshakeOutput.WriteKeyChange) сразу за сообщением, после которого она действует.
    private TlsTrafficKeys readKeys;
    private boolean readKeysChanged;

    /** Сервер: ключи чтения приложения, вступающие после проверки Finished клиента. */
    private TlsTrafficKeys readKeysAfterPeerFinished;

    // Handshake traffic secrets (RFC 8446 §7.1: вычисляется из hash(CH+SH), необходимо для проверки
    // Finished)
    private byte[] serverHandshakeTrafficSecret;
    private byte[] clientHandshakeTrafficSecret;

    // Сертификат пира (для валидации вызывающим кодом)
    private List<GostCertificate> receivedCertificates;
    private boolean needsCertValidation;

    private byte[] resumptionMasterSecret;

    /** Секрет экспорта ключевого материала (RFC 8446 §7.5); null до завершения рукопожатия. */
    private byte[] exporterMasterSecret;

    // Application traffic secrets для KeyUpdate (RFC 8446 §7.2)
    private byte[] serverAppTrafficSecret;
    private byte[] clientAppTrafficSecret;
    private String errorMessage;

    /** Alert-код при ошибке (дефолт ALERT_HANDSHAKE_FAILURE для обратной совместимости) */
    private byte errorAlertCode = TlsConstants.ALERT_HANDSHAKE_FAILURE;

    // Клиентские PSK-параметры (передаются через start)
    private byte[] pskKey;

    private byte[] pskIdentity;

    private boolean pskAccepted;

    // Клиент предлагает ровно одну PSK identity
    private static final int OFFERED_PSK_IDENTITIES = 1;

    // Решение сервера по PSK в первом ClientHello, переносится во второй после HRR (RFC 8446
    // §4.1.2):
    // снимок всех identity CH1 одним массивом (null, если pre_shared_key не было или HRR не
    // отправлен)
    // и выбранная принятая (null, если PSK не принят). Выбор в CH2 не пересматривается и хранилище
    // не
    // опрашивается
    private byte[] ch1PskIdentitiesSnapshot;
    private byte[] ch1AcceptedPskIdentity;
    // Номер принятой identity в списке клиента для selected_identity в ServerHello
    private int acceptedPskIndex = TlsMessageBuilder.NO_SELECTED_PSK;

    private boolean pskOffered;
    // PSK был задан, но в ClientHello не поместился: рукопожатие идёт без него, а владелец тикета
    // обязан его убрать из кэша, иначе та же осечка повторялась бы на каждом соединении
    private boolean pskOfferWithdrawn;

    private long obfuscatedTicketAge;

    private PskStore serverPskStore;

    // mTLS — сервер запросил клиентский сертификат, и клиент его отправит
    private boolean clientAuthRequested;

    // Сервер: просить staple клиентского сертификата (status_request в CertificateRequest).
    private boolean requestClientOcsp;

    // Клиент: сервер запросил staple (status_request в CertificateRequest).
    private boolean clientOcspRequested;

    // Транскрипт для app traffic keys (RFC 8446 §7.1 Table 2):
    // ClientHello...server Finished включительно, БЕЗ client Cert/CV/Finished.
    // Захватывается после ctx.addToTranscript(serverFinished-frame),
    // до добавления любых клиентских сообщений.
    private byte[] appTranscriptHash;

    // SNI (Server Name Indication)
    private String serverHostname;
    private String requestedServerName;

    // ALPN (RFC 7301)
    private List<String> clientAlpnProtocols;

    /**
     * Типы расширений последнего отправленного ClientHello (второго, если был HRR).
     * EncryptedExtensions отвечает именно на него; берутся из итоговых байт, а не из конфигурации.
     */
    private Set<Integer> sentExtensionTypes = Set.of();

    private List<String> serverAlpnProtocols;
    private String selectedAlpnProtocol;

    // max_fragment_length (RFC 6066 §4): 0 = default (16384)
    private int maxFragmentLength;
    // Запрос клиента (1..4), 0 если не запрашивал — для проверки ответа сервера
    private int clientMaxFragLenRequest;
    private java.util.function.Function<java.util.List<String>, String> alpnSelector;

    // SNI certificate selection (RFC 6066 §3, RFC 8446 §4.4.2)
    private final SniCertificateSelector sniSelector;
    // OID-фильтры для CertificateRequest (сервер, RFC 8446 §4.2.5)
    private List<OIDFilter> oidFilters;
    // Селектор сертификата клиента по OID-фильтрам (клиент)
    private ClientCertificateSelector clientCertificateSelector;

    /**
     * Обход openssl-gost-provider v3.6.0: сервер всегда шлёт базовую
     * схему (0x0709 для 256-bit, 0x070D для 512-bit) независимо от
     * реальной кривой сертификата.
     * По умолчанию false (строгая проверка по RFC 9367 §5/§6.3.4).
     */
    private boolean interopAcceptGostBaseSigScheme;

    // Post-handshake (KeyUpdate): своё обновление стоит в потоке как [KeyUpdate][смена ключа] и
    // ждёт отдачи из poll(). Второе обновление до отдачи первого вывелось бы из того же секрета
    // записи, и пир сдвинул бы ключ чтения дважды, а мы — один раз
    private boolean keyUpdateQueued;

    // Скользящее окно чужих KeyUpdate - защита от потока сообщений (RFC 8446 §4.6.3 нормы не
    // задаёт, но каждый KeyUpdate требует HKDF и инициализации MGM). Окно, а не абсолютный предел
    // на соединение: приложение с периодической сменой ключа на долгом соединении естественно
    // порождает много обновлений, и общий счётчик убил бы его на фиксированном по номеру
    // обновлении.
    // Собственные обновления не считаются: их выбирает доверенное приложение.
    private boolean peerKeyUpdateWindowOpen;
    private long peerKeyUpdateWindowStartNanos;
    private int peerKeyUpdatesInWindow;
    private LongSupplier nanoClock = System::nanoTime;

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.tls13.engine.TlsHandshakeEngine");

    /** Счётчик меток соединений процесса: метка нужна только журналу. */
    private static final AtomicLong CONNECTION_IDS = new AtomicLong();

    /**
     * Диагностическая метка соединения: {@code conn#N}. Не session ID, в протокол не попадает.
     * Объявлена до {@link #log}: инициализаторы выполняются в порядке объявления.
     */
    private final String connectionLabel = "conn#" + CONNECTION_IDS.incrementAndGet();

    /** Логгер соединения: те же имя и уровень, плюс префикс {@code [conn#N]}. */
    private final GostLogger log = LOG.withContext(connectionLabel);

    private static final byte[] KU_NOT_REQUESTED =
            new byte[] {TlsConstants.KEY_UPDATE_NOT_REQUESTED};
    private static final byte[] KU_REQUESTED = new byte[] {TlsConstants.KEY_UPDATE_REQUESTED};

    // HRR (HelloRetryRequest): true после получения HRR (клиент, защита от цикла)
    private boolean hrrReceived;
    // HRR: true после отправки HRR (сервер, защита от цикла)
    private boolean hrrSent;
    // Группа, запрошенная в HRR — для проверки CH2
    private int hrrRequestedGroup;
    // Сервер должен отправить dummy change_cipher_spec после первого handshake-сообщения
    // (RFC 8446 §D.4: клиент прислал непустой legacy_session_id). AtomicBoolean: флаг взводится
    // при unwrap (под inboundLock GostSSLEngine), а читается и сбрасывается при wrap (под
    // outboundLock); getAndSet(false) делает «взять» атомарным и не зависит от внешних блокировок
    // вызывающего.
    private final AtomicBoolean serverCcsPending = new AtomicBoolean();

    // true если мы уже инициировали KeyUpdate (для crossed-in-flight:
    // RFC 8446 §4.6.3: "If a party has already sent a KeyUpdate,
    // it does not need to send another when it receives a KeyUpdate from the other peer")
    private boolean initiatedKeyUpdate;

    // ========================================================================
    // Конструктор
    // ========================================================================

    /**
     * @param role               CLIENT или SERVER
     * @param ciphersuite        cipher suite (может измениться после ServerHello)
     * @param messageBuilder     сборщик handshake-сообщений
     * @param ecParams           параметры эллиптической кривой
     * @param selectedNamedGroup идентификатор именованной группы
     * @param selectedSigScheme  выбранная схема подписи
     * @param hashLen            длина хеша (32 для Streebog-256)
     * @param ocspResponse       OCSP-ответ для степплинга (сервер, null = без OCSP)
     * @param requestClientAuth  запрашивать сертификат клиента (сервер, mTLS)
     * @param sniSelector        селектор сертификата по SNI (сервер, может быть null)
     * @throws IllegalArgumentException если {@code hashLen} не равен длине хеша набора шифров
     */
    public TlsHandshakeEngine(
            Role role,
            TlsCiphersuite ciphersuite,
            TlsMessageBuilder messageBuilder,
            ECParameters ecParams,
            int selectedNamedGroup,
            int selectedSigScheme,
            int hashLen,
            byte[] ocspResponse,
            boolean requestClientAuth,
            SniCertificateSelector sniSelector) {
        this(
                role,
                ciphersuite,
                messageBuilder,
                ecParams,
                selectedNamedGroup,
                selectedSigScheme,
                hashLen,
                ocspResponse,
                requestClientAuth,
                sniSelector,
                false);
    }

    /**
     * @param role               CLIENT или SERVER
     * @param ciphersuite        cipher suite (может измениться после ServerHello)
     * @param messageBuilder     сборщик handshake-сообщений
     * @param ecParams           параметры эллиптической кривой
     * @param selectedNamedGroup идентификатор именованной группы
     * @param selectedSigScheme  выбранная схема подписи
     * @param hashLen            длина хеша (32 для Streebog-256)
     * @param ocspResponse       OCSP-ответ для степплинга (сервер, null = без OCSP)
     * @param requestClientAuth  запрашивать сертификат клиента (сервер, mTLS)
     * @param sniSelector        селектор сертификата по SNI (сервер, может быть null)
     * @param optionalClientAuth true = пустой сертификат не фатален (wantClientAuth).
     *                           Читается только при requestClientAuth=true.
     * @throws IllegalArgumentException если {@code hashLen} не равен длине хеша набора шифров
     */
    public TlsHandshakeEngine(
            Role role,
            TlsCiphersuite ciphersuite,
            TlsMessageBuilder messageBuilder,
            ECParameters ecParams,
            int selectedNamedGroup,
            int selectedSigScheme,
            int hashLen,
            byte[] ocspResponse,
            boolean requestClientAuth,
            SniCertificateSelector sniSelector,
            boolean optionalClientAuth) {
        // Длина хеша задаёт дайджест транскрипта и длины секретов, а ключи KeyUpdate выводятся
        // по длине из набора: расхождение дало бы неверные ключи без единой ошибки
        if (hashLen != ciphersuite.getHashLen()) {
            throw new IllegalArgumentException(
                    "hashLen " + hashLen + " does not match the ciphersuite hash length");
        }
        this.role = role;
        this.ciphersuite = ciphersuite;
        this.messageBuilder = messageBuilder;
        this.ecParams = ecParams;
        this.selectedNamedGroup = selectedNamedGroup;
        this.selectedSigScheme = selectedSigScheme;
        this.hashLen = hashLen;
        this.ocspResponse = ocspResponse;
        this.requestClientAuth = requestClientAuth;
        this.optionalClientAuth = optionalClientAuth;
        this.sniSelector = sniSelector;

        this.ctx = new HandshakeContext(hashLen);
        this.state = (role == Role.CLIENT) ? State.CLIENT_START : State.SERVER_WAIT_CLIENT_HELLO;
    }

    /**
     * Устанавливает OCSP-ответ для степплинга (сервер).
     * Может быть вызван после создания engine, до вызова start().
     *
     * @param response OCSP-ответ DER, или null
     */
    public void setOcspResponse(byte[] response) {
        this.ocspResponse = response;
    }

    /**
     * Включает запрос OCSP-staple клиентского сертификата (сервер, RFC 8446 §4.4.2.1):
     * в CertificateRequest добавляется пустое {@code status_request}, а присланный клиентом
     * staple принимается. Действует только при {@code requestClientAuth}. Политика
     * обязательности staple определяется вызывающим кодом при проверке сертификата,
     * engine отвечает только за формат на проводе.
     * <p>
     * Вызывается до начала handshake.
     *
     * @param request true - запрашивать staple
     */
    public void setRequestClientOcsp(boolean request) {
        this.requestClientOcsp = request;
    }

    /**
     * Устанавливает OID-фильтры для CertificateRequest (сервер).
     * @param filters список OID-фильтров, null = extension не отправляется
     */
    public void setOidFilters(List<OIDFilter> filters) {
        this.oidFilters = filters;
    }

    /**
     * Устанавливает селектор сертификата клиента (клиент).
     * Вызывается при получении CertificateRequest с oid_filters или
     * certificate_authorities для выбора подходящего сертификата.
     * @param selector селектор, null = используется дефолтный сертификат
     */
    public void setClientCertificateSelector(ClientCertificateSelector selector) {
        this.clientCertificateSelector = selector;
    }

    /**
     * Включает обход openssl-gost-provider: принимать базовые схемы
     * (0x0709 для 256-bit, 0x070D для 512-bit) для любых сертификатов
     * того же размера ключа. По умолчанию выключено.
     *
     * @see TlsCertUtils#hasSignatureScheme(PublicKeyParameters, int, boolean)
     */
    public void setInteropAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
    }

    // ========================================================================
    // Публичный API
    // ========================================================================

    /**
     * Запускает handshake.
     * <p>
     * Для клиента: генерирует ECDHE-ключи, строит и возвращает ClientHello.
     * Для сервера: возвращает null (ожидает ClientHello от клиента).
     *
     * @return handshake-фрейм (type + length + body) для отправки, или null
     * @throws TlsException при ошибке построения сообщения
     */
    public byte[] start() throws TlsException {
        if (state == State.CLIENT_START) {
            return startClient();
        }
        return null;
    }

    /**
     * Передаёт входящий handshake-фрейм (type + length + body, уже дешифрованный).
     * <p>
     * Фрейм парсится, валидируется, транскрипт обновляется, и при необходимости
     * во внутреннюю очередь помещаются исходящие фреймы. Вызывающий код
     * извлекает их через {@link #poll()}.
     *
     * @param handshakeFrame полный handshake-фрейм (type + length + body)
     * @throws TlsException при нарушении протокола
     * @throws IOException   при ошибке подписи/верификации
     *                       (пробрасывается из TlsMessageBuilder)
     */
    public void receive(byte[] handshakeFrame) throws TlsException, java.io.IOException {
        final State stageBefore = state;
        try {
            switch (state) {
                case CLIENT_WAIT_SERVER_HELLO:
                    receiveServerHello(handshakeFrame);
                    break;
                case CLIENT_WAIT_ENCRYPTED_EXTENSIONS:
                    receiveEncryptedExtensions(handshakeFrame);
                    break;
                case CLIENT_WAIT_CERTIFICATE_OR_CR:
                    receiveCertificateOrCr(handshakeFrame);
                    break;
                case CLIENT_WAIT_CERTIFICATE:
                    receiveCertificate(handshakeFrame);
                    break;
                case CLIENT_WAIT_CERTIFICATE_VERIFY:
                    receiveCertificateVerify(handshakeFrame, true);
                    break;
                case CLIENT_WAIT_FINISHED:
                    receiveFinished(handshakeFrame);
                    break;
                case SERVER_WAIT_CLIENT_HELLO:
                    receiveClientHello(handshakeFrame);
                    break;
                case SERVER_WAIT_CLIENT_CERTIFICATE:
                    receiveClientCertificate(handshakeFrame);
                    break;
                case SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY:
                    receiveCertificateVerify(handshakeFrame, false);
                    break;
                case SERVER_WAIT_CLIENT_FINISHED:
                    receiveClientFinished(handshakeFrame);
                    break;
                case POST_HANDSHAKE:
                    receivePostHandshake(handshakeFrame);
                    break;
                default:
                    throw new TlsException(
                            TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                            "Unexpected receive in state " + state);
            }
            if (state != stageBefore) {
                log.log(Level.DEBUG, "Handshake stage {0} -> {1}", stageBefore, state);
            }
        } catch (IOException e) {
            failedStage = stageBefore;
            state = State.ERROR;
            errorMessage = e.getMessage();
            throw e;
        } catch (RuntimeException e) {
            failedStage = stageBefore;
            state = State.ERROR;
            errorMessage = "Unexpected error: " + e.getMessage();
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "Unexpected error processing handshake message",
                    e);
        }
    }

    /**
     * Извлекает следующий элемент выходного потока: сообщение рукопожатия или смену ключа записи.
     * Получатель обязан обрабатывать элементы строго по порядку: сообщение — отправить текущим
     * ключом записи (пока его нет — открытым), смену ключа — применить к следующим записям.
     *
     * @return элемент потока или null, если поток пуст
     */
    public HandshakeOutput poll() {
        HandshakeOutput next = outgoingQueue.pollFirst();
        if (next != null) {
            // Смена ключа после KeyUpdate отдана: своё обновление больше не ждёт отправки
            // (RFC 8446 §4.6.3). Отдача, а не отправка: получатель отправляет поток по порядку,
            // поэтому KeyUpdate уйдёт раньше всего, что встанет за ним
            if (next instanceof HandshakeOutput.WriteKeyChange && state == State.POST_HANDSHAKE) {
                keyUpdateQueued = false;
                initiatedKeyUpdate = false;
            }
            return next;
        }
        // Переходы при отдаче потока тоже пишутся: без них в журнале нет ни «сервер отправил
        // свой полёт и ждёт клиента», ни завершения рукопожатия у клиента
        final State stageBefore = state;
        // Сервер: после опустошения очереди переходим в состояние ожидания
        if (state == State.SERVER_SEND_FLIGHT) {
            state = pendingNextState;
        }
        // Клиент: после отправки Finished завершаем handshake (переход в POST_HANDSHAKE)
        if (state == State.CLIENT_SEND_FINISHED) {
            finishHandshake();
        }
        if (state != stageBefore) {
            log.log(Level.DEBUG, "Handshake stage {0} -> {1}", stageBefore, state);
        }
        return null;
    }

    /**
     * Показывает, что сервер должен отправить dummy change_cipher_spec сразу после первого
     * handshake-сообщения (RFC 8446 §D.4), но ещё не отправил его.
     *
     * <p>Не меняет состояние: транспорт использует метод, чтобы проверить место в выходном буфере
     * до записи.</p>
     *
     * @return true, если клиент прислал непустой {@code legacy_session_id} и CCS не отправлен
     */
    public boolean isServerCompatCcsPending() {
        return serverCcsPending.get();
    }

    /**
     * Однократно подтверждает отправку dummy change_cipher_spec (RFC 8446 §D.4).
     *
     * <p>Вызывается транспортом сразу после записи в сеть первого handshake-сообщения сервера
     * (HRR или ServerHello). Повторные вызовы возвращают false, поэтому после HRR CCS не
     * отправляется второй раз вместе с ServerHello.</p>
     *
     * @return true, если CCS нужно отправить сейчас
     */
    public boolean takeServerCompatCcs() {
        return serverCcsPending.getAndSet(false);
    }

    /** @return текущее состояние handshake */
    public State getState() {
        return state;
    }

    /**
     * Стадия, на которой рукопожатие закончилось отказом: состояние движка в момент приёма
     * сообщения, не принятого из-за ошибки. Нужна журналу, потому что после отказа {@link
     * #getState()} всегда {@link State#ERROR}.
     *
     * @return стадия отказа или {@code null}, если отказа приёма сообщения не было
     */
    public State getFailedStage() {
        return failedStage;
    }

    /**
     * Диагностическая метка соединения для журнала.
     *
     * <p>Монотонный номер, а не идентификатор сессии: в протокол не попадает, ключей и
     * персональных данных не несёт. Владелец (TlsSession, GostSSLEngine) ставит её префиксом
     * к своим записям.
     *
     * @return метка вида {@code conn#17}
     */
    public String getConnectionLabel() {
        return connectionLabel;
    }

    /** @return true если handshake успешно завершён (включая POST_HANDSHAKE) */
    public boolean isDone() {
        return state == State.POST_HANDSHAKE;
    }

    /** @return true если handshake в состоянии ошибки */
    public boolean isError() {
        return state == State.ERROR;
    }

    /** @return сообщение об ошибке или null */
    public String getErrorMessage() {
        return errorMessage;
    }

    // ========================================================================
    // Методы получения статуса и ключей
    // ========================================================================

    /**
     * @return ключи для чтения (дешифрация) или null, если ещё не доступны
     */
    public TlsTrafficKeys getReadKeys() {
        return readKeys;
    }

    /**
     * @return true если ключи чтения изменились с момента последнего acknowledge
     */
    public boolean hasReadKeysChanged() {
        return readKeysChanged;
    }

    /** Сбрасывает флаг смены ключей чтения (вызывается после их применения). */
    public void acknowledgeReadKeyChange() {
        readKeysChanged = false;
    }

    /**
     * Ставит новые ключи чтения. Ячейка одна: прежняя смена обязана быть применена вызывающим,
     * иначе её ключи молча пропали бы и записи пира расшифровывались бы не тем ключом.
     */
    private void changeReadKeys(TlsTrafficKeys keys) {
        if (readKeysChanged) {
            throw new IllegalStateException("Previous read key change not acknowledged");
        }
        readKeys = keys;
        readKeysChanged = true;
    }

    private void queueMessage(byte[] frame) {
        outgoingQueue.addLast(new HandshakeOutput.Message(frame));
    }

    /** Ставит в поток смену ключа записи сразу за последним поставленным сообщением. */
    private void queueWriteKeyChange(TlsTrafficKeys keys) {
        // Набор шифров к этому моменту согласован: ключи выведены по нему же
        outgoingQueue.addLast(new HandshakeOutput.WriteKeyChange(keys, ciphersuite));
    }

    /**
     * Вырабатывает мастер-секрет, секрет экспорта и секреты трафика приложения по транскрипту
     * ClientHello...Finished сервера (RFC 8446 §7.1, таблица 2). Секрет рукопожатия после этого не
     * нужен: секреты трафика рукопожатия уже выработаны, а schedule затирает его здесь же.
     *
     * @return ключи приложения: [0] сервера, [1] клиента
     */
    private TlsTrafficKeys[] deriveApplicationKeys() throws TlsException {
        // Хэш снимается сразу после Finished сервера; хэш, взятый позже, мог бы уже включать
        // сообщения клиента и молча дал бы неверные секреты, поэтому его отсутствие — ошибка кода.
        // TlsException, а не IllegalStateException: это обычный фатальный путь рукопожатия
        if (appTranscriptHash == null) {
            throw new TlsException(
                    TlsConstants.ALERT_INTERNAL_ERROR, "Application transcript hash not captured");
        }
        ctx.getKeySchedule().deriveMasterSecret();
        deriveExporterMasterSecret(appTranscriptHash);
        this.serverAppTrafficSecret =
                ctx.getKeySchedule().getServerApplicationTrafficSecret(appTranscriptHash);
        this.clientAppTrafficSecret =
                ctx.getKeySchedule().getClientApplicationTrafficSecret(appTranscriptHash);
        TlsUtils.wipeArray(appTranscriptHash);
        appTranscriptHash = null;
        return new TlsTrafficKeys[] {
            ctx.getKeySchedule().deriveTrafficKeys(serverAppTrafficSecret),
            ctx.getKeySchedule().deriveTrafficKeys(clientAppTrafficSecret)
        };
    }

    // ========================================================================
    // Post-handshake (KeyUpdate)
    // ========================================================================

    /**
     * @return текущая роль (CLIENT/SERVER) — нужно для определения mapping
     *         readerSecret/writerSecret при KeyUpdate
     */
    public boolean isServer() {
        return role == Role.SERVER;
    }

    /**
     * Инициирует KeyUpdate (RFC 8446 §4.6.3): ставит в поток сообщение KeyUpdate и сразу за ним
     * смену ключа записи. Сообщение уходит прежним ключом, следующие записи — новым.
     * <p>
     * Секрет записи сдвигается сразу (RFC 8446 §7.2): следующий KeyUpdate выводится уже из нового.
     * Если своё обновление ещё стоит в потоке, новое не ставится, а объединяется с ним: запрос
     * {@code update_requested} повышает стоящее сообщение и не теряется. Второе обновление вывелось
     * бы из того же секрета, и пир сдвинул бы ключ чтения дважды, а мы — один раз.
     *
     * @param request true = update_requested (пир обязан ответить своим KeyUpdate)
     * @throws TlsException если handshake не завершён
     */
    public void initiateKeyUpdate(boolean request) throws TlsException {
        if (state != State.POST_HANDSHAKE) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Cannot initiate KeyUpdate before handshake completion");
        }
        initiatedKeyUpdate = true;
        if (keyUpdateQueued) {
            if (request) {
                requestUpdateInQueuedKeyUpdate(outgoingQueue);
            }
            return;
        }
        queueKeyUpdate(request ? KU_REQUESTED : KU_NOT_REQUESTED);
    }

    /**
     * Повышает стоящее в очереди сообщение KeyUpdate до {@code update_requested}. Тело KeyUpdate —
     * один байт сразу за заголовком (RFC 8446 §4.6.3).
     *
     * @param queue очередь отправки (движка или получателя потока)
     */
    public static void requestUpdateInQueuedKeyUpdate(Iterable<HandshakeOutput> queue) {
        for (HandshakeOutput item : queue) {
            if (item instanceof HandshakeOutput.Message message
                    && message.frame()[0] == TlsConstants.HT_KEY_UPDATE) {
                message.frame()[TlsConstants.HANDSHAKE_HEADER_SIZE] =
                        TlsConstants.KEY_UPDATE_REQUESTED;
            }
        }
    }

    /**
     * @return {@code true}, пока своё обновление ключа (KeyUpdate и смена ключа за ним) стоит в
     *     потоке и не отдано из {@link #poll()}. Получатель, который забирает поток только при
     *     отправке, по этому признаку не инициирует второе обновление.
     */
    public boolean isKeyUpdateQueued() {
        return keyUpdateQueued;
    }

    /**
     * Ставит в поток KeyUpdate и смену ключа записи на следующий секрет (RFC 8446 §7.2). Общая
     * часть собственного обновления и ответа на запрос пира.
     * <p>
     * Предусловие: прежнее обновление отдано ({@code keyUpdateQueued == false}).
     */
    private void queueKeyUpdate(byte[] kuBody) {
        queueMessage(new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode());
        byte[] writerSecret = role == Role.SERVER ? serverAppTrafficSecret : clientAppTrafficSecret;
        byte[] nextWriterSecret = TlsKeySchedule.nextTrafficSecret(writerSecret, hashLen);
        TlsUtils.wipeArray(writerSecret);
        if (role == Role.SERVER) {
            serverAppTrafficSecret = nextWriterSecret;
        } else {
            clientAppTrafficSecret = nextWriterSecret;
        }
        TlsTrafficKeys nextWriteKeys =
                TlsKeySchedule.deriveTrafficKeys(nextWriterSecret, ciphersuite);
        queueWriteKeyChange(nextWriteKeys);
        nextWriteKeys.destroy();
        keyUpdateQueued = true;
        log.log(Level.DEBUG, "KeyUpdate queued: update_requested={0}", kuBody[0] != 0);
    }

    /**
     * Ограничивает частоту KeyUpdate пира скользящим окном. При превышении fatal alert
     * {@code unexpected_message}: поток обновлений это злоупотребление, а не расширяемость
     * протокола (fail-closed). Собственные обновления окно не учитывает.
     */
    private void enforcePeerKeyUpdateRate() throws TlsException {
        long now = nanoClock.getAsLong();
        if (!peerKeyUpdateWindowOpen
                || now - peerKeyUpdateWindowStartNanos
                        > TlsConstants.KEY_UPDATE_RATE_WINDOW_NANOS) {
            peerKeyUpdateWindowOpen = true;
            peerKeyUpdateWindowStartNanos = now;
            peerKeyUpdatesInWindow = 0;
        }
        if (++peerKeyUpdatesInWindow > TlsConstants.MAX_PEER_KEY_UPDATES_PER_WINDOW) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Peer KeyUpdate rate limit exceeded: "
                            + peerKeyUpdatesInWindow
                            + " within window");
        }
    }

    /** Для тестов: подменяет источник времени окна, чтобы не ждать реальную секунду. */
    void setNanoClockForTest(LongSupplier clock) {
        this.nanoClock = clock;
    }

    /**
     * Принимает post-handshake сообщение (KeyUpdate или NewSessionTicket)
     * после завершения handshake (state == POST_HANDSHAKE).
     * <p>
     * Не использует transcript (ctx уже уничтожен) — KeyUpdate и NST
     * не добавляются в транскрипт после handshake (RFC 8446 §4.4.1).
     * <p>
     * Частота KeyUpdate пира ограничена скользящим окном
     * ({@link TlsConstants#MAX_PEER_KEY_UPDATES_PER_WINDOW} за
     * {@link TlsConstants#KEY_UPDATE_RATE_WINDOW_NANOS}); у прямых пользователей движка (не через
     * {@code TlsSession.read()}) это единственная защита от потока KeyUpdate.
     * <p>
     * NewSessionTicket принимается только в роли CLIENT: по RFC 8446 §4.6.1
     * его отправляет исключительно сервер. NST от клиента на сервере — это
     * unexpected_message, иначе клиент смог бы инжектить тикеты в серверный
     * PskStore в обход политики выдачи.
     *
     * @param handshakeFrame полный handshake-фрейм (type + length + body)
     * @return результат обработки: KEY_UPDATE_HANDLED или NEW_SESSION_TICKET
     * @throws TlsException при нарушении протокола, в том числе при превышении окна KeyUpdate
     * @throws IOException   при ошибке подписи/верификации
     */
    public PostHandshakeResult receivePostHandshake(byte[] handshakeFrame)
            throws TlsException, java.io.IOException {
        TlsHandshakeMessage hm = TlsHandshakeMessage.decode(handshakeFrame);
        if (hm.getType() == TlsConstants.HT_KEY_UPDATE) {
            handlePostHandshakeKeyUpdate(hm.getBody());
            return PostHandshakeResult.keyUpdateHandled();
        }
        if (hm.getType() == TlsConstants.HT_NEW_SESSION_TICKET) {
            if (isServer()) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "NewSessionTicket is not allowed from client");
            }
            // Разбор здесь, до того как результат попадёт к вызывающему: искажённый NST (RFC 8446
            // §4.6.1) фатален независимо от того, нужен ли тикет хранилищу, а правило одно для всех
            // слоёв (TlsSession, jsse)
            return PostHandshakeResult.newSessionTicket(
                    TlsMessageParser.parseNewSessionTicket(hm.getBody()));
        }
        throw new TlsException(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "Unexpected post-handshake message type: " + hm.getType());
    }

    /**
     * Обрабатывает KeyUpdate от пира (RFC 8446 §4.6.3).
     * <p>
     * Деривация reader/writer secrets из app traffic secrets:
     * - reader update: безусловно (пир сменил свои write-ключи)
     * - writer update: только если пир запросил (request_update=1) И мы не
     *   инициировали свой KeyUpdate (crossed-in-flight — RFC: "already sent,
     *   does not need to send another")
     * <p>
     * Ключи чтения обновляются немедленно; ответный KeyUpdate встаёт в поток вместе со сменой
     * ключа записи сразу за ним, поэтому он уходит прежним ключом.
     */
    private void handlePostHandshakeKeyUpdate(byte[] body) throws TlsException {
        if (body.length != 1) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "KeyUpdate: invalid body length " + body.length);
        }
        // RFC 8446 §4.6.3: допустимы только 0 и 1, любое другое значение - illegal_parameter.
        // Проверка до учёта частоты: некорректное сообщение не должно считаться штатным обновлением
        if (body[0] != TlsConstants.KEY_UPDATE_NOT_REQUESTED
                && body[0] != TlsConstants.KEY_UPDATE_REQUESTED) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "KeyUpdate: invalid request_update value");
        }
        enforcePeerKeyUpdateRate();

        boolean requested = body[0] == TlsConstants.KEY_UPDATE_REQUESTED;
        log.log(Level.DEBUG, "KeyUpdate received: update_requested={0}", requested);

        // RFC 8446 §7.2: направление читатель/писатель зависит от роли
        // Сервер: читает client-ключи, пишет server-ключи
        // Клиент: читает server-ключи, пишет client-ключи
        byte[] readerSecret = role == Role.SERVER ? clientAppTrafficSecret : serverAppTrafficSecret;

        // Новый reader secret и ключи (RFC 8446 §7.2); reader-ключи обновляются всегда: пир сменил
        // свои write-ключи
        byte[] newReaderSecret = TlsKeySchedule.nextTrafficSecret(readerSecret, hashLen);
        TlsTrafficKeys newReadKeys = TlsKeySchedule.deriveTrafficKeys(newReaderSecret, ciphersuite);

        // Замена старого reader secret на новый (для цепочки будущих KU)
        TlsUtils.wipeArray(readerSecret);
        if (role == Role.SERVER) {
            clientAppTrafficSecret = newReaderSecret;
        } else {
            serverAppTrafficSecret = newReaderSecret;
        }

        // Все последующие записи расшифровываются новыми ключами. Прежний объект затираем: записи
        // получателя держат свои копии ключа
        TlsTrafficKeys previousReadKeys = readKeys;
        changeReadKeys(newReadKeys);
        if (previousReadKeys != null) previousReadKeys.destroy();

        if (requested) {
            // RFC 8446 §4.6.3: "If a party has already sent a KeyUpdate,
            // it does not need to send another when it receives a KeyUpdate from the other peer."
            // Один ответ на несколько запросов: пока своё обновление стоит в потоке, оно и служит
            // ответом
            if (!initiatedKeyUpdate && !keyUpdateQueued) {
                queueKeyUpdate(KU_NOT_REQUESTED);
            }
            // Crossed-in-flight: мы уже инициировали KU, дублирующий ответ не нужен
        }
    }

    /**
     * Отдаёт копию Resumption Master Secret: оригинал остаётся в движке и затирается в
     * {@link #destroy()}, а копию вызывающий обязан затереть сам сразу после использования.
     *
     * @return Resumption Master Secret (defensive copy), или null если handshake не завершён
     */
    public byte[] getResumptionMasterSecret() {
        return resumptionMasterSecret == null ? null : resumptionMasterSecret.clone();
    }

    /**
     * Экспорт ключевого материала (RFC 8446 §7.5) по секрету этого соединения.
     * <p>
     * Доступен только после завершения рукопожатия и до {@link #destroy()}. Результат секретный:
     * вызывающий обязан затереть его после использования. Подробности аргументов см. в
     * {@link TlsKeyExporter#export}.
     *
     * @param label метка назначения
     * @param context контекст или {@code null}
     * @param length длина результата в байтах
     * @return экспортированное значение
     * @throws IllegalStateException если рукопожатие не завершено или движок уничтожен
     * @throws IllegalArgumentException если аргументы выходят за допустимые пределы
     */
    public byte[] exportKeyingMaterial(String label, byte[] context, int length) {
        byte[] secret = exporterMasterSecret;
        if (secret == null) {
            throw new IllegalStateException("Exporter master secret not available");
        }
        // Derive-Secret даёт ровно hashLen байт согласованного хэша: длина секрета и есть
        // длина хэша набора, поэтому она не может разойтись с реально использованным хэшем
        return TlsKeyExporter.export(secret, label, context, length, secret.length);
    }

    /**
     * @return true, если рукопожатие завершено и движок не уничтожен, то есть экспорт возможен
     */
    public boolean isExportAvailable() {
        return exporterMasterSecret != null;
    }

    /**
     * Выводит секрет экспорта из хэша транскрипта до server Finished. Вызывается там же, где
     * этот хэш потребляется для application traffic secrets и до его затирания: после client
     * Finished хэш другой (RFC 8446 §7.1), и значение разошлось бы с другими реализациями.
     */
    private void deriveExporterMasterSecret(byte[] appTranscript) {
        this.exporterMasterSecret = ctx.getKeySchedule().getExporterMasterSecret(appTranscript);
    }

    /**
     * Для модульных тестов — инициализирует engine без полного handshake.
     * Устанавливает состояние POST_HANDSHAKE и app traffic secrets.
     * ResumptionMasterSecret получает значение по умолчанию (нули) —
     * для тестов NewSessionTicket. Секрет экспорта тоже нулевой: экспорт на такой сессии
     * проверяет только проводку, а не корректность значения (её проверяют тесты на настоящем
     * рукопожатии).
     * Вызывается из {@code TlsSession.setAppTrafficSecrets} и
     * {@code TlsSession.createForTest}.
     */
    public void initForTesting(byte[] serverSecret, byte[] clientSecret) {
        this.serverAppTrafficSecret = serverSecret;
        this.clientAppTrafficSecret = clientSecret;
        if (resumptionMasterSecret == null) {
            this.resumptionMasterSecret = new byte[hashLen];
        }
        if (exporterMasterSecret == null) {
            this.exporterMasterSecret = new byte[hashLen];
        }
        if (state == State.CLIENT_START || state == State.SERVER_WAIT_CLIENT_HELLO) {
            this.state = State.POST_HANDSHAKE;
        }
    }

    // ========================================================================

    /**
     * @return true если вызывающий код должен проверить сертификаты пира
     */
    public boolean needsCertificateValidation() {
        return needsCertValidation;
    }

    /**
     * @return сертификаты пира (для проверки вызывающим кодом)
     */
    public List<GostCertificate> getReceivedCertificates() {
        return receivedCertificates;
    }

    /**
     * @return alert-код при ошибке (дефолт ALERT_HANDSHAKE_FAILURE)
     */
    public byte getErrorAlertCode() {
        return errorAlertCode;
    }

    /**
     * Подтверждает (или отклоняет) валидацию сертификата пира.
     * <p>
     * Должен быть вызван после {@link #needsCertificateValidation()} == true.
     * Если {@code valid == false}, engine переходит в ERROR.
     *
     * @param valid true если сертификат прошёл проверку
     */
    public void acknowledgeCertificateValidation(boolean valid) {
        acknowledgeCertificateValidation(valid, TlsConstants.ALERT_HANDSHAKE_FAILURE);
    }

    /**
     * Подтверждает (или отклоняет) валидацию сертификата пира с указанием alert-кода.
     * <p>
     * Позволяет вызывающему коду передать диагностически правильный alert
     * (например, {@link TlsConstants#ALERT_UNKNOWN_CA} при отсутствии доверенного CA).
     * Если {@code valid == false}, engine переходит в ERROR, и {@link #getErrorAlertCode()}
     * возвращает переданный alertCode. Для обратной совместимости без вызова этой перегрузки
     * значение по умолчанию — {@link TlsConstants#ALERT_HANDSHAKE_FAILURE}.
     *
     * @param valid     true если сертификат прошёл проверку
     * @param alertCode код TLS-алерта при отказе (игнорируется при valid == true)
     */
    public void acknowledgeCertificateValidation(boolean valid, byte alertCode) {
        needsCertValidation = false;
        if (!valid) {
            state = State.ERROR;
            errorMessage = "Peer certificate rejected";
            errorAlertCode = alertCode;
        }
    }

    // ========================================================================
    // Результаты handshake
    // ========================================================================

    /**
     * @return согласованный cipher suite (может отличаться от переданного в конструктор)
     */
    public TlsCiphersuite getNegotiatedCiphersuite() {
        return ciphersuite;
    }

    // ========================================================================
    // Реализация клиентского handshake
    // ========================================================================

    /**
     * Формирует и отправляет ClientHello со стороны клиента.
     * <p>
     * Генерирует ECDHE-ключи, строит тело ClientHello (с PSK если задан),
     * вычисляет binder для PSK, добавляет в транскрипт и переходит в
     * CLIENT_WAIT_SERVER_HELLO.
     *
     * @return handshake-фрейм ClientHello
     * @throws TlsException при ошибке построения сообщения
     */
    private byte[] startClient() throws TlsException {
        try {
            // Генерация одной ECDHE-пары для предпочтительной группы (RFC 8446 §4.2.8).
            // Single key_share: клиент предлагает selectedNamedGroup, сервер принимает
            // или возвращает HRR с другой группой. Multi key_share (все 7 групп RFC 9367)
            // давал 7× ECDHE keygen на каждый handshake — избыточно для горячего пути.
            ECParameters params = TlsCiphersuite.namedGroupToParams(selectedNamedGroup);
            KeyPair kp = KeyGenerator.generateKeyPair(params);
            ctx.addEcdheKey(selectedNamedGroup, kp.getPrivate());
            Map<Integer, byte[]> keyShares =
                    Map.of(selectedNamedGroup, TlsEncoding.encodePoint(kp.getPublic()));

            if (clientAlpnProtocols != null) {
                messageBuilder.setClientAlpnProtocols(clientAlpnProtocols);
            }

            byte[] clientHelloBody =
                    pskKey != null ? buildFirstClientHelloWithPsk(keyShares) : null;
            if (clientHelloBody != null) {
                // RFC 8446 §4.2.11.2: binder считается от полного handshake-фрейма
                // (тип + длина + тело).
                byte[] chFrameBeforeBinder =
                        new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, clientHelloBody)
                                .encode();
                byte[] binder = TlsPskHelper.computeBinder(chFrameBeforeBinder, pskKey, hashLen);
                System.arraycopy(
                        binder,
                        0,
                        clientHelloBody,
                        clientHelloBody.length - binder.length,
                        binder.length);
                pskOffered = true;
            } else {
                clientHelloBody = messageBuilder.buildClientHello(keyShares, serverHostname);
            }
            sentExtensionTypes = TlsMessageParser.extensionTypesOfClientHello(clientHelloBody);
            byte[] chFrame =
                    new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, clientHelloBody).encode();
            ctx.addToTranscript(chFrame);
            state = State.CLIENT_WAIT_SERVER_HELLO;
            log.log(Level.DEBUG, "Handshake stage {0} -> {1}", State.CLIENT_START, state);
            return chFrame;
        } catch (RuntimeException e) {
            state = State.ERROR;
            errorMessage = "Failed to build ClientHello: " + e.getMessage();
            throw e;
        }
    }

    /**
     * Собирает первый ClientHello с PSK или возвращает null, если с ним блок расширений не
     * помещается в uint16.
     *
     * <p>Размер остальных расширений известен только здесь, поэтому ранние проверки длины тикета
     * (в {@link #setPsk}, при приёме NewSessionTicket) - лишь грубый фильтр. Не поместилось:
     * предложение PSK снимается, рукопожатие идёт полным, а {@link #isPskOfferWithdrawn()}
     * сообщает владельцу тикета, что его надо убрать из кэша.
     */
    private byte[] buildFirstClientHelloWithPsk(Map<Integer, byte[]> keyShares) {
        try {
            return messageBuilder.buildClientHelloWithPsk(
                    keyShares,
                    pskIdentity != null ? pskIdentity : new byte[0],
                    obfuscatedTicketAge,
                    serverHostname);
        } catch (TlsMessageBuilder.ExtensionsOverflowException e) {
            // Тикет принесён сервером прежнего соединения и по размеру не годится: полное
            // рукопожатие штатно, оператору вмешиваться не нужно
            log.log(
                    Level.DEBUG,
                    "PSK ticket does not fit into ClientHello, continuing with a full handshake");
            wipePskKey();
            pskIdentity = null;
            obfuscatedTicketAge = 0;
            pskOffered = false;
            pskOfferWithdrawn = true;
            return null;
        }
    }

    /**
     * Обрабатывает ServerHello от сервера.
     * <p>
     * Парсит сообщение, проверяет cipher suite, вычисляет ECDHE shared secret,
     * выводит handshake traffic keys (серверные для чтения, клиентские — позже),
     * инициализирует key schedule с PSK early secret если PSK принят.
     * <p>
     * Ключи чтения устанавливаются сразу — последующие сообщения (EE, Cert, CV, Finished)
     * уже зашифрованы серверными handshake-ключами.
     *
     * @param frame полный handshake-фрейм ServerHello
     * @throws TlsException при нарушении протокола
     */
    private void receiveServerHello(byte[] frame) throws TlsException {
        TlsHandshakeMessage shMsg = TlsHandshakeMessage.decode(frame);
        if (shMsg.getType() != TlsConstants.HT_SERVER_HELLO) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected ServerHello, got " + shMsg.getType());
        }

        // Парсим ECDHE, cipher suite, random, requestedGroup
        TlsMessageParser.ParsedServerHello parsedSH;
        try {
            parsedSH = TlsMessageParser.parseServerHello(shMsg.getBody(), sentExtensionTypes);
        } catch (TlsException e) {
            state = State.ERROR;
            errorMessage = "Failed to parse ServerHello: " + e.getMessage();
            throw e;
        }

        // Эхо legacy_session_id должно совпасть с отправленным (RFC 8446 §4.1.3). Проверка до
        // ветки HRR: правило одно и то же для HRR и для настоящего ServerHello
        if (!Arrays.equals(parsedSH.legacySessionIdEcho, messageBuilder.getSentLegacySessionId())) {
            state = State.ERROR;
            errorMessage = "ServerHello: legacy_session_id_echo does not match ClientHello";
            throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER, errorMessage);
        }

        // Проверка HRR ДО добавления в транскрипт (RFC 8446 §4.1.3)
        if (TlsMessageParser.isHelloRetryRequest(parsedSH)) {
            handleHelloRetryRequest(parsedSH, frame);
            return;
        }

        // PSK принят, если в ServerHello есть pre_shared_key; selected_identity обязан указывать на
        // предложенную identity (RFC 8446 §4.2.11). Клиент предлагает ровно одну identity
        int selectedPsk = parsedSH.selectedPskIdentity;
        if (selectedPsk >= 0) {
            // pre_shared_key без предложенного PSK парсер уже отверг (unsupported_extension,
            // RFC 8446 §4.2), здесь остаётся только проверка индекса
            if (selectedPsk >= OFFERED_PSK_IDENTITIES) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ServerHello: selected_identity " + selectedPsk + " was not offered");
            }
        }
        pskAccepted = selectedPsk >= 0;

        // Downgrade-sentinel (RFC 8446 §4.1.3) не проверяется намеренно: клиент
        // предлагает только TLS 1.3 (см. SV_CLIENT) и не имеет кода для завершения
        // хендшейка TLS 1.2/1.1 — понижать версию некуда, атака неприменима.

        // Настоящий ServerHello — добавляем в транскрипт
        ctx.addToTranscript(frame);

        // Набор из ServerHello должен быть из предложенных клиентом всегда, в том числе когда он
        // совпадает с начальным: начальный набор не обязан быть предложенным (приложение могло
        // отключить его), и без проверки сервер навязал бы отключённый набор
        if (!messageBuilder.getOfferedCipherSuiteIds().contains(parsedSH.cipherSuiteId)) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "ServerHello: cipher suite "
                            + parsedSH.cipherSuiteId
                            + " не в списке предложенных");
        }
        if (parsedSH.cipherSuiteId != ciphersuite.getId()) {
            // Сервер выбрал другой cipher suite из предложенных клиентом
            TlsCiphersuite chosen = TlsCiphersuite.byId(parsedSH.cipherSuiteId);
            if (chosen == null) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ServerHello: неподдерживаемый cipher suite " + parsedSH.cipherSuiteId);
            }
            // Одно поле набора у обеих ролей: по нему выводятся ключи и собираются эпохи записи
            // (метки смены ключа, KeyUpdate). Отдельное поле «согласованного» набора расходилось
            // с ним у клиента, и запись собиралась по первому предложенному набору
            ciphersuite = chosen;
        }

        // ECDHE: декодируем публичный ключ сервера, вычисляем общий секрет
        byte[] pubKeyRaw = parsedSH.ecdhePublicKeyRaw;
        // Ищем ECDHE-ключ для группы, выбранной сервером (multi key_share, RFC 8446 §4.2.8)
        PrivateKeyParameters priv = ctx.getEcdheKey(parsedSH.actualGroup);
        if (priv == null) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "ServerHello: key_share group 0x"
                            + Integer.toHexString(parsedSH.actualGroup)
                            + " was not offered in ClientHello");
        }
        ECParameters serverSelectedParams = TlsCiphersuite.namedGroupToParams(parsedSH.actualGroup);

        byte[] sharedSecret;
        try {
            PublicKeyParameters peerPub = TlsEncoding.decodePoint(pubKeyRaw, serverSelectedParams);
            ctx.setPeerEcdhePublicKey(peerPub);
            sharedSecret = computeEcdheShared(priv, peerPub);
        } finally {
            ctx.destroyEcdheKeys();
        }

        // Key schedule: инициализация и derivation handshake secret
        ctx.setKeySchedule(new TlsKeySchedule(ciphersuite));
        if (pskAccepted) {
            ctx.getKeySchedule().deriveEarlySecret(pskKey);
        }
        TlsUtils.wipeArray(pskKey);
        pskKey = null;
        try {
            ctx.getKeySchedule().deriveHandshakeSecret(sharedSecret);
        } finally {
            TlsUtils.wipeArray(sharedSecret);
        }

        // Вырабатываем handshake traffic keys (RFC 8446 §7.1)
        byte[] hsTranscript = ctx.transcriptHash();
        this.serverHandshakeTrafficSecret =
                ctx.getKeySchedule().getServerHandshakeTrafficSecret(hsTranscript);
        this.clientHandshakeTrafficSecret =
                ctx.getKeySchedule().getClientHandshakeTrafficSecret(hsTranscript);
        TlsUtils.wipeArray(hsTranscript);

        handshakeServerKeys = ctx.getKeySchedule().deriveTrafficKeys(serverHandshakeTrafficSecret);
        handshakeClientKeys = ctx.getKeySchedule().deriveTrafficKeys(clientHandshakeTrafficSecret);

        // Устанавливаем ключи чтения (расшифровка EE, Cert, CV, Finished от сервера)
        changeReadKeys(handshakeServerKeys);

        // Ключ записи клиента тоже включается сразу (RFC 8446 приложение A.1: клиент SHOULD сначала
        // сменить ключ на ключ рукопожатия, если возможно; ранних данных в библиотеке нет). Так
        // alert клиента при отказе до Finished сервера уходит зашифрованным, а не открытым. До
        // Finished сервера клиент ничего не отправляет, поэтому на проводе успешного рукопожатия
        // ничего не меняется, а нумерация записей начинается с нуля на Certificate или Finished.
        queueWriteKeyChange(handshakeClientKeys);

        if (log.isLoggable(Level.DEBUG)) {
            log.log(
                    Level.DEBUG,
                    "ServerHello accepted: cipher suite {0}, group 0x{1}, PSK accepted={2}",
                    ciphersuite.forLog(),
                    String.format("%04x", parsedSH.actualGroup),
                    pskAccepted);
        }
        state = State.CLIENT_WAIT_ENCRYPTED_EXTENSIONS;
    }

    /**
     * Обрабатывает HelloRetryRequest (RFC 8446 §4.1.3).
     * <p>
     * Заменяет транскрипт на message_hash(CH1) + HRR, генерирует новый ECDHE-ключ
     * для запрошенной группы, строит второй ClientHello (с пересчётом PSK binder при
     * необходимости) и ставит его в очередь отправки. Транскрипт после выхода:
     * message_hash + HRR + CH2.
     *
     * @param parsedSH распарсенный HRR (random равен значению HelloRetryRequest)
     * @param frame    полный handshake-фрейм HRR
     * @throws TlsException при нарушении протокола
     */
    private void handleHelloRetryRequest(TlsMessageParser.ParsedServerHello parsedSH, byte[] frame)
            throws TlsException {
        // HRR не должен содержать pre_shared_key extension (RFC 8446 §4.1.3)
        pskAccepted = false;

        int requestedGroup = parsedSH.requestedGroup;

        // RFC 8446 §4.2.8 допускает HRR без key_share — сервер
        //      не запрашивает смену группы; продолжаем с той же, что в CH1.
        if (requestedGroup == 0) {
            requestedGroup = selectedNamedGroup;
        }

        // Проверка: группа должна быть известна
        try {
            TlsCiphersuite.namedGroupToParams(requestedGroup);
        } catch (IllegalArgumentException e) {
            throw new TlsException(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "HRR: requested group 0x"
                            + Integer.toHexString(requestedGroup)
                            + " not supported");
        }

        // Защита от цикла: второй HRR подряд
        if (hrrReceived) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Received second HelloRetryRequest");
        }

        // Замена транскрипта: CH1 -> message_hash (RFC 8446 §4.4.1)
        ctx.replaceTranscriptWithMessageHash();

        // Добавляем HRR в новый транскрипт
        ctx.addToTranscript(frame);

        // Префикс транскрипта для PSK binder: message_hash || HRR в сыром виде. RFC 8446 §4.2.11.2
        // хэширует префикс и усечённый CH2 одним проходом, готовый Hash(префикса) не подходит.
        byte[] hrrPrefix = ctx.transcriptPrefix();

        // Затираем старый ECDHE-ключ (от первого CH)
        ctx.destroyEcdheKeys();

        // Генерируем новый ECDHE-ключ для запрошенной группы
        if (log.isLoggable(Level.DEBUG)) {
            log.log(
                    Level.DEBUG,
                    "HelloRetryRequest received: group 0x{0}",
                    String.format("%04x", requestedGroup));
        }
        ECParameters newParams = TlsCiphersuite.namedGroupToParams(requestedGroup);
        KeyPair kp = KeyGenerator.generateKeyPair(newParams);
        ctx.addEcdheKey(requestedGroup, kp.getPrivate());
        Map<Integer, byte[]> keyShares =
                Map.of(requestedGroup, TlsEncoding.encodePoint(kp.getPublic()));

        // Строим второй ClientHello
        byte[] cookie = parsedSH.cookie;
        byte[] clientHelloBody;
        if (pskKey != null) {
            try {
                clientHelloBody =
                        messageBuilder.buildClientHelloWithPsk(
                                keyShares,
                                pskIdentity != null ? pskIdentity : new byte[0],
                                obfuscatedTicketAge,
                                serverHostname,
                                cookie);
            } catch (TlsMessageBuilder.ExtensionsOverflowException e) {
                // PSK из CH1 снять нельзя (RFC 8446 §4.1.2 разрешает только обновить binder),
                // а cookie сервера вытолкнула блок за предел: продолжать нечем
                TlsUtils.wipeArray(hrrPrefix);
                throw new TlsException(
                        TlsConstants.ALERT_INTERNAL_ERROR,
                        "ClientHello after HRR does not fit with the server cookie");
            }
            // RFC 8446 §4.2.11.2: Через HMAC считаем от полного handshake-фрейма
            byte[] ch2BeforeBinder =
                    new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, clientHelloBody).encode();
            byte[] binder =
                    TlsPskHelper.computeBinderAfterHrr(hrrPrefix, ch2BeforeBinder, pskKey, hashLen);
            System.arraycopy(
                    binder,
                    0,
                    clientHelloBody,
                    clientHelloBody.length - binder.length,
                    binder.length);
        } else {
            clientHelloBody = messageBuilder.buildClientHello(keyShares, serverHostname, cookie);
        }
        sentExtensionTypes = TlsMessageParser.extensionTypesOfClientHello(clientHelloBody);
        TlsUtils.wipeArray(hrrPrefix);

        byte[] ch2Frame =
                new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, clientHelloBody).encode();
        ctx.addToTranscript(ch2Frame);
        queueMessage(ch2Frame);

        hrrReceived = true;
    }

    /**
     * Обрабатывает EncryptedExtensions (RFC 8446 §4.3.1).
     * <p>
     * В ГОСТ-профиле RFC 9367 §6.1.2 расширения на этом этапе пустые.
     * Если PSK принят — сертификат не нужен, переходим сразу к Finished.
     *
     * @param frame полный handshake-фрейм EncryptedExtensions
     * @throws TlsException при нарушении протокола
     */
    private void receiveEncryptedExtensions(byte[] frame) throws TlsException {
        TlsHandshakeMessage eeMsg = TlsHandshakeMessage.decode(frame);
        if (eeMsg.getType() != TlsConstants.HT_ENCRYPTED_EXTENSIONS) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected EncryptedExtensions, got " + eeMsg.getType());
        }
        ctx.addToTranscript(frame);

        // Парсим ALPN и max_fragment_length из EncryptedExtensions. Ответ на расширение, которого
        // не было в последнем ClientHello, парсер отвергает сам (unsupported_extension, RFC 8446
        // §4.2)
        TlsMessageParser.ParsedEncryptedExtensions parsedEE =
                TlsMessageParser.parseEncryptedExtensions(eeMsg.getBody(), sentExtensionTypes);

        // ALPN: RFC 7301 §3.2 — клиент обязан проверить, что сервер выбрал протокол из нашего
        // списка. Если ALPN есть в ответе, парсер уже убедился, что мы его отправляли
        if (parsedEE.alpn != null) {
            if (clientAlpnProtocols == null || !clientAlpnProtocols.contains(parsedEE.alpn)) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "Server selected ALPN protocol not offered: "
                                + SafeText.printableAscii(
                                        parsedEE.alpn, TlsConstants.LOG_PEER_STRING_LIMIT));
            }
            this.selectedAlpnProtocol = parsedEE.alpn;
        }

        // max_fragment_length: RFC 6066 §4.1 — значение в ответе обязано совпасть с запрошенным.
        // Незапрошенное расширение отвергнуто парсером
        if (parsedEE.maxFragLen != 0) {
            if (parsedEE.maxFragLen != clientMaxFragLenRequest) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "Server returned unexpected max_fragment_length: requested "
                                + clientMaxFragLenRequest
                                + ", got "
                                + parsedEE.maxFragLen);
            }
            this.maxFragmentLength = parsedEE.maxFragLen;
        }

        state = pskAccepted ? State.CLIENT_WAIT_FINISHED : State.CLIENT_WAIT_CERTIFICATE_OR_CR;
    }

    /**
     * Принимает Certificate или CertificateRequest от сервера.
     * <p>
     * CertificateRequest -> включаем mTLS, ожидаем серверный Certificate.
     * Certificate -> штатный разбор цепочки + ожидание CertificateVerify.
     * Иное сообщение -> ALERT_UNEXPECTED_MESSAGE.
     *
     * @param frame полный handshake-фрейм Certificate или CertificateRequest
     * @throws TlsException при нарушении протокола
     * @throws IOException   при ошибке парсинга
     */
    private void receiveCertificateOrCr(byte[] frame) throws TlsException, java.io.IOException {
        TlsHandshakeMessage msg = TlsHandshakeMessage.decode(frame);
        if (msg.getType() == TlsConstants.HT_CERTIFICATE_REQUEST) {
            ctx.addToTranscript(frame);
            ClientCertificateRequest cri = TlsMessageParser.parseCertificateRequest(msg.getBody());
            clientAuthRequested = true;
            clientOcspRequested = cri.ocspRequested();

            // Заданный селектор - единственный источник учётных данных клиента и вызывается на
            // каждый CertificateRequest, в том числе без фильтров: схемы сервера он тоже учитывает.
            // null от него - пустой Certificate, цепочка из конфигурации не подставляется
            if (clientCertificateSelector != null) {
                TlsClientCredentials selected;
                try {
                    selected = clientCertificateSelector.select(cri);
                } catch (RuntimeException e) {
                    // Сбой кода приложения - наша внутренняя ошибка, а не нарушение протокола
                    // пиром: без перехвата receive() выдал бы её как decode_error. Текст
                    // исключения в сообщение не попадает: там может быть что угодно.
                    throw new TlsException(
                            TlsConstants.ALERT_INTERNAL_ERROR,
                            "Client certificate selector failed",
                            e);
                }
                if (selected != null) {
                    if (selected.chain().isEmpty()
                            || selected.chain().get(0).getPublicKey() == null) {
                        throw new TlsException(
                                TlsConstants.ALERT_INTERNAL_ERROR,
                                "Selected client certificate chain leaf has no public key");
                    }
                    messageBuilder.setCertificateChain(selected.chain());
                    messageBuilder.setPrivateKey(selected.privateKey());
                    int newScheme =
                            TlsCiphersuite.namedGroupToSignatureScheme(
                                    TlsCertUtils.getNamedGroup(
                                            selected.chain().get(0).getPublicKey()));
                    messageBuilder.updateSigScheme(newScheme);
                    // Staple относится к выбранному leaf; staple из конфигурации принадлежит
                    // другому сертификату, поэтому заменяется (в том числе на null).
                    this.ocspResponse = selected.ocspResponse();
                } else {
                    // Ни один сертификат не подошёл -> пустой certificate_list
                    messageBuilder.setCertificateChain(null);
                    messageBuilder.setPrivateKey(null);
                    this.ocspResponse = null;
                }
            }
            // Если селектор не задан — используем цепочку из конфигурации
            applyServerSignatureSchemes(cri.signatureSchemes(), cri.certificateSignatureSchemes());
            state = State.CLIENT_WAIT_CERTIFICATE;
            return;
        }
        if (msg.getType() == TlsConstants.HT_CERTIFICATE) {
            receiveCertificate(frame);
            return;
        }
        throw new TlsException(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "Expected Certificate or CertificateRequest, got " + msg.getType());
    }

    /**
     * Единая точка решения о схеме подписи клиента после выбора сертификата (селектор мог заменить
     * цепочку) и до сборки Certificate и CertificateVerify.
     *
     * <p>Схема ключа листа не в списке {@code signature_algorithms} сервера: RFC 8446 §4.4.3
     * запрещает подписывать такой схемой, а §4.4.2.3 велит отправить пустой Certificate без
     * CertificateVerify; staple относился к отвергнутому листу и сбрасывается. Схема подписи
     * сертификата цепочки не в списке: сервер вправе отказать, но молча терять mTLS там, где он
     * цепочку принял бы, хуже, поэтому отправляем нашу цепочку и пишем предупреждение. Это
     * сознательное отступление от буквы §4.4.2.3 ради совместимости.</p>
     *
     * @param offered      схемы подписи CertificateVerify из signature_algorithms
     * @param chainOffered схемы подписи сертификатов цепочки (signature_algorithms_cert, а без
     *                     него тот же список)
     */
    private void applyServerSignatureSchemes(int[] offered, int[] chainOffered) {
        List<GostCertificate> chain = messageBuilder.getCertificateChain();
        if (chain == null || chain.isEmpty()) {
            return;
        }
        int leafScheme = TlsCertUtils.leafSignatureScheme(chain);
        if (!TlsCertUtils.isSchemeOffered(offered, leafScheme)) {
            // Схемы подписи собеседника: отказ, если он последует, придёт alert сервера
            log.log(
                    Level.DEBUG,
                    "Server did not offer the signature scheme 0x{0} of the client certificate,"
                            + " sending an empty Certificate",
                    String.format("%04x", leafScheme));
            messageBuilder.setCertificateChain(null);
            messageBuilder.setPrivateKey(null);
            this.ocspResponse = null;
            return;
        }
        messageBuilder.updateSigScheme(leafScheme);
        List<Integer> unoffered = TlsCertUtils.unofferedChainSchemes(chain, chainOffered);
        if (!unoffered.isEmpty()) {
            log.log(
                    Level.DEBUG,
                    "Server did not offer the signature schemes of the client certificate chain"
                            + " (codes {0}), sending the chain anyway",
                    unoffered.stream()
                            .map(code -> String.format("0x%04x", code))
                            .collect(Collectors.joining(", ")));
        }
    }

    /**
     * Принимает Certificate от сервера (RFC 8446 §4.4.2).
     * <p>
     * Парсит цепочку сертификатов, сохраняет для валидации вызывающим кодом,
     * переходит в ожидание CertificateVerify.
     *
     * @param frame полный handshake-фрейм Certificate
     * @throws TlsException при нарушении протокола
     */
    private void receiveCertificate(byte[] frame) throws TlsException {
        TlsHandshakeMessage certMsg = TlsHandshakeMessage.decode(frame);
        if (certMsg.getType() != TlsConstants.HT_CERTIFICATE) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected Certificate, got " + certMsg.getType());
        }
        ctx.addToTranscript(frame);

        // Расширения CertificateEntry - ответ на наш ClientHello: сверяем с тем, что реально
        // отправили (status_request, если запрашивали staple), остальное парсер отвергает.
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(certMsg.getBody(), sentExtensionTypes);
        if (chain.isEmpty()) {
            // RFC 8446 §4.4.2: сервер обязан прислать непустой certificate_list.
            // Пустой список — нарушение протокола, не certificate_required (этот алерт только для
            // сервера).
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Server sent empty certificate list");
        }
        receivedCertificates = chain;
        needsCertValidation = true;
        state = State.CLIENT_WAIT_CERTIFICATE_VERIFY;
    }

    /**
     * Верифицирует CertificateVerify (RFC 8446 §4.4.3, RFC 9367 §3.2).
     * <p>
     * Берёт transcript-hash ДО добавления CV (RFC 8446 §4.4.3: подпись покрывает
     * все предыдущие handshake-сообщения), добавляет CV в транскрипт,
     * проверяет подпись через TlsCertificateValidator.
     * <p>
     * isServer=true — верификация серверной подписи (клиент),
     * isServer=false — верификация клиентской подписи (сервер, mTLS).
     *
     * @param frame    полный handshake-фрейм CertificateVerify
     * @param isServer true для серверной подписи, false для клиентской
     * @throws TlsException при нарушении протокола
     * @throws IOException   при ошибке верификации подписи
     */
    private void receiveCertificateVerify(byte[] frame, boolean isServer)
            throws TlsException, java.io.IOException {
        TlsHandshakeMessage cvMsg = TlsHandshakeMessage.decode(frame);
        if (cvMsg.getType() != TlsConstants.HT_CERTIFICATE_VERIFY) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected CertificateVerify, got " + cvMsg.getType());
        }
        // Transcript-hash до включения CV — подпись покрывает предыдущие сообщения
        byte[] cvTranscript = ctx.transcriptHash();
        ctx.addToTranscript(frame);

        byte[] cvBody = cvMsg.getBody();
        GostCertificate cert = receivedCertificates.get(0);
        TlsCertificateValidator.verifyCertificateVerify(
                cvBody, cert, cvTranscript, isServer, interopAcceptGostBaseSigScheme);
        TlsUtils.wipeArray(cvTranscript);

        state = isServer ? State.CLIENT_WAIT_FINISHED : State.SERVER_WAIT_CLIENT_FINISHED;
    }

    /**
     * Принимает и верифицирует серверный Finished (RFC 8446 §4.4.4).
     * <p>
     * Пересчитывает verify_data через handshake-транскрипт и serverHandshakeTrafficSecret,
     * сравнивает с полученным значением. При успехе:
     * <ul>
     *   <li>если mTLS (clientAuthRequested) — строит и ставит в очередь Certificate + CertificateVerify</li>
     *   <li>строит и ставит в очередь клиентский Finished</li>
     * </ul>
     * Ключ записи рукопожатия клиента уже включён с ServerHello, здесь он не меняется.
     *
     * @param frame полный handshake-фрейм Finished
     * @throws TlsException при нарушении протокола
     */
    private void receiveFinished(byte[] frame) throws TlsException {
        TlsHandshakeMessage sfMsg = TlsHandshakeMessage.decode(frame);
        if (sfMsg.getType() != TlsConstants.HT_FINISHED) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected Finished, got " + sfMsg.getType());
        }
        byte[] serverFinishedTranscript = ctx.transcriptHash();
        ctx.addToTranscript(frame);

        // Пересчитываем verify_data и сравниваем
        byte[] expectedVerifyData =
                TlsMessageBuilder.buildFinished(
                        ctx.getKeySchedule(),
                        serverHandshakeTrafficSecret,
                        serverFinishedTranscript);
        TlsUtils.wipeArray(serverFinishedTranscript);
        if (!java.security.MessageDigest.isEqual(sfMsg.getBody(), expectedVerifyData)) {
            throw new TlsException(
                    TlsConstants.ALERT_DECRYPT_ERROR, "Server Finished verification failed");
        }

        // RFC 8446 §7.1 Table 2: app transcript = ClientHello...server Finished (БЕЗ client
        // Cert/CV/CF)
        this.appTranscriptHash = ctx.transcriptHash();

        // Строим клиентский Certificate + CertificateVerify (если mTLS)
        if (clientAuthRequested) {
            if (messageBuilder.getCertificateChain() == null
                    || messageBuilder.getCertificateChain().isEmpty()) {
                // RFC 8446 §4.4.2: если сервер запросил сертификат, но у клиента
                // его нет, клиент ОБЯЗАН отправить пустой certificate_list
                // (без CertificateVerify), затем Finished.
                byte[] emptyBody = messageBuilder.buildEmptyCertificateBody();
                byte[] emptyFrame =
                        new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, emptyBody).encode();
                ctx.addToTranscript(emptyFrame);
                queueMessage(emptyFrame);
            } else {
                // RFC 8446 §4.2: staple допустим только в ответ на status_request сервера.
                byte[] certBody =
                        messageBuilder.buildCertificateBody(
                                clientOcspRequested ? ocspResponse : null);
                byte[] certFrame =
                        new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, certBody).encode();
                ctx.addToTranscript(certFrame);

                byte[] cvTranscript = ctx.transcriptHash();
                byte[] cvBody =
                        messageBuilder.buildCertificateVerify(
                                cvTranscript, TlsConstants.CLIENT_CERTIFICATE_VERIFY_CTX);
                TlsUtils.wipeArray(cvTranscript);
                byte[] cvFrame =
                        new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE_VERIFY, cvBody)
                                .encode();
                ctx.addToTranscript(cvFrame);

                queueMessage(certFrame);
                queueMessage(cvFrame);
            }
        }

        // Клиентский Finished ставим в очередь (НО НЕ ДОБАВЛЯЕМ В ТРАНСКРИПТ —
        // транскрипт для app traffic keys (RFC 8446 §4.4.1) идёт ДО client Finished)
        byte[] clientFinishedTranscript = ctx.transcriptHash();
        byte[] clientFinishedBody =
                TlsMessageBuilder.buildFinished(
                        ctx.getKeySchedule(),
                        clientHandshakeTrafficSecret,
                        clientFinishedTranscript);
        TlsUtils.wipeArray(clientFinishedTranscript);
        byte[] cfFrame =
                new TlsHandshakeMessage(TlsConstants.HT_FINISHED, clientFinishedBody).encode();
        this.pendingClientFinished = cfFrame;

        queueMessage(cfFrame);

        // Ключи приложения вырабатываются после сборки ответа клиента: его Certificate,
        // CertificateVerify и Finished опираются на секреты рукопожатия. Читать ключами приложения
        // клиент начинает сразу: за Finished сервера идут уже его данные (RFC 8446 §4.4.4). Писать
        // — после своего Finished: смена ключа стоит в потоке сразу за ним
        TlsTrafficKeys[] appKeys = deriveApplicationKeys();
        changeReadKeys(appKeys[0]);
        queueWriteKeyChange(appKeys[1]);
        appKeys[1].destroy();
        state = State.CLIENT_SEND_FINISHED;
    }

    /**
     * Клиент: завершает рукопожатие, когда его Finished отдан из очереди ({@link #poll()}).
     * <p>
     * Предусловие: ключи приложения выработаны в {@link #receiveFinished}, ключ чтения уже сменён,
     * смена ключа записи отдана из потока вслед за Finished. Постусловие: Resumption Master Secret
     * выработан по полному транскрипту, контекст рукопожатия уничтожен.
     */
    private void finishHandshake() {
        // RFC 8446 §4.6.1: res_master требует транскрипт вместе с Finished клиента
        if (pendingClientFinished != null) {
            ctx.addToTranscript(pendingClientFinished);
            pendingClientFinished = null;
        }
        byte[] hsTranscript = ctx.transcriptHash();
        this.resumptionMasterSecret = ctx.getKeySchedule().getResumptionMasterSecret(hsTranscript);
        TlsUtils.wipeArray(hsTranscript);

        // После handshake engine остаётся жив (POST_HANDSHAKE)
        // для обработки KeyUpdate и NewSessionTicket. ctx уничтожается
        // (транскрипт после handshake не нужен), но app traffic secrets
        // сохранены в полях экземпляра.
        // Handshake-ключи больше не нужны — соединение перешло на app traffic keys
        if (handshakeServerKeys != null) {
            handshakeServerKeys.destroy();
            handshakeServerKeys = null;
        }
        if (handshakeClientKeys != null) {
            handshakeClientKeys.destroy();
            handshakeClientKeys = null;
        }
        TlsUtils.wipeArray(serverHandshakeTrafficSecret);
        serverHandshakeTrafficSecret = null;
        TlsUtils.wipeArray(clientHandshakeTrafficSecret);
        clientHandshakeTrafficSecret = null;

        receivedCertificates = null;
        state = State.POST_HANDSHAKE;
        ctx.destroy();
    }

    /**
     * Выбирает группу для HRR из supported_groups клиента: первую поддерживаемую сервером,
     * которой нет ни в одной записи key_share (RFC 8446 §4.2.8: selected_group в HRR не должна
     * совпадать с группой, для которой клиент уже прислал key_share; иначе клиент обязан
     * прервать handshake с illegal_parameter).
     *
     * @param clientGroups   группы из supported_groups клиента
     * @param keyShareGroups группы всех записей key_share клиента
     * @return NamedGroup для HRR или 0, если подходящей нет
     */
    private static int selectHrrGroup(int[] clientGroups, int[] keyShareGroups) {
        for (int cg : clientGroups) {
            if (containsGroup(keyShareGroups, cg)) {
                continue;
            }
            try {
                TlsCiphersuite.namedGroupToParams(cg);
                return cg;
            } catch (IllegalArgumentException e) {
                // Группа не поддерживается сервером - пропускаем
            }
        }
        return 0;
    }

    private static boolean containsGroup(int[] groups, int group) {
        for (int g : groups) {
            if (g == group) {
                return true;
            }
        }
        return false;
    }

    private static boolean isServerSupportedGroup(int group) {
        try {
            TlsCiphersuite.namedGroupToParams(group);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Отправляет HelloRetryRequest (RFC 8446 §4.1.3).
     * <p>
     * Заменяет транскрипт на message_hash(CH1), добавляет HRR-сообщение
     * в новый транскрипт и ставит HRR-фрейм в очередь отправки.
     * Key schedule НЕ создаётся — он будет инициализирован при получении CH2.
     *
     * @param requestedGroup группа, которую запрашивает HRR
     * @param clientPsk      разобранные PSK-расширения первого ClientHello или null
     */
    private void sendHelloRetryRequest(
            int requestedGroup, TlsMessageParser.ParsedClientPsk clientPsk) throws TlsException {
        // Второй ClientHello сверяется с первым по списку identity (RFC 8446 §4.1.2); снимок нужен
        // только на пути HRR и одним массивом, а не по массиву на каждую identity
        if (clientPsk != null) {
            ch1PskIdentitiesSnapshot = clientPsk.identitiesSnapshot();
        }
        // Замена транскрипта: CH1 -> message_hash (RFC 8446 §4.4.1)
        ctx.replaceTranscriptWithMessageHash();

        byte[] hrrBody = messageBuilder.buildHelloRetryRequest(requestedGroup, ciphersuite.getId());
        byte[] hrrFrame = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, hrrBody).encode();
        ctx.addToTranscript(hrrFrame);
        queueMessage(hrrFrame);

        if (log.isLoggable(Level.DEBUG)) {
            log.log(
                    Level.DEBUG,
                    "HelloRetryRequest sent: group 0x{0}",
                    String.format("%04x", requestedGroup));
        }
        hrrSent = true;
    }

    // ========================================================================
    // Реализация серверного handshake
    // ========================================================================

    /**
     * Принимает или отвергает PSK в первом ClientHello (RFC 8446 §4.2.11).
     * <p>
     * Просматривает в хранилище не больше {@link TlsConstants#MAX_PSK_IDENTITIES} первых identity
     * (явный PSK сервера хранилища не требует и привязан к первой identity) и выбирает первую
     * известную: есть в хранилище, не просрочена, привязана к этому имени сервера. Binder
     * проверяется только у выбранной (§4.2.11); к следующей identity после отказа по возрасту
     * сервер не переходит. Итог запоминается для второго ClientHello: после HRR решение не
     * пересматривается. Непринятый PSK затирается сразу, чтобы он не дожил до CH2.
     *
     * @param chBody тело ClientHello
     * @param frame  полный handshake-фрейм ClientHello
     * @param psk    разобранные расширения PSK или null, если pre_shared_key нет
     * @param clientServerName проверенное имя из SNI или null, если расширения нет
     * @throws TlsException при неверном binder выбранной identity
     */
    private void resolvePskInFirstClientHello(
            byte[] chBody,
            byte[] frame,
            TlsMessageParser.ParsedClientPsk psk,
            String clientServerName)
            throws TlsException {
        wipeCh1PskState();
        if (psk == null) {
            wipePskKey();
            return;
        }

        int selected = -1;
        boolean pskKeyFromStore = false;
        long pskEntryIssueTime = 0;
        long pskEntryTicketAgeAdd = 0;
        if (!requestClientAuth && psk.dheKeOffered()) {
            if (pskKey != null) {
                // Явный PSK сервера: identity для поиска не нужна, binder проверяется у первой
                selected = 0;
            } else if (serverPskStore != null) {
                // peek() - lookup без удаления из стора. Верификация binder ниже.
                // Если binder провалится, тикет останется в сторе для повторных попыток.
                // Неатомарность peek->verify->get не является проблемой безопасности:
                //   - если другой поток успел забрать тикет между peek и get,
                //     get() вернёт null -> PSK не принят -> full handshake;
                //   - при TCP-ретрансмите второй remove() вернёт null безвредно.
                // Атомарная синхронизация здесь избыточна и ударила бы по горячему пути.
                // RFC 6066 §3: возобновление при другом имени SNI недопустимо, сервер переходит к
                // полному рукопожатию. Несовпадение не расходует тикет: запись остаётся в
                // хранилище для соединения со своим именем.
                PskBinding serverBinding = PskBinding.forServer(clientServerName);
                long now = System.currentTimeMillis();
                int scanned = Math.min(psk.count(), TlsConstants.MAX_PSK_IDENTITIES);
                for (int i = 0; i < scanned; i++) {
                    byte[] identity = psk.identity(i);
                    PskEntry entry = serverPskStore.peek(identity);
                    TlsUtils.wipeArray(identity);
                    if (entry == null || entry.isExpired(now)) {
                        continue;
                    }
                    if (!serverBinding.equals(entry.getBinding())) {
                        // Решение библиотеки пропустить тикет по имени сервера: штатно
                        log.log(
                                Level.DEBUG,
                                "PSK ticket was issued for a different server name, skipping it");
                        continue;
                    }
                    // Параллельное соединение с тем же тикетом могло успеть забрать запись и
                    // затереть
                    // ключ между peek и этим местом: getPsk() тогда возвращает null. Для нас это
                    // как неизвестная identity: берём следующую или идём полным рукопожатием
                    byte[] storedPsk = entry.getPsk();
                    if (storedPsk == null) {
                        continue;
                    }
                    pskKey = storedPsk;
                    pskKeyFromStore = true;
                    pskEntryIssueTime = entry.getIssueTime();
                    pskEntryTicketAgeAdd = entry.getTicketAgeAdd();
                    selected = i;
                    break;
                }
            }
        }

        if (selected >= 0) {
            // Все шифронаборы библиотеки на Стрибоге-256. Появление шифронабора с другим хэшем
            // потребует здесь сверки хэша шифронабора и PSK (RFC 8446 §4.2.11).
            // RFC 8446 §4.2.11.2: binder считается от полного handshake-фрейма
            boolean binderOk =
                    TlsPskHelper.verifyBinder(
                            frame,
                            frameOffset(psk.bindersVectorOffset()),
                            frameOffset(psk.binderOffset(selected)),
                            pskKey,
                            hashLen);
            if (!binderOk) {
                // Причина целиком в TlsException и в alert decrypt_error; запись не дублируется
                wipePskKey();
                wipeCh1PskState();
                throw new TlsException(
                        TlsConstants.ALERT_DECRYPT_ERROR, "PSK binder verification failed");
            }
            if (!pskKeyFromStore) {
                pskAccepted = true;
            } else {
                byte[] identity = psk.identity(selected);
                PskEntry consumed = serverPskStore.get(identity);
                TlsUtils.wipeArray(identity);
                if (consumed != null) {
                    boolean ageOk =
                            validatePskTicketAge(
                                    psk.obfuscatedTicketAge(selected),
                                    pskEntryIssueTime,
                                    pskEntryTicketAgeAdd);
                    consumed.destroy();
                    if (ageOk) {
                        pskAccepted = true;
                    } else {
                        log.log(
                                Level.DEBUG,
                                "PSK ticket age mismatch, falling back to full handshake");
                    }
                }
            }
        }

        log.log(
                Level.DEBUG,
                "PSK offered: {0} identity(ies), accepted={1}",
                psk.count(),
                pskAccepted);

        // Решение CH1 переносится в CH2 (при HRR): иначе тикет, отвергнутый здесь по возрасту
        // или из-за гонки peek->get, мог бы быть принят во втором ClientHello.
        if (pskAccepted) {
            ch1AcceptedPskIdentity = psk.identity(selected);
            acceptedPskIndex = selected;
        } else {
            wipePskKey();
        }
    }

    /**
     * Определяет судьбу PSK во втором ClientHello после HRR (RFC 8446 §4.1.2, §4.2.11).
     * <p>
     * Хранилище не опрашивается: решение целиком берётся из первого ClientHello. Identity второго
     * ClientHello обязаны быть подмножеством identity первого с тем же порядком (клиент вправе
     * только удалять записи); добавление, замена и перестановка - {@code illegal_parameter}.
     * Принятая в CH1 identity ищется в CH2 по байтам, не по номеру: после удалений номер меняется.
     * Её нет - полное рукопожатие, к другой identity сервер не переходит. Известная identity за
     * пределом просмотра в CH1 не становится выбранной в CH2, сколько бы записей клиент ни удалил.
     *
     * @param psk   разобранные расширения PSK второго ClientHello или null
     * @param frame полный handshake-фрейм второго ClientHello
     * @throws TlsException при нарушении подмножества или неверном binder
     */
    private void resolvePskAfterHrr(TlsMessageParser.ParsedClientPsk psk, byte[] frame)
            throws TlsException {
        pskAccepted = false;
        acceptedPskIndex = TlsMessageBuilder.NO_SELECTED_PSK;
        try {
            if (psk == null) {
                return;
            }
            if (ch1PskIdentitiesSnapshot == null) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ClientHello after HRR: pre_shared_key was absent in the first ClientHello");
            }
            // Подпоследовательность с сохранением порядка: клиент вправе только удалять записи
            if (!psk.isOrderedSubsetOf(ch1PskIdentitiesSnapshot)) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ClientHello after HRR: PSK identities were added, replaced or reordered");
            }
            if (ch1AcceptedPskIdentity == null || pskKey == null || !psk.dheKeOffered()) {
                // PSK отвергнут в CH1: игнорируем и идём полным рукопожатием
                return;
            }
            int accepted = -1;
            for (int i = 0; i < psk.count(); i++) {
                if (psk.identityEquals(i, ch1AcceptedPskIdentity)) {
                    accepted = i;
                    break;
                }
            }
            if (accepted < 0) {
                // Клиент убрал принятую identity: PSK не используется
                return;
            }
            // Префикс транскрипта (message_hash || HRR) - до добавления CH2
            byte[] transcriptPrefix = ctx.transcriptPrefix();
            boolean binderOk;
            try {
                binderOk =
                        TlsPskHelper.verifyBinderAfterHrr(
                                transcriptPrefix,
                                frame,
                                frameOffset(psk.bindersVectorOffset()),
                                frameOffset(psk.binderOffset(accepted)),
                                pskKey,
                                hashLen);
            } finally {
                TlsUtils.wipeArray(transcriptPrefix);
            }
            if (!binderOk) {
                throw new TlsException(
                        TlsConstants.ALERT_DECRYPT_ERROR,
                        "PSK binder verification failed for CH2 after HRR");
            }
            // Тикет потреблён в CH1, возраст там же проверен и не пересчитывается
            pskAccepted = true;
            acceptedPskIndex = accepted;
        } finally {
            if (!pskAccepted) {
                wipePskKey();
            }
            wipeCh1PskState();
        }
    }

    /** Смещение во фрейме handshake по смещению в теле сообщения (фрейм = заголовок + тело). */
    private static int frameOffset(int bodyOffset) {
        return TlsConstants.HANDSHAKE_HEADER_SIZE + bodyOffset;
    }

    private void wipePskKey() {
        TlsUtils.wipeArray(pskKey);
        pskKey = null;
    }

    /** Затирает запомненное решение первого ClientHello: identity - это тикеты, их не держим дольше нужного. */
    private void wipeCh1PskState() {
        TlsUtils.wipeArray(ch1PskIdentitiesSnapshot);
        ch1PskIdentitiesSnapshot = null;
        TlsUtils.wipeArray(ch1AcceptedPskIdentity);
        ch1AcceptedPskIdentity = null;
    }

    /**
     * Обрабатывает ClientHello на стороне сервера.
     * <p>
     * Парсит PSK (если есть и binder верифицирован), ECDHE key_share и SNI.
     * Генерирует собственную ECDHE-пару, вычисляет shared secret,
     * инициализирует key schedule, строит ServerHello и EncryptedExtensions,
     * а при отсутствии PSK — CertificateRequest (mTLS), Certificate, CertificateVerify
     * и Server Finished. Все фреймы (кроме plaintext SH) ставятся в очередь
     * для отправки через {@link #poll()} с последующим шифрованием.
     *
     * @param frame полный handshake-фрейм ClientHello
     * @throws TlsException при нарушении протокола
     */
    /**
     * Сервер: ключи приложения вырабатываются, как только Finished сервера стоит в очереди. Смена
     * ключа записи встаёт в поток сразу за ним: дальше сервер пишет ключами приложения (RFC 8446
     * §4.4.4), ими защищён и alert при отказе клиентскому сертификату. Ключ чтения вступает после
     * проверки Finished клиента: до неё клиент пишет ключами рукопожатия.
     */
    private void scheduleServerApplicationKeys() throws TlsException {
        TlsTrafficKeys[] appKeys = deriveApplicationKeys();
        queueWriteKeyChange(appKeys[0]);
        appKeys[0].destroy();
        readKeysAfterPeerFinished = appKeys[1];
    }

    private void receiveClientHello(byte[] frame) throws TlsException {
        TlsHandshakeMessage chMsg = TlsHandshakeMessage.decode(frame);
        if (chMsg.getType() != TlsConstants.HT_CLIENT_HELLO) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected ClientHello, got " + chMsg.getType());
        }

        byte[] chBody = chMsg.getBody();
        // Имя разбирается один раз и строго, до PSK-привязки и выбора сертификата: недопустимое
        // имя не должно дойти ни до хранилища тикетов, ни до sniSelector (NUL в имени)
        String clientServerName = TlsMessageParser.parseClientHelloSni(chBody);
        // PSK. Структурная проверка расширений идёт до поиска в хранилище и независимо от него
        pskAccepted = false;
        acceptedPskIndex = TlsMessageBuilder.NO_SELECTED_PSK;
        TlsMessageParser.ParsedClientPsk clientPsk =
                TlsMessageParser.parseClientHelloPsk(chBody, hashLen);
        // PSK несовместим с запросом клиентского сертификата (need и want): принятый PSK
        // пропускает CertificateRequest. Сеттеры такой ключ не допускают; проверка здесь
        // — второй барьер на случай появления нового пути установки pskKey.
        if (requestClientAuth && pskKey != null) {
            TlsUtils.wipeArray(pskKey);
            pskKey = null;
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "PSK is not allowed with client certificate authentication");
        }
        if (hrrSent) {
            resolvePskAfterHrr(clientPsk, frame);
        } else {
            resolvePskInFirstClientHello(chBody, frame, clientPsk, clientServerName);
        }

        // Добавляем в транскрипт ПОСЛЕ PSK верификации (для CH2
        // префикс транскрипта нужен до добавления CH2),
        // но ДО проверки группы (транскрипт с CH1 нужен для
        // replaceTranscriptWithMessageHash при HRR).
        ctx.addToTranscript(frame);

        // --- SNI certificate selection (RFC 6066 §3, RFC 8446 §4.4.2) ---
        byte[] ocspForCert = this.ocspResponse;
        if (!pskAccepted && sniSelector != null) {
            if (clientServerName != null) {
                TlsServerCredentials creds = sniSelector.select(clientServerName);
                if (creds != null) {
                    List<GostCertificate> newChain = creds.getCertificateChain();
                    int newScheme =
                            TlsCiphersuite.namedGroupToSignatureScheme(
                                    TlsCertUtils.getNamedGroup(newChain.get(0).getPublicKey()));
                    // Список наборов остаётся прежним: новый сборщик не должен вернуть наборы,
                    // которые приложение отключило
                    this.messageBuilder =
                            new TlsMessageBuilder(
                                    ciphersuite,
                                    messageBuilder.getOfferedCipherSuiteIds(),
                                    selectedNamedGroup,
                                    newScheme,
                                    creds.getPrivateKey(),
                                    newChain,
                                    hashLen);
                    ocspForCert = creds.getOcspResponse();
                }
            }
        }

        // RFC 8446 §4.2: staple допустим только как ответ на status_request клиента.
        // Здесь chBody — итоговый ClientHello (CH2 после HRR), поэтому решение
        // принимается по тому сообщению, на которое сервер реально отвечает.
        if (ocspForCert != null && !TlsMessageParser.clientHelloRequestsOcsp(chBody)) {
            ocspForCert = null;
        }

        // Определяем схему подписи по кривой сертификата (RFC 9367 §5.2)
        int[] acceptableSchemes;
        if (messageBuilder.getCertificateChain() != null
                && !messageBuilder.getCertificateChain().isEmpty()) {
            int certNamedGroup =
                    TlsCertUtils.getNamedGroup(
                            messageBuilder.getCertificateChain().get(0).getPublicKey());
            int certScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
            acceptableSchemes = new int[] {certScheme};
        } else {
            acceptableSchemes = null;
        }

        // Парсим ECDHE key_share, SNI и согласуем схему подписи
        // 0 = skip single-suite check, т.к. сервер может предлагать несколько suite
        TlsMessageParser.ParsedKeyShare parsedCH =
                TlsMessageParser.parseClientHello(chBody, selectedNamedGroup, acceptableSchemes, 0);

        // RFC 8446 §9.2: без signature_algorithms рукопожатие возможно только по принятому PSK.
        // При отвергнутом PSK сервер перешёл бы к сертификату и подписал бы CertificateVerify без
        // согласия клиента, поэтому fail-closed
        if (!parsedCH.signatureAlgorithmsPresent && !pskAccepted) {
            throw new TlsException(
                    TlsConstants.ALERT_MISSING_EXTENSION,
                    "ClientHello: signature_algorithms required when the PSK is not accepted");
        }

        // RFC 8446 §4.4.2.2 требует схему из списка клиента, а §4.4.3 допускает схему вне списка,
        // если цепочку без неподдерживаемых алгоритмов составить нельзя: у сервера одна цепочка
        // на имя. Рукопожатие продолжается, а оператору остаётся строка в журнале: клиент со
        // строгой проверкой сам отвергнет подпись. Список схем клиента не пишется (до 64 КБ).
        if (!pskAccepted
                && acceptableSchemes != null
                && parsedCH.signatureAlgorithmsPresent
                && parsedCH.matchedSigScheme == 0) {
            log.log(
                    Level.DEBUG,
                    "Client did not offer the signature scheme 0x{0} of the server certificate,"
                            + " continuing the handshake (sni={1}, after HelloRetryRequest={2})",
                    String.format("%04x", acceptableSchemes[0]),
                    TlsUtils.peerTextForLog(parsedCH.serverName),
                    hrrSent);
        }

        // Определяем согласованный ciphersuite по пересечению списков
        TlsCiphersuite matchedSuite =
                messageBuilder.negotiateCiphersuite(chBody, this.ciphersuite, hashLen);
        if (matchedSuite == null) {
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "No common cipher suite: client did not offer any GOST suite");
        }
        if (matchedSuite != this.ciphersuite) {
            this.ciphersuite = matchedSuite;
        }
        if (parsedCH.matchedSigScheme != 0 && parsedCH.matchedSigScheme != selectedSigScheme) {
            messageBuilder.updateSigScheme(parsedCH.matchedSigScheme);
        }
        // То же проверенное значение, что получили привязка PSK и селектор: полный разбор
        // повторяет проверку имени (parseClientHello самодостаточен), но результат берётся один
        this.requestedServerName = clientServerName;
        this.maxFragmentLength = parsedCH.clientMaxFragLen;

        // Эхо-отражение legacy_session_id из ClientHello (RFC 8446 §4.1.3)
        // Должно быть выполнено ДО возможной отправки HRR, чтобы HRR тоже
        // содержал session_id клиента.
        int sidLen = chBody[34] & 0xFF;
        if (sidLen > 0) {
            byte[] sid = new byte[sidLen];
            System.arraycopy(chBody, 35, sid, 0, sidLen);
            messageBuilder.setClientSessionId(sid);
            // Только CH1: dummy CCS отправляется один раз, после первого сообщения сервера
            // (HRR или ServerHello). На CH2 после HRR он уже отправлен.
            if (!hrrSent) {
                serverCcsPending.set(true);
            }
        }

        // Выбор группы по ВСЕМ записям key_share (RFC 8446 §4.1.4, §4.2.8). Парсер записи не
        // выбирает: иначе HRR мог бы запросить группу, для которой клиент уже прислал key_share.
        List<TlsMessageParser.KeyShareEntry> shares = parsedCH.keyShareEntries;
        TlsMessageParser.KeyShareEntry chosen;
        if (hrrSent) {
            // CH2 после HRR: ровно одна запись с запрошенной группой (§4.1.2, §4.2.8)
            if (!parsedCH.keySharePresent
                    || shares.size() != 1
                    || shares.get(0).group() != hrrRequestedGroup) {
                throw new TlsException(
                        TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ClientHello after HRR: key_share must contain exactly one entry for"
                                + " group 0x"
                                + Integer.toHexString(hrrRequestedGroup));
            }
            chosen = shares.get(0);
        } else {
            if (!parsedCH.keySharePresent) {
                throw new TlsException(
                        TlsConstants.ALERT_MISSING_EXTENSION,
                        "ClientHello: key_share extension required");
            }
            // Пустой client_shares - запрос выбора группы у сервера (RFC 8446 §4.2.8). Выбирать
            // группу можно только из supported_groups, а он обязателен при key_share (§9.2).
            if (shares.isEmpty() && !parsedCH.supportedGroupsDeclared) {
                throw new TlsException(
                        TlsConstants.ALERT_MISSING_EXTENSION,
                        "ClientHello: supported_groups required with empty key_share");
            }
            int[] shareGroups = new int[shares.size()];
            for (int i = 0; i < shareGroups.length; i++) {
                shareGroups[i] = shares.get(i).group();
            }
            chosen = null;
            // 1. Предпочтение сервера есть среди записей key_share
            for (TlsMessageParser.KeyShareEntry e : shares) {
                if (e.group() == selectedNamedGroup) {
                    chosen = e;
                    break;
                }
            }
            // 2. Предпочтение сервера есть у клиента, но без key_share: HRR на него
            if (chosen == null
                    && parsedCH.supportedGroupsDeclared
                    && containsGroup(parsedCH.supportedGroups, selectedNamedGroup)) {
                hrrRequestedGroup = selectedNamedGroup;
                sendHelloRetryRequest(selectedNamedGroup, clientPsk);
                return;
            }
            // 3. Первая поддерживаемая сервером запись key_share: принимаем без HRR
            if (chosen == null) {
                for (TlsMessageParser.KeyShareEntry e : shares) {
                    // RFC 8701 §3.1: GREASE и другие неизвестные группы игнорируются
                    if (isServerSupportedGroup(e.group())) {
                        chosen = e;
                        break;
                    }
                }
            }
            // 4. Иначе HRR на поддерживаемую группу клиента, отсутствующую в key_share
            if (chosen == null) {
                int hrrGroup =
                        parsedCH.supportedGroupsDeclared
                                ? selectHrrGroup(parsedCH.supportedGroups, shareGroups)
                                : 0;
                // 5. Общей группы нет
                if (hrrGroup == 0) {
                    throw new TlsException(
                            TlsConstants.ALERT_HANDSHAKE_FAILURE,
                            "No compatible group between client and server");
                }
                hrrRequestedGroup = hrrGroup;
                sendHelloRetryRequest(hrrGroup, clientPsk);
                return;
            }
        }

        int actualGroup = chosen.group();
        // SNI пишется только на DEBUG и только очищенным: имя узла приходит от клиента
        if (log.isLoggable(Level.DEBUG)) {
            log.log(
                    Level.DEBUG,
                    "ClientHello accepted: cipher suite {0}, group 0x{1}, PSK accepted={2},"
                            + " sni={3}, after HelloRetryRequest={4}",
                    ciphersuite.forLog(),
                    String.format("%04x", actualGroup),
                    pskAccepted,
                    TlsUtils.peerTextForLog(clientServerName),
                    hrrSent);
        }
        ECParameters actualEcParams =
                actualGroup == selectedNamedGroup
                        ? ecParams
                        : TlsCiphersuite.namedGroupToParams(actualGroup);

        // Декодируем публичный ключ клиента
        byte[] peerKeyRaw = chosen.key();
        PublicKeyParameters peerPub = TlsEncoding.decodePoint(peerKeyRaw, actualEcParams);
        ctx.setPeerEcdhePublicKey(peerPub);

        // Генерируем свою ECDHE-пару на той же группе
        KeyPair ecdheKp = KeyGenerator.generateKeyPair(actualEcParams);
        ctx.setEcdhePrivateKey(ecdheKp.getPrivate());
        byte[] ecdhePoint = TlsEncoding.encodePoint(ecdheKp.getPublic());

        // Shared secret. Эфемерный ключ после расчёта не нужен (forward secrecy): затираем сам
        // ключ, а не только ссылку на него. Уже затёртый объект остаётся в контексте до его
        // уничтожения в конце рукопожатия: нулевые байты секрета не несут
        byte[] sharedSecret;
        try {
            sharedSecret =
                    computeEcdheShared(ctx.getEcdhePrivateKey(), ctx.getPeerEcdhePublicKey());
        } finally {
            ctx.getEcdhePrivateKey().destroy();
        }

        ctx.setKeySchedule(new TlsKeySchedule(ciphersuite));
        if (pskAccepted) {
            ctx.getKeySchedule().deriveEarlySecret(pskKey);
        }
        TlsUtils.wipeArray(pskKey);
        pskKey = null;
        wipeCh1PskState();
        try {
            ctx.getKeySchedule().deriveHandshakeSecret(sharedSecret);
        } finally {
            TlsUtils.wipeArray(sharedSecret);
        }

        // ServerHello: key_share с той же группой, что у клиента
        byte[] shBody = messageBuilder.buildServerHello(ecdhePoint, acceptedPskIndex, actualGroup);
        byte[] shFrame = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, shBody).encode();
        ctx.addToTranscript(shFrame);
        queueMessage(shFrame);

        // Вырабатываем handshake traffic keys
        byte[] hsTranscript = ctx.transcriptHash();
        this.serverHandshakeTrafficSecret =
                ctx.getKeySchedule().getServerHandshakeTrafficSecret(hsTranscript);
        this.clientHandshakeTrafficSecret =
                ctx.getKeySchedule().getClientHandshakeTrafficSecret(hsTranscript);
        TlsUtils.wipeArray(hsTranscript);

        handshakeServerKeys = ctx.getKeySchedule().deriveTrafficKeys(serverHandshakeTrafficSecret);
        handshakeClientKeys = ctx.getKeySchedule().deriveTrafficKeys(clientHandshakeTrafficSecret);

        // Читать ключами рукопожатия сервер начинает сразу (следующая запись клиента зашифрована),
        // а писать — после ServerHello: он уходит открытым, смена ключа стоит в потоке сразу за ним
        // (RFC 8446 §4.1.3, §5.1)
        changeReadKeys(handshakeClientKeys);
        queueWriteKeyChange(handshakeServerKeys);

        // ALPN (RFC 7301 §3.2): selector или auto-select.
        // Контракт селектора совпадает с JDK (SSLEngine.setHandshakeApplicationProtocolSelector):
        // null - отказ, рукопожатие завершается алертом no_application_protocol; пустая строка -
        // протокол не выбран, продолжаем без ALPN. Молчаливое превращение отказа в успех
        // позволило бы пиру обойти политику сервера.
        // Иначе auto-select по serverAlpnProtocols (как в фазе 3).
        List<String> clientAlpn = TlsMessageParser.parseClientHelloAlpn(chBody);
        if (clientAlpn != null && !clientAlpn.isEmpty()) {
            if (alpnSelector != null) {
                String selected = alpnSelector.apply(clientAlpn);
                if (selected == null) {
                    throw new TlsException(
                            TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                            "ALPN selector rejected the client protocol list");
                }
                if (!selected.isEmpty()) {
                    if (!clientAlpn.contains(selected)) {
                        throw new TlsException(
                                TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                                "Selector returned protocol not in client list");
                    }
                    this.selectedAlpnProtocol = selected;
                }
            } else if (serverAlpnProtocols != null) {
                String selected = TlsMessageParser.selectAlpn(serverAlpnProtocols, clientAlpn);
                if (selected == null) {
                    throw new TlsException(
                            TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                            "No common ALPN protocol between client and server");
                }
                this.selectedAlpnProtocol = selected;
            }
        }

        // EncryptedExtensions — с опциональным ALPN и max_fragment_length (RFC 6066 §4)
        byte[] eeBody =
                TlsMessageBuilder.buildEncryptedExtensions(selectedAlpnProtocol, maxFragmentLength);
        byte[] eeFrame =
                new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, eeBody).encode();
        ctx.addToTranscript(eeFrame);
        queueMessage(eeFrame);

        if (!pskAccepted) {
            // CertificateRequest (если требуется mTLS)
            if (requestClientAuth) {
                byte[] crBody =
                        TlsMessageBuilder.buildCertificateRequest(oidFilters, requestClientOcsp);
                byte[] crFrame =
                        new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE_REQUEST, crBody)
                                .encode();
                ctx.addToTranscript(crFrame);
                queueMessage(crFrame);
            }

            // Certificate
            byte[] certBody =
                    ocspForCert != null
                            ? messageBuilder.buildCertificateBody(ocspForCert)
                            : messageBuilder.buildCertificateBody();
            byte[] certFrame =
                    new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, certBody).encode();
            ctx.addToTranscript(certFrame);
            queueMessage(certFrame);

            // CertificateVerify
            byte[] cvTranscript = ctx.transcriptHash();
            byte[] cvBody = messageBuilder.buildCertificateVerify(cvTranscript);
            TlsUtils.wipeArray(cvTranscript);
            byte[] cvFrame =
                    new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE_VERIFY, cvBody).encode();
            ctx.addToTranscript(cvFrame);
            queueMessage(cvFrame);

            // Server Finished
            byte[] sfTranscript = ctx.transcriptHash();
            byte[] sfBody =
                    TlsMessageBuilder.buildFinished(
                            ctx.getKeySchedule(), serverHandshakeTrafficSecret, sfTranscript);
            TlsUtils.wipeArray(sfTranscript);
            byte[] sfFrame = new TlsHandshakeMessage(TlsConstants.HT_FINISHED, sfBody).encode();
            ctx.addToTranscript(sfFrame);
            // RFC 8446 §7.1 Table 2: app transcript = ClientHello...server Finished
            this.appTranscriptHash = ctx.transcriptHash();
            queueMessage(sfFrame);
            scheduleServerApplicationKeys();

            pendingNextState =
                    requestClientAuth
                            ? State.SERVER_WAIT_CLIENT_CERTIFICATE
                            : State.SERVER_WAIT_CLIENT_FINISHED;
        } else {
            // PSK сокращённый handshake: только Finished
            byte[] sfTranscript = ctx.transcriptHash();
            byte[] sfBody =
                    TlsMessageBuilder.buildFinished(
                            ctx.getKeySchedule(), serverHandshakeTrafficSecret, sfTranscript);
            TlsUtils.wipeArray(sfTranscript);
            byte[] sfFrame = new TlsHandshakeMessage(TlsConstants.HT_FINISHED, sfBody).encode();
            ctx.addToTranscript(sfFrame);
            this.appTranscriptHash = ctx.transcriptHash();
            queueMessage(sfFrame);
            scheduleServerApplicationKeys();

            pendingNextState = State.SERVER_WAIT_CLIENT_FINISHED;
        }

        state = State.SERVER_SEND_FLIGHT;
    }

    /**
     * Принимает клиентский Certificate (mTLS, RFC 8446 §4.4.2).
     * Парсит цепочку, сохраняет для валидации, переходит в ожидание CertificateVerify.
     *
     * @param frame полный handshake-фрейм Certificate
     * @throws TlsException при нарушении протокола
     */
    private void receiveClientCertificate(byte[] frame) throws TlsException {
        TlsHandshakeMessage certMsg = TlsHandshakeMessage.decode(frame);
        if (certMsg.getType() != TlsConstants.HT_CERTIFICATE) {
            // Почему CERTIFICATE_REQUIRED, а не UNEXPECTED_MESSAGE: алерт decode_error
            // пугает операторов (security incident), а certificate_required — это
            // configuration issue (клиент не настроен на mTLS). Разница в triage — часы.
            throw new TlsException(
                    TlsConstants.ALERT_CERTIFICATE_REQUIRED,
                    "Expected client Certificate, got " + certMsg.getType());
        }
        ctx.addToTranscript(frame);

        // status_request в CertificateEntry допустим, только если мы запросили его в
        // CertificateRequest; иначе это незапрошенное расширение (RFC 8446 §4.2).
        // Неизвестные расширения парсер игнорирует по §4.2.
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        certMsg.getBody(),
                        requestClientOcsp ? Set.of(TlsConstants.EXT_STATUS_REQUEST) : Set.of());
        if (chain.isEmpty()) {
            // RFC 8446 §4.4.2: клиент может прислать пустой certificate_list если нет сертификата.
            // Решение о том, обязателен ли сертификат, принимается на уровне engine
            // (requestClientAuth)
            // с учётом optionalClientAuth (wantClientAuth).
            if (requestClientAuth && !optionalClientAuth) {
                throw new TlsException(
                        TlsConstants.ALERT_CERTIFICATE_REQUIRED,
                        "Client did not provide certificate");
            }
            // wantClientAuth или requestClientAuth=false: пустой сертификат — штатно,
            // ожидаем Finished от клиента (без CertificateVerify).
            state = State.SERVER_WAIT_CLIENT_FINISHED;
            return;
        }
        receivedCertificates = chain;
        needsCertValidation = true;
        state = State.SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY;
    }

    /**
     * Принимает и верифицирует клиентский Finished (RFC 8446 §4.4.4).
     * <p>
     * Пересчитывает verify_data через handshake-транскрипт и clientHandshakeTrafficSecret.
     * При успехе вырабатывает Master Secret, application traffic keys (серверные для записи,
     * клиентские для чтения) и переводит handshake в POST_HANDSHAKE.
     *
     * @param frame полный handshake-фрейм Finished
     * @throws TlsException при нарушении протокола
     */
    private void receiveClientFinished(byte[] frame) throws TlsException {
        TlsHandshakeMessage cfMsg = TlsHandshakeMessage.decode(frame);
        if (cfMsg.getType() != TlsConstants.HT_FINISHED) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected client Finished, got " + cfMsg.getType());
        }
        byte[] clientFinishedTranscript = ctx.transcriptHash();
        ctx.addToTranscript(frame);

        byte[] expectedVerifyData =
                TlsMessageBuilder.buildFinished(
                        ctx.getKeySchedule(),
                        clientHandshakeTrafficSecret,
                        clientFinishedTranscript);
        if (!java.security.MessageDigest.isEqual(cfMsg.getBody(), expectedVerifyData)) {
            TlsUtils.wipeArray(clientFinishedTranscript);
            throw new TlsException(
                    TlsConstants.ALERT_DECRYPT_ERROR, "Client Finished verification failed");
        }

        // RMS = Derive-Secret(MS, "res master", Transcript-Hash) после включения CF; мастер-секрет
        // выработан вместе с ключами приложения, когда Finished сервера встал в очередь
        byte[] hsTranscript = ctx.transcriptHash();
        this.resumptionMasterSecret = ctx.getKeySchedule().getResumptionMasterSecret(hsTranscript);
        TlsUtils.wipeArray(hsTranscript);
        TlsUtils.wipeArray(clientFinishedTranscript);
        // Ключи приложения выработаны обеими серверными ветками (полной и PSK) при постановке
        // Finished сервера; их отсутствие значит ошибку кода
        if (readKeysAfterPeerFinished == null) {
            // TlsException, а не IllegalStateException: это обычный фатальный путь рукопожатия
            // (alert, закрытие, затирание ключей), а в jsse IllegalStateException читается как
            // «движок закрыт» и ошибку кода не выдаёт
            throw new TlsException(
                    TlsConstants.ALERT_INTERNAL_ERROR, "Application keys not derived");
        }
        // Ключ записи приложения уже действует с конца полёта сервера; меняется только ключ чтения
        changeReadKeys(readKeysAfterPeerFinished);
        readKeysAfterPeerFinished = null;

        // Handshake-ключи больше не нужны — соединение перешло на app traffic keys
        if (handshakeServerKeys != null) {
            handshakeServerKeys.destroy();
            handshakeServerKeys = null;
        }
        if (handshakeClientKeys != null) {
            handshakeClientKeys.destroy();
            handshakeClientKeys = null;
        }
        TlsUtils.wipeArray(serverHandshakeTrafficSecret);
        serverHandshakeTrafficSecret = null;
        TlsUtils.wipeArray(clientHandshakeTrafficSecret);
        clientHandshakeTrafficSecret = null;

        receivedCertificates = null;
        state = State.POST_HANDSHAKE;
        ctx.destroy();
    }

    // ========================================================================
    // SNI
    // ========================================================================

    /**
     * Устанавливает DNS-имя сервера для включения в расширение server_name ClientHello.
     * Вызывать до {@link #start()}.
     *
     * @param serverHostname DNS-имя сервера (null = без SNI)
     * @throws IllegalArgumentException если имя нельзя отправить в SNI: управляющие символы,
     *                                  не-ASCII, длина больше
     *                                  {@link TlsConstants#MAX_SERVER_NAME_LENGTH}, пустые метки
     */
    public void setServerHostname(String serverHostname) {
        // Ошибка в момент вызова, а не внутри start() и не как internal_error рукопожатия
        ServerNameCheck.requireValidForSni(serverHostname);
        this.serverHostname = serverHostname;
    }

    /**
     * @return DNS-имя, запрошенное клиентом через SNI (сервер), или null
     */
    public String getRequestedServerName() {
        return requestedServerName;
    }

    // ========================================================================
    // ALPN (RFC 7301)
    // ========================================================================

    /**
     * Устанавливает протоколы ALPN клиента для включения в ClientHello.
     * Вызывать до {@link #start()}.
     *
     * @param protocols список протоколов ALPN в порядке убывания предпочтения
     */
    public void setClientAlpnProtocols(List<String> protocols) {
        TlsUtils.validateAlpnProtocolsIfPresent(protocols);
        this.clientAlpnProtocols = protocols;
    }

    /**
     * Устанавливает протоколы ALPN сервера для выбора из списка клиента.
     * Вызывать до {@link #start()}.
     * Сервер выбирает первый протокол из этого списка, который также предлагает клиент
     * (RFC 7301 §3.2). При отсутствии пересечения — ALERT_NO_APPLICATION_PROTOCOL.
     *
     * @param protocols список протоколов ALPN в порядке убывания предпочтения
     */
    public void setServerAlpnProtocols(List<String> protocols) {
        TlsUtils.validateAlpnProtocolsIfPresent(protocols);
        this.serverAlpnProtocols = protocols;
    }

    /**
     * @return согласованный протокол ALPN, или null если ALPN не использовался
     */
    public String getSelectedAlpnProtocol() {
        return selectedAlpnProtocol;
    }

    /**
     * Устанавливает server-side ALPN-селектор.
     * <p>
     * Если задан, вызывается после парсинга ClientHello для выбора ALPN.
     * Избранный протокол проверяется на вхождение в список клиента.
     * null от selector = отказ: рукопожатие завершается фатальным алертом
     * no_application_protocol (120); пустая строка = ALPN не использовать
     * (EE без extension), как в контракте JDK.
     * <p>
     * Используется {@code javax.net.ssl.SSLParameters.setHandshakeApplicationProtocolSelector}
     * из JSSE.
     */
    public void setAlpnSelector(
            java.util.function.Function<java.util.List<String>, String> selector) {
        this.alpnSelector = selector;
    }

    // ========================================================================
    // PSK (публичный API, вызывается перед start())
    // ========================================================================

    /**
     * Устанавливает PSK-параметры для клиента.
     * Вызывать до {@link #start()}.
     * <p>Только путь возобновления: binder считается с меткой {@code res binder}. Внешние PSK
     * (метка {@code ext binder}, RFC 8446 §4.2.11.2) не поддерживаются.</p>
     *
     * @param psk                PSK-ключ
     * @param identity           тикет (opaque ticket)
     * @param obfuscatedTicketAge obfuscated_ticket_age
     * @throws IllegalStateException если engine работает в роли сервера: у сервера PSK
     *                               задаётся через {@link #setServerPsk} или
     *                               {@link #setServerPskStore}
     * @throws IllegalArgumentException если {@code psk} равен null или {@code identity} равна null,
     *                                  пуста или заведомо не помещается в расширение pre_shared_key
     *                                  ({@link TlsPskHelper#maxIdentityLength}). Проверка грубая:
     *                                  принятая identity всё же может не поместиться в ClientHello
     *                                  вместе с другими расширениями, тогда PSK снимается
     *                                  ({@link #isPskOfferWithdrawn()})
     */
    public void setPsk(byte[] psk, byte[] identity, long obfuscatedTicketAge) {
        // Клиентский PSK на сервере принимался бы binder-ом и молча отключал
        // CertificateRequest, то есть клиентскую аутентификацию (mTLS).
        if (role != Role.CLIENT) {
            throw new IllegalStateException("setPsk is a client-only operation");
        }
        if (psk == null) {
            throw new IllegalArgumentException("psk must not be null");
        }
        // Строгий сервер отвергает пустую identity (opaque identity<1..2^16-1>, RFC 8446 §4.2.11):
        // лучше отказать при настройке, чем получить decode_error от пира посреди рукопожатия
        // Верхняя граница - размер расширения, а не 2^16-1 из синтаксиса identity: длиннее тикет в
        // ClientHello не помещается
        int maxIdentityLength = TlsPskHelper.maxIdentityLength(hashLen);
        if (identity == null || identity.length == 0 || identity.length > maxIdentityLength) {
            throw new IllegalArgumentException(
                    "PSK identity must be 1.." + maxIdentityLength + " bytes");
        }
        this.pskKey = psk.clone();
        this.pskIdentity = identity;
        this.obfuscatedTicketAge = obfuscatedTicketAge;
        this.pskOffered = true;
    }

    /**
     * Устанавливает PSK-ключ для сервера (для верификации binder'а).
     * Вызывать до {@link #start()}.
     * <p>Только путь возобновления: binder проверяется с меткой {@code res binder}. Внешние PSK
     * (метка {@code ext binder}, RFC 8446 §4.2.11.2) не поддерживаются.</p>
     *
     * @param psk PSK-ключ
     * @throws IllegalStateException если engine не серверный или запрошен клиентский сертификат
     * @throws IllegalArgumentException если {@code psk} равен null
     */
    public void setServerPsk(byte[] psk) {
        if (role != Role.SERVER) {
            throw new IllegalStateException("setServerPsk is a server-only operation");
        }
        if (psk == null) {
            throw new IllegalArgumentException("psk must not be null");
        }
        if (requestClientAuth) {
            throw new IllegalStateException(
                    "Explicit server PSK is not allowed when client certificate authentication"
                            + " is requested");
        }
        this.pskKey = psk.clone();
    }

    /**
     * Устанавливает PskStore для автоматического PSK-lookup на сервере.
     * При получении ClientHello engine сам извлекает PSK identity, ищет в store
     * и устанавливает pskKey — без необходимости внешнего парсинга ClientHello.
     *
     * <p>При запросе клиентского сертификата (need и want) хранилище принимается, но не
     * используется: PSK несовместим с mTLS, поэтому handshake идёт полным.</p>
     *
     * @throws IllegalStateException если engine не серверный
     */
    public void setServerPskStore(PskStore store) {
        if (role != Role.SERVER) {
            throw new IllegalStateException("setServerPskStore is a server-only operation");
        }
        this.serverPskStore = store;
    }

    /**
     * @return true, если клиентский PSK был задан, но в ClientHello не поместился и снят: тикет
     *         предъявить нельзя, его следует убрать из кэша. Рукопожатие идёт полным.
     */
    public boolean isPskOfferWithdrawn() {
        return pskOfferWithdrawn;
    }

    /** @return true если PSK был принят */
    public boolean isPskAccepted() {
        return pskAccepted;
    }

    /**
     * @return true если сервер запрашивает сертификат клиента (mTLS) или клиент
     *         получил CertificateRequest
     */
    public boolean isClientAuthRequested() {
        return requestClientAuth || clientAuthRequested;
    }

    /**
     * Цепочка клиентского сертификата, которая реально уходит серверу (клиентская роль).
     * <p>
     * Читать после получения CertificateRequest: селектор или сверка схем подписи могли заменить
     * цепочку из конфигурации или обнулить её. Пустой результат означает пустой Certificate.
     *
     * @return неизменяемая цепочка (лист первым), пустой список при пустом Certificate или
     *         {@code null}, если сервер не присылал CertificateRequest (сертификат не запрашивался)
     */
    public List<GostCertificate> getSentClientCertificateChain() {
        if (!clientAuthRequested) {
            return null;
        }
        List<GostCertificate> chain = messageBuilder.getCertificateChain();
        return chain == null ? List.of() : List.copyOf(chain);
    }

    /**
     * @return код max_fragment_length (1..4) согласованный с пиром, или 0 если не согласован
     */
    public int getMaxFragmentLength() {
        return maxFragmentLength;
    }

    /**
     * Устанавливает код max_fragment_length, который клиент отправил в ClientHello
     * (для последующей верификации ответа сервера, RFC 6066 §4.1).
     */
    public void setClientMaxFragLenRequest(int code) {
        this.clientMaxFragLenRequest = code;
    }

    /**
     * Зачищает ключевой материал.
     * Вызывается владельцем engine после завершения или ошибки.
     */
    public void destroy() {
        serverCcsPending.set(false);
        if (handshakeServerKeys != null) handshakeServerKeys.destroy();
        if (handshakeClientKeys != null) handshakeClientKeys.destroy();
        if (readKeys != null
                && readKeys != handshakeServerKeys
                && readKeys != handshakeClientKeys) {
            readKeys.destroy();
        }
        if (serverHandshakeTrafficSecret != null) {
            TlsUtils.wipeArray(serverHandshakeTrafficSecret);
            serverHandshakeTrafficSecret = null;
        }
        if (clientHandshakeTrafficSecret != null) {
            TlsUtils.wipeArray(clientHandshakeTrafficSecret);
            clientHandshakeTrafficSecret = null;
        }
        if (serverAppTrafficSecret != null) {
            TlsUtils.wipeArray(serverAppTrafficSecret);
            serverAppTrafficSecret = null;
        }
        if (clientAppTrafficSecret != null) {
            TlsUtils.wipeArray(clientAppTrafficSecret);
            clientAppTrafficSecret = null;
        }
        if (appTranscriptHash != null) {
            TlsUtils.wipeArray(appTranscriptHash);
            appTranscriptHash = null;
        }
        // Отложенная смена ключа чтения: при срыве рукопожатия до Finished клиента ключи
        // приложения уже выработаны и иначе остались бы в памяти
        if (readKeysAfterPeerFinished != null) {
            readKeysAfterPeerFinished.destroy();
            readKeysAfterPeerFinished = null;
        }
        if (ctx != null) ctx.destroy();
        if (resumptionMasterSecret != null) {
            TlsUtils.wipeArray(resumptionMasterSecret);
            resumptionMasterSecret = null;
        }
        if (exporterMasterSecret != null) {
            TlsUtils.wipeArray(exporterMasterSecret);
            exporterMasterSecret = null;
        }
        TlsUtils.wipeArray(pskKey);
        pskKey = null;
        wipeCh1PskState();
        acceptedPskIndex = TlsMessageBuilder.NO_SELECTED_PSK;
        pskIdentity = null;
        obfuscatedTicketAge = 0;
        // Неотданный поток: сообщения и ключи в метках смены ключа записи
        HandshakeOutput item;
        while ((item = outgoingQueue.pollFirst()) != null) {
            if (item instanceof HandshakeOutput.Message message) {
                TlsUtils.wipeArray(message.frame());
            } else if (item instanceof HandshakeOutput.WriteKeyChange change) {
                change.destroy();
            }
        }
        receivedCertificates = null;
    }

    /**
     * Вычисляет ECDHE shared secret по RFC 9367 §6.1.1.1 (шаг 6, сторона клиента) и
     * §6.1.1.2 (шаг 5, сторона сервера): {@code Q = (h · d) · Q_peer}, где {@code h} — кофактор
     * кривой. Результат — координата X точки {@code Q} в little-endian длиной
     * {@code coordinate_length} (шаг 8 и шаг 7 соответственно).
     * <p>
     * Кофактор обязателен: на кривых с {@code h = 4} (GC256A, GC512C) секрет без него не совпадёт
     * с секретом пира, а свои клиент и сервер ошибались бы одинаково и расхождение не обнаружили
     * бы. Вычисление делегировано в {@link KeyAgreement#computeSharedSecret}, где кофактор
     * учтён и проверяется совпадение кривых ключей.
     * <p>
     * Метод static и не сохраняет shared secret в полях экземпляра — безопасность:
     * вызывающий код обязан занулить результат через {@code TlsUtils.wipeArray}.
     *
     * @return shared secret (X-координата в LE, {@code coordinate_length} байт)
     * @throws TlsException handshake_failure, если кривые ключей различаются или общая точка —
     *     бесконечность
     */
    static byte[] computeEcdheShared(PrivateKeyParameters myPriv, PublicKeyParameters peerPub)
            throws TlsException {
        try {
            return KeyAgreement.computeSharedSecret(myPriv, peerPub);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "ECDHE shared secret computation failed: " + e.getMessage(),
                    e);
        }
    }

    /**
     * Проверяет ticket_age при PSK-возобновлении (RFC 8446 §4.2.11.2).
     * <p>
     * Вычисляет ожидаемый возраст тикета (now - issueTime) mod 2^32,
     * сравнивает с возрастом клиента (obfuscated_ticket_age - ticket_age_add) mod 2^32.
     * Допуск {@link TlsConstants#PSK_AGE_TOLERANCE_MS} компенсирует clock skew
     * и сетевую задержку.
     *
     * @param obfuscatedTicketAge возраст от клиента (uint32)
     * @param issueTime           момент выписки тикета (мс)
     * @param ticketAgeAdd        обфускация возраста (uint32)
     * @return true если возраст в допуске, false — расхождение (не атака, отказ от PSK)
     */
    private static boolean validatePskTicketAge(
            long obfuscatedTicketAge, long issueTime, long ticketAgeAdd) {
        long expectedAge = (System.currentTimeMillis() - issueTime) & 0xFFFFFFFFL;
        long clientAge = (obfuscatedTicketAge - ticketAgeAdd) & 0xFFFFFFFFL;
        long diff = Math.abs(expectedAge - clientAge);
        diff = Math.min(diff, (1L << 32) - diff);
        return diff <= TlsConstants.PSK_AGE_TOLERANCE_MS;
    }
}
