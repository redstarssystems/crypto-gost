package org.rssys.gost.tls13;

import java.io.EOFException;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.PeerTrustBoundary;
import org.rssys.gost.tls13.cert.TlsCertUtils;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import org.rssys.gost.tls13.cert.TlsPeerPolicy;
import org.rssys.gost.tls13.config.ClientAuth;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.engine.HandshakeOutput;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.HandshakeMessageAssembler;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.psk.TlsTicketHelper;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.record.UnprotectResult;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.GostLogger;

/**
 * TLS 1.3 сессия с Kuznyechik-MGM-Streebog.
 * Полный handshake (клиент/сервер) + защищённая передача данных.
 * <p>Не thread-safe. Каждый экземпляр должен использоваться в одном потоке: рукопожатие, обмен
 * данными и {@link #close()} выполняет один и тот же поток (либо потоки, строго
 * упорядоченные по времени, например после {@code Future.get()}). Прервать зависшее рукопожатие
 * из другого потока можно только закрытием транспорта, см. {@link #close()}.
 */
public final class TlsSession implements AutoCloseable {

    private static final GostLogger LOG = GostLogger.getLogger("org.rssys.gost.tls13.TlsSession");

    /**
     * Логгер соединения. Не final: движок создаётся лениво в runHandshake, и метка
     * {@code conn#N} появляется только вместе с ним. До этого записи идут без префикса.
     * Сессия по контракту не потокобезопасна; volatile - на случай чтения из другого потока
     * после завершения рукопожатия (read()).
     */
    private volatile GostLogger log = LOG;

    private final TlsTransport transport;
    // Набор из конфигурации; по завершении рукопожатия заменяется согласованным (на любой стороне,
    // если пир выбрал другой из предложенных)
    private TlsCiphersuite ciphersuite;
    private final Digest.Algorithm offeredKdfHash;
    private final int hashLen; // Оба Kuznyechik-MGM suite (L и S) имеют hashLen=32

    // Аутентификация (долговременный ключ для CertificateVerify)
    private final List<GostCertificate> ourCertificateChain;
    private final PrivateKeyParameters ourPrivateKey;
    private final TrustAnchors trustAnchors;
    private final String serverHostname;
    private final boolean requireOcspStapling;
    // Явный режим: false только для createClientWithoutServerAuth.
    private final boolean verifyServerChain;
    private final byte[] ocspResponse;

    // Параметры, выбранные при handshake (RFC 8446: независимо от cipher suite)
    private int selectedNamedGroup = TlsConstants.GRP_GC256B;
    private ECParameters selectedEcParams = ECParameters.cryptoProA();
    private int selectedSigScheme;

    // Защищённая передача
    private TlsRecord readerRecord;
    private TlsRecord writerRecord;

    // Построитель сообщений
    private TlsMessageBuilder messageBuilder;

    // Состояние
    private boolean handshakeDone;
    // Итог последнего завершённого рукопожатия: переживает close(), когда engine уже уничтожен
    private boolean handshakeCompletedOnce;
    private boolean lastHandshakeResumed;
    private boolean closed;
    private List<GostCertificate> peerCertificates;

    // Сборка сообщений рукопожатия: общий с движком JSSE разбор, пределы и граница записи
    private final HandshakeMessageAssembler handshakeBuffer = new HandshakeMessageAssembler();

    // Переиспользуемые ByteBuffer-буферы для zero-alloc чтения. TlsRecord
    // скопирует данные в свой recordBuf (MGM принимает только byte[]), но
    // transport не аллоцирует промежуточные массивы.
    private final ByteBuffer sessionRecordBuf =
            ByteBuffer.allocate(
                    TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH);
    private final ByteBuffer sessionPlainBuf =
            ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

    // PSK-хранилище (session resumption)
    private PskStore pskStore;

    // SNI: для клиента — hostname из конфига, для сервера — что запросил клиент
    private String requestedServerName;

    // ALPN (RFC 7301)
    private List<String> alpnProtocols;

    // max_fragment_length (RFC 6066 §4): лимит на фрагментацию отправки
    private int maxPayload = TlsConstants.MAX_PLAINTEXT_LENGTH - 1;
    // Запрос клиента (1..4) для включения в ClientHello, 0 = не запрашивать
    private int maxFragLenRequest;

    // SNI certificate selection (сервер, RFC 6066 §3)
    private SniCertificateSelector sniSelector;
    // OID-фильтры для CertificateRequest (сервер, RFC 8446 §4.2.5)
    private List<OIDFilter> oidFilters;
    // Селектор сертификата клиента по oid_filters (клиент)
    private ClientCertificateSelector clientCertSelector;
    // Политика OCSP-staple клиентского сертификата (сервер, RFC 8446 §4.4.2.1)
    private ClientOcspPolicy clientOcspPolicy = ClientOcspPolicy.OFF;
    private ClientAuth clientAuthMode = ClientAuth.NONE;

    /** Обход openssl-gost-provider: принимать базовые схемы (0x0709/0x070D). */
    private boolean interopAcceptGostBaseSigScheme;

    /**
     * Явный отказ от сверки имени узла с сертификатом сервера. SNI при этом не меняется:
     * {@link #serverHostname} по-прежнему уходит серверу.
     */
    private boolean hostnameVerificationDisabled;

    /**
     * Привязка клиентских PSK-тикетов этой сессии; null, если PSK предлагать нельзя
     * (при сверке имени оно пусто). Вычисляется лениво, а не в конструкторе: флаги проверки
     * сервера фабрики выставляют уже после создания сессии.
     */
    private PskBinding clientPskBinding;

    private boolean clientPskBindingResolved;

    /**
     * Граница доверия к серверу по сроку его сертификатов (миллисекунды эпохи), полученная при
     * полном рукопожатии клиента; {@link #BOUND_UNKNOWN}, пока сервер не проверен.
     */
    private long peerTrustValidUntil = BOUND_UNKNOWN;

    /**
     * Граница использованной для возобновления записи: при PSK-возобновлении сертификата нет, и
     * новые тикеты наследуют границу прежнего, иначе доверие продлевалось бы бесконечно.
     */
    private long resumedValidUntil = BOUND_UNKNOWN;

    /** Граница не определена: тикет с такой границей сохранять нельзя. */
    private static final long BOUND_UNKNOWN = Long.MIN_VALUE;

    private int ticketsToSend = 1;

    /**
     * Снимок флага mTLS: TlsHandshakeEngine уничтожается в close(), а решение
     * о выдаче тикета нельзя пересчитывать по уже освобождённому движку.
     */
    private boolean clientAuthRequested;

    // Engine остается жив после handshake для post-handshake сообщений
    // (KeyUpdate, NewSessionTicket). Application traffic secrets хранятся
    // в engine, не копируются в TlsSession — это устраняет дублирование
    // и даёт JSSE-модулю прямой доступ к engine.initiateKeyUpdate().
    private TlsHandshakeEngine engine;

    // ========================================================================
    // Фабричные методы
    // ========================================================================

    /**
     * Создаёт сессию для клиента через конфигурационный объект и транспорт.
     * <p>
     * Использование с try-with-resources — transport ДО session:
     * {@code try (TlsTransport tp = ...; TlsSession s = createClient(config, tp)) }
     * <p>
     * Caller владеет жизненным циклом transport: {@code TlsSession.close()} не закрывает transport.
     * Закрывать transport нужно явно после session.close() (try-with-resources с правильным порядком).
     */
    public static TlsSession createClient(TlsClientConfig config, TlsTransport transport) {
        // Staple без сертификата никуда не уйдёт; тихое игнорирование скрыло бы ошибку настройки.
        // Сертификат, выбранный селектором, несёт собственный staple (TlsClientCredentials).
        // Геттер OCSP-ответа отдаёт копию: читаем один раз и используем это же значение ниже
        byte[] ocspResponse = config.getOcspStaplingResponse();
        List<GostCertificate> clientChain = config.getClientCertificateChain();
        if (ocspResponse != null && (clientChain == null || clientChain.isEmpty())) {
            throw new IllegalArgumentException(
                    "OCSP staple is set but no client certificate chain is configured");
        }
        if (config.getServerHostname() == null && !config.isHostnameVerificationDisabled()) {
            throw new IllegalArgumentException(
                    "Server hostname not set."
                            + " Call withServerHostname() or withoutHostnameVerification()");
        }
        TlsSession session =
                new TlsSession(
                        transport,
                        config.getCiphersuite(),
                        clientChain,
                        config.getClientPrivateKey(),
                        config.getTrustAnchors(),
                        config.getServerHostname(),
                        config.isOcspRequired(),
                        ocspResponse,
                        true);
        session.alpnProtocols = config.getAlpnProtocols();
        session.clientCertSelector = config.getClientCertificateSelector();
        session.interopAcceptGostBaseSigScheme = config.isInteropAcceptGostBaseSigScheme();
        session.hostnameVerificationDisabled = config.isHostnameVerificationDisabled();
        session.applySelectedNamedGroup(config.getSelectedNamedGroup());
        return session;
    }

    /**
     * Создаёт клиентскую сессию БЕЗ проверки цепочки и hostname сервера.
     * <strong>Только для тестов и отладки.</strong> Проверки срока, KU, EKU
     * и OCSP leaf-сертификата сохраняются. В production используйте
     * {@link #createClient(TlsClientConfig, TlsTransport)}
     * с {@link TlsClientConfig#TlsClientConfig(TlsCiphersuite, TrustAnchors)}.
     *
     * <p>PSK-тикеты этой сессии привязаны к режиму «без аутентификации сервера», а не к якорям:
     * они не смешиваются с тикетами сессий, где сервер проверялся, и сохраняют ту же модель
     * доверия, что у полного рукопожатия этого режима.</p>
     *
     * @param transport       транспорт для связи с сервером
     * @param ciphersuite     cipher suite
     * @param clientCertificate сертификат клиента (null — без mTLS)
     * @param clientPrivateKey  закрытый ключ клиента (null — без mTLS)
     * @return клиентская TLS-сессия без аутентификации сервера
     */
    public static TlsSession createClientWithoutServerAuth(
            TlsTransport transport,
            TlsCiphersuite ciphersuite,
            GostCertificate clientCertificate,
            PrivateKeyParameters clientPrivateKey) {
        List<GostCertificate> chain =
                clientCertificate != null ? Collections.singletonList(clientCertificate) : null;
        return new TlsSession(
                transport, ciphersuite, chain, clientPrivateKey, null, null, false, null, false);
    }

    /**
     * Создаёт сессию для сервера через конфигурацию и транспорт.
     * <p>
     * Использование с try-with-resources — transport ДО session:
     * {@code try (TlsTransport tp = ...; TlsSession s = createServer(config, tp)) }
     * <p>
     * Caller владеет жизненным циклом transport: {@code TlsSession.close()} не закрывает transport.
     */
    public static TlsSession createServer(TlsServerConfig config, TlsTransport transport) {
        // Запрос staple имеет смысл только при проверке клиента; иначе политика молча
        // не работала бы, а оператор считал бы отзыв клиентов проверяемым.
        if (config.getClientOcspPolicy() != ClientOcspPolicy.OFF && !config.isClientAuthEnabled()) {
            throw new IllegalArgumentException(
                    "clientOcspPolicy requires client authentication"
                            + " (needClientAuth or wantClientAuth)");
        }
        TlsSession session =
                new TlsSession(
                        transport,
                        config.getCiphersuite(),
                        config.getServerCertificateChain(),
                        config.getServerPrivateKey(),
                        config.getTrustAnchors(),
                        null,
                        false,
                        config.getOcspStaplingResponse(),
                        true);
        session.sniSelector = config.getSniSelector();
        session.oidFilters = config.getOidFilters();
        session.alpnProtocols = config.getAlpnProtocols();
        session.ticketsToSend = config.getTicketsToSend();
        session.interopAcceptGostBaseSigScheme = config.isInteropAcceptGostBaseSigScheme();
        session.clientOcspPolicy = config.getClientOcspPolicy();
        session.clientAuthMode = config.getClientAuthMode();
        session.applySelectedNamedGroup(config.getSelectedNamedGroup());
        return session;
    }

    /**
     * Переключает предпочитаемую группу ECDHE: группа, параметры кривой и построитель сообщений
     * обновляются вместе, иначе ClientHello/ServerHello объявили бы одну группу, а ключи
     * строились бы на другой.
     *
     * @param namedGroup группа или 0 (оставить значение по умолчанию)
     */
    private void applySelectedNamedGroup(int namedGroup) {
        if (namedGroup == 0 || namedGroup == selectedNamedGroup) {
            return;
        }
        selectedNamedGroup = namedGroup;
        selectedEcParams = TlsCiphersuite.namedGroupToParams(namedGroup);
        messageBuilder =
                new TlsMessageBuilder(
                        ciphersuite,
                        messageBuilder.getOfferedCipherSuiteIds(),
                        namedGroup,
                        selectedSigScheme,
                        ourPrivateKey,
                        ourCertificateChain,
                        hashLen);
    }

    /** Создаёт сессию для сервера (прямые параметры, без конфига). */
    public static TlsSession createServer(
            TlsTransport transport,
            TlsCiphersuite ciphersuite,
            GostCertificate ourCertificate,
            PrivateKeyParameters ourPrivateKey) {
        if (ourCertificate == null) {
            throw new IllegalArgumentException("ourCertificate must not be null");
        }
        return createServer(
                new TlsServerConfig(
                        ciphersuite, Collections.singletonList(ourCertificate), ourPrivateKey),
                transport);
    }

    private TlsSession(
            TlsTransport transport,
            TlsCiphersuite ciphersuite,
            List<GostCertificate> ourCertificateChain,
            PrivateKeyParameters ourPrivateKey,
            TrustAnchors trustAnchors,
            String serverHostname,
            boolean requireOcspStapling,
            byte[] ocspResponse,
            boolean verifyServerChain) {
        if (transport == null) throw new IllegalArgumentException("transport must not be null");
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        this.transport = transport;
        this.ciphersuite = ciphersuite;
        this.hashLen = ciphersuite.getHashLen();
        this.offeredKdfHash = ciphersuite.getKdfHashAlgorithm();
        this.ourCertificateChain = ourCertificateChain;
        this.ourPrivateKey = ourPrivateKey;
        this.trustAnchors = trustAnchors;
        this.serverHostname = serverHostname;
        this.requireOcspStapling = requireOcspStapling;
        this.ocspResponse = ocspResponse;
        this.verifyServerChain = verifyServerChain;
        GostCertificate leafCert =
                (ourCertificateChain != null && !ourCertificateChain.isEmpty())
                        ? ourCertificateChain.get(0)
                        : null;
        this.selectedSigScheme =
                leafCert != null ? resolveSigScheme(leafCert) : TlsConstants.SIG_GOST_TC26_A_256;
        this.messageBuilder =
                new TlsMessageBuilder(
                        ciphersuite,
                        List.of(
                                TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S),
                        selectedNamedGroup,
                        selectedSigScheme,
                        ourPrivateKey,
                        ourCertificateChain,
                        hashLen);
    }

    // ========================================================================
    // Handshake — общая реализация через TlsHandshakeEngine
    // ========================================================================

    /**
     * Выполняет handshake со стороны клиента.
     *
     * @throws IOException при ошибке handshake
     */
    public void handshakeAsClient() throws IOException {
        runHandshake(TlsHandshakeEngine.Role.CLIENT);
    }

    /**
     * Выполняет handshake со стороны сервера.
     *
     * @throws IOException при ошибке handshake
     */
    public void handshakeAsServer() throws IOException {
        runHandshake(TlsHandshakeEngine.Role.SERVER);
    }

    /**
     * Единый движок handshake через {@link TlsHandshakeEngine}.
     * <p>
     * Управляет циклом: receive -> decrypt -> assemble -> engine.receive ->
     * poll -> send -> key changes -> cert validation.
     *
     * @param role роль участника handshake (CLIENT или SERVER)
     * @throws IOException при ошибке handshake
     */
    private void runHandshake(TlsHandshakeEngine.Role role) throws IOException {
        checkNotClosed();
        // В TLS 1.3 нет повторного согласования: второй вызов на живой сессии заменил бы движок
        // и сломал состояние записей. После ошибки сессия закрыта, и её отсекает checkNotClosed().
        if (handshakeCompletedOnce) {
            throw new IllegalStateException("Handshake already completed");
        }
        byte[] pskKey = null;
        try {
            // Режим задаётся конфигом сервера вместе с якорями, поэтому якорей без режима
            // и режима без якорей здесь не бывает. Клиентская роль всегда NONE.
            boolean requestClientAuth =
                    role == TlsHandshakeEngine.Role.SERVER && clientAuthMode != ClientAuth.NONE;
            boolean optionalClientAuth =
                    role == TlsHandshakeEngine.Role.SERVER && clientAuthMode == ClientAuth.WANT;

            this.engine =
                    new TlsHandshakeEngine(
                            role,
                            ciphersuite,
                            messageBuilder,
                            selectedEcParams,
                            selectedNamedGroup,
                            selectedSigScheme,
                            hashLen,
                            ocspResponse,
                            requestClientAuth,
                            sniSelector,
                            optionalClientAuth);
            this.log = LOG.withContext(engine.getConnectionLabel());

            // Передаём DNS-имя сервера для SNI (только клиент)
            if (role == TlsHandshakeEngine.Role.CLIENT && serverHostname != null) {
                engine.setServerHostname(serverHostname);
            }

            // ALPN: передаём протоколы в engine (RFC 7301)
            if (alpnProtocols != null) {
                if (role == TlsHandshakeEngine.Role.CLIENT) {
                    engine.setClientAlpnProtocols(alpnProtocols);
                } else {
                    engine.setServerAlpnProtocols(alpnProtocols);
                }
            }
            // max_fragment_length: передаём запрос клиента в engine
            if (maxFragLenRequest != 0) {
                engine.setClientMaxFragLenRequest(maxFragLenRequest);
            }

            // OID-фильтры для CertificateRequest (сервер)
            if (role == TlsHandshakeEngine.Role.SERVER
                    && oidFilters != null
                    && !oidFilters.isEmpty()) {
                engine.setOidFilters(oidFilters);
            }
            // Селектор сертификата клиента по oid_filters (клиент)
            if (role == TlsHandshakeEngine.Role.CLIENT && clientCertSelector != null) {
                engine.setClientCertificateSelector(clientCertSelector);
            }
            // Запрос staple клиентского сертификата (сервер)
            if (role == TlsHandshakeEngine.Role.SERVER
                    && requestClientAuth
                    && clientOcspPolicy != ClientOcspPolicy.OFF) {
                engine.setRequestClientOcsp(true);
            }

            // Обход openssl-gost-provider (обе стороны — клиент для проверки подписи сервера,
            // сервер для проверки подписи клиента при mTLS)
            if (interopAcceptGostBaseSigScheme) {
                engine.setInteropAcceptGostBaseSigScheme(true);
            }

            // Поиск PSK на стороне клиента
            byte[] offeredTicket = null;
            if (pskStore != null && role == TlsHandshakeEngine.Role.CLIENT) {
                PskBinding binding = resolveClientPskBinding();
                PskEntry entry = binding != null ? pskStore.getForResumption(binding) : null;
                // Хранилище задаёт пользователь: привязку сверяем сами. Запись с чужой
                // привязкой при возобновлении пропустила бы проверку сервера.
                if (entry != null && !binding.equals(entry.getBinding())) {
                    log.log(
                            GostLogger.Level.WARNING,
                            "PskStore returned an entry with a foreign binding, entry ignored");
                    entry = null;
                }
                // Контракт PskStore требует не отдавать просроченное, но хранилище
                // пользовательское:
                // тикет за границей сертификата сервера предъявлять нельзя
                if (entry != null && entry.isExpired(System.currentTimeMillis())) {
                    log.log(
                            GostLogger.Level.WARNING,
                            "PskStore returned an expired entry, entry ignored");
                    entry = null;
                }
                if (entry != null) {
                    byte[] psk = entry.getPsk();
                    if (psk != null) {
                        offeredTicket = entry.getTicket();
                        resumedValidUntil = entry.getValidUntil();
                        pskKey = psk;
                        long ageMs = System.currentTimeMillis() - entry.getIssueTime();
                        long obfuscatedTicketAge = (ageMs + entry.getTicketAgeAdd()) & 0xFFFFFFFFL;
                        engine.setPsk(pskKey, entry.getTicket(), obfuscatedTicketAge);
                    }
                }
            }

            // Тикет подбирает только клиент; у сервера «offeredTicket» всегда пуст, и признак
            // ввёл бы оператора в заблуждение. Решение сервера пишет движок («PSK offered»).
            if (role == TlsHandshakeEngine.Role.CLIENT) {
                log.log(
                        GostLogger.Level.DEBUG,
                        "TLS handshake started: role=CLIENT, PSK offered={0}",
                        offeredTicket != null);
            } else {
                log.log(GostLogger.Level.DEBUG, "TLS handshake started: role=SERVER");
            }
            // Запуск: клиент -> ClientHello, сервер -> null
            byte[] firstOutgoing = engine.start();
            if (firstOutgoing != null) {
                sendPlaintextRecord(TlsConstants.CT_HANDSHAKE, firstOutgoing);
            }
            // Тикет не поместился в ClientHello: рукопожатие идёт полным, а тикет убираем, иначе
            // то же самое повторялось бы на каждом соединении
            if (offeredTicket != null && engine.isPskOfferWithdrawn()) {
                pskStore.remove(offeredTicket);
            }

            // engine сам ищет PSK в store при получении ClientHello (receiveClientHello)
            if (role == TlsHandshakeEngine.Role.SERVER && pskStore != null) {
                engine.setServerPskStore(pskStore);
            }

            // Принята ли хотя бы одна запись, не являющаяся CCS (для правила «CCS не раньше
            // ClientHello»)
            boolean handshakeRecordSeen = false;

            // Окно открытого alert (RFC 8446 приложение A.1) только у сервера: клиент включает
            // ключ записи рукопожатия лишь после Finished сервера и до этого вправе слать alert
            // открытым, а сервер включает его уже на ServerHello, и открытый alert от сервера
            // после ServerHello это нарушение. Окно длится, пока от клиента не принята ни одна
            // успешно расшифрованная запись. Флаг не сбрасывается: смена эпохи ключей окно не
            // открывает.
            boolean peerRecordDecrypted = false;

            // Главный цикл: receive -> assemble -> engine.receive -> poll -> key changes -> cert
            // validation
            while (!engine.isDone() && !engine.isError()) {
                sessionRecordBuf.clear();
                try {
                    transport.receiveRecord(sessionRecordBuf);
                } catch (BufferOverflowException e) {
                    throw new TlsException(
                            TlsConstants.ALERT_RECORD_OVERFLOW, "Record too long", e);
                }
                sessionRecordBuf.flip();

                // RFC 8446 §5, §D.4: совместимый change_cipher_spec отбрасывается молча, но его
                // содержимое проверяется; на сервере CCS не может быть первой записью (до
                // ClientHello).
                boolean firstRecordOnServer =
                        role == TlsHandshakeEngine.Role.SERVER && !handshakeRecordSeen;
                TlsUtils.CcsResult ccs = TlsUtils.consumeCompatibilityCcs(sessionRecordBuf);
                if (ccs.status() == TlsUtils.CcsStatus.CONSUMED) {
                    if (firstRecordOnServer) {
                        throw new TlsException(
                                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                                "change_cipher_spec received before ClientHello");
                    }
                    continue;
                }
                if (ccs.status() == TlsUtils.CcsStatus.INCOMPLETE) {
                    throw new TlsException(
                            TlsConstants.ALERT_DECODE_ERROR, "Truncated change_cipher_spec record");
                }
                handshakeRecordSeen = true;

                if (readerRecord != null) {
                    // Внешний тип 21 не бывает у шифротекста (тип зашифрованной записи всегда 23),
                    // поэтому опознание однозначно; формат тела проверяет общий разбор
                    if (role == TlsHandshakeEngine.Role.SERVER
                            && !peerRecordDecrypted
                            && startsWithAlert(sessionRecordBuf)) {
                        throw plaintextAlertFromPeer(sessionRecordBuf);
                    }
                    // Расшифровка прямо в хвост буфера сборки, без промежуточной копии
                    ByteBuffer dest =
                            handshakeBuffer.writableTail(TlsConstants.MAX_PLAINTEXT_LENGTH);
                    int destPosBefore = dest.position();
                    UnprotectResult r;
                    try {
                        r = readerRecord.unprotect(sessionRecordBuf, dest);
                    } catch (AuthenticationException e) {
                        throw new TlsException(
                                TlsConstants.ALERT_BAD_RECORD_MAC,
                                "Handshake record authentication failed",
                                e);
                    }
                    peerRecordDecrypted = true;
                    if (r.contentType == TlsConstants.CT_ALERT) {
                        throw alertFromPeer(
                                Arrays.copyOfRange(dest.array(), destPosBefore, dest.position()),
                                log);
                    }
                    if (r.contentType != TlsConstants.CT_HANDSHAKE) {
                        throw new TlsException(
                                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                                "Expected handshake, got " + r.contentType);
                    }
                    // RFC 8446 §5.4: пустой фрагмент сборщик отвергает, иначе он молча не
                    // продвигал бы рукопожатие, но и не прерывал бы его
                    handshakeBuffer.commit(dest.position() - destPosBefore);
                } else {
                    byte[] recordData = new byte[sessionRecordBuf.remaining()];
                    sessionRecordBuf.get(recordData);
                    acceptPlaintextRecord(TlsMessageParser.parsePlaintextRecord(recordData));
                }

                // собрать фрагментированные данные в целые фреймы и обработать их
                byte[] frame;
                while ((frame = handshakeBuffer.nextMessage(false)) != null) {
                    engine.receive(frame);

                    // Сервер: запоминаем запрошенное имя хоста из SNI
                    if (role == TlsHandshakeEngine.Role.SERVER) {
                        String sni = engine.getRequestedServerName();
                        if (sni != null) {
                            this.requestedServerName = sni;
                        }
                    }

                    // Выходной поток по порядку: сообщения и смены ключа записи на своих местах
                    sendEngineOutput(engine, role);
                    applyReadKeyChange(engine);

                    // Обрабатываем валидацию сертификата
                    if (engine.needsCertificateValidation()) {
                        List<GostCertificate> certs = engine.getReceivedCertificates();
                        try {
                            if (role == TlsHandshakeEngine.Role.SERVER) {
                                checkClientCertificateChain(certs);
                            } else if (verifyServerChain) {
                                checkServerCertificateChain(certs);
                            } else {
                                checkServerCertificateLeafOnly(certs);
                            }
                            engine.acknowledgeCertificateValidation(true);
                            this.peerCertificates = certs;
                        } catch (TlsException e) {
                            engine.acknowledgeCertificateValidation(false, e.getAlertCode());
                            throw e;
                        }
                    }

                    if (engine.isDone() || engine.isError()) break;
                }
            }

            if (engine.isError()) {
                throw new TlsException(
                        engine.getErrorAlertCode(),
                        "Handshake failed: " + engine.getErrorMessage());
            }

            // Последние смены ключей рукопожатия уже применены в цикле; проверка на случай, если
            // цикл прервался сразу после приёма
            sendEngineOutput(engine, role);
            applyReadKeyChange(engine);
            // После финальной смены ключей применяем согласованный max_fragment_length
            applyMaxFragmentLength();

            applyNegotiatedCiphersuite();
            // Снимаем флаг до возможного destroy движка: PSK-возобновление
            // не должно обходить повторную аутентификацию клиента (RFC 8446 §4.6.1).
            clientAuthRequested = engine.isClientAuthRequested();
            handshakeDone = true;
            handshakeCompletedOnce = true;
            lastHandshakeResumed = engine.isPskAccepted();
            handshakeBuffer.reset();
            // ALPN пришёл от пира: только очищенным
            if (log.isLoggable(GostLogger.Level.DEBUG)) {
                log.log(
                        GostLogger.Level.DEBUG,
                        "TLS handshake completed: role={0}, cipher suite {1}, resumed={2},"
                                + " client auth requested={3}, ALPN={4}",
                        role,
                        engine.getNegotiatedCiphersuite().forLog(),
                        lastHandshakeResumed,
                        clientAuthRequested,
                        TlsUtils.peerTextForLog(engine.getSelectedAlpnProtocol()));
            }

            // Хранилище задано либо нет для всего соединения: без него тикеты не выдаются вовсе
            if (role == TlsHandshakeEngine.Role.SERVER
                    && !clientAuthRequested
                    && pskStore != null) {
                for (int nst = 0; nst < ticketsToSend; nst++) {
                    // Причина отказа постоянна для соединения (нет цепочки, срок, сбой
                    // хранилища): остальные тикеты тоже не выдать
                    if (!issueNewSessionTicket(nst)) {
                        break;
                    }
                }
            }
        } catch (PeerClosedException e) {
            // RFC 8446 §6.1: на close_notify пира отвечаем close_notify, а не fatal alert. Здесь
            // единственное место ответа в рукопожатии: ветка разбора только бросает исключение
            sendCloseNotify();
            stopSession();
            throw e;
        } catch (TlsException e) {
            logHandshakeFailure(e);
            // Нарушение, найденное локально, пир узнаёт по alert; на fatal alert самого пира
            // ответа нет (RFC 8446 §6), иначе его код отражался бы обратно
            if (!e.isFromPeer()) {
                sendAlert(e.getAlertCode());
            }
            stopSession();
            throw e;
        } catch (IOException e) {
            // Простой IOException в стеке бросает только транспорт: alert отправлять некуда
            stopSession();
            throw e;
        } catch (RuntimeException e) {
            logUnexpectedFailure("handshake", e);
            // Как и для TlsException: alert уходит текущим ключом записи
            sendAlert(alertDescription(e));
            stopSession();
            throw e;
        } finally {
            // Engine НЕ уничтожается — он остаётся жив для post-handshake сообщений.
            // Уничтожается при close() или в catch при ошибке handshake.
            if (pskKey != null) TlsUtils.wipeArray(pskKey);
        }
    }

    /**
     * Отправляет выходной поток движка строго по порядку (см. {@link TlsHandshakeEngine#poll()}):
     * сообщение уходит текущим ключом записи, а пока его нет — открытым (ClientHello,
     * HelloRetryRequest, ServerHello); смена ключа записи применяется к следующим записям.
     * <p>
     * Отправка синхронная, поэтому смена ключа не может обогнать сообщение, стоящее перед ней.
     *
     * @param engine движок handshake
     * @param role   роль участника handshake
     * @throws IOException при ошибке отправки
     */
    private void sendEngineOutput(TlsHandshakeEngine engine, TlsHandshakeEngine.Role role)
            throws IOException {
        applySendFragmentLimit(engine);
        HandshakeOutput item;
        while ((item = engine.poll()) != null) {
            if (item instanceof HandshakeOutput.Message message) {
                if (writerRecord != null) {
                    sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, message.frame());
                } else {
                    sendPlaintextRecord(TlsConstants.CT_HANDSHAKE, message.frame());
                    // RFC 8446 §D.4: dummy CCS идёт сразу после первого сообщения сервера (HRR
                    // или ServerHello), до зашифрованных
                    sendServerCcsIfPending(engine, role);
                }
            } else if (item instanceof HandshakeOutput.WriteKeyChange change) {
                applyWriteKeyChange(change);
            }
        }
    }

    /** Новая запись отправки из смены ключа; ключи в элементе потока затираются сразу. */
    private void applyWriteKeyChange(HandshakeOutput.WriteKeyChange change) {
        try {
            TlsRecord previous = writerRecord;
            writerRecord = newRecord(change.keys(), change.ciphersuite());
            if (previous != null) {
                previous.destroy();
            }
        } finally {
            change.destroy();
        }
    }

    /**
     * Применяет смену ключа чтения: RFC 8446 §5.1 требует, чтобы сообщения не пересекали её, поэтому
     * в буфере сборки не должно остаться ни байта.
     */
    private void applyReadKeyChange(TlsHandshakeEngine engine) throws TlsException {
        if (!engine.hasReadKeysChanged()) {
            return;
        }
        requireRecordBoundaryAtKeyChange();
        TlsTrafficKeys newKeys = engine.getReadKeys();
        if (readerRecord != null) {
            readerRecord.destroy();
        }
        readerRecord = newRecord(newKeys);
        engine.acknowledgeReadKeyChange();
    }

    /**
     * Отправляет выходной поток движка после рукопожатия: KeyUpdate (свой или ответный) и смену
     * ключа записи за ним. Ключ записи к этому моменту всегда есть.
     */
    private void sendPostHandshakeOutput() throws IOException {
        HandshakeOutput item;
        while ((item = engine.poll()) != null) {
            if (item instanceof HandshakeOutput.Message message) {
                sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, message.frame());
            } else if (item instanceof HandshakeOutput.WriteKeyChange change) {
                applyWriteKeyChange(change);
            }
        }
    }

    /**
     * Отправляет dummy change_cipher_spec после первого handshake-сообщения сервера
     * (RFC 8446 §D.4), если клиент прислал непустой {@code legacy_session_id}.
     *
     * <p>Движок отдаёт признак один раз за соединение, поэтому после HRR второй CCS вместе с
     * ServerHello не отправляется. Запись открытая, в транскрипт не входит.</p>
     *
     * @param engine движок handshake
     * @param role   роль участника; клиент CCS не отправляет
     * @throws IOException при ошибке отправки
     */
    private void sendServerCcsIfPending(TlsHandshakeEngine engine, TlsHandshakeEngine.Role role)
            throws IOException {
        if (role == TlsHandshakeEngine.Role.SERVER && engine.takeServerCompatCcs()) {
            transport.sendRecord(TlsUtils.buildCompatibilityCcsRecord());
        }
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================
    // Передача данных
    // ========================================================================

    /**
     * Устанавливает лимит фрагментации отправки (RFC 6066 §4).
     *
     * @param maxFragLenCode код max_fragment_length (1=512, 2=1024, 3=2048, 4=4096), 0 = дефолт
     */
    public void setMaxSendFragment(int maxFragLenCode) {
        this.maxPayload = TlsUtils.maxFragmentLength(maxFragLenCode) - 1;
    }

    /**
     * Для тестов (package-private): снять лимит исходящих записей, чтобы собрать запись, которую
     * соблюдающий согласованный max_fragment_length пир не отправил бы.
     */
    void disableSendFragmentLimitForTest() {
        setMaxSendFragment(0);
        if (writerRecord != null) {
            writerRecord.setMaxFragmentLength(0);
        }
    }

    /** Для тестов (package-private): запись отправки, чтобы проверить её лимит после KeyUpdate. */
    TlsRecord writerRecordForTest() {
        return writerRecord;
    }

    /**
     * Запрашивает уменьшение max_fragment_length при handshake (RFC 6066 §4).
     * Вызывать до handshakeAsClient(). 0 = не запрашивать.
     */
    public void setMaxFragmentLengthRequest(int code) {
        if (handshakeDone) {
            throw new IllegalStateException(
                    "Cannot set max_fragment_length request after handshake completed");
        }
        this.maxFragLenRequest = TlsUtils.isMaxFragmentLengthCode(code) ? code : 0;
        if (messageBuilder != null) {
            messageBuilder.setClientMaxFragLen(this.maxFragLenRequest);
        }
    }

    /**
     * Строит запись защиты по набору шифров, согласованному в рукопожатии, для приёма и отправки.
     * <p>
     * Набор из конфигурации сессии может отличаться от выбранного пиром, а наборы L и S дают разные
     * TLSTREE-ключи и SNMAX уже с 9-й записи, поэтому запись всегда строится только здесь. До
     * появления движка (тестовая сессия без рукопожатия) берётся набор сессии.
     * <p>
     * После рукопожатия запись получает согласованный лимит открытого текста (RFC 6066 §4), иначе
     * лимит пропадал бы при смене ключей (KeyUpdate): для приёма это предел принимаемых фрагментов,
     * для отправки вторая защита поверх нарезки по {@code maxPayload}. Во время рукопожатия лимит
     * не ставится: приём его для сообщений рукопожатия не проверял и раньше, а отправку ограничивает
     * нарезка ({@link #applySendFragmentLimit}); лимит самой записи включает
     * {@link #applyMaxFragmentLength()} в конце рукопожатия.
     *
     * @param keys трафик-ключи, из которых копируются ключ и IV записи
     * @return новая запись
     */
    private TlsRecord newRecord(TlsTrafficKeys keys) {
        TlsCiphersuite suite = engine != null ? engine.getNegotiatedCiphersuite() : null;
        return newRecord(keys, suite != null ? suite : ciphersuite);
    }

    private TlsRecord newRecord(TlsTrafficKeys keys, TlsCiphersuite suite) {
        TlsRecord record = new TlsRecord(keys.getKey(), keys.getIv(), suite.getTagLen(), suite);
        if (handshakeDone && engine != null) {
            record.setMaxFragmentLength(engine.getMaxFragmentLength());
        }
        return record;
    }

    /**
     * Переносит согласованный в рукопожатии набор шифров в поле сессии.
     * <p>
     * {@code hashLen} и {@code offeredKdfHash} не меняются: хэш обоих поддерживаемых наборов один
     * (Стрибог-256), а {@code offeredKdfHash} нужен для проверки, что тикет выведен тем же хэшем,
     * который клиент предложил.
     */
    private void applyNegotiatedCiphersuite() {
        this.ciphersuite = engine.getNegotiatedCiphersuite();
    }

    private void applyMaxFragmentLength() {
        int mfl = engine != null ? engine.getMaxFragmentLength() : 0;
        if (TlsUtils.isMaxFragmentLengthCode(mfl)) {
            if (writerRecord != null) writerRecord.setMaxFragmentLength(mfl);
            if (readerRecord != null) readerRecord.setMaxFragmentLength(mfl);
            setMaxSendFragment(mfl);
        }
    }

    /**
     * Включает нарезку исходящих записей по согласованному max_fragment_length, как только он
     * известен: сервер знает его после ClientHello, клиент после EncryptedExtensions.
     * <p>
     * RFC 6066 §4 распространяет лимит на все записи после согласования, в том числе на
     * зашифрованные сообщения рукопожатия (Certificate сервера, Certificate и Finished клиента).
     * Ждать завершения рукопожатия нельзя: к тому моменту пир уже получил записи длиннее лимита.
     * Лимит самой записи и приём здесь не трогаются, их включает
     * {@link #applyMaxFragmentLength()} после рукопожатия.
     */
    private void applySendFragmentLimit(TlsHandshakeEngine handshakeEngine) {
        int mfl = handshakeEngine.getMaxFragmentLength();
        if (TlsUtils.isMaxFragmentLengthCode(mfl)) {
            setMaxSendFragment(mfl);
        }
    }

    /**
     * Отправляет данные приложения.
     * <p>
     * При сбое транспорта и при исчерпании SNMAX сессия закрывается: дальнейший обмен
     * рассогласован. Ошибка вызова (слишком большой фрагмент) сессию не закрывает.
     *
     * @param data открытые данные для отправки
     * @throws IOException при ошибке отправки
     */
    public void write(byte[] data) throws IOException {
        checkConnected();
        try {
            int offset = 0;
            while (offset < data.length) {
                int chunkLen = Math.min(data.length - offset, maxPayload);
                byte[] record =
                        writerRecord.protect(
                                TlsConstants.CT_APPLICATION_DATA, data, offset, chunkLen);
                transport.sendRecord(record);
                offset += chunkLen;
            }
        } catch (IllegalStateException e) {
            // Исчерпан SNMAX: записывать дальше этим ключом нельзя, так что alert, скорее всего,
            // не уйдёт (его тоже нечем зашифровать), а сессия остановится в любом случае.
            // IllegalArgumentException (слишком большой фрагмент) сюда не попадает: это ошибка
            // вызова, сессия цела.
            abortWithAlert(TlsConstants.ALERT_INTERNAL_ERROR);
            throw e;
        } catch (IOException e) {
            // Часть записи могла уйти в транспорт, дальнейший обмен рассогласован
            stopSession();
            throw e;
        }
    }

    /**
     * Принимает данные приложения.
     * <p>
     * Любая ошибка закрывает сессию: на нарушение протокола или подделку записи отправляется
     * fatal alert (при сбое проверки записи {@code bad_record_mac}), на сбой транспорта alert не
     * отправляется. После ошибки, {@code close_notify} и fatal alert пира сессия непригодна, а
     * вызовы {@code read()} и {@code write()} дают {@link IllegalStateException}.
     *
     * @return данные приложения
     * @throws EOFException если пир прислал close_notify (сессия закрыта)
     * @throws IOException  если пир прислал fatal alert или ошибка расшифровки
     */
    public byte[] read() throws IOException {
        checkConnected();
        try {
            return readApplicationData();
        } catch (TlsException e) {
            // RFC 8446 §6.2: на первой же ошибке отправляем fatal alert и закрываем соединение.
            // seqNum при отказе не растёт, поэтому без закрытия атакующий подбирал бы тег на
            // одном номере записи, а сессия продолжала бы работать. На fatal alert самого пира
            // alert не отправляем, только останавливаем сессию
            if (e.isFromPeer()) {
                stopSession();
            } else {
                abortWithAlert(e.getAlertCode());
            }
            throw e;
        } catch (RuntimeException e) {
            logUnexpectedFailure("reading", e);
            abortWithAlert(TlsConstants.ALERT_INTERNAL_ERROR);
            throw e;
        } catch (IOException e) {
            // Сбой транспорта: alert отправлять некуда. close_notify и fatal alert пира уже
            // остановили сессию, повторная остановка безвредна
            stopSession();
            throw e;
        }
    }

    /** Читает записи до первых данных приложения, обрабатывая post-handshake сообщения. */
    private byte[] readApplicationData() throws IOException {
        int postHandshakeMessages = 0;
        int postHandshakeRecords = 0;
        // Цикл заканчивается данными приложения, alert или ошибкой; только handshake-записи тратят
        // бюджет, поэтому данные после разрешённых сообщений читаются всегда
        while (true) {
            sessionRecordBuf.clear();
            try {
                transport.receiveRecord(sessionRecordBuf);
            } catch (BufferOverflowException e) {
                throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW, "Record too long", e);
            }
            sessionRecordBuf.flip();

            // RFC 8446 §5: change_cipher_spec после Finished пира недопустим. Без проверки
            // unprotect() принял бы короткое тело за повреждённую запись и бросил бы
            // IllegalArgumentException вместо fatal alert.
            if (sessionRecordBuf.hasRemaining()
                    && sessionRecordBuf.get(sessionRecordBuf.position())
                            == TlsConstants.CT_CHANGE_CIPHER_SPEC) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "change_cipher_spec received after peer Finished");
            }

            sessionPlainBuf.clear();
            UnprotectResult r;
            try {
                r = readerRecord.unprotect(sessionRecordBuf, sessionPlainBuf);
            } catch (AuthenticationException e) {
                throw new TlsException(
                        TlsConstants.ALERT_BAD_RECORD_MAC, "Record authentication failed", e);
            }
            byte ct = r.contentType;
            sessionPlainBuf.flip();

            if (ct == TlsConstants.CT_ALERT) {
                byte[] data = new byte[sessionPlainBuf.remaining()];
                sessionPlainBuf.get(data);
                IOException alert = alertFromPeer(data, log);
                // close_notify пира: здесь же отвечаем и останавливаем сессию; fatal alert пира и
                // ошибку формата останавливает catch в read()
                if (alert instanceof PeerClosedException) {
                    closeNotifyReceived();
                }
                throw alert;
            }
            if (ct == TlsConstants.CT_HANDSHAKE) {
                // Бюджет записей на вызов (а не на сообщение): поток мелких записей
                if (++postHandshakeRecords > TlsConstants.MAX_POST_HANDSHAKE_RECORDS) {
                    throw new TlsException(
                            TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                            "Too many post-handshake records in one read");
                }
                // RFC 8446 §5.4: пустой фрагмент сборщик отвергает
                handshakeBuffer.append(
                        sessionPlainBuf.array(),
                        sessionPlainBuf.arrayOffset() + sessionPlainBuf.position(),
                        sessionPlainBuf.remaining());
                sessionPlainBuf.position(sessionPlainBuf.limit());
                // Запись может нести несколько сообщений: разбираем все до приёма следующей, иначе
                // ответ на KeyUpdate из середины записи ждал бы следующей handshake-записи
                byte[] msg;
                while ((msg = handshakeBuffer.nextMessage(true)) != null) {
                    // Лимит проверяется перед каждым служебным сообщением, а не перед приёмом
                    // записи: данные приложения после разрешённых сообщений читаются
                    if (++postHandshakeMessages > TlsConstants.MAX_POST_HANDSHAKE) {
                        throw new TlsException(
                                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                                "Too many post-handshake messages in one read");
                    }
                    processPostHandshakeMessage(msg);
                }
                continue;
            }
            // RFC 8446 §5.1: фрагменты одного handshake-сообщения не перемежаются записями другого
            // типа. Alert разобран выше первым сознательно: он всё равно завершает соединение, а
            // пользователь получает настоящую причину
            if (!handshakeBuffer.isEmpty()) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "Handshake message interleaved with another record type");
            }
            if (ct != TlsConstants.CT_APPLICATION_DATA) {
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Unexpected content type: " + ct);
            }
            byte[] result = new byte[sessionPlainBuf.remaining()];
            sessionPlainBuf.get(result);
            return result;
        }
    }

    /**
     * Обрабатывает одно служебное сообщение после рукопожатия (KeyUpdate или NewSessionTicket).
     * Все такие сообщения идут через движок: это единственная точка входа, чтобы JSSE-модуль не
     * дублировал логику.
     */
    private void processPostHandshakeMessage(byte[] msg) throws IOException {
        TlsHandshakeEngine.PostHandshakeResult result = engine.receivePostHandshake(msg);
        switch (result.type) {
            case KEY_UPDATE_HANDLED:
                // RFC 8446 §5.1: сообщение не пересекает смену ключа, поэтому KeyUpdate замыкает
                // свою запись. Остаток после него пир отправил бы под прежним ключом уже после
                // смены, а разбор принял бы его как продолжение
                requireRecordBoundaryAtKeyChange();
                // Ключ чтения пира сменился сразу; ответный KeyUpdate (если пир его запросил) стоит
                // в
                // потоке со сменой ключа записи за ним и уходит прежним ключом
                applyReadKeyChange(engine);
                sendPostHandshakeOutput();
                return;
            case NEW_SESSION_TICKET:
                handleNewSessionTicket(result.ticket);
                return;
            default:
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "Unexpected post-handshake message: " + result.type);
        }
    }

    /**
     * RFC 8446 §5.1: handshake-сообщения не пересекают смену ключей, и все сообщения прямо перед
     * ней обязаны заканчиваться на границе записи; иначе {@code unexpected_message}. Вызывается в
     * момент смены ключа чтения: в буфере сборки не должно остаться ни одного байта.
     */
    private void requireRecordBoundaryAtKeyChange() throws TlsException {
        handshakeBuffer.requireRecordBoundaryAtKeyChange();
    }

    /**
     * Превращает тело alert-записи пира в исключение: решение сессии по описанию из
     * {@link TlsUtils#alertDescription(byte[])}.
     *
     * @param body тело alert-записи
     * @return {@link PeerClosedException} для {@code close_notify}, {@link TlsException#fromPeer}
     *         для alert пира, {@link TlsException} при нарушении формата alert
     */
    static IOException alertFromPeer(byte[] body) {
        return alertFromPeer(body, LOG);
    }

    static IOException alertFromPeer(byte[] body, GostLogger logger) {
        byte description;
        try {
            description = TlsUtils.alertDescription(body);
        } catch (TlsException e) {
            return e;
        }
        logger.log(GostLogger.Level.DEBUG, "Alert received: {0}", TlsAlerts.forLog(description));
        if (description == TlsConstants.CLOSE_NOTIFY) {
            return new PeerClosedException("Peer closed connection (close_notify)");
        }
        return TlsException.fromPeer(description, "Peer sent fatal alert: " + (description & 0xFF));
    }

    /** Начинается ли принятая запись с внешнего типа alert (открытая alert-запись). */
    private static boolean startsWithAlert(ByteBuffer record) {
        return record.remaining() >= TlsConstants.RECORD_HEADER_SIZE
                && record.get(record.position()) == TlsConstants.CT_ALERT;
    }

    /**
     * Разбирает открытую alert-запись, пришедшую при уже включённом ключе чтения рукопожатия.
     * Длина проверяется по заголовку, до тела.
     *
     * @return исключение для броска: см. {@link #alertFromPeer(byte[])}
     * @throws TlsException при неверной длине или усечённой записи
     */
    private IOException plaintextAlertFromPeer(ByteBuffer record) throws TlsException {
        int start = record.position();
        int bodyLength = ((record.get(start + 3) & 0xFF) << 8) | (record.get(start + 4) & 0xFF);
        TlsUtils.requireAlertLength(bodyLength);
        if (record.remaining() != TlsConstants.RECORD_HEADER_SIZE + bodyLength) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Truncated or oversized alert record");
        }
        int bodyStart = start + TlsConstants.RECORD_HEADER_SIZE;
        return alertFromPeer(new byte[] {record.get(bodyStart), record.get(bodyStart + 1)}, log);
    }

    /**
     * Принимает открытую запись до установки ключей: alert пира или фрагмент handshake.
     *
     * @throws IOException {@link #alertFromPeer} для alert, {@code unexpected_message} для пустого
     *         handshake-фрагмента и любого другого типа записи
     */
    private void acceptPlaintextRecord(TlsMessageParser.PlaintextRecord record) throws IOException {
        switch (record.contentType) {
            case TlsConstants.CT_ALERT:
                throw alertFromPeer(record.body, log);
            case TlsConstants.CT_HANDSHAKE:
                // RFC 8446 §5.1: нулевую длину фрагмента сборщик отвергает
                handshakeBuffer.append(record.body, 0, record.body.length);
                return;
            default:
                throw new TlsException(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "Unexpected content type before keys: " + (record.contentType & 0xFF));
        }
    }

    /**
     * Обрабатывает close_notify от пира (RFC 8446 §6.1).
     * <p>
     * Устанавливает флаг закрытия, отправляет ответный close_notify (best-effort),
     * зануляет ключевой материал. Не закрывает transport — это делает вызывающий код.
     */
    private void closeNotifyReceived() {
        if (closed) return;
        sendCloseNotify();
        stopSession();
    }

    /**
     * Инициирует KeyUpdate (RFC 8446 §4.6.3).
     * <p>
     * Отправляет KeyUpdate пиру текущим ключом записи, затем переходит на следующий (RFC 8446
     * §4.6.3, §7.2). Если {@code request = true},
     * пир обязан ответить своим KeyUpdate.
     * <p>
     * Вызов до завершения handshake — IllegalStateException.
     * <p>
     * Собственные обновления не ограничиваются: приложение доверенное и выбирает частоту смены
     * ключа само (например, раз в час). Не вызывайте метод в цикле: каждая смена ключа требует
     * HKDF и инициализации MGM у обеих сторон, а чужие обновления пир принимает в пределах окна
     * ({@link TlsConstants#MAX_PEER_KEY_UPDATES_PER_WINDOW} за
     * {@link TlsConstants#KEY_UPDATE_RATE_WINDOW_NANOS}) и закрывает соединение при превышении.
     *
     * @param request true = update_requested (пир ответит своим KeyUpdate)
     * @throws IOException если handshake не завершён, сессия закрыта, или ошибка отправки
     * @throws IllegalStateException если сессия закрыта (ошибка вызова)
     */
    public void initiateKeyUpdate(boolean request) throws IOException {
        checkConnected();
        // Движок ставит в поток KeyUpdate и смену ключа записи за ним: сообщение уходит прежним
        // ключом, следующие записи — новым
        engine.initiateKeyUpdate(request);
        try {
            sendPostHandshakeOutput();
        } catch (IllegalStateException e) {
            // Исчерпан SNMAX при отправке KU-фрейма: ключи движка и записи рассогласованы
            abortWithAlert(TlsConstants.ALERT_INTERNAL_ERROR);
            throw e;
        } catch (IOException e) {
            // Сбой транспорта после выработки новых ключей: секрет записи уже сдвинут, а пир мог
            // не получить KeyUpdate, дальнейший обмен рассогласован. Ошибки самого вызова
            // (рукопожатие не завершено, предыдущая смена ключа не подтверждена) выбрасываются
            // до этого блока и сессию не закрывают.
            stopSession();
            throw e;
        }
    }

    /**
     * Обрабатывает NewSessionTicket от сервера (RFC 8446 §4.6.1).
     * <p>
     * Парсит тело тикета, вырабатывает PSK через HKDF-Expand-Label(nonce -> resumption_master_secret)
     * и сохраняет в PskStore для последующего session resumption.
     *
     * @param nst разобранный NewSessionTicket
     * @throws IOException при ошибке сохранения
     */
    private void handleNewSessionTicket(TlsMessageParser.ParsedNewSessionTicket nst)
            throws IOException {
        // Искажённый NST отвергнут при разборе в движке (фатально и без хранилища); здесь
        // решается только, сохранять ли разобранный тикет
        if (pskStore == null) return;
        // Тикет, который не поместится в расширение pre_shared_key, предъявить нельзя: ClientHello
        // вышел бы с переполненными длинами. Лучше не сохранять и идти полным рукопожатием.
        if (nst.ticket.length > TlsPskHelper.maxIdentityLength(hashLen)) {
            // Билет принёс сервер, оператору клиента вмешиваться не в чем: DEBUG
            log.log(
                    GostLogger.Level.DEBUG,
                    "NewSessionTicket is too long to be offered, not saved");
            TlsUtils.wipeArray(nst.ticket);
            TlsUtils.wipeArray(nst.ticketNonce);
            return;
        }
        // Без привязки (пустое имя при сверке имени) или при смене хэша KDF относительно
        // исходного набора шифров тикет не сохраняется: его нельзя будет предъявить безопасно
        // (RFC 8446 §4.6.1: тот же хэш KDF).
        PskBinding binding = resolveClientPskBinding();
        if (binding == null || ciphersuite.getKdfHashAlgorithm() != offeredKdfHash) {
            log.log(
                    GostLogger.Level.DEBUG,
                    "NewSessionTicket not saved: no PSK binding or the KDF hash differs from the"
                            + " offered cipher suite");
            TlsUtils.wipeArray(nst.ticket);
            TlsUtils.wipeArray(nst.ticketNonce);
            return;
        }
        // Граница доверия: при возобновлении сертификата нет, берём границу использованной записи.
        // Не определена или уже наступила - тикет не сохраняем (fail-closed).
        boolean resumed = engine != null && engine.isPskAccepted();
        long validUntil = resumed ? resumedValidUntil : peerTrustValidUntil;
        long now = System.currentTimeMillis();
        long lifetime =
                validUntil == BOUND_UNKNOWN
                        ? 0
                        : PeerTrustBoundary.clampLifetimeSeconds(
                                nst.ticketLifetime, validUntil, now);
        if (lifetime <= 0) {
            log.log(
                    GostLogger.Level.DEBUG,
                    "NewSessionTicket not saved: no usable lifetime (trust boundary reached or"
                            + " unknown)");
            TlsUtils.wipeArray(nst.ticket);
            TlsUtils.wipeArray(nst.ticketNonce);
            return;
        }
        // Resumption Master Secret живёт в engine, но getResumptionMasterSecret() отдаёт копию:
        // её затираем в finally. nst - локальный объект, не покидает метод; затирание его полей
        // безопасно (запись хранилища получила копии)
        byte[] rms = engine != null ? engine.getResumptionMasterSecret() : null;
        if (rms == null) {
            TlsUtils.wipeArray(nst.ticket);
            TlsUtils.wipeArray(nst.ticketNonce);
            return;
        }
        try {
            TlsTicketHelper.storeReceived(
                    pskStore,
                    rms,
                    nst.ticket,
                    nst.ticketNonce,
                    nst.ticketAgeAdd,
                    lifetime,
                    now,
                    binding,
                    validUntil,
                    hashLen);
        } finally {
            TlsUtils.wipeArray(rms);
            TlsUtils.wipeArray(nst.ticket);
            TlsUtils.wipeArray(nst.ticketNonce);
        }
        log.log(
                GostLogger.Level.DEBUG,
                "NewSessionTicket received, lifetime {0,number,#} s",
                lifetime);
    }

    /**
     * Выдаёт NewSessionTicket со стороны сервера (RFC 8446 §4.6.1).
     * <p>
     * Генерация, вывод PSK и запись в хранилище вынесены в {@link TlsTicketHelper#issue}: PSK
     * сначала сохраняется, и только затем тикет шифруется и отправляется клиенту (тикет, которого
     * сервер не знает, клиенту бесполезен, а быстрое повторное подключение не должно обогнать
     * запись). Lifetime - 86400 секунд (24 часа), но не дольше срока собственной цепочки
     * сертификатов (с округлением вниз до секунд); если остаток меньше секунды, тикет не выдаётся.
     *
     * @return {@code true}, если тикет сохранён и отправлен; {@code false}, если выдать его не
     *     удалось: нет цепочки, исчерпан срок, нет секрета или отказало хранилище. Все эти причины
     *     постоянны для соединения, поэтому выдавать остальные тикеты бессмысленно
     * @throws IOException при ошибке отправки
     */
    private boolean issueNewSessionTicket(int nstIndex) throws IOException {
        // Тикет без хранилища бесполезен: сервер принимает PSK только из него
        if (pskStore == null) {
            return false;
        }
        // Тикет не должен пережить собственный сертификат: клиент при возобновлении цепочки не
        // видит. Без собственной цепочки границы нет, тикет не выдаём (fail-closed).
        if (ourCertificateChain == null || ourCertificateChain.isEmpty()) {
            log.log(GostLogger.Level.DEBUG, "NewSessionTicket not issued: no certificate chain");
            return false;
        }
        long validUntil = PeerTrustBoundary.validUntil(ourCertificateChain);
        long now = System.currentTimeMillis();
        // ticket_lifetime = 0 означает «удалить немедленно» (RFC 8446 §4.6.1): вместо него не
        // отправляем тикет вовсе
        long lifetime =
                PeerTrustBoundary.clampLifetimeSeconds(
                        TlsConstants.DEFAULT_SESSION_TIMEOUT, validUntil, now);
        if (lifetime <= 0) {
            log.log(
                    GostLogger.Level.DEBUG,
                    "NewSessionTicket not issued: the certificate chain expires too soon");
            return false;
        }
        // Resumption Master Secret живёт в engine, но getResumptionMasterSecret() отдаёт копию:
        // её затираем в finally. Без секрета PSK не вывести, и тикет клиенту бесполезен
        byte[] rms = engine != null ? engine.getResumptionMasterSecret() : null;
        if (rms == null) {
            log.log(GostLogger.Level.DEBUG, "NewSessionTicket not issued: no resumption secret");
            return false;
        }
        TlsTicketHelper.IssuedTicket issued;
        try {
            issued =
                    TlsTicketHelper.issue(
                            pskStore,
                            rms,
                            nstIndex,
                            hashLen,
                            lifetime,
                            now,
                            PskBinding.forServer(requestedServerName),
                            validUntil);
        } finally {
            TlsUtils.wipeArray(rms);
        }
        if (issued == null) {
            // Причина (сбой вывода PSK или хранилища) записана на WARNING в TlsTicketHelper
            return false;
        }
        try {
            byte[] body =
                    TlsMessageBuilder.buildNewSessionTicket(
                            issued.lifetimeSeconds(),
                            issued.ticketAgeAdd(),
                            issued.ticketNonce(),
                            issued.ticket());
            byte[] framed =
                    new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
            sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, framed);
            log.log(
                    GostLogger.Level.DEBUG,
                    "NewSessionTicket {0} issued, lifetime {1,number,#} s",
                    nstIndex,
                    issued.lifetimeSeconds());
            return true;
        } finally {
            issued.wipe();
        }
    }

    /**
     * Создаёт сессию с уже установленным защищённым каналом (ТОЛЬКО ДЛЯ ТЕСТОВ!!).
     * Handshake не выполняется. Позволяет тестировать read/write в обход handshake.
     *
     * @param transport транспорт
     * @param cs cipher suite
     * @param readerKeys ключи для чтения (decrypt)
     * @param writerKeys ключи для записи (encrypt)
     */
    static TlsSession createForTest(
            TlsTransport transport,
            TlsCiphersuite cs,
            TlsTrafficKeys readerKeys,
            TlsTrafficKeys writerKeys) {
        // Рукопожатия нет, имени сервера тоже: режим без аутентификации сервера, иначе привязка
        // PSK (режим «цепочка и имя» с пустым именем) отвергла бы тикеты, и они не сохранялись бы.
        TlsSession s = new TlsSession(transport, cs, null, null, null, null, false, null, false);
        s.readerRecord = s.newRecord(readerKeys);
        s.writerRecord = s.newRecord(writerKeys);
        // Минимальный engine в POST_HANDSHAKE — нужен для read() с post-handshake сообщениями
        s.engine =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs,
                        s.messageBuilder,
                        s.selectedEcParams,
                        s.selectedNamedGroup,
                        s.selectedSigScheme,
                        s.hashLen,
                        null,
                        false,
                        null);
        s.log = LOG.withContext(s.engine.getConnectionLabel());
        s.engine.initForTesting(new byte[cs.getHashLen()], new byte[cs.getHashLen()]);
        s.handshakeDone = true;
        s.handshakeCompletedOnce = true;
        // Сертификата сервера в тестовой сессии нет, а без границы доверия тикет не сохраняется
        // (fail-closed): тестам post-handshake сообщений граница не нужна
        s.peerTrustValidUntil = PskEntry.NO_CERTIFICATE_BOUND;
        return s;
    }

    /**
     * Устанавливает application traffic secrets для KeyUpdate (ТОЛЬКО ДЛЯ ТЕСТОВ!!).
     * Вызывать после createForTest() до вызова read() с KeyUpdate.
     * <p>
     * Создаёт минимальный engine если ещё не создан (для тестов без handshake).
     * Engine инициализируется через initForTesting() — устанавливаются
     * app traffic secrets и состояние POST_HANDSHAKE.
     */
    static void setAppTrafficSecrets(
            TlsSession session, byte[] serverSecret, byte[] clientSecret, boolean isServer) {
        if (session.engine == null) {
            session.engine =
                    new TlsHandshakeEngine(
                            isServer
                                    ? TlsHandshakeEngine.Role.SERVER
                                    : TlsHandshakeEngine.Role.CLIENT,
                            session.ciphersuite,
                            session.messageBuilder,
                            session.selectedEcParams,
                            session.selectedNamedGroup,
                            session.selectedSigScheme,
                            session.hashLen,
                            null,
                            false,
                            null); // sniSelector — тестовый engine, selector не нужен
        }
        session.log = LOG.withContext(session.engine.getConnectionLabel());
        session.engine.initForTesting(serverSecret, clientSecret);
    }

    /**
     * Закрывает сессию: отправляет close_notify, зачищает ключи.
     * <p>
     * close_notify отправляется best-effort (RFC 8446 §6.1: отправить и забыть).
     * Transport не закрывается — caller владеет его жизненным циклом.
     * После вызова экземпляр непригоден для использования.
     * <p>
     * Вызывать только из потока, который владеет сессией, или после того, как этот поток
     * завершился. Закрытие из другого потока во время рукопожатия не поддерживается: поля
     * ключевого материала не синхронизированы, и закрытие могло бы затереть записи, которые поток
     * рукопожатия ещё создаёт. Безопасный способ прервать зависшее рукопожатие: из другого потока
     * закрыть транспорт (у потокобезопасных транспортов, например {@code InMemoryTlsTransport},
     * ждущее чтение просыпается с {@link IOException}), дождаться завершения потока-владельца
     * (он попытается отправить alert, best-effort: транспорт уже закрыт, остановит сессию и затрёт
     * ключи) и только затем вызвать этот метод, повторный вызов безопасен.
     */
    @Override
    public void close() throws IOException {
        if (!closed) {
            sendCloseNotify();
            stopSession();
        }
    }

    /** @return true после успешного handshake */
    public boolean isHandshakeDone() {
        return handshakeDone;
    }

    /**
     * @return код max_fragment_length (1..4), согласованный при handshake, или 0
     */
    public int getMaxFragmentLength() {
        return engine != null ? engine.getMaxFragmentLength() : 0;
    }

    /**
     * @return {@code true} если последнее завершённое рукопожатие выполнено через PSK
     *         resumption, {@code false} если полное. Значение запоминается при завершении
     *         рукопожатия и не меняется после {@link #close()}.
     * @throws IllegalStateException если ни одно рукопожатие не завершилось успешно (в том числе
     *         если рукопожатие закончилось ошибкой)
     */
    public boolean wasResumed() {
        if (!handshakeCompletedOnce) {
            throw new IllegalStateException(
                    "wasResumed() called before handshake completion on this session");
        }
        return lastHandshakeResumed;
    }

    /**
     * Устанавливает PSK-хранилище для выдачи и приёма тикетов возобновления.
     * <p>
     * <b>Сервер:</b> вызывать до рукопожатия. Тикеты выдаются в его конце и только при заданном
     * хранилище (сервер принимает PSK только из него), поэтому хранилище, заданное позже, тикетов
     * уже не получит. Без хранилища сервер тикеты не выдаёт, {@code ticketsToSend} не действует.
     * <p>
     * <b>Клиент:</b> вызывать до рукопожатия или сразу после, до первого {@code read()}: тикет
     * приходит после рукопожатия и разбирается при чтении.
     *
     * @param pskStore PSK-хранилище или null для отключения
     */
    public void setPskStore(PskStore pskStore) {
        this.pskStore = pskStore;
    }

    /**
     * Устанавливает протоколы ALPN для согласования (RFC 7301).
     * Вызывать до handshake. Для клиента протоколы отправляются в ClientHello;
     * для сервера используется первый общий протокол из списка.
     *
     * @param protocols протоколы в порядке убывания предпочтения, не null
     */
    public void setAlpnProtocols(List<String> protocols) {
        TlsUtils.validateAlpnProtocols(protocols);
        this.alpnProtocols = protocols;
    }

    /**
     * @return согласованный протокол ALPN (после handshake), или null
     */
    public String getAlpnProtocol() {
        return engine != null ? engine.getSelectedAlpnProtocol() : null;
    }

    /**
     * Экспортирует ключевой материал соединения (RFC 8446 §7.5, Exported Keying Material).
     * <p>
     * Применяется для привязки к каналу (tls-exporter, RFC 9266), EAP-TLS, NTS. Значение зависит
     * только от рукопожатия этого соединения: при возобновлении по PSK оно новое, а KeyUpdate его
     * не меняет. Обе стороны с одинаковыми аргументами получают одинаковые байты.
     * <p>
     * Для ГОСТ-наборов RFC 9367 экспорт не определяет; схема взята из RFC 8446 с хэшем Стрибог,
     * совместимость проверена с OpenSSL (gost-provider). Ранний экспорт (0-RTT) не поддерживается.
     *
     * @param label метка назначения (UTF-8), не null и не пуста, не длиннее 249 байт; для привязки
     *     к каналу метки берутся из реестра IANA «TLS Exporter Labels»
     * @param context контекст; {@code null} и пустой массив дают одно и то же значение (в отличие
     *     от TLS 1.2); не длиннее 65535 байт (наше ограничение, JDK принимает до 255)
     * @param length длина результата от 1 до {@code 255 * hashLen} набора шифров
     * @return секретное значение; вызывающий обязан затереть его, когда оно больше не нужно
     * @throws IllegalStateException если рукопожатие не завершено или сессия закрыта
     * @throws IllegalArgumentException если аргументы выходят за допустимые пределы
     */
    public byte[] exportKeyingMaterial(String label, byte[] context, int length) {
        if (closed) {
            throw new IllegalStateException("Session is closed");
        }
        if (engine == null) {
            throw new IllegalStateException("Handshake not completed");
        }
        return engine.exportKeyingMaterial(label, context, length);
    }

    /** @return true после close() */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Возвращает набор шифров сессии.
     * <p>
     * До завершения рукопожатия это набор из конфигурации, после успешного рукопожатия набор,
     * согласованный с пиром. Он может отличаться от настроенного на любой стороне: на клиенте,
     * если сервер выбрал другой из предложенных, на сервере, если клиент предложил не тот набор,
     * на который настроен сервер.
     *
     * @return настроенный набор шифров до рукопожатия, согласованный после него
     */
    public TlsCiphersuite getCipherSuite() {
        return ciphersuite;
    }

    /** @return "TLSv1.3" */
    public String getProtocol() {
        return TlsConstants.PROTOCOL_TLS13;
    }

    /** @return сертификаты пира (null, если handshake не завершён или PSK) */
    public List<GostCertificate> getPeerCertificates() {
        return peerCertificates;
    }

    /**
     * Показывает, предъявил ли пир сертификат, прошедший проверку.
     * <p>
     * Нужен серверу в режиме {@link ClientAuth#WANT}: клиент вправе не предъявлять сертификат,
     * handshake при этом завершается успешно, и приложение обязано проверить этот признак.
     * При возобновлении по PSK сертификатов нет, хотя пир аутентифицирован ключом, поэтому
     * {@code false} не означает неаутентифицированного пира.
     *
     * @return true, если пир предъявил сертификат и проверка пройдена
     */
    public boolean hasPeerCertificate() {
        return peerCertificates != null && !peerCertificates.isEmpty();
    }

    /** @return hostname сервера (только для клиента, иначе null) */
    public String getPeerHostname() {
        return serverHostname;
    }

    /** @return DNS-имя, запрошенное клиентом через SNI (только для сервера, иначе null) */
    public String getRequestedServerName() {
        return requestedServerName;
    }

    // ========================================================================
    // Проверка сертификата
    // ========================================================================

    /**
     * Проверяет цепочку сертификатов сервера (RFC 5280, RFC 8446 §4.4.2.2).
     * Выполняет проверки оконечного сертификата (expiry, hostname, KU, EKU, OCSP) и
     * проверку по цепочке при наличии доверенных сертификатов-якорей.
     *
     * <p>DN matching uses byte-exact DER comparison (RFC 5280 §7.1 semantic
     * normalization not implemented). CAs producing inconsistent DN encodings
     * (e.g. PrintableString vs UTF8String for the same value) will not interop.
     *
     * @throws TlsException при ошибке валидации
     */
    void checkServerCertificateChain(List<GostCertificate> chain) throws TlsException {
        List<GostCertificate> effective =
                TlsCertificateValidator.validate(
                        chain, serverPolicy().requireOcspStaple(requireOcspStapling));
        // Граница считается по проверенной эффективной цепочке, а не по присланной: сервер мог
        // прислать корень, срок которого валидатор допускает
        peerTrustValidUntil =
                PeerTrustBoundary.validUntil(
                        PeerTrustBoundary.boundaryChain(effective, trustAnchors));
    }

    /** Явный небезопасный режим: только leaf-проверки, без цепочки. */
    void checkServerCertificateLeafOnly(List<GostCertificate> chain) throws TlsException {
        TlsCertificateValidator.validateLeafOnly(
                chain, serverLeafOnlyPolicy().requireOcspStaple(requireOcspStapling));
        // В этом режиме проверяется только срок leaf, им и ограничиваем тикет
        peerTrustValidUntil = PeerTrustBoundary.validUntil(List.of(chain.get(0)));
    }

    /**
     * Привязка клиентских PSK-тикетов: сервер (SNI) и модель доверия, по которой он принят.
     *
     * @return привязка, или null, если PSK предлагать нельзя
     */
    private PskBinding resolveClientPskBinding() {
        if (!clientPskBindingResolved) {
            clientPskBinding =
                    PskBindingFactory.forClient(
                            serverHostname,
                            verifyServerChain,
                            hostnameVerificationDisabled,
                            trustAnchors,
                            requireOcspStapling,
                            interopAcceptGostBaseSigScheme,
                            offeredKdfHash);
            clientPskBindingResolved = true;
        }
        return clientPskBinding;
    }

    /**
     * Имя узла для сверки с сертификатом сервера.
     *
     * <p>При явном {@code withoutHostnameVerification()} возвращает {@code null}, а
     * {@code serverHostname} остаётся для SNI: отключается только сверка, а не передача имени.</p>
     */
    private String hostnameForVerification() {
        return hostnameVerificationDisabled ? null : serverHostname;
    }

    /**
     * Политика проверки сертификата сервера по якорям. Фабрика выбирается по явному флагу, а не
     * по {@code null}: {@code createClient} гарантирует, что имя задано либо сверка отключена
     * явно, поэтому забытое имя здесь даёт ошибку, а не пропуск сверки.
     */
    private TlsPeerPolicy serverPolicy() {
        return hostnameVerificationDisabled
                ? TlsPeerPolicy.serverWithoutHostnameVerification(trustAnchors)
                : TlsPeerPolicy.server(serverHostname, trustAnchors);
    }

    /**
     * Политика leaf-проверок без цепочки. Без имени (режим {@code createClientWithoutServerAuth}
     * или явное отключение сверки) имя не сверяется; это явный выбор режима, а не молчаливый
     * пропуск.
     */
    private TlsPeerPolicy serverLeafOnlyPolicy() {
        String hostname = hostnameForVerification();
        return hostname == null
                ? TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()
                : TlsPeerPolicy.serverLeafOnly(hostname);
    }

    /**
     * Проверяет цепочку сертификатов клиента (mTLS, RFC 8446 §4.4.2.2).
     * Аналогична checkServerCertificateChain, но без hostname и с clientAuth EKU.
     *
     * <p>DN matching uses byte-exact DER comparison (RFC 5280 §7.1 semantic
     * normalization not implemented). CAs producing inconsistent DN encodings
     * (e.g. PrintableString vs UTF8String for the same value) will not interop.
     *
     * @throws TlsException при ошибке валидации
     */
    void checkClientCertificateChain(List<GostCertificate> chain) throws TlsException {
        TlsCertificateValidator.validate(
                chain,
                TlsPeerPolicy.client(trustAnchors)
                        .requireOcspStaple(clientOcspPolicy == ClientOcspPolicy.REQUIRE));
    }

    // Проверка цепочки вынесена в TlsCertificateValidator.

    // ========================================================================
    // Проверка CertificateVerify
    // ========================================================================

    /**
     * Проверяет CertificateVerify (сервера или клиента).
     * Использует isServer для выбора контекстной строки (RFC 8446 §4.4.3).
     *
     * @param cvBody       тело CertificateVerify
     * @param cert         сертификат для верификации подписи
     * @param hsTranscript transcript-hash handshake-сообщений
     * @param isServer     true для серверной подписи, false для клиентской
     * @return true если подпись верна
     * @throws IOException при ошибке верификации
     */
    void verifyCertificateVerify(
            byte[] cvBody, GostCertificate cert, byte[] hsTranscript, boolean isServer)
            throws IOException {
        TlsCertificateValidator.verifyCertificateVerify(cvBody, cert, hsTranscript, isServer);
    }

    // ========================================================================
    // Работа с записями
    // ========================================================================

    /**
     * Отправляет незашифрованную TLS-запись (do handshake в открытом виде, alert до установки ключей).
     *
     * @param contentType тип содержимого записи
     * @param data        тело записи
     * @throws IOException при ошибке отправки
     */
    private void sendPlaintextRecord(byte contentType, byte[] data) throws IOException {
        transport.sendRecord(TlsMessageBuilder.buildPlaintextRecord(contentType, data));
    }

    /**
     * Отправляет зашифрованную TLS-запись через writerRecord.
     * Фрагментирует данные по maxPayload в случае превышения (RFC 8446 §5.1, RFC 6066 §4).
     *
     * @param contentType тип содержимого записи
     * @param data        тело записи
     * @throws IOException при ошибке отправки
     */
    private void sendEncryptedRecord(byte contentType, byte[] data) throws IOException {
        int offset = 0;
        while (offset < data.length) {
            int chunkLen = Math.min(data.length - offset, maxPayload);
            byte[] record = writerRecord.protect(contentType, data, offset, chunkLen);
            transport.sendRecord(record);
            offset += chunkLen;
        }
    }

    /**
     * Отправляет TLS Alert пиру (best-effort, игнорирует ошибки).
     * Использует writerRecord если ключи установлены, иначе plaintext.
     *
     * @param description код alert-описания
     */
    private void sendAlert(byte description) {
        try {
            byte[] alertPayload = new byte[] {TlsConstants.ALERT_FATAL, description};
            if (writerRecord != null) {
                transport.sendRecord(writerRecord.protect(TlsConstants.CT_ALERT, alertPayload));
            } else {
                transport.sendRecord(
                        TlsMessageBuilder.buildPlaintextRecord(
                                TlsConstants.CT_ALERT, alertPayload));
            }
            // Запись после отправки: при сбое транспорта «Alert sent» было бы неправдой
            log.log(
                    GostLogger.Level.DEBUG,
                    "Alert sent: fatal, {0}",
                    TlsAlerts.forLog(description));
        } catch (Exception e) {
            log.log(
                    GostLogger.Level.DEBUG,
                    "Alert not sent: fatal, {0}, {1}",
                    TlsAlerts.forLog(description),
                    e.getClass().getSimpleName());
        }
    }

    /**
     * Маппинг IOException на код TLS-алерта.
     * TlsException несёт собственный alertCode; остальные -> ALERT_HANDSHAKE_FAILURE.
     *
     * @param e исключение
     * @return код alert-описания
     */
    private static byte alertDescription(IOException e) {
        if (e instanceof TlsException) return ((TlsException) e).getAlertCode();
        return TlsConstants.ALERT_HANDSHAKE_FAILURE;
    }

    private static byte alertDescription(RuntimeException e) {
        return TlsConstants.ALERT_INTERNAL_ERROR;
    }

    /**
     * Проверяет, что сессия не закрыта.
     *
     * @throws IllegalStateException если сессия закрыта
     */
    private void checkNotClosed() {
        if (closed) throw new IllegalStateException("Session is closed");
    }

    /**
     * Проверяет, что handshake завершён и сессия не закрыта.
     *
     * @throws IllegalStateException если handshake не завершён или сессия закрыта
     */
    private void checkConnected() {
        if (!handshakeDone) throw new IllegalStateException("Handshake not completed");
        if (closed) throw new IllegalStateException("Session is closed");
    }

    /**
     * Единая остановка сессии: помечает её закрытой, уничтожает движок (секреты трафика и
     * Resumption Master Secret живут в нём) и ключевой материал записей. Идемпотентна.
     * <p>
     * Alert пиру нужно отправить ДО вызова: после остановки {@code writerRecord} уничтожен и
     * alert ушёл бы открытым текстом.
     */
    private void stopSession() {
        closed = true;
        handshakeDone = false;
        if (engine != null) {
            engine.destroy();
            engine = null;
        }
        destroyKeyMaterial();
    }

    /**
     * Записывает отказ рукопожатия: стадию и код alert. Причина остаётся в исключении, поэтому
     * запись только на DEBUG и без текста исключения: оно может нести данные пира.
     */
    private void logHandshakeFailure(TlsException e) {
        // Отказ вне приёма сообщения (запись, проверка сертификата) стадии отказа не имеет:
        // берётся текущая
        TlsHandshakeEngine.State stage = null;
        if (engine != null) {
            stage = engine.getFailedStage() != null ? engine.getFailedStage() : engine.getState();
        }
        log.log(
                GostLogger.Level.DEBUG,
                "TLS handshake failed: stage={0}, alert={1}, alert from peer={2}",
                stage,
                TlsAlerts.forLog(e.getAlertCode()),
                e.isFromPeer());
    }

    /**
     * Записывает непредвиденный сбой (ошибку самой библиотеки): сессия закрывается с alert
     * {@code internal_error}. Исключение пробрасывается вызывающему, но запись оставлена на
     * WARNING: прикладной код мог его проглотить, а сбой в библиотеке оператору нужно видеть.
     * Только класс исключения: сообщение может нести данные записи.
     *
     * @param phase фаза работы сессии для записи
     */
    private void logUnexpectedFailure(String phase, RuntimeException e) {
        log.log(
                GostLogger.Level.WARNING,
                "Unexpected failure during {0}, session closed: {1}",
                phase,
                e.getClass().getName());
    }

    /** Отправляет fatal alert и останавливает сессию; на уже закрытой сессии ничего не делает. */
    private void abortWithAlert(byte description) {
        if (closed) return;
        sendAlert(description);
        stopSession();
    }

    /**
     * Отправляет warning-уровня close_notify (RFC 8446 §6.1), best-effort: зашифрованным, если
     * ключи записи уже есть, иначе открытой записью.
     */
    private void sendCloseNotify() {
        try {
            byte[] alertPayload =
                    new byte[] {TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY};
            if (writerRecord != null) {
                transport.sendRecord(writerRecord.protect(TlsConstants.CT_ALERT, alertPayload));
            } else {
                transport.sendRecord(
                        TlsMessageBuilder.buildPlaintextRecord(
                                TlsConstants.CT_ALERT, alertPayload));
            }
            log.log(
                    GostLogger.Level.DEBUG,
                    "Alert sent: warning, {0}",
                    TlsAlerts.forLog(TlsConstants.CLOSE_NOTIFY));
        } catch (Exception e) {
            // best-effort согласно RFC 8446 §6.1
            log.log(
                    GostLogger.Level.DEBUG,
                    "Alert not sent: warning, {0}, {1}",
                    TlsAlerts.forLog(TlsConstants.CLOSE_NOTIFY),
                    e.getClass().getSimpleName());
        }
    }

    /**
     * Зануляет ключевой материал записей и буферы с открытым текстом: readerRecord, writerRecord,
     * handshakeBuffer и копию расшифрованных данных приложения. Безопасный вызов после закрытия
     * сессии или ошибки. Секреты трафика и Resumption Master Secret живут в движке и затираются в
     * {@link TlsHandshakeEngine#destroy()}.
     */
    private void destroyKeyMaterial() {
        if (readerRecord != null) readerRecord.destroy();
        readerRecord = null;
        if (writerRecord != null) writerRecord.destroy();
        writerRecord = null;
        handshakeBuffer.reset();
        TlsUtils.wipeArray(sessionPlainBuf.array());
    }

    /**
     * Определяет схему подписи по named group сертификата.
     *
     * <p>Раньше перебирал 7 известных ГОСТ-схем через hasSignatureScheme().
     * Теперь — прямая конверсия: TlsCertUtils.getNamedGroup() -> namedGroupToSignatureScheme(),
     * что делает ровно то же самое без цикла.</p>
     *
     * @param cert сертификат для определения схемы подписи
     * @return идентификатор схемы подписи
     */
    private static int resolveSigScheme(GostCertificate cert) {
        return TlsCiphersuite.namedGroupToSignatureScheme(
                TlsCertUtils.getNamedGroup(cert.getPublicKey()));
    }
}
