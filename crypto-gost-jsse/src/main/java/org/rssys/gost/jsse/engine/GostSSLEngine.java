package org.rssys.gost.jsse.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.record.UnprotectResult;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * SSLEngine для ГОСТ TLS 1.3 (RFC 8446 + RFC 9367).
 * <p>
 * Реализует клиентский и серверный handshake, wrap/unwrap данных.
 * Управляет TlsHandshakeEngine для handshake и TlsRecord для protect/unwrap.
 * <p>
 * Lock discipline: два ReentrantLock (inbound/outbound). Lock удерживается
 * только на время state-mutation — валидация сертификата выполняется вне лока
 * (NEED_TASK).
 */
public final class GostSSLEngine extends SSLEngine {

    private static Logger LOG = System.getLogger("org.rssys.gost.jsse.GostSSLEngine");

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

    /** Максимальный размер буфера сборки handshake-сообщений (защита от OOM). */
    private static final int MAX_HANDSHAKE_BUFFER =
            TlsConstants.MAX_CERT_SIZE * TlsConstants.MAX_CERT_CHAIN_LENGTH + 65536;

    private final GostX509KeyManager keyManager;
    private final GostX509TrustManager trustManager;
    private boolean clientMode = true;
    // serverMode определяется как !clientMode — поле не нужно
    private final String peerHost;
    private final int peerPort;
    private volatile TlsCiphersuite ciphersuite;

    /** ECDHE-группа для key_share (клиент, RFC 8446 §4.2.8). 0 = GC256B по умолчанию. */
    private int clientNamedGroup;

    private final ByteArrayOutputStream handshakeInputBuf = new ByteArrayOutputStream();
    private final ConcurrentLinkedDeque<byte[]> outgoingQueue = new ConcurrentLinkedDeque<>();
    private final ByteArrayOutputStream incomingAppBuf = new ByteArrayOutputStream();

    private volatile EngineState engineState = EngineState.INITIAL;
    private boolean handshakeStarted;
    private volatile boolean handshakeDone;
    private volatile boolean closeSent;
    private volatile boolean closeReceived;
    // Готовый зашифрованный close_notify — отдельно от outgoingQueue,
    // чтобы wrap() не перешифровал его второй раз
    private byte[] pendingCloseRecord;

    // два отдельных lock для inbound/outbound — SSLEngine допускает параллельные
    // wrap (outbound) и unwrap (inbound). Один lock заблокировал бы оба направления.
    private final ReentrantLock inboundLock = new ReentrantLock();
    private final ReentrantLock outboundLock = new ReentrantLock();

    private final AtomicBoolean taskInProgress = new AtomicBoolean(false);
    // переиспользуемый буфер — каждый unwrap() аллоцирует 16 КБ на горячем пути
    private final ByteBuffer plaintextBuf =
            ByteBuffer.allocate(
                    TlsConstants.MAX_PLAINTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    private final AtomicReference<Runnable> pendingTask = new AtomicReference<>();

    // Сессия и OCSP
    private GostSSLSession session;

    /** null-сессия до handshake (кэш для getSession(), RFC JSSE spec) */
    private final GostSSLSession preHandshakeSession;

    /** peer-сертификаты, сохранённые до создания session (immutable pattern) */
    private java.security.cert.X509Certificate[] peerCertificates;

    // OCSP-ответ (приватный канал от сессии к trust manager)
    private byte[] ocspResponse;

    // SSLParameters
    private String[] enabledCipherSuites = GostJsseConstants.SUPPORTED_CIPHER_SUITES;
    private String[] enabledProtocols = GostJsseConstants.SUPPORTED_PROTOCOLS;
    private boolean needClientAuth;
    private boolean wantClientAuth;
    private boolean enableSessionCreation = true;
    private String endpointIdentificationAlgorithm;

    // max_fragment_length (RFC 6066 §4): 0 = default (16384)
    private int maxFragmentLength;
    // Запрос клиента (1..4): 0 = не запрашивать. Устанавливается до beginHandshake.
    private int clientMaxFragLenRequest;
    // Промежуточный буфер для фрагментации handshake-сообщений (Variant A)
    private byte[] pendingHsFragment;
    private int pendingHsOffset;

    /** @return код max_fragment_length, согласованный при handshake (0 = default) */
    public int getMaxFragmentLength() {
        return maxFragmentLength;
    }

    /** Максимальный размер данных (без inner_type) для одного TLS-рекорда при handshake */
    private int hsChunkSize() {
        int mfl =
                handshakeEngine != null
                        ? handshakeEngine.getMaxFragmentLength()
                        : maxFragmentLength;
        return (mfl >= 1 && mfl <= 4)
                ? TlsConstants.MAX_FRAG_LEN_VALUES[mfl] - 1
                : TlsConstants.MAX_PLAINTEXT_LENGTH - 1;
    }

    /**
     * Устанавливает запрос max_fragment_length для ClientHello (RFC 6066 §4).
     * @param code 0 = не запрашивать, 1=512, 2=1024, 3=2048, 4=4096 байт
     */
    public void setClientMaxFragLenRequest(int code) {
        if (engineState != EngineState.INITIAL) {
            throw new IllegalStateException(
                    "Cannot set max_fragment_length request after handshake started");
        }
        this.clientMaxFragLenRequest = (code >= 1 && code <= 4) ? code : 0;
    }

    // ALPN: протоколы прикладного уровня (RFC 7301)
    private String[] applicationProtocols;
    private String selectedAlpnProtocol;

    // Deferred writerRecord для сервера. RFC 8446 §4.1.3: ServerHello
    // отправляется plaintext. Ключи вырабатываются ДО отправки SH,
    // но writerRecord создаётся только после — первый фрейм (SH) идёт
    // plaintext, остальные (EE, Cert, CV, Fin) уже под защитой.
    private byte[] pendingWriteKey;
    private byte[] pendingWriteIv;
    private int pendingWriteTagLen;
    private volatile boolean pendingWriteKeysExist;

    /** Старый writerRecord, ожидающий destroy() под outboundLock. */
    private volatile TlsRecord deferredWriterDestroy;

    // Переиспользуемый массив для отслеживания позиций dst-буферов в unwrap (GC pressure: #8)
    private int[] dstPosBefore = new int[1];

    // Локальная цепочка сертификатов для сервера — сохраняется в сессию
    private java.security.cert.X509Certificate[] localCertChain;
    // DNS-имя, запрошенное клиентом через SNI (для тестов и GostSSLContextSpi)
    private String requestedServerName;

    /** Тикет текущего PSK resumption — для remove после подтверждения сервером */
    private byte[] currentPskTicketIdentity;

    // Контекст сессии (PSK resumption)
    private GostSSLSessionContext sessionContext;
    // Серверный контекст — передаётся из SSLContextSpi при createSSLEngine,
    // переключается из clientSessionContext в setUseClientMode(false)
    private GostSSLSessionContext serverSessionContext;

    // Клиентский режим по умолчанию
    private static final boolean DEFAULT_USE_CLIENT_MODE = true;

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
        // serverMode = !clientMode — логика зеркальная, явное поле не нужно
        this.ciphersuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
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
     * Создаёт клиентский GostSSLEngine с контекстом сессии.
     */
    public static GostSSLEngine createForClient(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            GostSSLSessionContext sessionContext) {
        return new GostSSLEngine(keyManager, trustManager, host, port, true, sessionContext, null);
    }

    /**
     * Создаёт серверный GostSSLEngine с контекстом сессии.
     * <p>
     * serverSessionContext передаётся в оба слота приватного конструктора:
     * sessionContext используется для PSK lookup на сервере; serverSessionContext
     * не используется, т.к. режим установлен явно (delayed-mode createSSLEngine
     * не применяется).
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

    public GostSSLEngine(
            GostX509KeyManager keyManager,
            GostX509TrustManager trustManager,
            String host,
            int port,
            boolean clientMode) {
        this(keyManager, trustManager, host, port, clientMode, null, null);
    }

    public GostSSLEngine(GostX509KeyManager keyManager, GostX509TrustManager trustManager) {
        this(keyManager, trustManager, "", -1, DEFAULT_USE_CLIENT_MODE, null, null);
    }

    // ========================================================================
    // Внутренняя инициализация handshake
    // ========================================================================

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
        // RFC 9367: cipher suites L и S используют 256-бит кривую и Streebog-256,
        // различаются только в TLSTREE-константах (C1/C2/C3, SNMAX).
        // 256-битные константы корректны для обеих suite.
        int effectiveNamedGroup =
                clientNamedGroup != 0 ? clientNamedGroup : TlsConstants.GRP_GC256B;
        ECParameters ecParams = TlsCiphersuite.namedGroupToParams(effectiveNamedGroup);
        int namedGroup = effectiveNamedGroup;
        int sigScheme = TlsConstants.SIG_GOST_CRYPTOPRO_A;
        int hashLen = ciphersuite.getHashLen();

        List<GostCertificate> certChain = null;
        PrivateKeyParameters privateKey = null;

        if (clientMode) {
            // Клиент: извлекаем сертификат и ключ для mTLS (если сервер запросит)
            if (keyManager != null) {
                String alias =
                        keyManager.chooseClientAlias(
                                new String[] {
                                    GostJsseConstants.KEY_TYPE_ECGOST_256,
                                    GostJsseConstants.KEY_TYPE_ECGOST_512
                                },
                                null,
                                null);
                if (alias != null) {
                    localCertChain = keyManager.getCertificateChain(alias);
                    if (localCertChain != null && localCertChain.length > 0) {
                        certChain =
                                org.rssys.gost.jsse.bridge.CertificateBridge.toGost(localCertChain);
                    }
                    java.security.PrivateKey pk = keyManager.getPrivateKey(alias);
                    if (pk instanceof org.rssys.gost.jsse.bridge.KeyBridge.GostPrivateKeyAdapter) {
                        privateKey =
                                ((org.rssys.gost.jsse.bridge.KeyBridge.GostPrivateKeyAdapter) pk)
                                        .getDelegate();
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
                            List.of(
                                    TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                    TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S),
                            namedGroup,
                            sigScheme,
                            privateKey,
                            certChain,
                            hashLen);

            this.handshakeEngine =
                    new TlsHandshakeEngine(
                            TlsHandshakeEngine.Role.CLIENT,
                            ciphersuite,
                            messageBuilder,
                            ecParams,
                            namedGroup,
                            sigScheme,
                            hashLen,
                            null,
                            false,
                            null);

            if (peerHost != null && !peerHost.isEmpty()) {
                handshakeEngine.setServerHostname(peerHost);
            }
            if (applicationProtocols != null && applicationProtocols.length > 0) {
                handshakeEngine.setClientAlpnProtocols(
                        java.util.Arrays.asList(applicationProtocols));
            }
            if (clientMaxFragLenRequest != 0) {
                messageBuilder.setClientMaxFragLen(clientMaxFragLenRequest);
                handshakeEngine.setClientMaxFragLenRequest(clientMaxFragLenRequest);
            }

            // PSK resumption: ищем тикет для этого сервера
            if (sessionContext != null && peerHost != null && !peerHost.isEmpty()) {
                PskEntry entry = sessionContext.getForClientResumption(peerHost, peerPort);
                if (entry != null) {
                    byte[] psk = entry.getPsk();
                    if (psk != null) {
                        currentPskTicketIdentity = entry.getTicket();
                        long ticketAge =
                                ((System.currentTimeMillis() - entry.getIssueTime()) / 1000L)
                                        & 0xFFFFFFFFL;
                        long obfuscatedAge = (ticketAge + entry.getTicketAgeAdd()) & 0xFFFFFFFFL;
                        handshakeEngine.setPsk(psk, entry.getTicket(), obfuscatedAge);
                    }
                }
            }

            // engine.start() возвращает ClientHello
            byte[] firstOutgoing = handshakeEngine.start();
            if (firstOutgoing != null) {
                outgoingQueue.addLast(firstOutgoing);
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
                        certChain =
                                org.rssys.gost.jsse.bridge.CertificateBridge.toGost(localCertChain);
                    }
                    java.security.PrivateKey pk = keyManager.getPrivateKey(alias);
                    if (pk instanceof org.rssys.gost.jsse.bridge.KeyBridge.GostPrivateKeyAdapter) {
                        privateKey =
                                ((org.rssys.gost.jsse.bridge.KeyBridge.GostPrivateKeyAdapter) pk)
                                        .getDelegate();
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
                            List.of(
                                    TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                    TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S),
                            namedGroup,
                            sigScheme,
                            privateKey,
                            certChain,
                            hashLen);

            // requestClientAuth = need || want: в обоих случаях CR отправляется.
            // optionalClientAuth = !needClientAuth: если только want (без need),
            // пустой certificate_list не фатален. Флаг читается в tls13 engine
            // только при requestClientAuth=true.
            SniCertificateSelector sniSel = keyManager != null ? keyManager.asSniSelector() : null;

            this.handshakeEngine =
                    new TlsHandshakeEngine(
                            TlsHandshakeEngine.Role.SERVER,
                            ciphersuite,
                            messageBuilder,
                            ecParams,
                            namedGroup,
                            sigScheme,
                            hashLen,
                            null,
                            needClientAuth || wantClientAuth,
                            sniSel,
                            !needClientAuth);

            // serverPskStore — engine сам ищет PSK при получении ClientHello
            if (sessionContext != null) {
                handshakeEngine.setServerPskStore(sessionContext.getPskStore());
            }

            if (applicationProtocols != null && applicationProtocols.length > 0) {
                handshakeEngine.setServerAlpnProtocols(
                        java.util.Arrays.asList(applicationProtocols));
            }

            // Для сервера start() возвращает null
            handshakeEngine.start();
        }

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

    /** Для тестов (package-private): writerRecord key epoch (null если не создан) */
    org.rssys.gost.tls13.record.TlsRecord getWriterRecordForTest() {
        return writerRecord;
    }

    /**
     * Устанавливает ECDHE-группу для key_share (RFC 8446 §4.2.8).
     * По умолчанию — GC256B. Должен быть вызван до {@link #beginHandshake()}.
     * <p>
     * Разные серверы могут поддерживать разные группы; клиент выбирает
     * группу для key_share в ClientHello. Если сервер не поддерживает
     * выбранную группу, он вернёт HelloRetryRequest с желаемой группой
     * (RFC 8446 §4.1.3).
     *
     * @param namedGroup идентификатор именованной группы (TlsConstants.GRP_*)
     * @throws IllegalArgumentException если группа не распознана
     */
    public void setClientNamedGroup(int namedGroup) {
        // Валидация на входе, а не в initHandshake() — ранняя диагностика
        TlsCiphersuite.namedGroupToParams(namedGroup);
        this.clientNamedGroup = namedGroup;
    }

    @Override
    public void beginHandshake() throws SSLException {
        if (engineState == EngineState.CLOSED) throw new SSLException("Engine is closed");
        if (handshakeStarted) throw new SSLException("Handshake already started");

        try {
            initHandshake();
            installAlpnSelector();
        } catch (TlsException e) {
            throw AlertMapper.toException(e.getAlertCode(), e.getMessage());
        }
        LOG.log(
                Level.DEBUG,
                "Handshake started: role={0}, host={1}, port={2}",
                clientMode ? "CLIENT" : "SERVER",
                peerHost,
                peerPort);
    }

    // ========================================================================
    // wrap
    // ========================================================================

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
            throws SSLException {
        outboundLock.lock();
        try {
            checkNotClosed();

            // симметричный implicit-start для клиента. JSSE-контракт
            // требует, чтобы первый wrap() без beginHandshake() сам начинал
            // handshake. Netty 4.2 зовёт beginHandshake() явно через
            // SslHandler.channelActive, но не-Netty consumer может не знать.
            // Сервер: wrap() в INITIAL — ошибка, возвращаем NEED_UNWRAP.
            // Безопасно: beginHandshake() lock'и не захватывает,
            // handshakeStarted проверяется внутри.
            if (engineState == EngineState.INITIAL) {
                if (clientMode) {
                    beginHandshake();
                    if (engineState != EngineState.HANDSHAKE) {
                        throw new SSLException(
                                "beginHandshake() failed to start handshake, state=" + engineState);
                    }
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

            // Отправляем close_notify напрямую, без повторного шифрования
            // через writerRecord.protect — запись уже зашифрована в closeOutbound().
            // Ставим перед state-switch, чтобы отработать в любом состоянии engine.
            if (pendingCloseRecord != null) {
                byte[] rec = pendingCloseRecord;
                if (dst.remaining() < rec.length) {
                    // Не хватает места — не обнуляем поле, повторим в следующем wrap()
                    return new SSLEngineResult(
                            SSLEngineResult.Status.BUFFER_OVERFLOW,
                            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                            0,
                            0);
                }
                pendingCloseRecord = null;
                dst.put(rec);
                // closeReceived неизбежно false здесь (closeOutbound при
                // closeReceived=true уходит по early-return), поэтому всегда OK.
                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                        0,
                        rec.length);
            }

            if (engineState == EngineState.HANDSHAKE) {
                // Отправляем handshake-фреймы из очереди (с фрагментацией при max_fragment_length)
                applyDeferredWriterDestroy();
                byte[] frame;
                int frameOffset;
                if (pendingHsFragment != null) {
                    frame = pendingHsFragment;
                    frameOffset = pendingHsOffset;
                } else {
                    frame = outgoingQueue.poll();
                    frameOffset = 0;
                }
                if (frame != null) {
                    int chunkSize = hsChunkSize();
                    int remaining = frame.length - frameOffset;
                    int sendLen = Math.min(remaining, chunkSize);

                    byte[] record;
                    if (writerRecord != null) {
                        record =
                                writerRecord.protect(
                                        TlsConstants.CT_HANDSHAKE, frame, frameOffset, sendLen);
                    } else if (pendingWriteKeysExist) {
                        // RFC 8446 §4.1.3: ServerHello должен быть отправлен
                        // plaintext, хотя handshake-ключи уже выработаны.
                        // SH идёт без защиты, затем создаём writerRecord
                        // для оставшихся фреймов (EE, Cert, CV, Fin).
                        byte[] chunk = new byte[sendLen];
                        System.arraycopy(frame, frameOffset, chunk, 0, sendLen);
                        record = buildPlaintextRecord(TlsConstants.CT_HANDSHAKE, chunk);
                        writerRecord =
                                new TlsRecord(
                                        pendingWriteKey, pendingWriteIv,
                                        pendingWriteTagLen, ciphersuite);
                        pendingWriteKeysExist = false;
                        pendingWriteKey = null;
                        pendingWriteIv = null;
                        // writerRecord создан — применяем лимит из handshakeEngine
                        int hsMfl =
                                handshakeEngine != null
                                        ? handshakeEngine.getMaxFragmentLength()
                                        : 0;
                        if (hsMfl >= 1 && hsMfl <= 4) {
                            writerRecord.setMaxFragmentLength(hsMfl);
                        }
                    } else {
                        // Клиентский ClientHello или серверный HelloRetryRequest
                        // отправляются plaintext — handshake-ключи ещё не выработаны.
                        byte[] chunk = new byte[sendLen];
                        System.arraycopy(frame, frameOffset, chunk, 0, sendLen);
                        record = buildPlaintextRecord(TlsConstants.CT_HANDSHAKE, chunk);
                    }

                    if (dst.remaining() < record.length) {
                        // Недостаточно места — возвращаем фрейм в очередь или сбрасываем pending
                        if (pendingHsFragment != null) {
                            // Откатываем offset — повторная попытка в следующем wrap()
                            pendingHsOffset = frameOffset;
                        } else {
                            outgoingQueue.addFirst(frame);
                        }
                        return new SSLEngineResult(
                                SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
                    }
                    dst.put(record);
                    bytesProduced = record.length;

                    // Фрагментация: если не всё отправлено — буферизируем остаток
                    if (sendLen < remaining) {
                        pendingHsFragment = frame;
                        pendingHsOffset = frameOffset + sendLen;
                    } else {
                        pendingHsFragment = null;
                        pendingHsOffset = 0;
                    }
                }

                // Данные рукопожатия отправлены, но app-ключи ещё не применены
                // (handleEngineKeyChanges не вызывался в finishHandshake,
                // чтобы клиентский Finished был отправлен с handshake-ключами).
                // Теперь переключаем writerRecord на app-ключи.
                if (outgoingQueue.isEmpty() && pendingHsFragment == null && handshakeDone) {
                    handleEngineKeyChanges();
                    // для клиента app-ключи отложены в pendingWriteKeysExist —
                    // применяем здесь, после отправки Finished (handshake-ключами).
                    // Для сервера pending не будет (keys уже применены в handleEngineKeyChanges
                    // при получении Client Finished — writerRecord != null).
                    if (clientMode && pendingWriteKeysExist) {
                        if (writerRecord != null) writerRecord.destroy();
                        writerRecord =
                                new TlsRecord(
                                        pendingWriteKey, pendingWriteIv,
                                        pendingWriteTagLen, ciphersuite);
                        if (maxFragmentLength >= 1 && maxFragmentLength <= 4) {
                            writerRecord.setMaxFragmentLength(maxFragmentLength);
                        }
                        pendingWriteKeysExist = false;
                        pendingWriteKey = null;
                        pendingWriteIv = null;
                    }
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
                // Post-handshake сообщения (KeyUpdate, NewSessionTicket) из очереди
                byte[] postFrame = outgoingQueue.poll();
                if (postFrame != null) {
                    if (dst.remaining()
                            < TlsConstants.RECORD_HEADER_SIZE
                                    + postFrame.length
                                    + 1
                                    + ciphersuite.getTagLen()) {
                        outgoingQueue.addFirst(postFrame);
                        return new SSLEngineResult(
                                SSLEngineResult.Status.BUFFER_OVERFLOW,
                                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                0,
                                0);
                    }
                    applyDeferredWriterDestroy();
                    byte[] encrypted = writerRecord.protect(TlsConstants.CT_HANDSHAKE, postFrame);
                    dst.put(encrypted);

                    // Если был отправлен KU — подтверждаем смену ключей
                    if (handshakeEngine.hasPendingWriteUpdate()) {
                        handshakeEngine.confirmWriteUpdate();
                        handleEngineKeyChanges();
                        handshakeEngine.acknowledgeKeyChange();
                    }
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

                applyDeferredWriterDestroy();

                // Фрагментируем по согласованному max_fragment_length (RFC 6066 §4)
                int maxFragment =
                        (maxFragmentLength >= 1 && maxFragmentLength <= 4)
                                ? TlsConstants.MAX_FRAG_LEN_VALUES[maxFragmentLength] - 1
                                : TlsConstants.MAX_PLAINTEXT_LENGTH - 1;

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

                    int neededSize =
                            TlsConstants.RECORD_HEADER_SIZE
                                    + chunkLen
                                    + 1
                                    + ciphersuite.getTagLen();
                    if (dst.remaining() < neededSize) {
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
        } finally {
            outboundLock.unlock();
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return wrap(new ByteBuffer[] {src}, 0, 1, dst);
    }

    // ========================================================================
    // unwrap
    // ========================================================================

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws SSLException {
        inboundLock.lock();
        try {
            checkNotClosed();

            int srcRemaining = src.remaining();

            // проверка srcRemaining ДО implicit-start — пустой unwrap()
            // на сервере не должен преждевременно стартовать handshake.
            if (srcRemaining < TlsConstants.RECORD_HEADER_SIZE) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
            }

            // если unwrap() вызван на серверном engine в INITIAL, это
            // означает, что прибыл ClientHello. Автоматически начинаем handshake,
            // иначе SslHandler.decode интерпретирует consumption=0 как ошибку.
            // Безопасно: beginHandshake() сам lock'и не захватывает,
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
            if (engineState == EngineState.CLOSED) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.CLOSED,
                        SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                        0,
                        0);
            }

            int consumed;
            int produced = 0;

            // drain incomingAppBuf перед обработкой новых данных.
            // incomingAppBuf заполняется в handleEncryptedRecord когда AppData
            // не поместилось в dsts (rare overflow). Без drain данные потеряются.
            if (incomingAppBuf.size() > 0) {
                byte[] buffered = incomingAppBuf.toByteArray();
                incomingAppBuf.reset();
                int written = 0;
                for (int i = 0; i < length; i++) {
                    ByteBuffer dst = dsts[offset + i];
                    if (dst == null) continue;
                    int toWrite = Math.min(buffered.length - written, dst.remaining());
                    dst.put(buffered, written, toWrite);
                    written += toWrite;
                    if (written >= buffered.length) break;
                }
                produced = written;
                if (written < buffered.length) {
                    incomingAppBuf.write(buffered, written, buffered.length - written);
                }
            }

            if (readerRecord == null) {
                consumed = handlePlaintextRecord(src, dsts, offset, length);
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
                for (int i = 0; i < length; i++) {
                    if (dstPosBefore[i] >= 0) {
                        // Math.max защищает от wrap-around: если буфер был сброшен или перемотан,
                        // позиция могла уменьшиться. В этом случае bytesProduced = 0 корректно.
                        produced += Math.max(0, dsts[offset + i].position() - dstPosBefore[i]);
                    }
                }

                // после обработки последнего Handshake-записи (Client Finished)
                // handshakeDone=true, но engineState может остаться HANDSHAKE
                // (NST в очереди). Если в src остались AppData-записи — обрабатываем
                // их здесь, иначе Tomcat выйдет из handshake-цикла после wrap()
                // без вызова unwrap(), и данные потеряются.
                while (handshakeDone
                        && engineState == EngineState.HANDSHAKE
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
                    if (addConsumed == 0) break;
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
            // produced==0 — защита от drain из incomingAppBuf, который
            // мог записать данные в dst при consumed=0 (см. drain выше).
            if (consumed == 0 && produced == 0) {
                return new SSLEngineResult(
                        SSLEngineResult.Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
            }

            SSLEngineResult.Status status =
                    closeReceived ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
            return new SSLEngineResult(status, getHandshakeStatus(), consumed, produced);
        } catch (TlsException e) {
            engineState = EngineState.CLOSED;
            destroyHandshakeEngine();
            throw AlertMapper.toException(e.getAlertCode(), e.getMessage());
        } catch (IOException e) {
            engineState = EngineState.CLOSED;
            destroyHandshakeEngine();
            throw new SSLException("I/O error during unwrap", e);
        } finally {
            inboundLock.unlock();
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return unwrap(src, new ByteBuffer[] {dst}, 0, 1);
    }

    /**
     * Обрабатывает plaintext TLS-запись (до установки handshake-ключей).
     */
    private int handlePlaintextRecord(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws IOException, TlsException {
        int srcPos = src.position();

        byte contentType = src.get(srcPos);
        int payloadLen = ((src.get(srcPos + 3) & 0xFF) << 8) | (src.get(srcPos + 4) & 0xFF);
        int totalLen = TlsConstants.RECORD_HEADER_SIZE + payloadLen;

        if (src.remaining() < totalLen) {
            return 0; // BUFFER_UNDERFLOW
        }

        byte[] recordData = new byte[totalLen];
        src.get(recordData);

        byte[] body = Arrays.copyOfRange(recordData, TlsConstants.RECORD_HEADER_SIZE, totalLen);

        if (contentType == TlsConstants.CT_ALERT) {
            handleAlert(body);
            return totalLen;
        }

        if (contentType != TlsConstants.CT_HANDSHAKE) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected handshake, got " + contentType);
        }

        handshakeInputBuf.write(body);
        processHandshakeFrames();

        return totalLen;
    }

    private int handleEncryptedRecord(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws IOException, TlsException {
        int srcPos = src.position();
        int remaining = src.remaining();

        // RFC 8446 §D.4: legacy Change Cipher Spec — silently ignore
        if (remaining >= TlsConstants.RECORD_HEADER_SIZE + 1) {
            byte ct = src.get(srcPos);
            if (ct == TlsConstants.CT_CHANGE_CIPHER_SPEC) {
                int ccsLen = ((src.get(srcPos + 3) & 0xFF) << 8) | (src.get(srcPos + 4) & 0xFF);
                src.position(srcPos + TlsConstants.RECORD_HEADER_SIZE + ccsLen);
                return src.position() - srcPos;
            }
        }

        plaintextBuf.clear();
        UnprotectResult r;
        try {
            r = readerRecord.unprotect(src, plaintextBuf);
        } catch (AuthenticationException e) {
            throw new TlsException(
                    TlsConstants.ALERT_DECRYPT_ERROR, "Record authentication failed", e);
        }

        switch (r.status) {
            case NEED_MORE_INPUT:
                return 0;
            case OUTPUT_TOO_SMALL:
                return 0;
            case OK:
                break;
        }

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
            handshakeInputBuf.write(rawArray, rawOffset, dataLen);
            processHandshakeFrames();
            return consumed;
        }

        if (contentType == TlsConstants.CT_APPLICATION_DATA) {
            // Копируем в dst буферы напрямую из backing array plaintextBuf
            int remainingData = dataLen;
            int dataOff = rawOffset;
            int dstIndex = offset;
            while (remainingData > 0 && dstIndex < offset + length) {
                ByteBuffer dst = dsts[dstIndex];
                if (dst == null) {
                    dstIndex++;
                    continue;
                }
                int toWrite = Math.min(remainingData, dst.remaining());
                dst.put(rawArray, dataOff, toWrite);
                dataOff += toWrite;
                remainingData -= toWrite;
                dstIndex++;
            }
            if (remainingData > 0) {
                incomingAppBuf.write(rawArray, dataOff, remainingData);
            }
            return consumed;
        }

        throw new TlsException(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Unexpected content type: " + contentType);
    }

    /**
     * Собирает полные handshake-фреймы из буфера и передаёт их в TlsHandshakeEngine.
     */
    private void processHandshakeFrames() throws IOException, TlsException {
        // злоумышленник может фрагментировать Certificate на множество
        // TLS-записей (каждая ≤ 16640). Без лимита буфер растёт до OOM.
        // Проверка до toByteArray() предотвращает аллокацию гигантского массива.
        if (handshakeInputBuf.size() > MAX_HANDSHAKE_BUFFER) {
            handshakeInputBuf.reset();
            throw new TlsException(
                    TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Handshake buffer overflow: " + handshakeInputBuf.size());
        }

        byte[] buf = handshakeInputBuf.toByteArray();
        int pos = 0;

        while (pos + TlsConstants.HANDSHAKE_HEADER_SIZE <= buf.length) {
            int msgLen =
                    ((buf[pos + 1] & 0xFF) << 16)
                            | ((buf[pos + 2] & 0xFF) << 8)
                            | (buf[pos + 3] & 0xFF);
            int totalLen = TlsConstants.HANDSHAKE_HEADER_SIZE + msgLen;

            if (pos + totalLen > buf.length) {
                break;
            }

            byte[] frame = Arrays.copyOfRange(buf, pos, pos + totalLen);
            pos += totalLen;

            // После handshake: post-handshake сообщения
            if (handshakeDone) {
                if (handshakeEngine != null) {
                    TlsHandshakeEngine.PostHandshakeResult result =
                            handshakeEngine.receivePostHandshake(frame);
                    if (result.type
                            == TlsHandshakeEngine.PostHandshakeResult.Type.KEY_UPDATE_HANDLED) {
                        peerKeyUpdateCount++;
                        LOG.log(Level.DEBUG, "KeyUpdate received");
                        // Читатель-ключи обновляются немедленно — пир сменил свои write-ключи
                        handleEngineKeyChanges();
                        // Если пир запросил ответный KU — перемещаем его в исходящую очередь.
                        // WRITE-ключи НЕ обновляются здесь: ответный KU должен быть отправлен
                        // через СТАРЫЙ writerRecord (RFC 8446 §4.6.3), а смена write-ключей
                        // произойдёт в wrap() после шифрования KU-фрейма.
                        if (handshakeEngine.hasPendingWriteUpdate()) {
                            byte[] kuFrame;
                            while ((kuFrame = handshakeEngine.poll()) != null) {
                                outgoingQueue.addLast(kuFrame);
                            }
                        }
                        handshakeEngine.acknowledgeKeyChange();
                    }
                    if (result.type
                            == TlsHandshakeEngine.PostHandshakeResult.Type.NEW_SESSION_TICKET) {
                        if (sessionContext != null) {
                            byte[] rms = handshakeEngine.getResumptionMasterSecret();
                            if (rms != null) {
                                try {
                                    sessionContext.saveNewSessionTicket(
                                            peerHost, peerPort, rms, result.nstBody);
                                } catch (TlsException e) {
                                    // NST — опциональное сообщение для resumption.
                                    // Битая NST (уже прошедшая AEAD) указывает на баг реализации,
                                    // но не нарушает протокол — работа продолжается без resumption.
                                } finally {
                                    TlsUtils.wipeArray(rms);
                                }
                            }
                        }
                    }
                }
                continue;
            }

            if (handshakeEngine == null) break;

            try {
                handshakeEngine.receive(frame);
            } catch (IOException e) {
                if (handshakeEngine.isError()) {
                    handshakeInputBuf.reset();
                    String err = handshakeEngine.getErrorMessage();
                    LOG.log(
                            Level.DEBUG,
                            "Handshake error: {0}",
                            err != null ? err : e.getMessage());
                    String message = (err != null) ? err : e.getMessage();
                    throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE, message);
                }
                handshakeInputBuf.reset();
                throw e;
            }

            try {
                handleEngineKeyChanges();
            } catch (RuntimeException e) {
                handshakeInputBuf.reset();
                throw e;
            }

            // PSK принят сервером — удаляем тикет из store (single-use, RFC 8446 §8.1)
            if (clientMode
                    && handshakeEngine != null
                    && handshakeEngine.isPskAccepted()
                    && currentPskTicketIdentity != null) {
                if (sessionContext != null) {
                    sessionContext.getPskStore().remove(currentPskTicketIdentity);
                    sessionContext.removeIdentity(peerHost, peerPort);
                }
                currentPskTicketIdentity = null;
            }

            // SNI нужен GostSSLContextSpi для выбора сертификата и тестам для проверки
            if (!clientMode && handshakeEngine != null && requestedServerName == null) {
                String sni = handshakeEngine.getRequestedServerName();
                if (sni != null) {
                    this.requestedServerName = sni;
                }
            }

            // setEnableSessionCreation(false) на сервере = не принимай full
            // handshake, только PSK resumption. Проверка после receive() —
            // PSK уже определён (isPskAccepted).
            if (!clientMode
                    && !enableSessionCreation
                    && handshakeEngine != null
                    && !handshakeEngine.isPskAccepted()) {
                handshakeInputBuf.reset();
                throw new TlsException(
                        TlsConstants.ALERT_HANDSHAKE_FAILURE,
                        "Session creation disabled, PSK required");
            }

            // валидация сертификата асинхронна (NEED_TASK) — не блокируем handshake-поток
            if (handshakeEngine.needsCertificateValidation()) {
                List<GostCertificate> certs = handshakeEngine.getReceivedCertificates();
                String keyType = resolveKeyType(certs);
                pendingTask.set(createCertValidationTask(certs, keyType));
                taskInProgress.set(true);
                break;
            }

            byte[] outgoing;
            while ((outgoing = handshakeEngine.poll()) != null) {
                outgoingQueue.addLast(outgoing);
            }

            if (handshakeEngine.isDone()) {
                finishHandshake();
            }
            if (handshakeEngine.isError()) {
                handshakeInputBuf.reset();
                LOG.log(Level.DEBUG, "Handshake failed: {0}", handshakeEngine.getErrorMessage());
                throw new TlsException(handshakeEngine.getErrorAlertCode(), "Handshake failed");
            }
        }

        if (pos > 0) {
            byte[] remaining = Arrays.copyOfRange(buf, pos, buf.length);
            handshakeInputBuf.reset();
            handshakeInputBuf.write(remaining, 0, remaining.length);
        }
    }

    /**
     * Обновляет readerRecord/writerRecord при смене ключей.
     * <p>
     * Для сервера: writerRecord НЕ создаётся сразу — SH должен быть отправлен
     * plaintext. Ключи сохраняются в pendingWriteKey/Iv, writerRecord создаётся
     * в wrap() после извлечения SH из очереди.
     * <p>
     * Предусловие: handshakeEngine не null
     * Постусловие: ключи прочитаны, флаги acknowledgeKeyChange сброшены,
     *              writerRecord может быть null для сервера.
     */
    private void handleEngineKeyChanges() {
        if (handshakeEngine == null) return;
        // обновить согласованный ciphersuite
        TlsCiphersuite negotiated = handshakeEngine.getNegotiatedCiphersuite();
        if (negotiated != null) this.ciphersuite = negotiated;
        if (handshakeEngine.hasReadKeysChanged()) {
            TlsTrafficKeys newKeys = handshakeEngine.getReadKeys();
            if (readerRecord != null) readerRecord.destroy();
            readerRecord =
                    new TlsRecord(
                            newKeys.getKey(),
                            newKeys.getIv(),
                            ciphersuite.getTagLen(),
                            ciphersuite);
        }
        if (handshakeEngine.hasWriteKeysChanged()) {
            TlsTrafficKeys newKeys = handshakeEngine.getWriteKeys();
            if (clientMode) {
                // на клиенте смена writeKeys происходит дважды —
                // handshake-ключи (после ECDHE) и app-ключи (после Server Finished).
                // App-ключи нельзя применять немедленно — клиентский Finished
                // должен быть отправлен с handshake-ключами (RFC 8446 §4.1.3).
                // Сохраняем app-ключи в pending, применяем в wrap() после
                // отправки Finished (outgoingQueue пуста).
                // Откладываем ТОЛЬКО на этапе HANDSHAKE — KeyUpdate в DATA
                // применяется немедленно.
                if (handshakeEngine.isDone() && engineState == EngineState.HANDSHAKE) {
                    setPendingWriteKeys(newKeys);
                } else {
                    swapWriterRecord(newKeys);
                }
            } else {
                // Сервер: если writerRecord уже создан — переключаем без destroy()
                // под inboundLock (гонка с protect() в wrap под outboundLock).
                // destroy() откладывается в deferredWriterDestroy и выполняется
                // под outboundLock. Иначе — через pendingWriteKeysExist.
                if (writerRecord != null) {
                    swapWriterRecord(newKeys);
                } else {
                    setPendingWriteKeys(newKeys);
                }
            }
        }
        if (handshakeEngine.hasReadKeysChanged() || handshakeEngine.hasWriteKeysChanged()) {
            handshakeEngine.acknowledgeKeyChange();
        }
    }

    /** Уничтожает writerRecord, отложенный из handleEngineKeyChanges (под outboundLock). */
    private void applyDeferredWriterDestroy() {
        if (deferredWriterDestroy != null) {
            deferredWriterDestroy.destroy();
            deferredWriterDestroy = null;
        }
    }

    /** Авто-KeyUpdate при приближении к SNMAX (RFC 8446 §4.6.3). */
    private void tryAutoKeyUpdate() throws SSLException {
        if (writerRecord != null
                && writerRecord.isApproachingRekeyLimit()
                && handshakeEngine != null
                && !handshakeEngine.hasPendingWriteUpdate()) {
            try {
                handshakeEngine.initiateKeyUpdate(false);
                byte[] kuFrame;
                while ((kuFrame = handshakeEngine.poll()) != null) {
                    outgoingQueue.addLast(kuFrame);
                }
            } catch (TlsException e) {
                throw new SSLException("KeyUpdate initiation failed", e);
            }
        }
    }

    /** Устанавливает новый writerRecord, уничтожая старый через deferred (под outboundLock). */
    private void swapWriterRecord(TlsTrafficKeys newKeys) {
        if (writerRecord != null) {
            deferredWriterDestroy = writerRecord;
        }
        writerRecord =
                new TlsRecord(
                        newKeys.getKey(), newKeys.getIv(), ciphersuite.getTagLen(), ciphersuite);
    }

    /** Сохраняет ключи для отложенного создания writerRecord в wrap(). */
    private void setPendingWriteKeys(TlsTrafficKeys newKeys) {
        this.pendingWriteKey = newKeys.getKey();
        this.pendingWriteIv = newKeys.getIv();
        this.pendingWriteTagLen = ciphersuite.getTagLen();
        this.pendingWriteKeysExist = true;
    }

    /**
     * Создаёт задачу валидации сертификата для NEED_TASK.
     * <p>
     * Валидирует напрямую через GostCertificate, минуя JCA-конверсию — так OCSP-ответы
     * из stapled CertificateEntry не теряются. JCA-конверсия делается только для
     * peerCertificates (JSSE-контракт).
     */
    private Runnable createCertValidationTask(List<GostCertificate> certs, String keyType) {
        return () -> {
            try {
                if (trustManager != null) {
                    if (clientMode) {
                        String hostname = GostX509TrustManager.extractHostnameForEndpointId(this);
                        trustManager.validateChainWithOcsp(
                                certs, hostname, trustManager.isRequireOcspStapling());
                    } else {
                        // mTLS: валидация клиентского сертификата — OCSP не поддерживается
                        java.security.cert.X509Certificate[] jcaChain =
                                org.rssys.gost.jsse.bridge.CertificateBridge.toJca(certs);
                        trustManager.checkClientTrusted(jcaChain, keyType, this);
                    }
                }
                handshakeEngine.acknowledgeCertificateValidation(true);
                this.peerCertificates = org.rssys.gost.jsse.bridge.CertificateBridge.toJca(certs);
            } catch (CertificateException | RuntimeException e) {
                LOG.log(Level.WARNING, "Certificate validation failed unexpectedly", e);
                byte alertCode = TlsConstants.ALERT_BAD_CERTIFICATE;
                Throwable cause = (e instanceof CertificateException) ? e.getCause() : null;
                if (cause instanceof TlsException) {
                    alertCode = ((TlsException) cause).getAlertCode();
                }
                handshakeEngine.acknowledgeCertificateValidation(false, alertCode);
            } finally {
                taskInProgress.set(false);
                pendingTask.set(null);
            }
        };
    }

    /**
     * Завершает handshake: создаёт сессию с финальными данными.
     * <p>
     * Предусловие: handshakeDone == false
     * Постусловие: session создан, handshakeDone == true,
     *              writerRecord не тронут (будет переключен в wrap при DATA).
     */
    private void finishHandshake() {
        if (handshakeDone) return;

        // НЕ вызываем handleEngineKeyChanges() — writerRecord должен остаться
        // с handshake-ключами до отправки клиентского Finished.
        // App-ключи будут установлены после flush очереди в wrap().

        // Сохраняем ALPN-протокол
        if (handshakeEngine != null) {
            this.selectedAlpnProtocol = handshakeEngine.getSelectedAlpnProtocol();
        }

        // Создаём session один раз с финальными данными
        String csName = ciphersuite.getIanaName();
        this.session =
                new GostSSLSession(
                        csName,
                        peerHost,
                        peerPort,
                        peerCertificates,
                        localCertChain != null
                                ? localCertChain
                                : new java.security.cert.X509Certificate[0],
                        selectedAlpnProtocol);
        if (ocspResponse != null) {
            session.setOcspResponse(ocspResponse);
        }

        // Привязываем сессию к контексту (putSession устанавливает back-reference)
        if (sessionContext != null) {
            sessionContext.putSession(session);
        }

        // Сервер: генерируем NewSessionTicket для resumption
        if (!clientMode && sessionContext != null) {
            byte[] rms = handshakeEngine.getResumptionMasterSecret();
            if (rms != null) {
                byte[] ticketNonce = new byte[ciphersuite.getHashLen()];
                CryptoRandom.INSTANCE.nextBytes(ticketNonce);
                byte[] psk = TlsPskHelper.derivePsk(rms, ticketNonce, ciphersuite.getHashLen());
                if (psk != null) {
                    byte[] ticketIdentity = new byte[TlsConstants.RANDOM_LENGTH];
                    CryptoRandom.INSTANCE.nextBytes(ticketIdentity);
                    long ticketLifetime =
                            Math.min(
                                    sessionContext.getSessionTimeout(),
                                    GostSSLSessionContext.RFC_MAX_TICKET_LIFETIME);
                    if (ticketLifetime == 0)
                        ticketLifetime = GostSSLSessionContext.RFC_MAX_TICKET_LIFETIME;
                    byte[] ageAddBytes = new byte[4];
                    CryptoRandom.INSTANCE.nextBytes(ageAddBytes);
                    long ticketAgeAdd =
                            ((ageAddBytes[0] & 0xFFL) << 24)
                                    | ((ageAddBytes[1] & 0xFFL) << 16)
                                    | ((ageAddBytes[2] & 0xFFL) << 8)
                                    | (ageAddBytes[3] & 0xFFL);
                    byte[] nstBody =
                            TlsMessageBuilder.buildNewSessionTicket(
                                    ticketLifetime, ticketAgeAdd, ticketNonce, ticketIdentity);
                    byte[] nstFrame =
                            new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, nstBody)
                                    .encode();
                    outgoingQueue.addLast(nstFrame);

                    // Кэшируем на сервере
                    PskEntry entry =
                            new PskEntry(
                                    ticketIdentity,
                                    ticketLifetime,
                                    ticketAgeAdd,
                                    ticketNonce,
                                    psk,
                                    System.currentTimeMillis());
                    sessionContext.getPskStore().onTicketReceived(entry);
                }
                TlsUtils.wipeArray(rms);
            }
        }

        currentPskTicketIdentity = null;

        // Сохраняем согласованный max_fragment_length до destroy handshakeEngine
        this.maxFragmentLength = handshakeEngine.getMaxFragmentLength();

        handshakeDone = true;

        LOG.log(
                Level.INFO,
                "Handshake completed: suite={0}, alpn={1}",
                ciphersuite.getIanaName(),
                selectedAlpnProtocol != null ? selectedAlpnProtocol : "none");

        // Сервер: handshake завершён и нет исходящих фреймов -> переходим в DATA
        // (для клиента переход произойдёт в wrap() после flush Finished)
        if (!clientMode && outgoingQueue.isEmpty()) {
            handleEngineKeyChanges();
            engineState = EngineState.DATA;
        }
    }

    // ========================================================================
    // Alert handling
    // ========================================================================

    private void handleAlert(byte[] alertData) throws SSLException {
        if (alertData.length < 2) {
            throw new SSLException("Truncated alert message");
        }
        byte level = alertData[0];
        byte description = alertData[1];

        if (description == TlsConstants.CLOSE_NOTIFY) {
            closeReceived = true;
            LOG.log(Level.DEBUG, "close_notify received");
            if (closeSent) {
                engineState = EngineState.CLOSED;
                destroyHandshakeEngine();
            }
            return;
        }

        if (level == TlsConstants.ALERT_FATAL) {
            LOG.log(Level.ERROR, "Fatal alert received: code={0}", description & 0xFF);
        } else {
            LOG.log(Level.WARNING, "Warning alert received: code={0}", description & 0xFF);
        }

        // Fatal alert
        closeReceived = true;
        engineState = EngineState.CLOSED;
        destroyHandshakeEngine();
        throw AlertMapper.toException(
                description, "Received fatal alert " + (description & 0xFF) + " from peer");
    }

    private void destroyHandshakeEngine() {
        // Зачистка ключевого материала при закрытии — предотвращает утечку
        // RMS, PSK и traffic secrets в heap при долгоживущих engine.
        // Зачистка pending write-ключей если handshake прерван до wrap()
        TlsUtils.wipeArray(pendingWriteKey);
        pendingWriteKey = null;
        TlsUtils.wipeArray(pendingWriteIv);
        pendingWriteIv = null;
        pendingWriteKeysExist = false;
        // Отложенный writerRecord (swap без destroy под inboundLock) — зачищаем
        if (deferredWriterDestroy != null) {
            deferredWriterDestroy.destroy();
            deferredWriterDestroy = null;
        }
        if (handshakeEngine != null) {
            handshakeEngine.destroy();
        }
        currentPskTicketIdentity = null;
        pendingCloseRecord = null;
    }

    // ========================================================================
    // Close
    // ========================================================================

    @Override
    public void closeOutbound() {
        outboundLock.lock();
        try {
            if (closeSent) return;
            if (closeReceived) {
                closeSent = true;
                engineState = EngineState.CLOSED;
                destroyHandshakeEngine();
                LOG.log(Level.DEBUG, "close_notify sent");
                return;
            }
            // Отправляем close_notify (best-effort, RFC 8446 §6.1)
            try {
                byte[] alertPayload =
                        new byte[] {TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY};
                byte[] record;
                if (writerRecord != null) {
                    record = writerRecord.protect(TlsConstants.CT_ALERT, alertPayload);
                } else {
                    record = buildPlaintextRecord(TlsConstants.CT_ALERT, alertPayload);
                }
                pendingCloseRecord = record;
                closeSent = true;
                LOG.log(Level.DEBUG, "close_notify sent");
            } catch (Exception e) {
                // RFC 8446 §6.1: close_notify best-effort, не кидаем исключение
                closeSent = true;
            }
        } finally {
            outboundLock.unlock();
        }
    }

    @Override
    public void closeInbound() throws SSLException {
        inboundLock.lock();
        try {
            if (closeReceived) return;
            if (!closeSent) {
                // RFC 8446 §6.1 не требует closeSent перед closeInbound.
                // Netty SslHandler вызывает closeInbound() при channelInactive
                // (обрыв TCP, таймаут) — без close_notify.
                LOG.log(Level.DEBUG, "closeInbound without closeOutbound — close_notify not sent");
            }
            closeReceived = true;
            engineState = EngineState.CLOSED;
            destroyHandshakeEngine();
        } finally {
            inboundLock.unlock();
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
        outboundLock.lock();
        try {
            byte[] rec = pendingCloseRecord;
            pendingCloseRecord = null;
            return rec;
        } finally {
            outboundLock.unlock();
        }
    }

    @Override
    public boolean isOutboundDone() {
        return closeSent;
    }

    @Override
    public boolean isInboundDone() {
        return closeReceived || engineState == EngineState.CLOSED;
    }

    // ========================================================================
    // Application protocol (ALPN)
    // ========================================================================

    @Override
    public String getApplicationProtocol() {
        return selectedAlpnProtocol;
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return selectedAlpnProtocol;
    }

    /**
     * ALPN-селектор (BiFunction): вызывается на серверной стороне при получении
     * ClientHello с ALPN-расширением. Получает список протоколов от клиента,
     * должен вернуть выбранный или null.
     * <p>
     * Поведение при mismatch:
     * <ul>
     *   <li>Если селектор вернул null или протокол не в списке клиента —
     *       handshake продолжается без ALPN (applicationProtocol = null).</li>
     *   <li>FATAL_ALERT не отправляется — в SSLEngine это level-контракт,
     *       решение об alert принимает caller (SslHandler).</li>
     *   <li>SelectorFailureBehavior не настраивается — всегда "no match -> continue".</li>
     * </ul>
     */
    private java.util.function.BiFunction<SSLEngine, java.util.List<String>, String> alpnSelector;

    @Override
    public void setHandshakeApplicationProtocolSelector(
            java.util.function.BiFunction<SSLEngine, java.util.List<String>, String> selector) {
        this.alpnSelector = selector;
        installAlpnSelector();
    }

    @Override
    public java.util.function.BiFunction<SSLEngine, java.util.List<String>, String>
            getHandshakeApplicationProtocolSelector() {
        return alpnSelector;
    }

    private void installAlpnSelector() {
        if (handshakeEngine != null) {
            if (alpnSelector != null) {
                java.util.function.Function<java.util.List<String>, String> fn =
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

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        if (taskInProgress.get()) {
            return SSLEngineResult.HandshakeStatus.NEED_TASK;
        }
        if (engineState == EngineState.DATA || engineState == EngineState.CLOSED) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        // до вызова beginHandshake() engine не handshaking.
        // SslHandler в Netty проверяет этот статус, чтобы решить,
        // нужно ли инициировать handshake. NOT_HANDSHAKING означает
        // «ещё не начали», NEED_UNWRAP — «ждём входящие данные».
        // Возврат NEED_UNWRAP на INITIAL ломает SslHandler.
        if (engineState == EngineState.INITIAL) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        if (engineState == EngineState.HANDSHAKE) {
            // По JSSE-контракту FINISHED возвращается однократно после
            // завершения handshake. unwrap()/wrap() могут завершить
            // handshake, но transition в DATA происходит только в wrap().
            if (handshakeDone && outgoingQueue.isEmpty()) {
                return SSLEngineResult.HandshakeStatus.FINISHED;
            }
            if (!outgoingQueue.isEmpty()) {
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }
            return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }
        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    /**
     * Инициирует KeyUpdate (RFC 8446 §4.6.3).
     * <p>
     * Нестандартное расширение JSSE для ручного управления ре-кейингом.
     * После вызова следующий {@link #wrap(ByteBuffer, ByteBuffer)} отправит
     * KU-фрейм старыми ключами и переключится на новые.
     *
     * @param requestUpdate true = запросить ответный KU от пира
     * @throws SSLException если handshake не завершён или превышен лимит KU
     */
    public void initiateKeyUpdate(boolean requestUpdate) throws SSLException {
        if (handshakeEngine == null || !handshakeDone) {
            throw new SSLException("Cannot initiate KeyUpdate before handshake complete");
        }
        outboundLock.lock();
        try {
            if (handshakeEngine.hasPendingWriteUpdate()) return;
            handshakeEngine.initiateKeyUpdate(requestUpdate);
            LOG.log(Level.DEBUG, "KeyUpdate sent: requestUpdate={0}", requestUpdate);
            byte[] kuFrame;
            while ((kuFrame = handshakeEngine.poll()) != null) {
                outgoingQueue.addLast(kuFrame);
            }
        } catch (TlsException e) {
            throw AlertMapper.toException(e.getAlertCode(), e.getMessage());
        } finally {
            outboundLock.unlock();
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

    @Override
    public SSLSession getHandshakeSession() {
        return session;
    }

    // ========================================================================
    // Client/Server mode
    // ========================================================================

    @Override
    public void setUseClientMode(boolean mode) {
        if (handshakeStarted) {
            throw new IllegalArgumentException("Cannot change mode after handshake started");
        }
        // Сервер без host/port: PSK lookup не работает (sessionContext не находит entry
        // по пустому peerHost). Используйте createSSLEngine(host, port) для сервера,
        // или createServerEngine() через GostSSLContextSpi.
        // Исключение НЕ бросаем — Tomcat/Spring Boot создают engine через
        // createSSLEngine() без host; PSK в этом сценарии не используется.
        if (!mode && (peerHost == null || peerHost.isEmpty())) {
            LOG.log(
                    System.Logger.Level.WARNING,
                    "Server engine created without host — PSK resumption disabled");
        }
        // Переключаем sessionContext на серверный, если engine создан через SSLContextSpi
        if (!mode && serverSessionContext != null) {
            this.sessionContext = serverSessionContext;
        }
        this.clientMode = mode;
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        this.needClientAuth = need;
    }

    @Override
    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        this.wantClientAuth = want;
    }

    @Override
    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    // ========================================================================
    // Cipher suites / Protocols
    // ========================================================================

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        // Validate that all suites are supported
        for (String s : suites) {
            if (TlsCiphersuite.byIanaName(s) == null) {
                throw new IllegalArgumentException("Unsupported cipher suite: " + s);
            }
        }
        this.enabledCipherSuites = suites.clone();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        for (String p : protocols) {
            if (!GostJsseConstants.PROTOCOL_TLS_1_3.equals(p)) {
                throw new IllegalArgumentException("Unsupported protocol: " + p);
            }
        }
        this.enabledProtocols = protocols.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public String[] getSupportedProtocols() {
        return GostJsseConstants.SUPPORTED_PROTOCOLS.clone();
    }

    // ========================================================================
    // SSLParameters
    // ========================================================================

    @Override
    public SSLParameters getSSLParameters() {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(enabledCipherSuites);
        params.setProtocols(enabledProtocols);
        params.setNeedClientAuth(needClientAuth);
        params.setWantClientAuth(wantClientAuth);
        if (endpointIdentificationAlgorithm != null) {
            params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }
        if (applicationProtocols != null) {
            params.setApplicationProtocols(applicationProtocols);
        }
        return params;
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        if (params == null) return;
        String[] suites = params.getCipherSuites();
        if (suites != null) setEnabledCipherSuites(suites);
        String[] protocols = params.getProtocols();
        if (protocols != null) setEnabledProtocols(protocols);
        if (params.getNeedClientAuth()) setNeedClientAuth(true);
        if (params.getWantClientAuth()) setWantClientAuth(true);
        if (params.getEndpointIdentificationAlgorithm() != null) {
            this.endpointIdentificationAlgorithm = params.getEndpointIdentificationAlgorithm();
        }
        String[] appProtocols = params.getApplicationProtocols();
        if (appProtocols != null && appProtocols.length > 0) {
            this.applicationProtocols = appProtocols.clone();
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
        this.enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private void checkNotClosed() throws SSLException {
        if (engineState == EngineState.CLOSED) {
            throw new SSLException("Engine is closed");
        }
    }

    /**
     * Определяет keyType по цепочке сертификатов пира.
     */
    private static String resolveKeyType(List<GostCertificate> certs) {
        if (certs != null && !certs.isEmpty()) {
            int hlen = certs.get(0).getPublicKey().getParams().hlen;
            return hlen == TlsConstants.STREEBOG_512_HASH_LEN
                    ? GostJsseConstants.KEY_TYPE_ECGOST_512
                    : GostJsseConstants.KEY_TYPE_ECGOST_256;
        }
        return GostJsseConstants.KEY_TYPE_ECGOST_256;
    }

    /**
     * Устанавливает OCSP-ответ для степплинга (сервер).
     * Приложение загружает OCSP-ответ заранее и передаёт в engine.
     * Ответ будет отправлен в CertificateEntry сервера.
     *
     * @param response DER-кодированный OCSP-ответ, или null
     */
    public void setOcspResponse(byte[] response) {
        this.ocspResponse = response;
        if (handshakeEngine != null) {
            handshakeEngine.setOcspResponse(response);
        }
    }

    byte[] getOcspResponseForTest() {
        return ocspResponse;
    }

    /** Тестовый хелпер: подменить logger для перехвата сообщений. Возвращает предыдущий для restore в tearDown. */
    static System.Logger setLoggerForTest(System.Logger testLogger) {
        System.Logger prev = LOG;
        LOG = testLogger;
        return prev;
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
