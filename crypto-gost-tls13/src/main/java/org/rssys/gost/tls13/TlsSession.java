package org.rssys.gost.tls13;

import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.engine.HandshakeContext;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.record.TlsParsedRecord;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.record.UnprotectResult;
import java.io.EOFException;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/**
 * TLS 1.3 сессия с Kuznyechik-MGM-Streebog.
 * Полный handshake (клиент/сервер) + защищённая передача данных.
 * <p>Не thread-safe. Каждый экземпляр должен использоваться в одном потоке.
 */
public final class TlsSession implements AutoCloseable {

    private final TlsTransport transport;
    private TlsCiphersuite ciphersuite;     // Меняется на клиенте после ServerHello если сервер выбрал другой suite
    private final int hashLen;              // Оба Kuznyechik-MGM suite (L и S) имеют hashLen=32

    // Аутентификация (долговременный ключ для CertificateVerify)
    private final List<TlsCertificate> ourCertificateChain;
    private final PrivateKeyParameters ourPrivateKey;
    private final List<PublicKeyParameters> caPublicKeys;
    private final String serverHostname;
    private final boolean requireOcspStapling;
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
    private boolean closed;
    private List<TlsCertificate> peerCertificates;

    // Буфер сборки handshake чтобы избежать GC pressure.
    private final GrowableBuffer handshakeBuffer = new GrowableBuffer();

    // Переиспользуемые ByteBuffer-буферы для zero-alloc чтения. TlsRecord
    // скопирует данные в свой recordBuf (MGM принимает только byte[]), но
    // transport не аллоцирует промежуточные массивы.
    private final ByteBuffer sessionRecordBuf = ByteBuffer.allocate(
            TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH);
    private final ByteBuffer sessionPlainBuf = ByteBuffer.allocate(
            TlsConstants.MAX_PLAINTEXT_LENGTH);

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
    private int ticketsToSend = 1;

    // Engine остается жив после handshake для post-handshake сообщений
    // (KeyUpdate, NewSessionTicket). Application traffic secrets хранятся
    // в engine, не копируются в TlsSession — это устраняет дублирование
    // и даёт JSSE-модулю прямой доступ к engine.initiateKeyUpdate().
    private TlsHandshakeEngine engine;

    // Максимум post-handshake сообщений за один read() (RFC 8446 §5: защита от flooding)
    private static final int MAX_POST_HANDSHAKE = 8;

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
        TlsSession session = new TlsSession(transport, config.getCiphersuite(),
                config.getClientCertificateChain(), config.getClientPrivateKey(),
                config.getCaPublicKeys(), config.getServerHostname(),
                config.isOcspRequired(), null);
        session.alpnProtocols = config.getAlpnProtocols();
        session.clientCertSelector = config.getClientCertificateSelector();
        return session;
    }

    /** Создаёт сессию для клиента (прямые параметры, без конфига). */
    public static TlsSession createClient(TlsTransport transport,
                                          TlsCiphersuite ciphersuite,
                                          TlsCertificate ourCertificate,
                                          PrivateKeyParameters ourPrivateKey) {
        return createClient(transport, ciphersuite, ourCertificate, ourPrivateKey, null);
    }

    /** Создаёт сессию для клиента с валидацией CA. */
    public static TlsSession createClient(TlsTransport transport,
                                          TlsCiphersuite ciphersuite,
                                          TlsCertificate ourCertificate,
                                          PrivateKeyParameters ourPrivateKey,
                                          PublicKeyParameters caPublicKey) {
        List<PublicKeyParameters> keys = caPublicKey != null
                ? Collections.singletonList(caPublicKey) : null;
        return createClient(new TlsClientConfig(ciphersuite)
                .withClientCertificateChain(ourCertificate)
                .withClientPrivateKey(ourPrivateKey)
                .withCaPublicKeys(keys), transport);
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
        TlsSession session = new TlsSession(transport, config.getCiphersuite(),
                config.getServerCertificateChain(), config.getServerPrivateKey(),
                config.getCaPublicKeys(), null, false, config.getOcspStaplingResponse());
        session.sniSelector = config.getSniSelector();
        session.oidFilters = config.getOidFilters();
        session.alpnProtocols = config.getAlpnProtocols();
        session.ticketsToSend = config.getTicketsToSend();
        int configNamedGroup = config.getSelectedNamedGroup();
        if (configNamedGroup != 0 && configNamedGroup != session.selectedNamedGroup) {
            session.selectedNamedGroup = configNamedGroup;
            session.selectedEcParams = TlsCiphersuite.namedGroupToParams(configNamedGroup);
            session.messageBuilder = new TlsMessageBuilder(
                    session.ciphersuite,
                    session.messageBuilder.getOfferedCipherSuiteIds(),
                    configNamedGroup,
                    session.selectedSigScheme,
                    session.ourPrivateKey,
                    session.ourCertificateChain,
                    session.hashLen);
        }
        return session;
    }

    /** Создаёт сессию для сервера (прямые параметры, без конфига). */
    public static TlsSession createServer(TlsTransport transport,
                                          TlsCiphersuite ciphersuite,
                                          TlsCertificate ourCertificate,
                                          PrivateKeyParameters ourPrivateKey) {
        return createServer(new TlsServerConfig(ciphersuite,
                Collections.singletonList(ourCertificate), ourPrivateKey), transport);
    }

    private TlsSession(TlsTransport transport,
                       TlsCiphersuite ciphersuite,
                       List<TlsCertificate> ourCertificateChain,
                       PrivateKeyParameters ourPrivateKey,
                       List<PublicKeyParameters> caPublicKeys,
                       String serverHostname,
                       boolean requireOcspStapling,
                       byte[] ocspResponse) {
        if (transport == null) throw new IllegalArgumentException("transport must not be null");
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        this.transport = transport;
        this.ciphersuite = ciphersuite;
        this.hashLen = ciphersuite.getHashLen();
        this.ourCertificateChain = ourCertificateChain;
        this.ourPrivateKey = ourPrivateKey;
        this.caPublicKeys = caPublicKeys;
        this.serverHostname = serverHostname;
        this.requireOcspStapling = requireOcspStapling;
        this.ocspResponse = ocspResponse;
        TlsCertificate leafCert = (ourCertificateChain != null && !ourCertificateChain.isEmpty())
                ? ourCertificateChain.get(0) : null;
        this.selectedSigScheme = leafCert != null
                ? resolveSigScheme(leafCert)
                : TlsConstants.SIG_GOST_TC26_A_256;
        this.messageBuilder = new TlsMessageBuilder(ciphersuite,
                List.of(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S),
                selectedNamedGroup, selectedSigScheme,
                ourPrivateKey, ourCertificateChain, hashLen);
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
     * Управляет циклом: receive → decrypt → assemble → engine.receive →
     * poll → send → key changes → cert validation.
     *
     * @param role роль участника handshake (CLIENT или SERVER)
     * @throws IOException при ошибке handshake
     */
    private void runHandshake(TlsHandshakeEngine.Role role) throws IOException {
        checkNotClosed();
        byte[] pskKey = null;
        try {
            boolean requestClientAuth = (role == TlsHandshakeEngine.Role.SERVER
                    && caPublicKeys != null && !caPublicKeys.isEmpty());

            this.engine = new TlsHandshakeEngine(role, ciphersuite, messageBuilder,
                    selectedEcParams, selectedNamedGroup, selectedSigScheme,
                    hashLen, ocspResponse, requestClientAuth,
                    sniSelector);

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
            if (role == TlsHandshakeEngine.Role.SERVER && oidFilters != null && !oidFilters.isEmpty()) {
                engine.setOidFilters(oidFilters);
            }
            // Селектор сертификата клиента по oid_filters (клиент)
            if (role == TlsHandshakeEngine.Role.CLIENT && clientCertSelector != null) {
                engine.setClientCertificateSelector(clientCertSelector);
            }

            // Поиск PSK на стороне клиента
            if (pskStore != null && role == TlsHandshakeEngine.Role.CLIENT) {
                PskEntry entry = pskStore.getForResumption();
                if (entry != null) {
                    byte[] psk = entry.getPsk();
                    if (psk != null) {
                        pskKey = psk;
                        long ageMs = System.currentTimeMillis() - entry.getIssueTime();
                        long obfuscatedTicketAge = (ageMs + entry.getTicketAgeAdd()) & 0xFFFFFFFFL;
                        engine.setPsk(pskKey, entry.getTicket(), obfuscatedTicketAge);
                    }
                }
            }

            // Запуск: клиент → ClientHello, сервер → null
            byte[] firstOutgoing = engine.start();
            if (firstOutgoing != null) {
                sendPlaintextRecord(TlsConstants.CT_HANDSHAKE, firstOutgoing);
            }

            // engine сам ищет PSK в store при получении ClientHello (receiveClientHello)
            if (role == TlsHandshakeEngine.Role.SERVER && pskStore != null) {
                engine.setServerPskStore(pskStore);
            }

            // Главный цикл: receive → assemble → engine.receive → poll → key changes → cert validation
            while (!engine.isDone() && !engine.isError()) {
                sessionRecordBuf.clear();
                try {
                    transport.receiveRecord(sessionRecordBuf);
                } catch (BufferOverflowException e) {
                    throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                            "Record too long", e);
                }
                sessionRecordBuf.flip();

                // RFC 8446 §D.4: CCS в TLS 1.3 silently ignored (middlebox compatibility)
                if (sessionRecordBuf.get(sessionRecordBuf.position())
                        == TlsConstants.CT_CHANGE_CIPHER_SPEC) {
                    continue;
                }

                if (readerRecord != null) {
                    handshakeBuffer.ensureCapacity(handshakeBuffer.size + TlsConstants.MAX_PLAINTEXT_LENGTH);
                    ByteBuffer dest = ByteBuffer.wrap(handshakeBuffer.buf, handshakeBuffer.size,
                            handshakeBuffer.buf.length - handshakeBuffer.size);
                    int destPosBefore = dest.position();
                    UnprotectResult r;
                    try {
                        r = readerRecord.unprotect(sessionRecordBuf, dest);
                    } catch (AuthenticationException e) {
                        throw new TlsException(TlsConstants.ALERT_DECRYPT_ERROR,
                                "Handshake record authentication failed", e);
                    }
                    if (r.contentType == TlsConstants.CT_ALERT) {
                        int alertLen = dest.position() - destPosBefore;
                        if (alertLen < 2) {
                            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                                    "Malformed alert during handshake");
                        }
                        // Per RFC 8446 §6: level field ignored, all alerts are fatal in TLS 1.3
                        byte description = dest.get(destPosBefore + 1);
                        if (description == TlsConstants.CLOSE_NOTIFY) {
                            throw new EOFException("Peer closed connection during handshake");
                        }
                        throw new TlsException(description,
                                "Received fatal alert during handshake: code=" + (description & 0xFF));
                    }
                    if (r.contentType != TlsConstants.CT_HANDSHAKE) {
                        throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                                "Expected handshake, got " + r.contentType);
                    }
                    handshakeBuffer.size += dest.position() - destPosBefore;
                } else {
                    byte[] recordData = new byte[sessionRecordBuf.remaining()];
                    sessionRecordBuf.get(recordData);
                    handshakeBuffer.write(TlsMessageParser.extractRecordData(recordData));
                }

                // собрать фрагментированные данные в целые фреймы и обработать их
                byte[] frame;
                while ((frame = assembleHandshakeMessage()) != null) {
                    engine.receive(frame);

                    // Сервер: запоминаем запрошенное имя хоста из SNI
                    if (role == TlsHandshakeEngine.Role.SERVER) {
                        String sni = engine.getRequestedServerName();
                        if (sni != null) {
                            this.requestedServerName = sni;
                        }
                    }

                    // Обрабатываем исходящие фреймы
                    processEngineOutgoing(engine, role);

                    // Обрабатываем смену ключей
                    if (engine.hasReadKeysChanged()) {
                        TlsTrafficKeys newKeys = engine.getReadKeys();
                        if (readerRecord != null) readerRecord.destroy();
                        readerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                                ciphersuite.getTagLen(), ciphersuite);
                    }
                    if (engine.hasWriteKeysChanged()) {
                        TlsTrafficKeys newKeys = engine.getWriteKeys();
                        if (writerRecord != null) writerRecord.destroy();
                        writerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                                ciphersuite.getTagLen(), ciphersuite);
                    }
                    if (engine.hasReadKeysChanged() || engine.hasWriteKeysChanged()) {
                        engine.acknowledgeKeyChange();
                    }

                    // Обрабатываем валидацию сертификата
                    if (engine.needsCertificateValidation()) {
                        List<TlsCertificate> certs = engine.getReceivedCertificates();
                        try {
                            if (role == TlsHandshakeEngine.Role.SERVER) {
                                checkClientCertificateChain(certs);
                            } else {
                                checkServerCertificateChain(certs);
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
                throw new TlsException(engine.getErrorAlertCode(),
                        "Handshake failed: " + engine.getErrorMessage());
            }

            // Финальная смена ключей (app keys из finishHandshake/receiveClientFinished)
            if (engine.hasReadKeysChanged()) {
                TlsTrafficKeys newKeys = engine.getReadKeys();
                if (readerRecord != null) readerRecord.destroy();
                readerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                        ciphersuite.getTagLen(), ciphersuite);
            }
            if (engine.hasWriteKeysChanged()) {
                TlsTrafficKeys newKeys = engine.getWriteKeys();
                if (writerRecord != null) writerRecord.destroy();
                writerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                        ciphersuite.getTagLen(), ciphersuite);
            }
            if (engine.hasReadKeysChanged() || engine.hasWriteKeysChanged()) {
                engine.acknowledgeKeyChange();
            }
            // После финальной смены ключей применяем согласованный max_fragment_length
            applyMaxFragmentLength();

            this.ciphersuite = engine.getNegotiatedCiphersuite();
            handshakeDone = true;
            handshakeBuffer.reset();

            if (role == TlsHandshakeEngine.Role.SERVER) {
                    for (int nst = 0; nst < ticketsToSend; nst++) {
                        sendNewSessionTicket(nst);
                    }
            }
        } catch (IOException e) {
            // Если writerRecord ещё не инициализирован, но handshake-ключи уже
            // установлены (например, failure в receiveFinished после writeKeys = handshakeClientKeys),
            // создаём writerRecord для отправки зашифрованного alert (RFC 8446 §6).
            if (writerRecord == null && engine != null && engine.getWriteKeys() != null) {
                writerRecord = new TlsRecord(
                        engine.getWriteKeys().getKey(),
                        engine.getWriteKeys().getIv(),
                        ciphersuite.getTagLen(), ciphersuite);
            }
            sendAlert(alertDescription(e));
            if (engine != null) { engine.destroy(); engine = null; }
            destroyKeyMaterial();
            throw e;
        } catch (RuntimeException e) {
            sendAlert(alertDescription(e));
            if (engine != null) { engine.destroy(); engine = null; }
            destroyKeyMaterial();
            throw e;
        } finally {
            // Engine НЕ уничтожается — он остаётся жив для post-handshake сообщений.
            // Уничтожается при close() или в catch при ошибке handshake.
            if (pskKey != null) TlsUtils.wipeArray(pskKey);
        }
    }

    /**
     * Извлекает и отправляет исходящие handshake-фреймы из engine.
     * <p>
     * Особенность сервера: первый фрейм после receiveClientHello —
     * ServerHello (plaintext). После него применяются ключи записи,
     * остальные фреймы (EE, CR, Cert, CV, Finished) шифруются.
     *
     * @param engine движок handshake
     * @param role   роль участника handshake
     * @throws IOException при ошибке отправки
     */
    private void processEngineOutgoing(TlsHandshakeEngine engine,
                                        TlsHandshakeEngine.Role role) throws IOException {
        boolean isServerSendFlight = (role == TlsHandshakeEngine.Role.SERVER
                && engine.getState() == TlsHandshakeEngine.State.SERVER_SEND_FLIGHT);

        if (isServerSendFlight) {
            // Сервер: первый фрейм — SH (plaintext)
            byte[] sh = engine.poll();
            if (sh != null) {
                sendPlaintextRecord(TlsConstants.CT_HANDSHAKE, sh);
            }
            // Подтверждаем write keys → создаём writerRecord для последующих зашифрованных фреймов
            if (engine.hasWriteKeysChanged()) {
                TlsTrafficKeys newKeys = engine.getWriteKeys();
                if (writerRecord != null) writerRecord.destroy();
                writerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                        ciphersuite.getTagLen(), ciphersuite);
            }
            if (engine.hasReadKeysChanged()) {
                TlsTrafficKeys newKeys = engine.getReadKeys();
                if (readerRecord != null) readerRecord.destroy();
                readerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                        ciphersuite.getTagLen(), ciphersuite);
            }
            if (engine.hasReadKeysChanged() || engine.hasWriteKeysChanged()) {
                engine.acknowledgeKeyChange();
            }
            // Оставшиеся фреймы: зашифрованные
            byte[] rest;
            while ((rest = engine.poll()) != null) {
                sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, rest);
            }
            return;
        }

        // Обычный кейс: подтверждаем смену ключей, затем poll
        if (engine.hasReadKeysChanged()) {
            TlsTrafficKeys newKeys = engine.getReadKeys();
            if (readerRecord != null) readerRecord.destroy();
            readerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                    ciphersuite.getTagLen(), ciphersuite);
        }
        if (engine.hasWriteKeysChanged()) {
            TlsTrafficKeys newKeys = engine.getWriteKeys();
            if (writerRecord != null) writerRecord.destroy();
            writerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                    ciphersuite.getTagLen(), ciphersuite);
        }
        if (engine.hasReadKeysChanged() || engine.hasWriteKeysChanged()) {
            engine.acknowledgeKeyChange();
        }

        byte[] outgoing;
        while ((outgoing = engine.poll()) != null) {
            if (writerRecord != null) {
                sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, outgoing);
            } else {
                sendPlaintextRecord(TlsConstants.CT_HANDSHAKE, outgoing);
            }
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
        this.maxPayload = (maxFragLenCode >= 1 && maxFragLenCode <= 4)
                ? TlsConstants.MAX_FRAG_LEN_VALUES[maxFragLenCode] - 1
                : TlsConstants.MAX_PLAINTEXT_LENGTH - 1;
    }

    /**
     * Запрашивает уменьшение max_fragment_length при handshake (RFC 6066 §4).
     * Вызывать до handshakeAsClient(). 0 = не запрашивать.
     */
    public void setMaxFragmentLengthRequest(int code) {
        if (handshakeDone) {
            throw new IllegalStateException("Cannot set max_fragment_length request after handshake completed");
        }
        this.maxFragLenRequest = (code >= 1 && code <= 4) ? code : 0;
        if (messageBuilder != null) {
            messageBuilder.setClientMaxFragLen(this.maxFragLenRequest);
        }
    }

    private void applyMaxFragmentLength() {
        int mfl = engine != null ? engine.getMaxFragmentLength() : 0;
        if (mfl >= 1 && mfl <= 4) {
            int actualLen = TlsConstants.MAX_FRAG_LEN_VALUES[mfl];
            if (writerRecord != null) writerRecord.setMaxFragmentLength(mfl);
            if (readerRecord != null) readerRecord.setMaxFragmentLength(mfl);
            setMaxSendFragment(mfl);
        }
    }

    /**
     * Отправляет данные приложения.
     *
     * @param data открытые данные для отправки
     * @throws IOException при ошибке отправки
     */
    public void write(byte[] data) throws IOException {
        checkConnected();
        int offset = 0;
        while (offset < data.length) {
            int chunkLen = Math.min(data.length - offset, maxPayload);
            byte[] record = writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, data, offset, chunkLen);
            transport.sendRecord(record);
            offset += chunkLen;
        }
    }

    /**
     * Принимает данные приложения.
     *
     * @return данные приложения
     * @throws EOFException если пир прислал close_notify (сессия закрыта)
     * @throws IOException  если пир прислал fatal alert или ошибка расшифровки
     */
    public byte[] read() throws IOException {
        checkConnected();
        for (int i = 0; i < MAX_POST_HANDSHAKE; i++) {
            sessionRecordBuf.clear();
            try {
                transport.receiveRecord(sessionRecordBuf);
            } catch (BufferOverflowException e) {
                throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                        "Record too long", e);
            }
            sessionRecordBuf.flip();

            sessionPlainBuf.clear();
            UnprotectResult r;
            try {
                r = readerRecord.unprotect(sessionRecordBuf, sessionPlainBuf);
            } catch (AuthenticationException e) {
                throw new TlsException(TlsConstants.ALERT_DECRYPT_ERROR,
                        "Record authentication failed", e);
            }
            byte ct = r.contentType;
            sessionPlainBuf.flip();

            if (ct == TlsConstants.CT_ALERT) {
                byte[] data = new byte[sessionPlainBuf.remaining()];
                sessionPlainBuf.get(data);
                byte desc = parseAlertDescription(data);
                if (desc == TlsConstants.CLOSE_NOTIFY) {
                    closeNotifyReceived();
                    throw new EOFException("Peer closed connection (close_notify)");
                }
                fatalAlertReceived();
                throw new IOException("Peer sent fatal alert: " + (desc & 0xFF));
            }
            if (ct == TlsConstants.CT_HANDSHAKE) {
                byte[] data = new byte[sessionPlainBuf.remaining()];
                sessionPlainBuf.get(data);
                handshakeBuffer.write(data);
                byte[] msg = assembleHandshakeMessage();
                if (msg == null) {
                    continue;
                }
                // Все post-handshake сообщения (KeyUpdate, NewSessionTicket)
                // маршрутизируются через engine — это единственная точка входа
                // для post-handshake, чтобы JSSE-модуль не дублировал логику.
                TlsHandshakeEngine.PostHandshakeResult result =
                        engine.receivePostHandshake(msg);
                switch (result.type) {
                    case KEY_UPDATE_HANDLED:
                        // Сначала reader — новые ключи применяются немедленно
                        if (engine.hasReadKeysChanged()) {
                            TlsTrafficKeys newKeys = engine.getReadKeys();
                            if (readerRecord != null) readerRecord.destroy();
                            readerRecord = new TlsRecord(newKeys.getKey(),
                                    newKeys.getIv(),
                                    ciphersuite.getTagLen(), ciphersuite);
                        }
                        // Затем отложенный писатель: KU-ответ (если pending) —
                        // отправляется ДО подтверждения, через старый writerRecord
                        if (engine.hasPendingWriteUpdate()) {
                            byte[] kuFrame;
                            while ((kuFrame = engine.poll()) != null) {
                                sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, kuFrame);
                            }
                            engine.confirmWriteUpdate();
                        }
                        // После подтверждения — обновляем writerRecord
                        if (engine.hasWriteKeysChanged()) {
                            TlsTrafficKeys newKeys = engine.getWriteKeys();
                            if (writerRecord != null) writerRecord.destroy();
                            writerRecord = new TlsRecord(newKeys.getKey(),
                                    newKeys.getIv(),
                                    ciphersuite.getTagLen(), ciphersuite);
                        }
                        engine.acknowledgeKeyChange();
                        continue;
                    case NEW_SESSION_TICKET:
                        handleNewSessionTicket(result.nstBody);
                        continue;
                }
            }
            if (ct != TlsConstants.CT_APPLICATION_DATA) {
                throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "Unexpected content type: " + ct);
            }
            byte[] result = new byte[sessionPlainBuf.remaining()];
            sessionPlainBuf.get(result);
            return result;
        }
        throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "Too many consecutive post-handshake messages");
    }

    /**
     * Парсит alert payload: {@code [level, description]}.
     *
     * @param data тело alert-сообщения
     * @return код alert-описания
     * @throws TlsException при усечённом сообщении
     */
    static byte parseAlertDescription(byte[] data) throws TlsException {
        if (data.length < 2) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "Truncated alert message");
        }
        return data[1];
    }

    /**
     * Обрабатывает close_notify от пира (RFC 8446 §6.1).
     * <p>
     * Устанавливает флаг закрытия, отправляет ответный close_notify (best-effort),
     * зануляет ключевой материал. Не закрывает transport — это делает вызывающий код.
     */
    private void closeNotifyReceived() {
        if (closed) return;
        closed = true;
        handshakeDone = false;
        try {
            byte[] alertPayload = new byte[]{TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY};
            transport.sendRecord(writerRecord.protect(TlsConstants.CT_ALERT, alertPayload));
        } catch (Exception ignored) {}
        if (engine != null) {
            engine.destroy();
            engine = null;
        }
        destroyKeyMaterial();
    }

    /**
     * Обрабатывает fatal alert от пира (RFC 8446 §6).
     * Зануляет ключевой материал, сессия становится непригодной для использования.
     */
    private void fatalAlertReceived() {
        closed = true;
        handshakeDone = false;
        destroyKeyMaterial();
    }

    /**
     * Инициирует KeyUpdate (RFC 8446 §4.6.3).
     * <p>
     * Вырабатывает новые write-ключи, отправляет KU-фрейм пиру через текущий
     * writerRecord (старые ключи), затем применяет новые. Если {@code request = true},
     * пир обязан ответить своим KeyUpdate.
     * <p>
     * Вызов до завершения handshake — IllegalStateException.
     *
     * @param request true = update_requested (пир ответит своим KeyUpdate)
     * @throws IOException если handshake не завершён, сессия закрыта, или ошибка отправки
     */
    public void initiateKeyUpdate(boolean request) throws IOException {
        checkConnected();
        // Двухфазное подтверждение через engine:
        // 1. engine.initiateKeyUpdate — деривация pending write keys + очередь KU-фрейма
        engine.initiateKeyUpdate(request);
        // 2. Отправка KU-фрейма через старый writerRecord
        byte[] kuFrame;
        while ((kuFrame = engine.poll()) != null) {
            sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, kuFrame);
        }
        // 3. Подтверждение — новые write-ключи вступают в силу
        engine.confirmWriteUpdate();
        if (engine.hasWriteKeysChanged()) {
            TlsTrafficKeys newKeys = engine.getWriteKeys();
            if (writerRecord != null) writerRecord.destroy();
            writerRecord = new TlsRecord(newKeys.getKey(), newKeys.getIv(),
                    ciphersuite.getTagLen(), ciphersuite);
            engine.acknowledgeKeyChange();
        }
    }

    /**
     * Обрабатывает NewSessionTicket от сервера (RFC 8446 §4.6.1).
     * <p>
     * Парсит тело тикета, вырабатывает PSK через HKDF-Expand-Label(nonce → resumption_master_secret)
     * и сохраняет в PskStore для последующего session resumption.
     *
     * @param body тело NewSessionTicket
     * @throws IOException при ошибке парсинга
     */
    private void handleNewSessionTicket(byte[] body) throws IOException {
        if (pskStore == null) return;
        TlsMessageParser.ParsedNewSessionTicket nst = TlsMessageParser.parseNewSessionTicket(body);
        // Resumption Master Secret живёт в engine (не копируется)
        byte[] rms = engine != null ? engine.getResumptionMasterSecret() : null;
        if (rms == null) return;
        byte[] psk = TlsPskHelper.derivePsk(rms, nst.ticketNonce, hashLen);
        // RuntimeException от PskStore (например RedisException) не ломает handshake
        try {
            pskStore.onTicketReceived(new PskEntry(
                    nst.ticket, nst.ticketLifetime, nst.ticketAgeAdd, nst.ticketNonce, psk,
                    System.currentTimeMillis()));
        } catch (RuntimeException e) {
            // Silent catch by design: вызывающий код владеет PskStore, и если его реализация
            // кидает RuntimeException — это не ошибка handshake. Resumption будет
            // недоступен, что очевидно вызывающему коду. См. javadoc onTicketReceived().
        }
    }

    /**
     * Отправляет NewSessionTicket со стороны сервера (RFC 8446 §4.6.1).
     * <p>
     * Генерирует случайный 32-байтовый тикет и 8-байтовый ticket_nonce для диверсификации PSK.
     * Тикет шифруется и отправляется клиенту; PSK сохраняется в PskStore для последующего
     * session resumption. Lifetime фиксирован — 86400 секунд (24 часа).
     *
     * @throws IOException при ошибке отправки
     */
    private void sendNewSessionTicket(int nstIndex) throws IOException {
        byte[] ticket = new byte[32];
        // Монотонный nonce: ticket_nonce = 8-байтовый big-endian индекс
        // (RFC 8446 §4.6.1: MUST be unique across all tickets on this connection)
        byte[] ticketNonce = new byte[8];
        ticketNonce[7] = (byte) (nstIndex & 0xFF);
        ticketNonce[6] = (byte) ((nstIndex >>> 8) & 0xFF);
        ticketNonce[5] = (byte) ((nstIndex >>> 16) & 0xFF);
        ticketNonce[4] = (byte) ((nstIndex >>> 24) & 0xFF);
        int ageAddRaw = CryptoRandom.INSTANCE.nextInt();
        long ticketAgeAdd = ageAddRaw & 0xFFFFFFFFL;
        CryptoRandom.INSTANCE.nextBytes(ticket);
        byte[] body = TlsMessageBuilder.buildNewSessionTicket(86400, ticketAgeAdd, ticketNonce, ticket);
        byte[] framed = new TlsHandshakeMessage(
                TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
        sendEncryptedRecord(TlsConstants.CT_HANDSHAKE, framed);
        // Resumption Master Secret живёт в engine
        byte[] rms = engine != null ? engine.getResumptionMasterSecret() : null;
        if (pskStore != null && rms != null) {
            byte[] psk = TlsPskHelper.derivePsk(rms, ticketNonce, hashLen);
            // RuntimeException от PskStore не ломает handshake
            try {
                pskStore.onTicketReceived(new PskEntry(
                        ticket, 86400, ticketAgeAdd, ticketNonce, psk,
                        System.currentTimeMillis()));
            } catch (RuntimeException e) {
                // Silent catch by design: вызывающий код владеет PskStore, и если его реализация
                // кидает RuntimeException — это не ошибка handshake. Resumption будет
                // недоступен, что очевидно вызывающему коду. См. javadoc onTicketReceived().
            }
        }
    }

    /**
     * Собирает полное handshake-сообщение из буфера фрагментов.
     * <p>
     * Проверяет наличие минимум 4-байтового заголовка (type + 3-byte length),
     * затем ждёт накопления полной длины body. Сообщение копируется в новый массив,
     * потреблённые байты удаляются из буфера.
     *
     * @return полный handshake-фрейм (type + length + body) или null если недостаточно данных
     */
    private byte[] assembleHandshakeMessage() {
        byte[] buf = handshakeBuffer.getBuf();
        int size = handshakeBuffer.size();
        if (size < TlsConstants.HANDSHAKE_HEADER_SIZE) {
            return null;
        }
        int msgLen = ((buf[1] & 0xFF) << 16) | ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
        int totalLen = TlsConstants.HANDSHAKE_HEADER_SIZE + msgLen;
        if (size < totalLen) {
            return null;
        }
        byte[] msg = Arrays.copyOf(buf, totalLen);
        handshakeBuffer.consume(totalLen);
        return msg;
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
    static TlsSession createForTest(TlsTransport transport, TlsCiphersuite cs,
                                     TlsTrafficKeys readerKeys,
                                     TlsTrafficKeys writerKeys) {
        TlsSession s = new TlsSession(transport, cs, null, null, null, null, false, null);
        s.readerRecord = new TlsRecord(readerKeys.getKey(), readerKeys.getIv(),
                cs.getTagLen(), cs);
        s.writerRecord = new TlsRecord(writerKeys.getKey(), writerKeys.getIv(),
                cs.getTagLen(), cs);
        // Минимальный engine в POST_HANDSHAKE — нужен для read() с post-handshake сообщениями
        s.engine = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT,
                cs, s.messageBuilder,
                s.selectedEcParams, s.selectedNamedGroup, s.selectedSigScheme,
                s.hashLen, null, false, null);
        s.engine.initForTesting(new byte[cs.getHashLen()], new byte[cs.getHashLen()]);
        s.handshakeDone = true;
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
    static void setAppTrafficSecrets(TlsSession session,
                                      byte[] serverSecret, byte[] clientSecret,
                                      boolean isServer) {
        if (session.engine == null) {
            session.engine = new TlsHandshakeEngine(
                    isServer ? TlsHandshakeEngine.Role.SERVER : TlsHandshakeEngine.Role.CLIENT,
                    session.ciphersuite,
                    session.messageBuilder,
                    session.selectedEcParams,
                    session.selectedNamedGroup,
                    session.selectedSigScheme,
                    session.hashLen,
                    null, false,
                    null); // sniSelector — тестовый engine, selector не нужен
        }
        session.engine.initForTesting(serverSecret, clientSecret);
    }

    /**
     * Закрывает сессию: отправляет close_notify, зачищает ключи.
     * <p>
     * close_notify отправляется best-effort (RFC 8446 §6.1: отправить и забыть).
     * Transport не закрывается — caller владеет его жизненным циклом.
     * После вызова экземпляр непригоден для использования.
     */
    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            handshakeDone = false;
            try {
                byte[] alertPayload = new byte[]{TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY};
                if (writerRecord != null) {
                    transport.sendRecord(writerRecord.protect(TlsConstants.CT_ALERT, alertPayload));
                } else {
                    transport.sendRecord(TlsMessageBuilder.buildPlaintextRecord(TlsConstants.CT_ALERT, alertPayload));
                }
            } catch (Exception ignored) { /* best-effort согласно RFC 8446 §6.1 */ }
            if (engine != null) {
                engine.destroy();
                engine = null;
            }
            destroyKeyMaterial();
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
     * @return {@code true} если handshake выполнен через PSK resumption (без ECDHE),
     *         {@code false} если полный handshake. После {@link #close()} всегда
     *         возвращает {@code false}.
     * @throws IllegalStateException если handshake не завершён (вызов до
     *         завершения handshake на этой сессии)
     */
    public boolean wasResumed() {
        if (!handshakeDone) {
            throw new IllegalStateException(
                    "wasResumed() called before handshake completion on this session");
        }
        return engine != null && engine.isPskAccepted();
    }

    /**
     * Устанавливает PSK-хранилище для приёма NewSessionTicket.
     * Вызывать до handshake или сразу после.
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

    /** @return true после close() */
    public boolean isClosed() {
        return closed;
    }

    /** @return cipher suite, согласованный в handshake */
    public TlsCiphersuite getCipherSuite() {
        return ciphersuite;
    }

    /** @return "TLSv1.3" */
    public String getProtocol() {
        return TlsConstants.PROTOCOL_TLS13;
    }

    /** @return сертификаты пира (null, если handshake не завершён или PSK) */
    public List<TlsCertificate> getPeerCertificates() {
        return peerCertificates;
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
     * проверку по цепочке при наличии caPublicKey.
     *
     * <p>DN matching uses byte-exact DER comparison (RFC 5280 §7.1 semantic
     * normalization not implemented). CAs producing inconsistent DN encodings
     * (e.g. PrintableString vs UTF8String for the same value) will not interop.
     *
     * @throws TlsException при ошибке валидации
     */
    void checkServerCertificateChain(List<TlsCertificate> chain) throws TlsException {
        TlsCertificateValidator.checkServerCertificateChain(
                chain, serverHostname, requireOcspStapling, caPublicKeys);
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
    void checkClientCertificateChain(List<TlsCertificate> chain) throws TlsException {
        TlsCertificateValidator.checkClientCertificateChain(chain, caPublicKeys);
    }

    // validateChain вынесен в TlsCertificateValidator.validateChain()

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
    void verifyCertificateVerify(byte[] cvBody, TlsCertificate cert,
                                           byte[] hsTranscript,
                                           boolean isServer) throws IOException {
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
            byte[] alertPayload = new byte[]{TlsConstants.ALERT_FATAL, description};
            if (writerRecord != null) {
                transport.sendRecord(writerRecord.protect(TlsConstants.CT_ALERT, alertPayload));
            } else {
                transport.sendRecord(TlsMessageBuilder.buildPlaintextRecord(TlsConstants.CT_ALERT, alertPayload));
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Маппинг IOException на код TLS-алерта.
     * TlsException несёт собственный alertCode; остальные → ALERT_HANDSHAKE_FAILURE.
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
     * Читает и собирает зашифрованное handshake-сообщение, декодирует в
     * {@link TlsHandshakeMessage} и автоматически добавляет фрейм в транскрипт.
     * <p>
     * <b>Внимание:</b> используется ТОЛЬКО ДЛЯ ТЕСТОВ!!. Продуктовый код использует
     * {@link TlsHandshakeEngine} через {@link #runHandshake}.
     *
     * @param ctx контекст handshake (в него пишется транскрипт)
     * @return декодированное handshake-сообщение
     * @throws IOException    при ошибке ввода-вывода
     * @throws TlsException   при ошибке дешифрации
     */
    TlsHandshakeMessage receiveDecryptedHandshake(HandshakeContext ctx) throws IOException {
        while (true) {
            if (handshakeBuffer.size() < TlsConstants.HANDSHAKE_HEADER_SIZE) {
                readNextHandshakeRecord();
            }
            byte[] buf = handshakeBuffer.getBuf();
            int size = handshakeBuffer.size();
            int msgLen = ((buf[1] & 0xFF) << 16) | ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
            int totalLen = TlsConstants.HANDSHAKE_HEADER_SIZE + msgLen;
            while (size < totalLen) {
                readNextHandshakeRecord();
                buf = handshakeBuffer.getBuf();
                size = handshakeBuffer.size();
            }
            byte msgType = buf[0];
            byte[] body = Arrays.copyOfRange(buf, TlsConstants.HANDSHAKE_HEADER_SIZE, totalLen);
            ctx.addToTranscript(buf, 0, totalLen);
            handshakeBuffer.consume(totalLen);
            return new TlsHandshakeMessage(msgType, body);
        }
    }

    /**
     * Читает следующую TLS-запись, дешифрует её и дописывает handshake-данные
     * в handshakeBuffer (RFC 8446 §5.1). Используется для сборки фрагментированных
     * handshake-сообщений.
     * <p>
     * <b>Внимание:</b> используется только из {@link #receiveDecryptedHandshake}.
     * Продуктовый код не вызывает этот метод.
     *
     * @throws IOException при ошибке чтения или дешифрации
     */
        void readNextHandshakeRecord() throws IOException {
        sessionRecordBuf.clear();
        try {
            transport.receiveRecord(sessionRecordBuf);
        } catch (BufferOverflowException e) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Record too long", e);
        }
        sessionRecordBuf.flip();
        try {
            handshakeBuffer.ensureCapacity(handshakeBuffer.size + TlsConstants.MAX_PLAINTEXT_LENGTH);
            ByteBuffer dest = ByteBuffer.wrap(handshakeBuffer.buf, handshakeBuffer.size,
                    handshakeBuffer.buf.length - handshakeBuffer.size);
            int destPosBefore = dest.position();
            UnprotectResult r = readerRecord.unprotect(sessionRecordBuf, dest);
            if (r.contentType != TlsConstants.CT_HANDSHAKE) {
                throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        "Expected handshake, got " + r.contentType);
            }
            handshakeBuffer.size += dest.position() - destPosBefore;
        } catch (AuthenticationException e) {
            throw new TlsException(TlsConstants.ALERT_DECRYPT_ERROR,
                    "Handshake record authentication failed", e);
        }
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
     * Зануляет ключевой материал: readerRecord, writerRecord, handshakeBuffer,
     * resumptionMasterSecret. Безопасный вызов после закрытия сессии или ошибки.
     */
    private void destroyKeyMaterial() {
        if (readerRecord != null) readerRecord.destroy();
        readerRecord = null;
        if (writerRecord != null) writerRecord.destroy();
        writerRecord = null;
        handshakeBuffer.reset();
        // Application traffic secrets живут в engine — уничтожаются при engine.destroy()
    }

    /**
     * Определяет схему подписи по named group сертификата.
     *
     * <p>Раньше перебирал 7 известных ГОСТ-схем через hasSignatureScheme().
     * Теперь — прямая конверсия: getNamedGroup() → namedGroupToSignatureScheme(),
     * что делает ровно то же самое без цикла.</p>
     *
     * @param cert сертификат для определения схемы подписи
     * @return идентификатор схемы подписи
     */
    private static int resolveSigScheme(TlsCertificate cert) {
        return TlsCiphersuite.namedGroupToSignatureScheme(cert.getNamedGroup());
    }

    /**
     * Буфер для сборки фрагментированных handshake-сообщений.
     *
     * ByteArrayOutputStream.toByteArray() копирует весь буфер — а нам часто нужно
     * только прочитать 4-байтовый заголовок из начала. GrowableBuffer даёт прямой
     * доступ к внутреннему массиву (getBuf()) без копирования, а consume(n) сдвигает
     * остаток вместо создания нового BAOS и перезаписи.
     *
     * Не thread-safe.
     */
    private static final class GrowableBuffer {
        byte[] buf;
        int size;

        GrowableBuffer() {
            buf = new byte[2048];
            size = 0;
        }

        /** Копирует весь массив data в буфер (см. write(data, off, len)). */
        void write(byte[] data) {
            write(data, 0, data.length);
        }

        /**
         * Копирует len байт из data[off] в конец буфера.
         * Расширяет внутренний массив при необходимости (удвоение).
         */
        void write(byte[] data, int off, int len) {
            ensureCapacity(size + len);
            System.arraycopy(data, off, buf, size, len);
            size += len;
        }

        /** @return текущее количество накопленных байт */
        int size() {
            return size;
        }

        /** @return прямой доступ к внутреннему массиву (без копирования) */
        byte[] getBuf() {
            return buf;
        }

        /**
         * Удаляет первые n байт из буфера, сдвигая остаток к началу.
         * Оптимизация: избегает создания нового массива (в отличие от BAOS).
         */
        void consume(int n) {
            int remainder = size - n;
            if (remainder > 0) {
                System.arraycopy(buf, n, buf, 0, remainder);
            }
            size = remainder;
        }

        /**
         * Очищает буфер: зануляет ключевой материал, сбрасывает размер.
         * Если массив превышает 2048 байт, заменяет его новым (освобождение памяти).
         */
        void reset() {
            TlsUtils.wipeArray(buf);
            size = 0;
            if (buf.length > 2048) {
                buf = new byte[2048];
            }
        }

        /**
         * Расширяет внутренний массив до max(текущий*2, minCapacity).
         * Политика удвоения: амортизированная O(1) на вставку.
         */
        private void ensureCapacity(int minCapacity) {
            if (minCapacity > buf.length) {
                buf = Arrays.copyOf(buf, Math.max(buf.length * 2, minCapacity));
            }
        }
    }

}
