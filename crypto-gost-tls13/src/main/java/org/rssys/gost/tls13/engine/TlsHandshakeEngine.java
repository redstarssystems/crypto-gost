package org.rssys.gost.tls13.engine;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.Pack;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsServerCredentials;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

import java.io.IOException;
import java.util.Arrays;
import org.rssys.gost.signature.ECPoint;
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.List;

/**
 * Пошаговый state machine для handshake TLS 1.3.
 * <p>
 * Отвязан от I/O: принимает handshake-фреймы (уже дешифрованные, если требуется),
 * возвращает handshake-фреймы для отправки и сигналы о смене ключей.
 * <p>
 * Используется:
 * <ul>
 *   <li>{@link TlsSession} — как тонкая обёртка с I/O (читает запись → engine.receive →
 *       poll → отправляет)</li>
 *   <li>Будущий JSSE-модуль (GostSSLEngine) — для управления handshake
 *       через wrap/unwrap</li>
 * </ul>
 * <p>
 * Состояния перечислены в {@link State}. Переходы:
 * <pre>
 *   CLIENT:
 *     CLIENT_START → (send ClientHello) → CLIENT_WAIT_SERVER_HELLO
 *       → receive SH → CLIENT_WAIT_ENCRYPTED_EXTENSIONS
 *       → receive EE → CLIENT_WAIT_CERTIFICATE_OR_CR
 *       → receive CR → CLIENT_WAIT_CERTIFICATE
 *       → receive Certificate → CLIENT_WAIT_CERTIFICATE_VERIFY
 *       → receive CV → CLIENT_WAIT_FINISHED
 *       → receive Finished → CLIENT_SEND_FINISHED
 *       → poll() → HANDSHAKE_DONE
 *
 *   SERVER:
 *     SERVER_WAIT_CLIENT_HELLO → receive CH → SERVER_SEND_FLIGHT
 *       → poll() → (SH, EE, CR?, Cert, CV, Finished) →
 *         SERVER_WAIT_CLIENT_FINISHED | SERVER_WAIT_CLIENT_CERTIFICATE
 *       → receive Cert → SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY
 *       → receive CV → SERVER_WAIT_CLIENT_FINISHED
 *       → receive Finished → HANDSHAKE_DONE
 * </pre>
 * <p>
 * Не thread-safe. Каждый экземпляр — для одного handshake.
 */
public final class TlsHandshakeEngine {

    // ========================================================================
    // Роль и состояния
    // ========================================================================

    public enum Role { CLIENT, SERVER }

    /**
     * Результат post-handshake сообщения.
     * Заменяет схему "byte[] → null=KU, non-null=NST",
     * которая была неочевидна для вызывающего кода.
     */
    public static final class PostHandshakeResult {
        public enum Type { KEY_UPDATE_HANDLED, NEW_SESSION_TICKET }

        public final Type type;
        /** Тело NewSessionTicket (null если тип не NEW_SESSION_TICKET) */
        public final byte[] nstBody;

        private PostHandshakeResult(Type type, byte[] nstBody) {
            this.type = type;
            this.nstBody = nstBody;
        }

        static PostHandshakeResult keyUpdateHandled() {
            return new PostHandshakeResult(Type.KEY_UPDATE_HANDLED, null);
        }

        static PostHandshakeResult newSessionTicket(byte[] body) {
            return new PostHandshakeResult(Type.NEW_SESSION_TICKET, body);
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

        HANDSHAKE_DONE,
        /** Финальное состояние после handshake.
         *  В отличие от HANDSHAKE_DONE, engine остаётся жив:
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
    private State pendingNextState; // для SERVER_SEND_FLIGHT → следующее состояние ожидания
    private final TlsCiphersuite ciphersuite;
    private final int hashLen;
    private TlsMessageBuilder messageBuilder;
    private final ECParameters ecParams;
    private final int selectedNamedGroup;
    private final int selectedSigScheme;
    private byte[] ocspResponse;
    private final boolean requestClientAuth;
    /** true = wantClientAuth (пустой сертификат не фатален, только когда requestClientAuth=true) */
    private final boolean optionalClientAuth;

    private final ArrayDeque<byte[]> outgoingQueue = new ArrayDeque<>();
    private HandshakeContext ctx;

    // Ключи
    private TlsTrafficKeys handshakeServerKeys;
    private TlsTrafficKeys handshakeClientKeys;
    private TlsTrafficKeys readKeys;
    private TlsTrafficKeys writeKeys;
    private boolean readKeysChanged;
    private boolean writeKeysChanged;

    // Handshake traffic secrets (RFC 8446 §7.1: вычисляется из hash(CH+SH), необходимо для проверки Finished)
    private byte[] serverHandshakeTrafficSecret;
    private byte[] clientHandshakeTrafficSecret;

    // Сертификат пира (для валидации вызывающим кодом)
    private List<TlsCertificate> receivedCertificates;
    private boolean needsCertValidation;

    // Результаты
    private TlsCiphersuite negotiatedCiphersuite;
    private byte[] resumptionMasterSecret;
    // Application traffic secrets для KeyUpdate (RFC 8446 §7.2)
    private byte[] serverAppTrafficSecret;
    private byte[] clientAppTrafficSecret;
    private String errorMessage;

    // Клиентские PSK-параметры (передаются через start)
    private byte[] pskKey;

    private byte[] pskIdentity;

    private boolean pskAccepted;

    private boolean pskOffered;

    private long obfuscatedTicketAge;

    private PskStore serverPskStore;

    // mTLS — сервер запросил клиентский сертификат, и клиент его отправит
    private boolean clientAuthRequested;

    // SNI (Server Name Indication)
    private String serverHostname;
    private String requestedServerName;

    // ALPN (RFC 7301)
    private List<String> clientAlpnProtocols;
    private List<String> serverAlpnProtocols;
    private String selectedAlpnProtocol;
    private java.util.function.Function<java.util.List<String>, String> alpnSelector;

    // SNI certificate selection (RFC 6066 §3, RFC 8446 §4.4.2)
    private final SniCertificateSelector sniSelector;

    // Post-handshake (KeyUpdate)
    // Флаги и ключи для двухфазного подтверждения KeyUpdate:
    // 1. engine выставляет pendingWriteUpdate → caller отправляет KU-фрейм через старый writerRecord
    // 2. caller вызывает confirmWriteUpdate() → новые writeKeys вступают в силу
    private boolean pendingWriteUpdate;
    private TlsTrafficKeys pendingWriteKeys;
    private byte[] pendingWriterSecret;  // app traffic secret для замены после confirm

    // Счётчик KeyUpdate — защита от флуда (RFC 8446 §5 явно не задаёт лимит,
    // но без него JSSE-путь уязвим к CPU-амплификации: каждый KU требует HKDF + MGM init)
    private int keyUpdateCount;
    private static final int MAX_KEY_UPDATES = 32;

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
     */
    public TlsHandshakeEngine(Role role, TlsCiphersuite ciphersuite,
                               TlsMessageBuilder messageBuilder,
                               ECParameters ecParams,
                               int selectedNamedGroup,
                               int selectedSigScheme,
                               int hashLen,
                               byte[] ocspResponse,
                               boolean requestClientAuth,
                               SniCertificateSelector sniSelector) {
        this(role, ciphersuite, messageBuilder, ecParams,
             selectedNamedGroup, selectedSigScheme, hashLen,
             ocspResponse, requestClientAuth, sniSelector, false);
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
     */
    public TlsHandshakeEngine(Role role, TlsCiphersuite ciphersuite,
                               TlsMessageBuilder messageBuilder,
                               ECParameters ecParams,
                               int selectedNamedGroup,
                               int selectedSigScheme,
                               int hashLen,
                               byte[] ocspResponse,
                               boolean requestClientAuth,
                               SniCertificateSelector sniSelector,
                               boolean optionalClientAuth) {
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

        this.ctx = new HandshakeContext();
        this.state = (role == Role.CLIENT) ? State.CLIENT_START : State.SERVER_WAIT_CLIENT_HELLO;
        this.negotiatedCiphersuite = ciphersuite;
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
                    throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                            "Unexpected receive in state " + state);
            }
        } catch (IOException e) {
            state = State.ERROR;
            errorMessage = e.getMessage();
            throw e;
        } catch (RuntimeException e) {
            state = State.ERROR;
            errorMessage = "Unexpected error: " + e.getMessage();
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "Unexpected error processing handshake message", e);
        }
    }

    /**
     * Извлекает следующий исходящий handshake-фрейм из очереди.
     *
     * @return handshake-фрейм (type + length + body) или null, если очередь пуста
     */
    public byte[] poll() {
        if (!outgoingQueue.isEmpty()) {
            return outgoingQueue.pollFirst();
        }
        // Сервер: после опустошения очереди переходим в состояние ожидания
        if (state == State.SERVER_SEND_FLIGHT) {
            state = pendingNextState;
        }
        // Клиент: после отправки Finished переходим в HANDSHAKE_DONE
        if (state == State.CLIENT_SEND_FINISHED) {
            finishHandshake();
        }
        return null;
    }

    /** @return текущее состояние handshake */
    public State getState() { return state; }
    /** @return true если handshake успешно завершён (включая POST_HANDSHAKE) */
    public boolean isDone() { return state == State.HANDSHAKE_DONE || state == State.POST_HANDSHAKE; }
    /** @return true если handshake в состоянии ошибки */
    public boolean isError() { return state == State.ERROR; }
    /** @return сообщение об ошибке или null */
    public String getErrorMessage() { return errorMessage; }

    // ========================================================================
    // Методы получения статуса и ключей
    // ========================================================================

    /**
     * @return ключи для чтения (дешифрация) или null, если ещё не доступны
     */
    public TlsTrafficKeys getReadKeys() { return readKeys; }

    /**
     * @return ключи для записи (шифрование) или null, если ещё не доступны
     */
    public TlsTrafficKeys getWriteKeys() { return writeKeys; }

    /**
     * @return true если ключи чтения изменились с момента последнего acknowledge
     */
    public boolean hasReadKeysChanged() { return readKeysChanged; }

    /**
     * @return true если ключи записи изменились с момента последнего acknowledge
     */
    public boolean hasWriteKeysChanged() { return writeKeysChanged; }

    /** Сбрасывает флаги смены ключей (вызывается после применения ключей). */
    public void acknowledgeKeyChange() {
        readKeysChanged = false;
        writeKeysChanged = false;
    }

    // ========================================================================
    // Post-handshake (KeyUpdate)
    // ========================================================================

    /**
     * @return текущая роль (CLIENT/SERVER) — нужно для определения mapping
     *         readerSecret/writerSecret при KeyUpdate
     */
    public boolean isServer() { return role == Role.SERVER; }

    /**
     * @return true если есть отложенная смена write-ключей.
     *         Вызывается после KEY_UPDATE_HANDLED.
     *         Caller должен: (1) отправить KU-фрейм через старый writerRecord,
     *         (2) вызвать {@link #confirmWriteUpdate()}.
     */
    public boolean hasPendingWriteUpdate() { return pendingWriteUpdate; }

    /**
     * Подтверждает смену write-ключей.
     * Вызывается ПОСЛЕ отправки KU-фрейма (который должен быть отправлен
     * через старый writerRecord — RFC 8446 §4.6.3: ответный KU отправляется
     * ДО обновления ключей записи).
     * <p>
     * После вызова {@link #hasWriteKeysChanged()} == true,
     * caller создаёт новый writerRecord из {@link #getWriteKeys()}.
     */
    public void confirmWriteUpdate() {
        if (!pendingWriteUpdate) return;

        // Переносим pending keys в рабочие
        writeKeys = pendingWriteKeys;
        writeKeysChanged = true;

        // Замена app traffic secret для будущих KeyUpdate
        byte[] writerSecret = role == Role.SERVER ? serverAppTrafficSecret : clientAppTrafficSecret;
        TlsUtils.wipeArray(writerSecret);
        if (role == Role.SERVER) {
            serverAppTrafficSecret = pendingWriterSecret;
        } else {
            clientAppTrafficSecret = pendingWriterSecret;
        }

        pendingWriteKeys = null;
        pendingWriterSecret = null;
        pendingWriteUpdate = false;

        // Crossed-in-flight: если мы получили KU от пира после того, как сами
        // инициировали, не отправляем дублирующий ответ
        initiatedKeyUpdate = false;
    }

    /**
     * Инициирует KeyUpdate (RFC 8446 §4.6.3).
     * <p>
     * Вырабатывает новые write-ключи (сохраняет как pending) и ставит в очередь
     * KU-фрейм. Caller отправляет KU через старый writerRecord, затем вызывает
     * {@link #confirmWriteUpdate()}.
     * <p>
     * Двухфазность: KU-фрейм должен быть отправлен ДО применения новых ключей,
     * чтобы пир мог расшифровать его старыми ключами.
     *
     * @param request true = update_requested (пир обязан ответить своим KeyUpdate)
     * @throws TlsException если handshake не завершён или превышен лимит KU
     */
    public void initiateKeyUpdate(boolean request) throws TlsException {
        if (state != State.POST_HANDSHAKE) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Cannot initiate KeyUpdate before handshake completion");
        }
        if (keyUpdateCount >= MAX_KEY_UPDATES) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Too many KeyUpdates");
        }
        keyUpdateCount++;
        initiatedKeyUpdate = true;

        // Вырабатываем новый writer secret из текущего (RFC 8446 §7.2)
        byte[] writerSecret = role == Role.SERVER ? serverAppTrafficSecret : clientAppTrafficSecret;
        this.pendingWriterSecret = HkdfStreebog.expandLabel(
                writerSecret, TlsConstants.LABEL_TRAFFIC_UPD, new byte[0], hashLen, hashLen);

        byte[] newKey = HkdfStreebog.expandLabel(
                pendingWriterSecret, TlsConstants.LABEL_KEY, new byte[0],
                ciphersuite.getKeyLen(), hashLen);
        byte[] newIv = HkdfStreebog.expandLabel(
                pendingWriterSecret, TlsConstants.LABEL_IV, new byte[0],
                ciphersuite.getIvLen(), hashLen);
        this.pendingWriteKeys = new TlsTrafficKeys(newKey, newIv);
        this.pendingWriteUpdate = true;

        // Формируем KU-фрейм (он пойдёт в очередь и будет отправлен через poll)
        byte[] kuBody = new byte[]{ request ? (byte)1 : 0 };
        byte[] kuMsg = new TlsHandshakeMessage(
                TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        outgoingQueue.addLast(kuMsg);
    }

    /**
     * Принимает post-handshake сообщение (KeyUpdate или NewSessionTicket)
     * после завершения handshake (state == POST_HANDSHAKE).
     * <p>
     * Не использует transcript (ctx уже уничтожен) — KeyUpdate и NST
     * не добавляются в транскрипт после handshake (RFC 8446 §4.4.1).
     *
     * @param handshakeFrame полный handshake-фрейм (type + length + body)
     * @return результат обработки: KEY_UPDATE_HANDLED или NEW_SESSION_TICKET
     * @throws TlsException при нарушении протокола
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
            return PostHandshakeResult.newSessionTicket(hm.getBody());
        }
        throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
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
     * ВАЖНО: reader-ключи обновляются немедленно, writer-ключи становятся pending
     * (двухфазное подтверждение: caller отправляет KU-ответ старыми ключами,
     * затем confirmWriteUpdate).
     */
    private void handlePostHandshakeKeyUpdate(byte[] body) throws TlsException {
        if (body.length != 1) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "KeyUpdate: invalid body length " + body.length);
        }
        if (keyUpdateCount >= MAX_KEY_UPDATES) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Too many KeyUpdates");
        }
        keyUpdateCount++;

        boolean requested = (body[0] & 0xFF) != 0;

        // RFC 8446 §7.2: направление читатель/писатель зависит от роли
        // Сервер: читает client-ключи, пишет server-ключи
        // Клиент: читает server-ключи, пишет client-ключи
        byte[] readerSecret = role == Role.SERVER
                ? clientAppTrafficSecret : serverAppTrafficSecret;

        // Деривация нового reader secret (RFC 8446 §7.2: "traffic upd" + пустой hash)
        byte[] newReaderSecret = HkdfStreebog.expandLabel(
                readerSecret, TlsConstants.LABEL_TRAFFIC_UPD, new byte[0], hashLen, hashLen);

        // reader-ключи обновляются всегда — пир сменил свои write-ключи
        byte[] newReaderKey = HkdfStreebog.expandLabel(
                newReaderSecret, TlsConstants.LABEL_KEY, new byte[0],
                ciphersuite.getKeyLen(), hashLen);
        byte[] newReaderIv = HkdfStreebog.expandLabel(
                newReaderSecret, TlsConstants.LABEL_IV, new byte[0],
                ciphersuite.getIvLen(), hashLen);
        TlsTrafficKeys newReadKeys = new TlsTrafficKeys(newReaderKey, newReaderIv);

        // Замена старого reader secret на новый (для цепочки будущих KU)
        TlsUtils.wipeArray(readerSecret);
        if (role == Role.SERVER) {
            clientAppTrafficSecret = newReaderSecret;
        } else {
            serverAppTrafficSecret = newReaderSecret;
        }

        // Устанавливаем новые readKeys — все последующие записи расшифровываются новыми ключами
        readKeys = newReadKeys;
        readKeysChanged = true;

        if (requested) {
            // RFC 8446 §4.6.3: "If a party has already sent a KeyUpdate,
            // it does not need to send another when it receives a KeyUpdate from the other peer."
            if (!initiatedKeyUpdate) {
                // Нормальный случай: пир запросил — готовим ответ KU(not_requested)
                byte[] kuBody = new byte[]{0};
                byte[] kuMsg = new TlsHandshakeMessage(
                        TlsConstants.HT_KEY_UPDATE, kuBody).encode();
                outgoingQueue.addLast(kuMsg);

                // Деривация нового writer secret (pending — не применяем до отправки ответа)
                byte[] writerSecret = role == Role.SERVER
                        ? serverAppTrafficSecret : clientAppTrafficSecret;
                this.pendingWriterSecret = HkdfStreebog.expandLabel(
                        writerSecret, TlsConstants.LABEL_TRAFFIC_UPD, new byte[0], hashLen, hashLen);

                byte[] newWriterKey = HkdfStreebog.expandLabel(
                        pendingWriterSecret, TlsConstants.LABEL_KEY, new byte[0],
                        ciphersuite.getKeyLen(), hashLen);
                byte[] newWriterIv = HkdfStreebog.expandLabel(
                        pendingWriterSecret, TlsConstants.LABEL_IV, new byte[0],
                        ciphersuite.getIvLen(), hashLen);
                this.pendingWriteKeys = new TlsTrafficKeys(newWriterKey, newWriterIv);
                this.pendingWriteUpdate = true;
            }
            // Crossed-in-flight: мы уже инициировали KU, не отправляем дублирующий ответ.
            // Собственный pendingWriteKeys (от initiateKeyUpdate) остаётся в силе.
        }
    }

    /**
     * @return Resumption Master Secret (defensive copy), или null если handshake не завершён
     */
    public byte[] getResumptionMasterSecret() {
        return resumptionMasterSecret == null ? null : resumptionMasterSecret.clone();
    }

    /**
     * Для модульных тестов — инициализирует engine без полного handshake.
     * Устанавливает состояние POST_HANDSHAKE и app traffic secrets.
     * ResumptionMasterSecret получает значение по умолчанию (нули) —
     * для тестов NewSessionTicket.
     * Вызывается из {@code TlsSession.setAppTrafficSecrets} и
     * {@code TlsSession.createForTest}.
     */
    public void initForTesting(byte[] serverSecret, byte[] clientSecret) {
        this.serverAppTrafficSecret = serverSecret;
        this.clientAppTrafficSecret = clientSecret;
        if (resumptionMasterSecret == null) {
            this.resumptionMasterSecret = new byte[hashLen];
        }
        if (state == State.CLIENT_START || state == State.SERVER_WAIT_CLIENT_HELLO) {
            this.state = State.POST_HANDSHAKE;
        }
    }
    // ========================================================================

    /**
     * @return true если вызывающий код должен проверить сертификаты пира
     */
    public boolean needsCertificateValidation() { return needsCertValidation; }

    /**
     * @return сертификаты пира (для проверки вызывающим кодом)
     */
    public List<TlsCertificate> getReceivedCertificates() { return receivedCertificates; }

    /**
     * Подтверждает (или отклоняет) валидацию сертификата пира.
     * <p>
     * Должен быть вызван после {@link #needsCertificateValidation()} == true.
     * Если {@code valid == false}, engine переходит в ERROR.
     *
     * @param valid true если сертификат прошёл проверку
     */
    public void acknowledgeCertificateValidation(boolean valid) {
        needsCertValidation = false;
        if (!valid) {
            state = State.ERROR;
            errorMessage = "Peer certificate rejected";
        }
    }

    // ========================================================================
    // Результаты handshake
    // ========================================================================

    /**
     * @return согласованный cipher suite (может отличаться от переданного в конструктор)
     */
    public TlsCiphersuite getNegotiatedCiphersuite() { return negotiatedCiphersuite; }

    /**
     * @return server application traffic secret для KeyUpdate, или null
     */
    public byte[] getServerAppTrafficSecret() {
        return serverAppTrafficSecret != null ? serverAppTrafficSecret.clone() : null;
    }

    /**
     * @return client application traffic secret для KeyUpdate, или null
     */
    public byte[] getClientAppTrafficSecret() {
        return clientAppTrafficSecret != null ? clientAppTrafficSecret.clone() : null;
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
            // Генерация эфемерной ECDHE-пары для key_share
            KeyPair ecdheKp = KeyGenerator.generateKeyPair(ecParams);
            ctx.setEcdhePrivateKey(ecdheKp.getPrivate());
            byte[] ecdhePoint = TlsEncoding.encodePoint(ecdheKp.getPublic());

            // ALPN: messageBuilder вставит расширение в ClientHello, но только
            // если протоколы заданы — иначе CH не содержит ALPN (обратная совместимость).
            if (clientAlpnProtocols != null) {
                messageBuilder.setClientAlpnProtocols(clientAlpnProtocols);
            }

            byte[] clientHelloBody;
            if (pskKey != null) {
                clientHelloBody = messageBuilder.buildClientHelloWithPsk(
                        ecdhePoint, pskIdentity != null ? pskIdentity : new byte[0],
                        obfuscatedTicketAge, serverHostname);
                // Binder вычисляется по телу CH с placeholder-нулями, затем вставляется
                byte[] binder = TlsPskHelper.computeBinder(clientHelloBody, pskKey, hashLen);
                System.arraycopy(binder, 0, clientHelloBody,
                        clientHelloBody.length - binder.length, binder.length);
                pskOffered = true;
            } else {
                clientHelloBody = messageBuilder.buildClientHello(ecdhePoint, serverHostname);
            }
            byte[] chFrame = new TlsHandshakeMessage(
                    TlsConstants.HT_CLIENT_HELLO, clientHelloBody).encode();
            ctx.addToTranscript(chFrame);
            state = State.CLIENT_WAIT_SERVER_HELLO;
            return chFrame;
        } catch (RuntimeException e) {
            state = State.ERROR;
            errorMessage = "Failed to build ClientHello: " + e.getMessage();
            throw e;
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
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected ServerHello, got " + shMsg.getType());
        }
        ctx.addToTranscript(frame);

        // Проверяем PSK-принятие: наличие pre_shared_key в ServerHello = PSK accepted
        if (pskOffered) {
            pskAccepted = TlsMessageParser.parseServerHelloHasPsk(shMsg.getBody());
        }

        // Парсим ECDHE и cipher suite
        TlsMessageParser.ParsedServerHello parsedSH;
        try {
            parsedSH = TlsMessageParser.parseServerHello(shMsg.getBody(), selectedNamedGroup);
        } catch (TlsException e) {
            state = State.ERROR;
            errorMessage = "Failed to parse ServerHello: " + e.getMessage();
            throw e;
        }

        if (parsedSH.cipherSuiteId != ciphersuite.getId()) {
            // Сервер выбрал другой cipher suite из предложенных клиентом
            if (!TlsConstants.OFFERED_CIPHER_SUITE_IDS.contains(parsedSH.cipherSuiteId)) {
                throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ServerHello: cipher suite " + parsedSH.cipherSuiteId + " не в списке предложенных");
            }
            TlsCiphersuite chosen = TlsCiphersuite.byId(parsedSH.cipherSuiteId);
            if (chosen == null) {
                throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER,
                        "ServerHello: неподдерживаемый cipher suite " + parsedSH.cipherSuiteId);
            }
            negotiatedCiphersuite = chosen;
        }

        // ECDHE: декодируем публичный ключ сервера, вычисляем общий секрет
        byte[] pubKeyRaw = parsedSH.ecdhePublicKeyRaw;
        // Проверяем, что сервер выбрал группу из нашего key_share (RFC 8446 §4.2.8)
        if (parsedSH.actualGroup != selectedNamedGroup) {
            throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    "ServerHello: key_share group 0x" + Integer.toHexString(parsedSH.actualGroup)
                    + " does not match offered group 0x" + Integer.toHexString(selectedNamedGroup));
        }
        ECParameters shEcParams = TlsCiphersuite.namedGroupToParams(parsedSH.actualGroup);
        PublicKeyParameters peerPub = TlsEncoding.decodePoint(pubKeyRaw, shEcParams);
        ctx.setPeerEcdhePublicKey(peerPub);

        PrivateKeyParameters priv = ctx.getEcdhePrivateKey();
        byte[] sharedSecret = computeEcdheShared(
                priv, peerPub, negotiatedCiphersuite.getCofactor(), hashLen);
        ctx.setEcdhePrivateKey(null);

        // Key schedule: инициализация и derivation handshake secret
        ctx.setKeySchedule(new TlsKeySchedule(negotiatedCiphersuite));
        if (pskAccepted) {
            ctx.getKeySchedule().deriveEarlySecret(pskKey);
        }
        try {
            ctx.getKeySchedule().deriveHandshakeSecret(sharedSecret);
        } finally {
            // sharedSecret больше не нужен — зануляем сразу
            TlsUtils.wipeArray(sharedSecret);
        }

        // Вырабатываем handshake traffic keys (RFC 8446 §7.1)
        byte[] hsTranscript = ctx.transcriptHash(hashLen);
        this.serverHandshakeTrafficSecret = ctx.getKeySchedule().getServerHandshakeTrafficSecret(hsTranscript);
        this.clientHandshakeTrafficSecret = ctx.getKeySchedule().getClientHandshakeTrafficSecret(hsTranscript);
        TlsUtils.wipeArray(hsTranscript);

        handshakeServerKeys = ctx.getKeySchedule().deriveTrafficKeys(serverHandshakeTrafficSecret);
        handshakeClientKeys = ctx.getKeySchedule().deriveTrafficKeys(clientHandshakeTrafficSecret);

        // Устанавливаем ключи чтения (расшифровка EE, Cert, CV, Finished от сервера)
        readKeys = handshakeServerKeys;
        readKeysChanged = true;

        state = State.CLIENT_WAIT_ENCRYPTED_EXTENSIONS;
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
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected EncryptedExtensions, got " + eeMsg.getType());
        }
        ctx.addToTranscript(frame);

        // ALPN: RFC 7301 §3.2 — клиент обязан проверить, что сервер выбрал протокол из нашего списка.
        // Если сервер отвечает неожиданным протоколом — это либо баг, либо атака (ILOGICAL_PARAMETER).
        if (clientAlpnProtocols != null) {
            String serverSelected = TlsMessageParser.parseEncryptedExtensionsAlpn(eeMsg.getBody());
            if (serverSelected != null) {
                if (!clientAlpnProtocols.contains(serverSelected)) {
                    throw new TlsException(TlsConstants.ALERT_ILLEGAL_PARAMETER,
                            "Server selected ALPN protocol not offered: " + serverSelected);
                }
                this.selectedAlpnProtocol = serverSelected;
            }
            // Сервер может не поддерживать ALPN — это штатный сценарий, протокол не назначается.
        }

        state = pskAccepted ? State.CLIENT_WAIT_FINISHED : State.CLIENT_WAIT_CERTIFICATE_OR_CR;
    }

    /**
     * Принимает Certificate или CertificateRequest от сервера.
     * <p>
     * CertificateRequest → включаем mTLS, ожидаем серверный Certificate.
     * Certificate → штатный разбор цепочки + ожидание CertificateVerify.
     * Иное сообщение → ALERT_UNEXPECTED_MESSAGE.
     *
     * @param frame полный handshake-фрейм Certificate или CertificateRequest
     * @throws TlsException при нарушении протокола
     * @throws IOException   при ошибке парсинга
     */
    private void receiveCertificateOrCr(byte[] frame) throws TlsException, java.io.IOException {
        TlsHandshakeMessage msg = TlsHandshakeMessage.decode(frame);
        if (msg.getType() == TlsConstants.HT_CERTIFICATE_REQUEST) {
            ctx.addToTranscript(frame);
            List<byte[]> caDns = TlsMessageParser.parseCertificateRequest(msg.getBody());
            ctx.setAcceptedCaDns(caDns);
            clientAuthRequested = true;
            state = State.CLIENT_WAIT_CERTIFICATE;
            return;
        }
        if (msg.getType() == TlsConstants.HT_CERTIFICATE) {
            receiveCertificate(frame);
            return;
        }
        throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "Expected Certificate or CertificateRequest, got " + msg.getType());
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
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected Certificate, got " + certMsg.getType());
        }
        ctx.addToTranscript(frame);

        List<TlsCertificate> chain = TlsMessageParser.parseCertificate(certMsg.getBody());
        if (chain.isEmpty()) {
            // RFC 8446 §4.4.2: сервер обязан прислать непустой certificate_list.
            // Пустой список — нарушение протокола, не certificate_required (этот алерт только для сервера).
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "Server sent empty certificate list");
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
    private void receiveCertificateVerify(byte[] frame, boolean isServer) throws TlsException, java.io.IOException {
        TlsHandshakeMessage cvMsg = TlsHandshakeMessage.decode(frame);
        if (cvMsg.getType() != TlsConstants.HT_CERTIFICATE_VERIFY) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected CertificateVerify, got " + cvMsg.getType());
        }
        // Transcript-hash до включения CV — подпись покрывает предыдущие сообщения
        byte[] cvTranscript = ctx.transcriptHash(hashLen);
        ctx.addToTranscript(frame);

        byte[] cvBody = cvMsg.getBody();
        TlsCertificate cert = receivedCertificates.get(0);
        TlsCertificateValidator.verifyCertificateVerify(cvBody, cert, cvTranscript, isServer);
        TlsUtils.wipeArray(cvTranscript);

        state = isServer ? State.CLIENT_WAIT_FINISHED : State.SERVER_WAIT_CLIENT_FINISHED;
    }

    /**
     * Принимает и верифицирует серверный Finished (RFC 8446 §4.4.4).
     * <p>
     * Пересчитывает verify_data через handshake-транскрипт и serverHandshakeTrafficSecret,
     * сравнивает с полученным значением. При успехе:
     * <ul>
     *   <li>устанавливает клиентские handshake-ключи записи для отправки Certificate/CV/Finished</li>
     *   <li>если mTLS (clientAuthRequested) — строит и ставит в очередь Certificate + CertificateVerify</li>
     *   <li>строит и ставит в очередь клиентский Finished</li>
     * </ul>
     *
     * @param frame полный handshake-фрейм Finished
     * @throws TlsException при нарушении протокола
     */
    private void receiveFinished(byte[] frame) throws TlsException {
        TlsHandshakeMessage sfMsg = TlsHandshakeMessage.decode(frame);
        if (sfMsg.getType() != TlsConstants.HT_FINISHED) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected Finished, got " + sfMsg.getType());
        }
        byte[] serverFinishedTranscript = ctx.transcriptHash(hashLen);
        ctx.addToTranscript(frame);

        // Пересчитываем verify_data и сравниваем
        byte[] expectedVerifyData = TlsMessageBuilder.buildFinished(
                ctx.getKeySchedule(), serverHandshakeTrafficSecret, serverFinishedTranscript);
        TlsUtils.wipeArray(serverFinishedTranscript);
        if (!java.security.MessageDigest.isEqual(sfMsg.getBody(), expectedVerifyData)) {
            throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "Server Finished verification failed");
        }

        // Устанавливаем ключи записи (клиентский Certificate + CertificateVerify + Finished)
        writeKeys = handshakeClientKeys;
        writeKeysChanged = true;

        // Строим клиентский Certificate + CertificateVerify (если mTLS)
        if (clientAuthRequested) {
            if (messageBuilder.getCertificateChain() == null
                    || messageBuilder.getCertificateChain().isEmpty()) {
                // RFC 8446 §4.4.2: если сервер запросил сертификат, но у клиента
                // его нет, клиент ОБЯЗАН отправить пустой certificate_list
                // (без CertificateVerify), затем Finished.
                byte[] emptyBody = messageBuilder.buildEmptyCertificateBody();
                byte[] emptyFrame = new TlsHandshakeMessage(
                        TlsConstants.HT_CERTIFICATE, emptyBody).encode();
                ctx.addToTranscript(emptyFrame);
                outgoingQueue.addLast(emptyFrame);
            } else {
                byte[] certBody = messageBuilder.buildCertificateBody();
                byte[] certFrame = new TlsHandshakeMessage(
                        TlsConstants.HT_CERTIFICATE, certBody).encode();
                ctx.addToTranscript(certFrame);

                byte[] cvTranscript = ctx.transcriptHash(hashLen);
                byte[] cvBody = messageBuilder.buildCertificateVerify(cvTranscript,
                        TlsConstants.CLIENT_CERTIFICATE_VERIFY_CTX);
                TlsUtils.wipeArray(cvTranscript);
                byte[] cvFrame = new TlsHandshakeMessage(
                        TlsConstants.HT_CERTIFICATE_VERIFY, cvBody).encode();
                ctx.addToTranscript(cvFrame);

                outgoingQueue.addLast(certFrame);
                outgoingQueue.addLast(cvFrame);
            }
        }

        // Клиентский Finished ставим в очередь
        byte[] clientFinishedTranscript = ctx.transcriptHash(hashLen);
        byte[] clientFinishedBody = TlsMessageBuilder.buildFinished(
                ctx.getKeySchedule(), clientHandshakeTrafficSecret, clientFinishedTranscript);
        TlsUtils.wipeArray(clientFinishedTranscript);
        byte[] cfFrame = new TlsHandshakeMessage(
                TlsConstants.HT_FINISHED, clientFinishedBody).encode();
        ctx.addToTranscript(cfFrame);

        outgoingQueue.addLast(cfFrame);

        state = State.CLIENT_SEND_FINISHED;
    }

    /**
     * Завершает handshake: вырабатывает Master Secret и application traffic keys.
     * <p>
     * После вызова {@link #receiveFinished} клиент отправляет свой Finished,
     * после чего вызывается этот метод для финализации key schedule:
     * <ul>
     *   <li>deriveMasterSecret() — общий мастер-секрет из handshake secret</li>
     *   <li>getServerApplicationTrafficKeys / getClientApplicationTrafficKeys — ключи защищённого канала</li>
     *   <li>устанавливает readKeys и writeKeys для прикладных данных</li>
     *   <li>уничтожает контекст handshake (транскрипт, промежуточные ключи)</li>
     * </ul>
     */
    private void finishHandshake() {
        ctx.getKeySchedule().deriveMasterSecret();
        this.resumptionMasterSecret = ctx.getKeySchedule().getResumptionMasterSecret();
        byte[] appTranscript = ctx.transcriptHash(hashLen);

        // Capture app traffic secrets для KeyUpdate до ctx.destroy()
        this.serverAppTrafficSecret = ctx.getKeySchedule().getServerApplicationTrafficSecret(appTranscript);
        this.clientAppTrafficSecret = ctx.getKeySchedule().getClientApplicationTrafficSecret(appTranscript);

        TlsTrafficKeys appServerKeys = ctx.getKeySchedule().deriveTrafficKeys(serverAppTrafficSecret);
        TlsTrafficKeys appClientKeys = ctx.getKeySchedule().deriveTrafficKeys(clientAppTrafficSecret);
        TlsUtils.wipeArray(appTranscript);

        readKeys = appServerKeys;
        readKeysChanged = true;
        writeKeys = appClientKeys;
        writeKeysChanged = true;

        // POST_HANDSHAKE вместо HANDSHAKE_DONE — engine остаётся жив
        // для обработки KeyUpdate и NewSessionTicket. ctx уничтожается
        // (транскрипт после handshake не нужен), но app traffic secrets
        // сохранены в полях экземпляра.
        state = State.POST_HANDSHAKE;
        ctx.destroy();
    }

    // ========================================================================
    // Реализация серверного handshake
    // ========================================================================

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
    private void receiveClientHello(byte[] frame) throws TlsException {
        TlsHandshakeMessage chMsg = TlsHandshakeMessage.decode(frame);
        if (chMsg.getType() != TlsConstants.HT_CLIENT_HELLO) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected ClientHello, got " + chMsg.getType());
        }

        byte[] chBody = chMsg.getBody();
        ctx.addToTranscript(frame);

        // PSK
        pskAccepted = false;
        byte[] pskIdentityRaw = TlsMessageParser.parseClientHelloPskIdentity(chBody);
        // NEW: auto-PSK lookup from server store if no explicit pskKey
        if (pskIdentityRaw != null && pskKey == null && serverPskStore != null) {
            PskEntry entry = serverPskStore.get(pskIdentityRaw);
            if (entry != null && !entry.isExpired(System.currentTimeMillis())) {
                pskKey = entry.getPsk();
            }
        }
        if (pskIdentityRaw != null && pskKey != null) {
            if (TlsPskHelper.verifyBinder(chBody, pskKey, hashLen)) {
                pskAccepted = true;
            } else {
                throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                        "PSK binder verification failed");
            }
        }

        // --- SNI certificate selection (RFC 6066 §3, RFC 8446 §4.4.2) ---
        byte[] ocspForCert = this.ocspResponse;
        if (!pskAccepted && sniSelector != null) {
            String sni = TlsMessageParser.parseClientHelloSni(chBody);
            if (sni != null) {
                TlsServerCredentials creds = sniSelector.select(sni);
                if (creds != null) {
                    List<TlsCertificate> newChain = creds.getCertificateChain();
                    int newScheme = TlsCiphersuite.namedGroupToSignatureScheme(
                            TlsCiphersuite.paramsToNamedGroup(
                                    newChain.get(0).getPublicKey().getParams()));
                    this.messageBuilder = new TlsMessageBuilder(
                            ciphersuite, selectedNamedGroup, newScheme,
                            creds.getPrivateKey(), newChain, hashLen);
                    ocspForCert = creds.getOcspResponse();
                }
            }
        }

        // Определяем схему подписи по кривой сертификата (RFC 9367 §5.2)
        int[] acceptableSchemes;
        if (messageBuilder.getCertificateChain() != null
                && !messageBuilder.getCertificateChain().isEmpty()) {
            int certNamedGroup = TlsCiphersuite.paramsToNamedGroup(
                    messageBuilder.getCertificateChain().get(0).getPublicKey().getParams());
            int certScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
            acceptableSchemes = new int[]{ certScheme };
        } else {
            acceptableSchemes = null;
        }

        // Парсим ECDHE key_share, SNI и согласуем схему подписи
        TlsMessageParser.ParsedKeyShare parsedCH = TlsMessageParser.parseClientHello(
                chBody, selectedNamedGroup, acceptableSchemes, ciphersuite.getId());
        if (parsedCH.matchedSigScheme != 0 && parsedCH.matchedSigScheme != selectedSigScheme) {
            messageBuilder.updateSigScheme(parsedCH.matchedSigScheme);
        }
        this.requestedServerName = parsedCH.serverName;

        // Определяем ECParams по фактической группе клиента
        int actualGroup = parsedCH.actualGroup;
        ECParameters actualEcParams;
        if (actualGroup == selectedNamedGroup) {
            actualEcParams = ecParams;
        } else {
            try {
                actualEcParams = TlsCiphersuite.namedGroupToParams(actualGroup);
            } catch (IllegalArgumentException e) {
                throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                        "ClientHello: key_share group 0x" + Integer.toHexString(actualGroup) + " not supported");
            }
        }

        // Декодируем публичный ключ клиента
        byte[] peerKeyRaw = parsedCH.ecdhePublicKeyRaw;
        PublicKeyParameters peerPub = TlsEncoding.decodePoint(peerKeyRaw, actualEcParams);
        ctx.setPeerEcdhePublicKey(peerPub);

        // Генерируем свою ECDHE-пару на той же группе
        KeyPair ecdheKp = KeyGenerator.generateKeyPair(actualEcParams);
        ctx.setEcdhePrivateKey(ecdheKp.getPrivate());
        byte[] ecdhePoint = TlsEncoding.encodePoint(ecdheKp.getPublic());

        // Shared secret
        byte[] sharedSecret = computeEcdheShared(
                ctx.getEcdhePrivateKey(), ctx.getPeerEcdhePublicKey(),
                ciphersuite.getCofactor(), hashLen);
        ctx.setEcdhePrivateKey(null);

        ctx.setKeySchedule(new TlsKeySchedule(ciphersuite));
        if (pskAccepted) {
            ctx.getKeySchedule().deriveEarlySecret(pskKey);
        }
        try {
            ctx.getKeySchedule().deriveHandshakeSecret(sharedSecret);
        } finally {
            TlsUtils.wipeArray(sharedSecret);
        }

        // ServerHello: key_share с той же группой, что у клиента
        byte[] shBody = messageBuilder.buildServerHello(ecdhePoint, pskAccepted, actualGroup);
        byte[] shFrame = new TlsHandshakeMessage(
                TlsConstants.HT_SERVER_HELLO, shBody).encode();
        ctx.addToTranscript(shFrame);
        outgoingQueue.addLast(shFrame);

        // Вырабатываем handshake traffic keys
        byte[] hsTranscript = ctx.transcriptHash(hashLen);
        this.serverHandshakeTrafficSecret = ctx.getKeySchedule().getServerHandshakeTrafficSecret(hsTranscript);
        this.clientHandshakeTrafficSecret = ctx.getKeySchedule().getClientHandshakeTrafficSecret(hsTranscript);
        TlsUtils.wipeArray(hsTranscript);

        handshakeServerKeys = ctx.getKeySchedule().deriveTrafficKeys(serverHandshakeTrafficSecret);
        handshakeClientKeys = ctx.getKeySchedule().deriveTrafficKeys(clientHandshakeTrafficSecret);

        // Сервер может сразу писать (SH уже отправлен в открытом виде,
        // остальное — через writerRecord) и читать (Finished от клиента)
        readKeys = handshakeClientKeys;
        readKeysChanged = true;
        writeKeys = handshakeServerKeys;
        writeKeysChanged = true;

        // ALPN (RFC 7301 §3.2): selector или auto-select.
        // Если задан alpnSelector — JSSE решает; null от selector = no ALPN.
        // Иначе auto-select по serverAlpnProtocols (как в фазе 3).
        List<String> clientAlpn = TlsMessageParser.parseClientHelloAlpn(chBody);
        if (clientAlpn != null && !clientAlpn.isEmpty()) {
            if (alpnSelector != null) {
                String selected = alpnSelector.apply(clientAlpn);
                // WHY: JDK-конвенция — JdkAlpnSslEngine возвращает "" при
                // отсутствии согласованного протокола (не null). Пустая строка
                // означает "ALPN не согласован" — продолжаем без него.
                if (selected != null && !selected.isEmpty()) {
                    if (!clientAlpn.contains(selected)) {
                        throw new TlsException(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                                "Selector returned protocol not in client list");
                    }
                    this.selectedAlpnProtocol = selected;
                }
                // null / "" от selector = ALPN не использовать, EE без extension
                // null от selector = ALPN не использовать, EE без extension
            } else if (serverAlpnProtocols != null) {
                String selected = TlsMessageParser.selectAlpn(serverAlpnProtocols, clientAlpn);
                if (selected == null) {
                    throw new TlsException(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                            "No common ALPN protocol between client and server");
                }
                this.selectedAlpnProtocol = selected;
            }
        }

        // EncryptedExtensions — с опциональным ALPN (RFC 7301 §3.2)
        byte[] eeBody = TlsMessageBuilder.buildEncryptedExtensions(selectedAlpnProtocol);
        byte[] eeFrame = new TlsHandshakeMessage(
                TlsConstants.HT_ENCRYPTED_EXTENSIONS, eeBody).encode();
        ctx.addToTranscript(eeFrame);
        outgoingQueue.addLast(eeFrame);

        if (!pskAccepted) {
            // CertificateRequest (если требуется mTLS)
            if (requestClientAuth) {
                byte[] crBody = TlsMessageBuilder.buildCertificateRequest();
                byte[] crFrame = new TlsHandshakeMessage(
                        TlsConstants.HT_CERTIFICATE_REQUEST, crBody).encode();
                ctx.addToTranscript(crFrame);
                outgoingQueue.addLast(crFrame);
            }

            // Certificate
            byte[] certBody = ocspForCert != null
                    ? messageBuilder.buildCertificateBody(ocspForCert)
                    : messageBuilder.buildCertificateBody();
            byte[] certFrame = new TlsHandshakeMessage(
                    TlsConstants.HT_CERTIFICATE, certBody).encode();
            ctx.addToTranscript(certFrame);
            outgoingQueue.addLast(certFrame);

            // CertificateVerify
            byte[] cvTranscript = ctx.transcriptHash(hashLen);
            byte[] cvBody = messageBuilder.buildCertificateVerify(cvTranscript);
            TlsUtils.wipeArray(cvTranscript);
            byte[] cvFrame = new TlsHandshakeMessage(
                    TlsConstants.HT_CERTIFICATE_VERIFY, cvBody).encode();
            ctx.addToTranscript(cvFrame);
            outgoingQueue.addLast(cvFrame);

            // Server Finished
            byte[] sfTranscript = ctx.transcriptHash(hashLen);
            byte[] sfBody = TlsMessageBuilder.buildFinished(
                    ctx.getKeySchedule(), serverHandshakeTrafficSecret, sfTranscript);
            TlsUtils.wipeArray(sfTranscript);
            byte[] sfFrame = new TlsHandshakeMessage(
                    TlsConstants.HT_FINISHED, sfBody).encode();
            ctx.addToTranscript(sfFrame);
            outgoingQueue.addLast(sfFrame);

            pendingNextState = requestClientAuth
                    ? State.SERVER_WAIT_CLIENT_CERTIFICATE
                    : State.SERVER_WAIT_CLIENT_FINISHED;
        } else {
            // PSK сокращённый handshake: только Finished
            byte[] sfTranscript = ctx.transcriptHash(hashLen);
            byte[] sfBody = TlsMessageBuilder.buildFinished(
                    ctx.getKeySchedule(), serverHandshakeTrafficSecret, sfTranscript);
            TlsUtils.wipeArray(sfTranscript);
            byte[] sfFrame = new TlsHandshakeMessage(
                    TlsConstants.HT_FINISHED, sfBody).encode();
            ctx.addToTranscript(sfFrame);
            outgoingQueue.addLast(sfFrame);

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
            throw new TlsException(TlsConstants.ALERT_CERTIFICATE_REQUIRED,
                    "Expected client Certificate, got " + certMsg.getType());
        }
        ctx.addToTranscript(frame);

        List<TlsCertificate> chain = TlsMessageParser.parseCertificate(certMsg.getBody());
        if (chain.isEmpty()) {
            // RFC 8446 §4.4.2: клиент может прислать пустой certificate_list если нет сертификата.
            // Решение о том, обязателен ли сертификат, принимается на уровне engine (requestClientAuth)
            // с учётом optionalClientAuth (wantClientAuth).
            if (requestClientAuth && !optionalClientAuth) {
                throw new TlsException(TlsConstants.ALERT_CERTIFICATE_REQUIRED,
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
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Expected client Finished, got " + cfMsg.getType());
        }
        byte[] clientFinishedTranscript = ctx.transcriptHash(hashLen);
        ctx.addToTranscript(frame);

        byte[] expectedVerifyData = TlsMessageBuilder.buildFinished(
                ctx.getKeySchedule(), clientHandshakeTrafficSecret, clientFinishedTranscript);
        TlsUtils.wipeArray(clientFinishedTranscript);
        if (!java.security.MessageDigest.isEqual(cfMsg.getBody(), expectedVerifyData)) {
            throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "Client Finished verification failed");
        }

        ctx.getKeySchedule().deriveMasterSecret();
        this.resumptionMasterSecret = ctx.getKeySchedule().getResumptionMasterSecret();
        byte[] appTranscript = ctx.transcriptHash(hashLen);

        // Capture app traffic secrets для KeyUpdate до ctx.destroy()
        this.serverAppTrafficSecret = ctx.getKeySchedule().getServerApplicationTrafficSecret(appTranscript);
        this.clientAppTrafficSecret = ctx.getKeySchedule().getClientApplicationTrafficSecret(appTranscript);

        TlsTrafficKeys appServerKeys = ctx.getKeySchedule().deriveTrafficKeys(serverAppTrafficSecret);
        TlsTrafficKeys appClientKeys = ctx.getKeySchedule().deriveTrafficKeys(clientAppTrafficSecret);
        TlsUtils.wipeArray(appTranscript);

        readKeys = appClientKeys;
        readKeysChanged = true;
        writeKeys = appServerKeys;
        writeKeysChanged = true;

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
     */
    public void setServerHostname(String serverHostname) {
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
     * null от selector = ALPN не использовать (EE без extension).
     * <p>
     * Используется {@code javax.net.ssl.SSLParameters.setHandshakeApplicationProtocolSelector}
     * из JSSE.
     */
    public void setAlpnSelector(java.util.function.Function<java.util.List<String>, String> selector) {
        this.alpnSelector = selector;
    }

    // ========================================================================
    // PSK (публичный API, вызывается перед start())
    // ========================================================================

    /**
     * Устанавливает PSK-параметры для клиента.
     * Вызывать до {@link #start()}.
     *
     * @param psk                PSK-ключ
     * @param identity           тикет (opaque ticket)
     * @param obfuscatedTicketAge obfuscated_ticket_age
     */
    public void setPsk(byte[] psk, byte[] identity, long obfuscatedTicketAge) {
        this.pskKey = psk.clone();
        this.pskIdentity = identity;
        this.obfuscatedTicketAge = obfuscatedTicketAge;
        this.pskOffered = true;
    }

    /**
     * Устанавливает PSK-ключ для сервера (для верификации binder'а).
     * Вызывать до {@link #start()}.
     *
     * @param psk PSK-ключ
     */
    public void setServerPsk(byte[] psk) {
        this.pskKey = psk.clone();
    }

    /**
     * Устанавливает PskStore для автоматического PSK-lookup на сервере.
     * При получении ClientHello engine сам извлекает PSK identity, ищет в store
     * и устанавливает pskKey — без необходимости внешнего парсинга ClientHello.
     */
    public void setServerPskStore(PskStore store) {
        this.serverPskStore = store;
    }

    /** @return true если PSK был принят */
    public boolean isPskAccepted() { return pskAccepted; }

    /**
     * Зачищает ключевой материал.
     * Вызывается владельцем engine после завершения или ошибки.
     */
    public void destroy() {
        if (handshakeServerKeys != null) handshakeServerKeys.destroy();
        if (handshakeClientKeys != null) handshakeClientKeys.destroy();
        if (readKeys != null && readKeys != handshakeServerKeys && readKeys != handshakeClientKeys) {
            readKeys.destroy();
        }
        if (writeKeys != null && writeKeys != handshakeServerKeys && writeKeys != handshakeClientKeys) {
            writeKeys.destroy();
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
        if (pendingWriteKeys != null) {
            pendingWriteKeys.destroy();
            pendingWriteKeys = null;
        }
        if (pendingWriterSecret != null) {
            TlsUtils.wipeArray(pendingWriterSecret);
            pendingWriterSecret = null;
        }
        if (ctx != null) ctx.destroy();
        if (resumptionMasterSecret != null) {
            TlsUtils.wipeArray(resumptionMasterSecret);
            resumptionMasterSecret = null;
        }
        TlsUtils.wipeArray(pskKey); pskKey = null;
        pskIdentity = null;
        obfuscatedTicketAge = 0;
        byte[] frame;
        while ((frame = outgoingQueue.pollFirst()) != null) {
            TlsUtils.wipeArray(frame);
        }
        receivedCertificates = null;
    }

    /**
     * Вычисляет ECDHE shared secret (RFC 6090, RFC 9367 §4.1).
     * <p>
     * Выполняет умножение {@code peerPub * (myPriv * cofactor)} на эллиптической кривой.
     * Результат — X-координата точки (BigInteger), переведённая в bytes big-endian
     * фиксированной длины через {@link #toFixedLengthBytes}.
     * <p>
     * Метод static и не сохращает shared secret в полях экземпляра — безопасность:
     * вызывающий код обязан занулить результат через {@code TlsUtils.wipeArray}.
     *
     * @return shared secret (X-координата, hashLen байт)
     * @throws TlsException если общая точка — бесконечность
     */
    private static byte[] computeEcdheShared(PrivateKeyParameters myPriv,
                                              PublicKeyParameters peerPub,
                                              BigInteger cofactor, int hashLen) throws TlsException {
        ECPoint shared = peerPub.getQ().multiply(myPriv.getD().multiply(cofactor));
        shared = shared.normalize();
        if (shared.isInfinity()) {
            throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "ECDHE shared secret is point at infinity");
        }
        BigInteger x = shared.getX();
        byte[] xBe = Pack.reverseBytes(toFixedLengthBytes(x, hashLen));
        return xBe;
    }

    /**
     * Приводит BigInteger к массиву байт фиксированной длины.
     * <p>
     * {@code BigInteger.toByteArray()} может вернуть массив короче (нулевой старший байт
     * удалён) или длиннее (добавлен знаковый байт) — этот метод дополняет нулями слева
     * или обрезает слева до нужной длины. Используется для ECDHE X-координаты (hashLen байт).
     */
    private static byte[] toFixedLengthBytes(BigInteger value, int len) {
        byte[] raw = value.toByteArray();
        if (raw.length == len) return raw;
        byte[] result = new byte[len];
        if (raw.length < len) {
            System.arraycopy(raw, 0, result, len - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - len, result, 0, len);
        }
        return result;
    }
}
