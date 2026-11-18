package org.rssys.gost.jsse.engine;

import java.lang.ref.WeakReference;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.util.CryptoRandom;

/**
 * Реализация SSLSession для ГОСТ TLS 1.3.
 * <p>
 * Содержит результаты согласования: cipher suite, сертификаты пира, протокол, ALPN. Движок
 * создаёт сессию по завершении рукопожатия; до него отдаётся пустая сессия без сертификатов.
 * <p>
 * Ответы OCSP хранятся в приватном поле, недоступном через {@link #getValue(String)};
 * приложению отдаются только копии через {@link #getStatusResponses()}.
 * <p>
 * Значения приложения ({@code putValue}/{@code getValue}) потокобезопасны: сессия лежит в общем
 * кэше контекста и доступна из разных соединений.
 */
public final class GostSSLSession extends ExtendedSSLSession {

    private final String cipherSuite;
    private final String protocol;
    private final String peerHost;
    private final int peerPort;
    private final X509Certificate[] peerCertificates;
    private final X509Certificate[] localCertificates;
    private final long creationTime;
    private final byte[] sessionId;
    private final String applicationProtocol;
    private final Map<String, Object> values = new ConcurrentHashMap<>();

    // Приватный канал для OCSP — невидим через getValue. Порядок записей соответствует
    // сертификатам, предъявленным сервером (ExtendedSSLSession.getStatusResponses());
    // запись нулевой длины означает «ответа нет». Хранятся копии: список уходит наружу.
    private volatile List<byte[]> statusResponses = List.of();

    // Контекст задаётся после создания, при помещении сессии в кэш; читается из любых потоков
    private volatile GostSSLSessionContext sessionContext;
    private volatile boolean invalidated;

    // Слабая ссылка: сессия живёт в кэше контекста дольше соединения и не должна удерживать
    // движок с ключами. Секрет экспорта здесь не хранится: после закрытия отказ даёт сам движок.
    private volatile WeakReference<GostSSLEngine> keyingMaterialEngine;

    private static final String[] LOCAL_SIG_ALGS = {GostJsseConstants.KEY_ALG_ECGOST_2012};

    static final String MSG_NO_PEER_CERTIFICATES = "No peer certificates";
    static final String MSG_EXPORTER_UNAVAILABLE = "Exporter master secret not available";

    /**
     * Создаёт сессию без согласованного протокола ALPN.
     *
     * @param cipherSuite       IANA-имя согласованного набора шифров
     * @param peerHost          DNS-имя пира (может быть пустым)
     * @param peerPort          порт пира (-1, если неизвестен)
     * @param peerCertificates  сертификаты пира (лист первым) или null
     * @param localCertificates собственные сертификаты (лист первым) или null
     */
    public GostSSLSession(
            String cipherSuite,
            String peerHost,
            int peerPort,
            X509Certificate[] peerCertificates,
            X509Certificate[] localCertificates) {
        this(cipherSuite, peerHost, peerPort, peerCertificates, localCertificates, null);
    }

    /**
     * Создаёт сессию со всеми параметрами согласования.
     * <p>
     * Предусловие: handshake успешно завершён, cipherSuite и hostname
     * зафиксированы. applicationProtocol может быть null (ALPN не использовался).
     * Постусловие: все поля immutable, sessionId сгенерирован через CryptoRandom.
     *
     * @param cipherSuite        IANA-имя согласованного cipher suite
     * @param peerHost           DNS-имя пира (может быть пустым)
     * @param peerPort           порт пира (-1 если неизвестен)
     * @param peerCertificates   сертификаты пира (leaf-first), не null
     * @param localCertificates  собственные сертификаты (leaf-first), не null
     * @param applicationProtocol согласованный протокол ALPN, или null
     */
    public GostSSLSession(
            String cipherSuite,
            String peerHost,
            int peerPort,
            X509Certificate[] peerCertificates,
            X509Certificate[] localCertificates,
            String applicationProtocol) {
        this.cipherSuite = cipherSuite;
        this.protocol = GostJsseConstants.PROTOCOL_TLS_1_3;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.peerCertificates =
                peerCertificates != null ? peerCertificates.clone() : new X509Certificate[0];
        this.localCertificates =
                localCertificates != null ? localCertificates.clone() : new X509Certificate[0];
        this.applicationProtocol = applicationProtocol;
        this.creationTime = System.currentTimeMillis();
        this.sessionId = new byte[TlsConstants.SESSION_ID_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(this.sessionId);
    }

    // ========================================================================
    // SSLSession
    // ========================================================================

    @Override
    public byte[] getId() {
        return sessionId.clone();
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    /**
     * Задаёт контекст сессии. Вызывается из {@link GostSSLSessionContext#putSession} при помещении
     * сессии в кэш. Непубличный: контекст назначается один раз и в течение жизни сессии не
     * меняется.
     */
    void setSessionContext(GostSSLSessionContext ctx) {
        this.sessionContext = ctx;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    /**
     * Возвращает время создания сессии: обращения к сессии не отслеживаются, потому что
     * возобновление в TLS 1.3 создаёт новую сессию, а не продлевает прежнюю.
     */
    @Override
    public long getLastAccessedTime() {
        return creationTime;
    }

    @Override
    public void invalidate() {
        invalidated = true;
        GostSSLSessionContext context = sessionContext;
        if (context != null) {
            context.removeSession(this);
        }
    }

    /** Привязывает сессию к движку соединения, у которого она запрашивает экспорт. */
    void setKeyingMaterialEngine(GostSSLEngine engine) {
        this.keyingMaterialEngine = new WeakReference<>(engine);
    }

    /**
     * Экспортирует ключевой материал соединения (RFC 8446 §7.5, tls-exporter RFC 9266).
     * <p>
     * Сигнатура и контракт совпадают с {@code ExtendedSSLSession.exportKeyingMaterialData} JDK 25:
     * на JDK 25 и новее этот метод переопределяет базовый, на более ранних работает как обычный.
     * Для ГОСТ-наборов RFC 9367 экспорт не определяет; схема взята из RFC 8446 с хэшем Стрибог.
     * <p>
     * Отличие от JDK: значение доступно только пока соединение открыто. Секрет живёт в движке и
     * затирается при закрытии, а в сессии, которая остаётся в кэше, его нет. {@code invalidate()}
     * экспорт не отключает.
     * <p>
     * Метка кодируется в UTF-8, для привязки к каналу метки берутся из реестра IANA «TLS Exporter
     * Labels». {@code null} и пустой контекст дают одно значение. Результат секретный: вызывающий
     * обязан затереть его.
     *
     * @param label метка, не null, от 1 до 249 байт в UTF-8
     * @param context контекст не длиннее 255 байт или null
     * @param length длина результата от 1 до {@code 255 * hashLen}
     * @return экспортированное значение
     * @throws NullPointerException если {@code label} равна null
     * @throws IllegalArgumentException если аргументы выходят за допустимые пределы
     * @throws IllegalStateException если рукопожатие не завершено или соединение закрыто
     * @throws SSLKeyException объявлено контрактом JDK; в этой реализации не бросается
     */
    public byte[] exportKeyingMaterialData(String label, byte[] context, int length)
            throws SSLKeyException {
        // Порядок как в JDK: null метки, длина, затем состояние, затем остальные пределы
        Objects.requireNonNull(label, "label can not be null");
        if (length < 1) {
            throw new IllegalArgumentException("length must be positive");
        }
        GostSSLEngine engine = keyingMaterialEngine != null ? keyingMaterialEngine.get() : null;
        if (engine == null) {
            throw new IllegalStateException(MSG_EXPORTER_UNAVAILABLE);
        }
        return engine.exportKeyingMaterial(label, context, length);
    }

    /**
     * Экспортирует ключевой материал как ключ; см. {@link #exportKeyingMaterialData}. Сигнатура и
     * контракт совпадают с {@code ExtendedSSLSession.exportKeyingMaterialKey} JDK 25.
     *
     * @param keyAlg алгоритм ключа, не null и не пуст
     * @param label метка; см. {@link #exportKeyingMaterialData}
     * @param context контекст или null
     * @param length длина ключа в байтах
     * @return ключ с экспортированным значением
     * @throws NullPointerException если {@code keyAlg} или {@code label} равны null
     * @throws IllegalArgumentException если {@code keyAlg} пуст или аргументы вне пределов
     * @throws IllegalStateException если рукопожатие не завершено или соединение закрыто
     * @throws SSLKeyException объявлено контрактом JDK; в этой реализации не бросается
     */
    public SecretKey exportKeyingMaterialKey(
            String keyAlg, String label, byte[] context, int length) throws SSLKeyException {
        Objects.requireNonNull(keyAlg, "keyAlg can not be null");
        if (keyAlg.isEmpty()) {
            throw new IllegalArgumentException("keyAlg must not be empty");
        }
        byte[] material = exportKeyingMaterialData(label, context, length);
        try {
            // SecretKeySpec копирует массив, поэтому исходный затирается сразу
            return new SecretKeySpec(material, keyAlg);
        } finally {
            TlsUtils.wipeArray(material);
        }
    }

    @Override
    public boolean isValid() {
        if (invalidated) return false;
        GostSSLSessionContext context = sessionContext;
        if (context == null) return true;
        int timeout = context.getSessionTimeout();
        if (timeout == 0) return true;
        long age = System.currentTimeMillis() - creationTime;
        return age < timeout * 1000L;
    }

    @Override
    public void putValue(String name, Object value) {
        requireName(name);
        if (value == null) throw new IllegalArgumentException("value must not be null");
        Object old = values.put(name, value);
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public Object getValue(String name) {
        requireName(name);
        return values.get(name);
    }

    @Override
    public void removeValue(String name) {
        requireName(name);
        Object old = values.remove(name);
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public String[] getValueNames() {
        return values.keySet().toArray(new String[0]);
    }

    // ConcurrentHashMap не принимает null-ключ, а контракт SSLSession требует IAE
    private static void requireName(String name) {
        if (name == null) throw new IllegalArgumentException("name must not be null");
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException(MSG_NO_PEER_CERTIFICATES);
        }
        return peerCertificates.clone();
    }

    /**
     * Сертификаты, отправленные пиру в этом рукопожатии (лист первым).
     * <p>
     * Клиент выбирает сертификат только после CertificateRequest, поэтому метод возвращает
     * {@code null}, если сервер сертификат не запрашивал, клиент отправил пустой Certificate
     * (подходящего не нашлось) или рукопожатие возобновлено по PSK.
     */
    @Override
    public Certificate[] getLocalCertificates() {
        return localCertificates.length > 0 ? localCertificates.clone() : null;
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() {
        // Устаревший метод JDK: поддерживается только getPeerCertificates()
        throw new UnsupportedOperationException("Use getPeerCertificates()");
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException(MSG_NO_PEER_CERTIFICATES);
        }
        return peerCertificates[0].getSubjectX500Principal();
    }

    /** Субъект первого отправленного сертификата; {@code null} в тех же случаях, что и выше. */
    @Override
    public Principal getLocalPrincipal() {
        if (localCertificates.length == 0) return null;
        return localCertificates[0].getSubjectX500Principal();
    }

    /**
     * Сессия хранит результат согласования как есть: {@code null}, если ALPN не использовался.
     * Контракт движка (пустая строка вместо {@code null} после рукопожатия) действует на
     * {@code SSLEngine.getApplicationProtocol()}, а не на сессию.
     *
     * @return согласованный протокол ALPN, или null если ALPN не использовался
     */
    public String getApplicationProtocol() {
        return applicationProtocol;
    }

    @Override
    public String getCipherSuite() {
        return cipherSuite;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public int getPacketBufferSize() {
        return GostJsseConstants.DEFAULT_PACKET_BUFFER_SIZE;
    }

    @Override
    public int getApplicationBufferSize() {
        return GostJsseConstants.DEFAULT_APPLICATION_BUFFER_SIZE;
    }

    // ========================================================================
    // ExtendedSSLSession
    // ========================================================================

    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        return LOCAL_SIG_ALGS.clone();
    }

    // Android: @Override снят — AGP-трансформация android.jar удаляет эти методы
    // из compile classpath, хотя они есть в android.jar API 34:
    //   javap -classpath android.jar javax.net.ssl.ExtendedSSLSession:
    //     public abstract String[] getPeerSupportedSignatureAlgorithms();
    //     public List<byte[]> getStatusResponses();
    /** @return пустой массив: схемы подписи пира сессия не хранит */
    public String[] getPeerSupportedSignatureAlgorithms() {
        return new String[0];
    }

    /**
     * Ответы OCSP, присланные сервером (в порядке его сертификатов); для серверной сессии
     * собственный staple. Запись нулевой длины означает «ответа нет». Возвращаются копии.
     */
    public List<byte[]> getStatusResponses() {
        return copyOf(statusResponses);
    }

    // ========================================================================
    // Приватный канал для OCSP (package-private)
    // ========================================================================

    /** Серверная сессия: собственный staple сервера как единственный ответ. */
    void setOcspResponse(byte[] ocspResponse) {
        this.statusResponses = ocspResponse != null ? List.of(ocspResponse.clone()) : List.of();
    }

    /**
     * Клиентская сессия: ответы, присланные сервером, в порядке его сертификатов.
     *
     * @param responses ответы по порядку цепочки ({@code byte[0]} - ответа нет), не null
     */
    void setStatusResponses(List<byte[]> responses) {
        this.statusResponses = copyOf(responses);
    }

    /** Неизменяемый список копий: ни приложение, ни источник не могут изменить содержимое. */
    private static List<byte[]> copyOf(List<byte[]> source) {
        List<byte[]> copy = new ArrayList<>(source.size());
        for (byte[] response : source) {
            copy.add(response.clone());
        }
        return Collections.unmodifiableList(copy);
    }
}
