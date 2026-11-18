package org.rssys.gost.tls13.config;

import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Конфигурация сервера TLS 1.3.
 *
 * <pre>{@code
 * TlsSession session = TlsSession.createServer(new TlsServerConfig(cs, chain, priv)
 *     .needClientAuth(TrustAnchors.ofCertificate(caCert)), transport);
 * }</pre>
 */
public final class TlsServerConfig {
    private final TlsCiphersuite ciphersuite;
    private final List<GostCertificate> serverCertificateChain;
    private final PrivateKeyParameters serverPrivateKey;
    private byte[] ocspResponse;
    private ClientAuth clientAuthMode = ClientAuth.NONE;
    private TrustAnchors trustAnchors;
    private List<String> alpnProtocols;
    private SniCertificateSelector sniSelector;
    private int ticketsToSend = 1;
    private int selectedNamedGroup;
    private List<OIDFilter> oidFilters;
    private boolean interopAcceptGostBaseSigScheme;
    private ClientOcspPolicy clientOcspPolicy = ClientOcspPolicy.OFF;

    /**
     * Включает обход openssl-gost-provider v3.6.0: клиент (в т.ч. Angie
     * в роли mTLS-клиента на upstream-части) всегда шлёт базовые схемы
     * (0x0709 для 256-bit, 0x070D для 512-bit) независимо от реальной
     * кривой сертификата.
     * <p>
     * По умолчанию выключено. Включение — осознанное решение разработчика
     * для совместимости с openssl-gost-provider. RFC 9367 §5 формально
     * требует точного соответствия схемы кривой сертификата.
     *
     * @param enabled true — принимать базовые схемы для любого ключа того же размера
     * @return this
     */
    public TlsServerConfig withInteropAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
        return this;
    }

    public boolean isInteropAcceptGostBaseSigScheme() {
        return interopAcceptGostBaseSigScheme;
    }

    /**
     * @param ciphersuite             cipher suite (не null)
     * @param serverCertificateChain  цепочка сертификатов сервера (leaf первый; не пуста)
     * @param serverPrivateKey        закрытый ключ для CertificateVerify
     */
    public TlsServerConfig(
            TlsCiphersuite ciphersuite,
            List<GostCertificate> serverCertificateChain,
            PrivateKeyParameters serverPrivateKey) {
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        // Проверка пустоты идёт над копией: исходный список мог бы опустеть после проверки
        List<GostCertificate> chainCopy =
                ConfigCopies.immutableCopy(serverCertificateChain, "serverCertificateChain");
        if (chainCopy == null || chainCopy.isEmpty()) {
            throw new IllegalArgumentException("serverCertificateChain must not be null or empty");
        }
        this.ciphersuite = ciphersuite;
        this.serverCertificateChain = chainCopy;
        this.serverPrivateKey = serverPrivateKey;
    }

    /**
     * Задаёт OCSP-ответ для stapling (RFC 8446 §4.4.2.1). Ответ отправляется только если клиент
     * запросил его расширением {@code status_request}.
     * <p>
     * Принимается сырой OCSPResponse DER; он кодируется как
     * {@code status_type(1) || uint24(len) || DER} (RFC 6066 §8). Отключить stapling можно только
     * значением {@code null}: пустой массив отвергается сразу.
     *
     * @param ocspResponse OCSPResponse DER или {@code null} (без stapling)
     * @return this
     * @throws IllegalArgumentException если массив пуст или длиннее 65527 байт
     */
    public TlsServerConfig withOcspStaplingResponse(byte[] ocspResponse) {
        this.ocspResponse = ConfigCopies.validatedOcspCopy(ocspResponse);
        return this;
    }

    /**
     * @param protocols список протоколов ALPN в порядке убывания предпочтения (RFC 7301). Имя - это
     *                  последовательность байт: каждый символ строки (не выше U+00FF) кодирует
     *                  один байт (ISO-8859-1, как в SunJSSE с Java SE 16)
     * @return this
     * @throws IllegalArgumentException если список пуст или имя не проходит
     *                                  {@link TlsUtils#validateAlpnProtocols}
     */
    public TlsServerConfig withAlpnProtocols(List<String> protocols) {
        this.alpnProtocols = ConfigCopies.validatedAlpnCopy(protocols);
        return this;
    }

    /**
     * Включает обязательную аутентификацию клиента (mTLS): сертификат запрашивается, клиент без
     * него получает {@code certificate_required}.
     *
     * <p>Режим и доверенные якоря задаются одним вызовом, поэтому режим без якорей
     * невозможен. Повторный вызов {@code needClientAuth}/{@link #wantClientAuth} заменяет
     * режим и якоря целиком.</p>
     *
     * <p>По умолчанию ({@link ClientOcspPolicy#OFF}) прямой tls13-путь отзыв клиентского
     * сертификата не проверяет: staple не запрашивается и отклоняется, поэтому отозванный
     * сертификат с валидной цепочкой, сроком, KeyUsage и EKU будет принят. Проверку
     * присланного клиентом OCSP-staple включает {@link #withClientOcspPolicy}. CRL и
     * загрузка OCSP по сети не выполняются: для них используйте JSSE
     * ({@code GostX509TrustManager}).</p>
     *
     * <p>Срок истёкшего якоря при цепочке из нескольких сертификатов по умолчанию
     * ({@code AnchorExpiryPolicy.DEFAULT}) не блокирует соединение: пишется предупреждение
     * (RFC 5280 §6.1). Чтобы отклонять истёкшие якоря, передайте
     * {@code anchors.withExpiryPolicy(AnchorExpiryPolicy.REJECT)}.</p>
     *
     * @param trustAnchors якоря для проверки клиентской цепочки (не null и не пуст)
     * @return this
     * @throws IllegalArgumentException если якоря null или пусты
     */
    public TlsServerConfig needClientAuth(TrustAnchors trustAnchors) {
        return setClientAuth(ClientAuth.NEED, trustAnchors);
    }

    /**
     * Включает необязательную аутентификацию клиента: сертификат запрашивается, но клиент вправе
     * не предъявлять его. Предъявленный сертификат проверяется так же строго, как при
     * {@link #needClientAuth}.
     *
     * <p>Приложение обязано проверять {@code TlsSession.hasPeerCertificate()}: соединение с
     * клиентом без сертификата завершается успешно.</p>
     *
     * @param trustAnchors якоря для проверки клиентской цепочки (не null и не пуст)
     * @return this
     * @throws IllegalArgumentException если якоря null или пусты
     * @see #needClientAuth
     */
    public TlsServerConfig wantClientAuth(TrustAnchors trustAnchors) {
        return setClientAuth(ClientAuth.WANT, trustAnchors);
    }

    private TlsServerConfig setClientAuth(ClientAuth mode, TrustAnchors anchors) {
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException(
                    "trustAnchors must not be null or empty for " + mode + " client auth");
        }
        this.clientAuthMode = mode;
        this.trustAnchors = anchors;
        return this;
    }

    /**
     * @param selector функциональный интерфейс для выбора сертификата по SNI.
     *                 Вызывается при получении ClientHello с server_name расширением.
     *                 Если selector возвращает null — сервер использует учётные данные
     *                 по умолчанию (fallback). Реализация MUST быть thread-safe,
     *                 быстрой и неблокирующей, так как вызывается синхронно
     *                 во время handshake из нескольких handshake-потоков.
     * @return this
     */
    public TlsServerConfig withSniSelector(SniCertificateSelector selector) {
        this.sniSelector = selector;
        return this;
    }

    /**
     * @param groupId идентификатор именованной группы (RFC 9367 §3.1),
     *                например {@link TlsConstants#GRP_GC512C}.
     *                0 = группа по умолчанию (GC256B).
     * @return this
     * @throws IllegalArgumentException если группа не поддерживается
     */
    public TlsServerConfig withSelectedNamedGroup(int groupId) {
        if (groupId != 0) {
            // ранняя валидация: группа должна быть в RFC 9367
            TlsCiphersuite.namedGroupToParams(groupId);
        }
        this.selectedNamedGroup = groupId;
        return this;
    }

    // Аксессоры для фабрик в TlsSession: она лежит в другом пакете, поэтому аксессоры публичные,
    // но предназначены для библиотеки, а не для приложения
    public TlsCiphersuite getCiphersuite() {
        return ciphersuite;
    }

    /** @return неизменяемый список сертификатов сервера leaf-first */
    public List<GostCertificate> getServerCertificateChain() {
        return serverCertificateChain;
    }

    public PrivateKeyParameters getServerPrivateKey() {
        return serverPrivateKey;
    }

    /** @return true — сертификат клиента запрашивается ({@code WANT} или {@code NEED}) */
    public boolean isClientAuthEnabled() {
        return clientAuthMode != ClientAuth.NONE;
    }

    /** @return режим аутентификации клиента (не null, по умолчанию {@link ClientAuth#NONE}) */
    public ClientAuth getClientAuthMode() {
        return clientAuthMode;
    }

    /**
     * @return доверенные якоря клиентской цепочки; null при {@link ClientAuth#NONE}
     */
    public TrustAnchors getTrustAnchors() {
        return trustAnchors;
    }

    /** @return копия OCSP-ответа для stapling или {@code null} */
    public byte[] getOcspStaplingResponse() {
        return ConfigCopies.copyOrNull(ocspResponse);
    }

    /**
     * Задаёт политику в отношении OCSP-staple клиентского сертификата (RFC 8446 §4.4.2.1).
     * <p>
     * Работает только при включённой проверке клиента ({@link #needClientAuth}/{@link #wantClientAuth}): без них
     * {@code TlsSession.createServer} бросает {@link IllegalArgumentException}, чтобы
     * проверка не отключалась молча. Значение по умолчанию - {@link ClientOcspPolicy#OFF}.
     *
     * @param policy политика (не null)
     * @return this
     * @throws IllegalArgumentException если policy равен null
     */
    public TlsServerConfig withClientOcspPolicy(ClientOcspPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("clientOcspPolicy must not be null");
        }
        this.clientOcspPolicy = policy;
        return this;
    }

    /**
     * @return политика в отношении OCSP-staple клиента (не null)
     */
    public ClientOcspPolicy getClientOcspPolicy() {
        return clientOcspPolicy;
    }

    /** @return неизменяемый список протоколов ALPN или {@code null}, если он не задан */
    public List<String> getAlpnProtocols() {
        return alpnProtocols;
    }

    public SniCertificateSelector getSniSelector() {
        return sniSelector;
    }

    public int getTicketsToSend() {
        return ticketsToSend;
    }

    public int getSelectedNamedGroup() {
        return selectedNamedGroup;
    }

    /** @return неизменяемый список OID-фильтров или {@code null}, если фильтры не заданы */
    public List<OIDFilter> getOidFilters() {
        return oidFilters;
    }

    /**
     * Устанавливает OID-фильтры для включения в CertificateRequest
     * (RFC 8446 §4.2.5). Сервер передаёт эти фильтры клиенту, чтобы
     * тот выбрал сертификат, удовлетворяющий требованиям (классы KC1/KC2,
     * keyUsage и т.д.).
     *
     * @param filters список OID-фильтров, может быть null (extension не отправляется)
     * @return this
     */
    public TlsServerConfig withOidFilters(List<OIDFilter> filters) {
        this.oidFilters = ConfigCopies.immutableCopy(filters, "filters");
        return this;
    }

    /**
     * Устанавливает количество NewSessionTicket, отправляемых клиенту
     * после каждого успешного handshake (RFC 8446 §4.6.1).
     * ticket_nonce монотонный (big-endian counter), гарантирует уникальность
     * nonce в пределах соединения.
     * <p>
     * Тикеты выдаются только при заданном хранилище PSK сессии
     * ({@code TlsSession.setPskStore}, до рукопожатия): сервер принимает PSK только из него. Без
     * хранилища параметр не действует, а после первого сбоя хранилища оставшиеся тикеты
     * соединения не выдаются.
     *
     * @param n количество тикетов, от 1 до {@link TlsConstants#MAX_TICKETS_TO_SEND}: клиентский
     *          {@code read()} обрабатывает ограниченное число post-handshake сообщений подряд, и
     *          при большем числе тикетов до данных приложения не дошёл бы
     * @return this
     * @throws IllegalArgumentException если n < 1 или n больше {@link TlsConstants#MAX_TICKETS_TO_SEND}
     */
    public TlsServerConfig withTicketsToSend(int n) {
        if (n < 1 || n > TlsConstants.MAX_TICKETS_TO_SEND) {
            throw new IllegalArgumentException(
                    "ticketsToSend must be between 1 and "
                            + TlsConstants.MAX_TICKETS_TO_SEND
                            + ", got "
                            + n);
        }
        this.ticketsToSend = n;
        return this;
    }
}
