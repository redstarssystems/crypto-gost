package org.rssys.gost.tls13.config;

import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostDnsName;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.message.ServerNameCheck;

/**
 * Конфигурация клиента TLS 1.3.
 *
 * <pre>{@code
 * TlsSession session = TlsSession.createClient(
 *     new TlsClientConfig(cs, TrustAnchors.ofCertificate(caCert))
 *         .withServerHostname("example.com"), transport);
 * }</pre>
 */
public final class TlsClientConfig {
    private final TlsCiphersuite ciphersuite;
    private List<GostCertificate> clientCertificateChain;
    private PrivateKeyParameters clientPrivateKey;
    private TrustAnchors trustAnchors;
    private String serverHostname;
    private boolean hostnameVerificationDisabled;
    private boolean requireOcspStapling;
    private byte[] ocspResponse;
    private List<String> alpnProtocols;
    private ClientCertificateSelector clientCertificateSelector;

    /**
     * Обход openssl-gost-provider v3.6.0: сервер всегда шлёт базовую
     * схему (0x0709 для 256-bit, 0x070D для 512-bit) независимо от
     * реальной кривой сертификата (GC256B/C/D, GC512B/C).
     * По умолчанию выключено — RFC 9367 §5 определяет каждую схему как
     * пару «алгоритм, кривая».
     */
    private boolean interopAcceptGostBaseSigScheme;

    /** Стартовая группа ECDHE; 0 - значение сессии по умолчанию (GC256B). */
    private int selectedNamedGroup;

    /**
     * Создаёт конфигурацию клиента с явными доверенными якорями.
     *
     * @param ciphersuite  cipher suite (не null)
     * @param trustAnchors доверенные якоря (не null, не пусто)
     * @throws IllegalArgumentException если ciphersuite или trustAnchors некорректны
     */
    public TlsClientConfig(TlsCiphersuite ciphersuite, TrustAnchors trustAnchors) {
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new IllegalArgumentException("trustAnchors must not be null or empty");
        }
        this.ciphersuite = ciphersuite;
        this.trustAnchors = trustAnchors;
    }

    /**
     * @param chain цепочка сертификатов клиента leaf-first (может содержать
     *              только листовой сертификат, если промежуточные не нужны)
     * @return this
     */
    public TlsClientConfig withClientCertificateChain(List<GostCertificate> chain) {
        this.clientCertificateChain = ConfigCopies.immutableCopy(chain, "chain");
        return this;
    }

    /**
     * Перегрузка для цепочки сертификатов.
     * Позволяет передать один или несколько сертификатов без создания списка:
     * <pre>{@code config.withClientCertificateChain(cert)}</pre>
     *
     * @param certs сертификаты клиента leaf-first
     * @return this
     * @throws IllegalArgumentException если {@code certs} или любой его элемент равен null
     */
    public TlsClientConfig withClientCertificateChain(GostCertificate... certs) {
        if (certs == null) {
            throw new IllegalArgumentException("certs must not be null");
        }
        return withClientCertificateChain(Arrays.asList(certs));
    }

    /**
     * @param key закрытый ключ клиента для mTLS
     * @return this
     */
    public TlsClientConfig withClientPrivateKey(PrivateKeyParameters key) {
        this.clientPrivateKey = key;
        return this;
    }

    /**
     * Заменяет доверенные якоря.
     *
     * <p>Срок истёкшего якоря при цепочке из нескольких сертификатов в TLS по умолчанию
     * ({@code AnchorExpiryPolicy.DEFAULT}) не блокирует соединение: пишется предупреждение
     * (RFC 5280 §6.1), в том числе для закреплённого истёкшего промежуточного CA. Чтобы
     * отклонять такие якоря, передайте {@code trustAnchors.withExpiryPolicy(
     * AnchorExpiryPolicy.REJECT)}.</p>
     *
     * @param trustAnchors якоря (не null, не пусто)
     * @return this
     * @throws IllegalArgumentException если trustAnchors null или пуст
     */
    public TlsClientConfig withTrustAnchors(TrustAnchors trustAnchors) {
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new IllegalArgumentException("trustAnchors must not be null or empty");
        }
        this.trustAnchors = trustAnchors;
        return this;
    }

    /**
     * Задаёт ожидаемое DNS-имя сервера.
     *
     * <p>Кириллическое имя преобразуется в A-label сразу, чтобы SNI и проверка
     * hostname использовали одно и то же ASCII-значение.</p>
     *
     * <p>Имя задаёт и SNI, и сверку с сертификатом. {@code null} имя не задаёт: тогда
     * {@code TlsSession.createClient} требует явного {@link #withoutHostnameVerification()} и
     * иначе бросает {@link IllegalArgumentException}.</p>
     *
     * @param hostname ожидаемое DNS-имя (null = имя не задано)
     * @return this
     * @throws IllegalArgumentException если имя пустое, не преобразуется в A-label или не может
     *                                  быть отправлено в SNI (длина больше 253, пустые метки)
     */
    public TlsClientConfig withServerHostname(String hostname) {
        String ascii = GostDnsName.toAsciiHostname(hostname);
        // Длину и пустые метки GostDnsName не проверяет; ошибка здесь, а не при сборке ClientHello
        ServerNameCheck.requireValidForSni(ascii);
        this.serverHostname = ascii;
        return this;
    }

    /**
     * @param require true  — сервер ОБЯЗАН прислать OCSP-степплинг (ALERT_BAD_CERTIFICATE иначе)
     *                false — мягкий режим (OCSP проверяется если есть, но не обязателен)
     * @return this
     */
    public TlsClientConfig withRequireOcspStapling(boolean require) {
        this.requireOcspStapling = require;
        return this;
    }

    /**
     * Задаёт OCSP-ответ для собственного сертификата клиента (stapling при mTLS,
     * RFC 8446 §4.4.2.1). Отправляется только если сервер запросил его расширением
     * {@code status_request} в CertificateRequest. Не путать с
     * {@link #withRequireOcspStapling(boolean)}: тот требует staple от сервера.
     * <p>
     * Принимается сырой OCSPResponse DER для первого сертификата цепочки из
     * {@link #withClientCertificateChain}. При выборе сертификата через
     * {@link ClientCertificateSelector} staple берётся из выбранных
     * {@link TlsClientCredentials}, а не отсюда: чужой staple сервер всё равно отвергнет.
     * Без клиентской цепочки в конфигурации {@code TlsSession.createClient} бросает
     * {@link IllegalArgumentException}.
     *
     * @param ocspResponse OCSPResponse DER или {@code null} (без stapling)
     * @return this
     * @throws IllegalArgumentException если массив пуст или длиннее допустимого предела
     */
    public TlsClientConfig withOcspStaplingResponse(byte[] ocspResponse) {
        this.ocspResponse = ConfigCopies.validatedOcspCopy(ocspResponse);
        return this;
    }

    /**
     * @return копия OCSP-ответа собственного сертификата клиента или null
     */
    public byte[] getOcspStaplingResponse() {
        return ConfigCopies.copyOrNull(ocspResponse);
    }

    /**
     * @param protocols список протоколов ALPN в порядке убывания предпочтения (RFC 7301). Имя - это
     *                  последовательность байт: каждый символ строки (не выше U+00FF) кодирует
     *                  один байт (ISO-8859-1, как в SunJSSE с Java SE 16)
     * @return this
     * @throws IllegalArgumentException если список пуст или имя не проходит
     *                                  {@link TlsUtils#validateAlpnProtocols}
     */
    public TlsClientConfig withAlpnProtocols(List<String> protocols) {
        this.alpnProtocols = ConfigCopies.validatedAlpnCopy(protocols);
        return this;
    }

    /**
     * Включает обход openssl-gost-provider v3.6.0: сервер всегда шлёт
     * базовые схемы (0x0709 для 256-bit, 0x070D для 512-bit) независимо
     * от реальной кривой сертификата (GC256B/C/D, GC512B/C).
     * <p>
     * По умолчанию выключено. Включение — осознанное решение разработчика
     * для совместимости с openssl-gost-provider. RFC 9367 §5 формально
     * требует точного соответствия схемы кривой сертификата.
     *
     * @param enabled true — принимать базовые схемы для любого ключа того же размера
     * @return this
     */
    public TlsClientConfig withInteropAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
        return this;
    }

    /**
     * @return true если включён обход openssl-gost-provider
     */
    public boolean isInteropAcceptGostBaseSigScheme() {
        return interopAcceptGostBaseSigScheme;
    }

    public boolean isOcspRequired() {
        return requireOcspStapling;
    }

    /**
     * Задаёт группу ECDHE, для которой клиент присылает key_share в первом ClientHello.
     * <p>
     * Если сервер предпочитает другую группу, рукопожатие пройдёт через HelloRetryRequest
     * (лишний обмен). Совпадение с группой сервера этот обмен убирает.
     *
     * @param groupId идентификатор именованной группы (RFC 9367 §3.1), например
     *                {@link org.rssys.gost.tls13.TlsConstants#GRP_GC512C}. 0 - группа по умолчанию
     *                (GC256B).
     * @return this
     * @throws IllegalArgumentException если группа не поддерживается
     */
    public TlsClientConfig withSelectedNamedGroup(int groupId) {
        if (groupId != 0) {
            // ранняя валидация: ошибка настройки не должна всплывать посреди рукопожатия
            TlsCiphersuite.namedGroupToParams(groupId);
        }
        this.selectedNamedGroup = groupId;
        return this;
    }

    /** @return стартовая группа ECDHE или 0 (значение по умолчанию) */
    public int getSelectedNamedGroup() {
        return selectedNamedGroup;
    }

    // Аксессоры для фабрик в TlsSession: она лежит в другом пакете, поэтому аксессоры публичные,
    // но предназначены для библиотеки, а не для приложения
    public TlsCiphersuite getCiphersuite() {
        return ciphersuite;
    }

    /**
     * @return неизменяемый список сертификатов клиента leaf-first или {@code null}, если цепочка
     *         не задана (режим без mTLS)
     */
    public List<GostCertificate> getClientCertificateChain() {
        return clientCertificateChain;
    }

    public PrivateKeyParameters getClientPrivateKey() {
        return clientPrivateKey;
    }

    /** @return true — доверенные якоря настроены (всегда true для клиента) */
    public boolean hasTrustAnchors() {
        return trustAnchors != null && !trustAnchors.isEmpty();
    }

    /** @return доверенные якоря-сертификаты; никогда не null */
    public TrustAnchors getTrustAnchors() {
        return trustAnchors;
    }

    public String getServerHostname() {
        return serverHostname;
    }

    /**
     * Отключает проверку hostname в сертификате сервера.
     * Только для mesh-сервисов, внутренних соединений и тестов,
     * где проверка hostname не нужна, но аутентификация CA обязательна.
     *
     * <p>Отключается только сверка имени с сертификатом. Если имя задано через
     * {@link #withServerHostname(String)}, оно по-прежнему передаётся серверу в SNI.</p>
     *
     * <p>PSK-тикеты такой конфигурации привязаны к отпечатку якорей, а имя сервера из SNI (если
     * задано) входит в привязку. Они не смешиваются с тикетами сессий со сверкой имени. Так
     * сохраняется уже принятая модель доверия: допустимость имени для сертификата исходной
     * сессии здесь не проверялась, поскольку пользователь отключил эту проверку.</p>
     *
     * @return this
     */
    public TlsClientConfig withoutHostnameVerification() {
        this.hostnameVerificationDisabled = true;
        return this;
    }

    public boolean isHostnameVerificationDisabled() {
        return hostnameVerificationDisabled;
    }

    /**
     * @return неизменяемый список протоколов ALPN или {@code null}, если он не задан
     */
    public List<String> getAlpnProtocols() {
        return alpnProtocols;
    }

    /**
     * Устанавливает селектор сертификата клиента для mTLS.
     * <p>
     * Селектор вызывается на каждый CertificateRequest и становится единственным источником
     * учётных данных клиента: {@code null} от него даёт пустой Certificate, а цепочка из
     * {@link #withClientCertificateChain(List)} в этом случае не подставляется (иначе уходил бы
     * сертификат, который селектор осознанно отверг). Без селектора используется цепочка из
     * конфигурации.
     *
     * @param selector селектор, может быть null
     * @return this
     */
    public TlsClientConfig withClientCertificateSelector(ClientCertificateSelector selector) {
        this.clientCertificateSelector = selector;
        return this;
    }

    public ClientCertificateSelector getClientCertificateSelector() {
        return clientCertificateSelector;
    }
}
