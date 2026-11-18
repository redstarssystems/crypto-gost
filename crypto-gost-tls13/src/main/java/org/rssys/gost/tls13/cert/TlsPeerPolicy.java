package org.rssys.gost.tls13.cert;

import java.time.Duration;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Политика проверки сертификата партнёра по TLS: чей сертификат проверяется, по каким якорям и
 * насколько обязателен OCSP-staple.
 *
 * <p>Роль задаётся фабрикой, а не именем метода валидатора:
 * <ul>
 *   <li>{@link #server(String, TrustAnchors)} - сертификат сервера (hostname, serverAuth);
 *   <li>{@link #client(TrustAnchors)} - сертификат клиента при mTLS (clientAuth).
 * </ul>
 * Фабрики {@link #serverLeafOnly(String)} и {@link #clientLeafOnly()} создают политику без якорей
 * для явного небезопасного режима (например, {@code GostX509TrustManager.insecureTrustAll()}):
 * цепочка не проверяется, срок, KeyUsage, EKU, hostname и присланный staple проверяются по-прежнему.
 * Методы валидатора, которым нужны якоря, для такой политики бросают {@link IllegalStateException}.
 *
 * <p>Имя сервера обязательно: {@code null} и пустое имя отвергаются, чтобы забытое имя не
 * отключало сверку молча. Проверку без сверки имени выбирают явно фабриками
 * {@link #serverWithoutHostnameVerification(TrustAnchors)} и
 * {@link #serverLeafOnlyWithoutHostnameVerification()}.</p>
 *
 * <p>Политика неизменяема: {@code with*}-методы возвращают новый экземпляр.</p>
 */
public final class TlsPeerPolicy {

    private final boolean server;
    private final String serverHostname;
    private final TrustAnchors anchors;
    private final boolean requireOcspStaple;
    private final long maxOcspAgeMs;
    private final Duration maxThisUpdateAge;

    private TlsPeerPolicy(
            boolean server,
            String serverHostname,
            TrustAnchors anchors,
            boolean requireOcspStaple,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge) {
        this.server = server;
        this.serverHostname = serverHostname;
        this.anchors = anchors;
        this.requireOcspStaple = requireOcspStaple;
        this.maxOcspAgeMs = maxOcspAgeMs;
        this.maxThisUpdateAge = maxThisUpdateAge;
    }

    /**
     * Политика проверки сертификата сервера по якорям.
     *
     * @param hostname ожидаемое DNS-имя сервера (не null и не пустое)
     * @param anchors  доверенные якоря (не null, не пусто)
     * @return политика с необязательным staple и возрастом OCSP по умолчанию
     * @throws IllegalArgumentException если имя null или пустое либо якоря null или пусты
     */
    public static TlsPeerPolicy server(String hostname, TrustAnchors anchors) {
        return new TlsPeerPolicy(
                true,
                requireHostname(hostname),
                requireAnchors(anchors),
                false,
                GostOids.MAX_OCSP_AGE_MS,
                null);
    }

    /**
     * Политика проверки сертификата сервера по якорям без сверки имени: явный выбор, когда имени
     * сервера нет или сверка отключена осознанно (например, JSSE с выключенным endpoint
     * identification).
     *
     * @param anchors доверенные якоря (не null, не пусто)
     * @return политика с необязательным staple и возрастом OCSP по умолчанию
     * @throws IllegalArgumentException если якоря null или пусты
     */
    public static TlsPeerPolicy serverWithoutHostnameVerification(TrustAnchors anchors) {
        return new TlsPeerPolicy(
                true, null, requireAnchors(anchors), false, GostOids.MAX_OCSP_AGE_MS, null);
    }

    /**
     * Политика проверки сертификата клиента при mTLS по якорям.
     *
     * @param anchors доверенные якоря (не null, не пусто)
     * @return политика с необязательным staple и возрастом OCSP по умолчанию
     * @throws IllegalArgumentException если якоря null или пусты
     */
    public static TlsPeerPolicy client(TrustAnchors anchors) {
        return new TlsPeerPolicy(
                false, null, requireAnchors(anchors), false, GostOids.MAX_OCSP_AGE_MS, null);
    }

    /**
     * Явный небезопасный режим для сервера: цепочка не проверяется, проверяется только leaf.
     *
     * @param hostname ожидаемое DNS-имя сервера (не null и не пустое)
     * @return политика без якорей
     * @throws IllegalArgumentException если имя null или пустое
     */
    public static TlsPeerPolicy serverLeafOnly(String hostname) {
        return new TlsPeerPolicy(
                true, requireHostname(hostname), null, false, GostOids.MAX_OCSP_AGE_MS, null);
    }

    /**
     * Явный небезопасный режим для сервера без сверки имени: цепочка не проверяется, имя не
     * сверяется, проверяются срок, KeyUsage, EKU и присланный staple.
     *
     * @return политика без якорей и без сверки имени
     */
    public static TlsPeerPolicy serverLeafOnlyWithoutHostnameVerification() {
        return new TlsPeerPolicy(true, null, null, false, GostOids.MAX_OCSP_AGE_MS, null);
    }

    /**
     * Явный небезопасный режим для клиента: цепочка не проверяется, проверяется только leaf.
     *
     * @return политика без якорей
     */
    public static TlsPeerPolicy clientLeafOnly() {
        return new TlsPeerPolicy(false, null, null, false, GostOids.MAX_OCSP_AGE_MS, null);
    }

    /**
     * Делает OCSP-staple leaf-сертификата обязательным (или необязательным). Присланный staple
     * проверяется всегда.
     *
     * @param required true - отсутствие staple даёт {@code bad_certificate}
     * @return новая политика
     */
    public TlsPeerPolicy requireOcspStaple(boolean required) {
        return new TlsPeerPolicy(
                server, serverHostname, anchors, required, maxOcspAgeMs, maxThisUpdateAge);
    }

    /**
     * Задаёт максимальный возраст OCSP-ответа без {@code nextUpdate}.
     *
     * @param maxAgeMs возраст в миллисекундах (положительный)
     * @return новая политика
     * @throws IllegalArgumentException если значение не положительное
     */
    public TlsPeerPolicy maxOcspAge(long maxAgeMs) {
        if (maxAgeMs <= 0) {
            throw new IllegalArgumentException("maxOcspAge must be positive");
        }
        return new TlsPeerPolicy(
                server, serverHostname, anchors, requireOcspStaple, maxAgeMs, maxThisUpdateAge);
    }

    /**
     * Задаёт необязательный предел возраста {@code thisUpdate} OCSP-ответа для всех ответов, в
     * том числе с {@code nextUpdate} (Р 1323565.1.059-2024, п. 5.3). {@link #maxOcspAge(long)}
     * остаётся в миллисекундах и по-прежнему действует на ответы без {@code nextUpdate}; без
     * {@code nextUpdate} действует меньший из двух пределов. Допуск часов не применяется.
     *
     * <p>Предел должен быть больше интервала обновления ответов у службы, иначе служба с заранее
     * выпущенными ответами получит отказы. Устаревший приложенный ответ даёт отказ сразу: запасного
     * запроса к службе в этом слое нет.</p>
     *
     * @param maxThisUpdateAge предел или {@code null} - не задан (так же сбрасывается)
     * @return новая политика
     * @throws IllegalArgumentException если значение нулевое или отрицательное
     */
    public TlsPeerPolicy maxThisUpdateAge(Duration maxThisUpdateAge) {
        OcspVerifier.requireValidMaxThisUpdateAge(maxThisUpdateAge);
        return new TlsPeerPolicy(
                server, serverHostname, anchors, requireOcspStaple, maxOcspAgeMs, maxThisUpdateAge);
    }

    /** @return true - проверяется сертификат сервера, false - клиента */
    boolean isServer() {
        return server;
    }

    String serverHostname() {
        return serverHostname;
    }

    /** @return якоря или null для политики {@code *LeafOnly} */
    TrustAnchors anchors() {
        return anchors;
    }

    /** @return якоря; для политики без якорей - {@link IllegalStateException} */
    TrustAnchors requiredAnchors() {
        if (anchors == null) {
            throw new IllegalStateException(
                    "The policy has no trust anchors (leaf-only mode): the chain cannot be validated");
        }
        return anchors;
    }

    boolean requiresOcspStaple() {
        return requireOcspStaple;
    }

    long maxOcspAgeMs() {
        return maxOcspAgeMs;
    }

    /** @return предел возраста {@code thisUpdate} или null - не задан */
    Duration maxThisUpdateAge() {
        return maxThisUpdateAge;
    }

    private static String requireHostname(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            throw new IllegalArgumentException(
                    "hostname must not be null or blank;"
                            + " use a WithoutHostnameVerification factory to skip the check");
        }
        return hostname;
    }

    private static TrustAnchors requireAnchors(TrustAnchors anchors) {
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("trustAnchors must not be null or empty");
        }
        return anchors;
    }

    /** Якоря и hostname не выводятся: достаточно роли и флагов. */
    @Override
    public String toString() {
        return "TlsPeerPolicy[role="
                + (server ? "server" : "client")
                + ", anchors="
                + (anchors == null ? "none" : "set")
                + ", requireOcspStaple="
                + requireOcspStaple
                + "]";
    }
}
