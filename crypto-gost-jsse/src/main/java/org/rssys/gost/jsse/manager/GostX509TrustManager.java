package org.rssys.gost.jsse.manager;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import org.rssys.gost.api.Digest;
import org.rssys.gost.jsse.EndpointIdentification;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlCache.CrlKey;
import org.rssys.gost.jsse.crl.CrlFetchResult;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.crl.CrlSizeLimitException;
import org.rssys.gost.jsse.ocsp.OcspFetchResult;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.SingleOcspResponse;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.cert.PeerTrustBoundary;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import org.rssys.gost.tls13.cert.TlsPeerPolicy;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.SafeText;

/**
 * X509TrustManager для ГОСТ-сертификатов.
 * <p>
 * <b>Сетевые загрузки отзыва ограничены.</b> Адреса OCSP и CDP задаёт тот, кто выпустил сертификат,
 * поэтому на одну проверку цепочки действуют две границы. Для каждого сертификата пробуются не
 * более {@value #MAX_REVOCATION_URIS_PER_KIND} адресов каждого вида (OCSP, CDP), остальные
 * игнорируются. И на всю проверку (вызов {@link #validateChainWithOcsp} или
 * {@link #validateClientChain}, на них опираются {@code checkServerTrusted} и
 * {@code checkClientTrusted}) выделен бюджет времени на загрузки (30 с): первая загрузка
 * разрешена всегда, после исчерпания бюджета новые загрузки не начинаются ни для текущего, ни для
 * следующих сертификатов цепочки, а каждая такая загрузка считается неудачной, и дальше решает
 * политика отзыва. Попадание в кэш бюджет не расходует. Бюджет ограничивает начало загрузок, а не
 * их длительность, поэтому потолок равен бюджету плюс срок одной загрузки текущего загрузчика. Для
 * CRL к бюджету относится и ожидание: если тот же CRL уже грузит другое соединение, поток ждёт его
 * не дольше остатка бюджета (все ожидания по всем зеркалам делят одно окно), а сдавшийся
 * ожидающий получает неудачу этого адреса (запись в журнале «Gave up waiting for a concurrent CRL
 * load», одна на серию сдач по адресу). Поток, не нашедший чужой загрузки, грузит сам. При значениях по
 * умолчанию (срок загрузчика OCSP 5 с, CRL 30 с): для OCSP 35 с, для CRL около 60 с (бюджет плюс
 * одна своя загрузка). Это оценка сетевой части: если бюджет к первой загрузке уже истёк, она всё
 * равно разрешена, и общее время может быть больше. Проверка подписи загруженного CRL срока не
 * имеет. Для пользовательских загрузчиков, игнорирующих свой срок, гарантии нет: менеджер может
 * лишь отказать в следующих попытках. Следствия: при {@link CrlPolicy#REQUIRE} исчерпание бюджета,
 * сдача ожидающего или адреса без пригодного CRL — жёсткий отказ (fail-closed), а при
 * {@link CrlPolicy#IF_CDP_PRESENT} — пропуск проверки, как при недоступном CDP (в том числе когда
 * подлинный CRL просто ещё не загрузился); сертификат с четырьмя зеркалами CDP, где первые три
 * отдают непригодный CRL, четвёртое
 * не используется; медленный УЦ на первом сертификате цепочки может лишить загрузки следующие.
 * <p>
 * <b>Перепроверка CRL.</b> Запись кэша CRL старше предельного возраста ({@code crlMaxAge}, по
 * умолчанию {@link CrlCache#DEFAULT_MAX_AGE}), но ещё не истёкшая, перепроверяется одним из
 * соединений; остальные берут действующую запись. Перепроверка необязательна: она идёт только при
 * остатке бюджета, не расходует «первую загрузку, разрешённую всегда», а при неудаче запись
 * остаётся до {@code nextUpdate}. Загрузка перепроверки не входит в окно бюджета: одно
 * соединение раз в {@code crlMaxAge} на адрес может занять до потолка проверки плюс срок
 * загрузчика CRL. Задержка видимости нового CRL равна {@code crlMaxAge} плюс интервал выпуска CRL
 * у УЦ. Подробности - {@link CrlCache}.
 * <p>
 * Валидирует цепочку сертификатов пира через TlsCertificateValidator:
 * срок действия, hostname (для сервера), KeyUsage, EKU, OCSP, цепочка до CA.
 * Поддерживает OCSP для всех сертификатов в цепочке (leaf + intermediate).
 * <p>
 * <b>Обязательность OCSP относится к серверному сертификату.</b> Для клиентских
 * сертификатов OCSP не обязателен: при {@link OcspPolicy#STAPLING_OR_FETCH}
 * выполняется best-effort fetch, при {@link OcspPolicy#STAPLING_REQUIRED}
 * загрузка не выполняется. Полученный ответ проверяется; отсутствие ответа не
 * блокирует mTLS. Присланный клиентом staple принимается только по запросу сервера
 * ({@link ClientOcspPolicy}, по умолчанию {@code OFF}); обязательным его делает
 * {@link ClientOcspPolicy#REQUIRE} через {@link #validateClientChain}. JCA-путь
 * {@code checkClientTrusted(X509Certificate[], ...)} staple не видит. Строгий отзыв
 * клиентских сертификатов без staple задаётся через {@link CrlPolicy#REQUIRE}: если OCSP
 * получен и валиден, CRL не проверяется.
 * <p>
 * Якоря задаются только сертификатами ({@link TrustAnchors}), поэтому pathLen
 * и NameConstraints корня аутентифицированы, в том числе при опущенном пире
 * корне.
 */
public final class GostX509TrustManager extends X509ExtendedTrustManager {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.manager.GostX509TrustManager");

    /** Размер идентификатора экземпляра для привязки состояния, 128 бит. */
    private static final int BINDING_ID_LENGTH = 16;

    private final TrustAnchors trustAnchors;
    private final boolean insecureTrustAll;
    private final byte[] bindingId = newBindingId();
    private final boolean requireOcspStapling;
    private final OcspPolicy ocspPolicy;
    private final OcspFetcher ocspFetcher;

    /**
     * Наибольшее число адресов одного вида (OCSP, CDP), которые пробуются для одного сертификата.
     * Адреса задаёт тот, кто выпустил сертификат: без предела он мог бы указать их тысячи, и каждый
     * медленный сервер добавил бы свой срок к рукопожатию. Адреса сверх предела игнорируются.
     */
    static final int MAX_REVOCATION_URIS_PER_KIND = 3;

    /**
     * Общий бюджет времени на сетевые загрузки отзыва за одну проверку цепочки. После его
     * исчерпания новые загрузки не начинаются ни для текущего, ни для следующих сертификатов
     * цепочки, а каждая такая загрузка считается неудачной (решает политика отзыва). Бюджет
     * ограничивает начало загрузок, а не саму загрузку: потолок проверки равен бюджету плюс срок
     * одной загрузки текущего загрузчика (по умолчанию 30 + 5 с для OCSP). Ожидание чужой загрузки
     * того же CRL ограничено остатком бюджета, поэтому для CRL потолок около 60 с (бюджет плюс одна
     * своя загрузка); если бюджет к первой загрузке уже истёк, она всё равно разрешена. Для
     * пользовательских загрузчиков, игнорирующих свой срок, гарантии нет.
     */
    static final Duration REVOCATION_FETCH_BUDGET = Duration.ofSeconds(30);

    /** Бюджет проверки; поле нужно тестам, чтобы не ждать 30 с (публичный API не меняется). */
    private volatile Duration revocationBudget = REVOCATION_FETCH_BUDGET;

    private final CrlPolicy crlPolicy;
    private final CrlFetcher crlFetcher;
    private volatile CrlCache crlCache;
    private final CrlLimits crlLimits;
    private final long maxOcspAgeMs;
    private final Duration maxThisUpdateAge;

    private static final long DEFAULT_OCSP_CACHE_TTL_MS = Duration.ofHours(1).toMillis();

    /**
     * Срок хранения записи кэша OCSP-ответов (key = (issuerCertHashHex, certSerialHex) ->
     * CachedStatus). Меняется из другого потока через {@link #setOcspCacheTtlMs(long)}.
     */
    private volatile long ocspCacheTtlMs = DEFAULT_OCSP_CACHE_TTL_MS;

    /** Максимум записей в кэше OCSP (soft cap — защита от OOM при большом числе уникальных сертификатов). */
    private static final int OCSP_CACHE_MAX_ENTRIES = 500;

    private final ConcurrentHashMap<OcspCacheKey, CachedOcspStatus> ocspCache =
            new ConcurrentHashMap<>();

    /**
     * Предупреждение о мягкой клиентской OCSP-политике выводится один раз:
     * иначе каждый mTLS-handshake засорял бы лог одинаковой строкой.
     */
    private final AtomicBoolean clientOcspSoftWarningLogged = new AtomicBoolean();

    /**
     * Задаёт срок хранения OCSP-ответов в кэше (по умолчанию 1 час). Фактический срок записи
     * не превышает и срок годности самого ответа. Действует на записи, добавленные после вызова.
     *
     * @param ttlMs срок в миллисекундах, строго больше нуля
     * @throws IllegalArgumentException если значение не положительно
     */
    public void setOcspCacheTtlMs(long ttlMs) {
        if (ttlMs <= 0) {
            throw new IllegalArgumentException("ocspCacheTtlMs must be positive: " + ttlMs);
        }
        this.ocspCacheTtlMs = ttlMs;
    }

    /**
     * Создаёт TrustManager с готовыми якорями доверия.
     *
     * <p>Сертификаты якорей аутентифицируют {@code pathLenConstraint} и
     * {@code NameConstraints} корня, даже если пир не прислал корневой
     * сертификат.</p>
     *
     * @param trustAnchors доверенные якоря (не null, не пустые)
     * @return TrustManager с политикой OCSP {@link OcspPolicy#IF_PRESENT}
     * @throws IllegalArgumentException если trustAnchors null или пуст
     */
    public static GostX509TrustManager fromTrustAnchors(TrustAnchors trustAnchors) {
        return fromTrustAnchors(trustAnchors, OcspPolicy.IF_PRESENT, null);
    }

    /**
     * Создаёт TrustManager с готовыми якорями и настройками OCSP.
     *
     * @param trustAnchors доверенные якоря (не null, не пустые)
     * @param ocspPolicy   политика проверки OCSP
     * @param ocspFetcher  fetcher для client-side OCSP-запросов (может быть null)
     * @return TrustManager
     * @throws IllegalArgumentException если trustAnchors null или пуст
     */
    public static GostX509TrustManager fromTrustAnchors(
            TrustAnchors trustAnchors, OcspPolicy ocspPolicy, OcspFetcher ocspFetcher) {
        return fromTrustAnchors(trustAnchors, ocspPolicy, ocspFetcher, CrlPolicy.DISABLED, null);
    }

    /**
     * Создаёт TrustManager с готовыми якорями, настройками OCSP и CRL.
     *
     * @param trustAnchors доверенные якоря (не null, не пустые)
     * @param ocspPolicy   политика проверки OCSP
     * @param ocspFetcher  fetcher для client-side OCSP-запросов (может быть null)
     * @param crlPolicy    политика проверки CRL
     * @param crlFetcher   fetcher для CRL по CDP URI (может быть null)
     * @return TrustManager
     * @throws IllegalArgumentException если trustAnchors null или пуст
     */
    public static GostX509TrustManager fromTrustAnchors(
            TrustAnchors trustAnchors,
            OcspPolicy ocspPolicy,
            OcspFetcher ocspFetcher,
            CrlPolicy crlPolicy,
            CrlFetcher crlFetcher) {
        return fromTrustAnchors(
                trustAnchors,
                ocspPolicy,
                ocspFetcher,
                crlPolicy,
                crlFetcher,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                CrlCache.DEFAULT_MAX_BYTES,
                CrlCache.DEFAULT_MAX_AGE,
                GostOids.MAX_OCSP_AGE_MS,
                null);
    }

    /**
     * Создаёт TrustManager с готовыми якорями и полной настройкой OCSP/CRL.
     *
     * @param trustAnchors      доверенные якоря (не null, не пустые)
     * @param ocspPolicy        политика проверки OCSP
     * @param ocspFetcher       fetcher для client-side OCSP-запросов (может быть null)
     * @param crlPolicy         политика проверки CRL
     * @param crlFetcher        fetcher для CRL по CDP URI (может быть null)
     * @param maxCrlSize        максимальный размер CRL в байтах; при включённой проверке CRL
     *                          предел загрузчика {@code CrlFetcher.maxResponseSize()} не может
     *                          быть меньше (иначе {@link IllegalArgumentException})
     * @param maxRevokedEntries максимальное число отозванных записей
     * @param crlCacheMaxBytes  бюджет кэша проверенных CRL в байтах оценки удержания (около шести
     *                          байт кучи на байт DER); 0 - не хранить CRL между соединениями
     *                          (каждое последовательное соединение загружает CRL заново).
     *                          Значение по умолчанию - {@link CrlCache#DEFAULT_MAX_BYTES}
     * @param crlMaxAge         предельный возраст записи кэша CRL с последней успешной загрузки:
     *                          запись старше перепроверяется раньше {@code nextUpdate} (при
     *                          неудаче остаётся прежняя запись). {@link Duration#ZERO} выключает
     *                          перепроверку, иначе от 1 минуты до 30 суток. Значение по умолчанию
     *                          - {@link CrlCache#DEFAULT_MAX_AGE}. Задержка видимости нового CRL
     *                          равна этому возрасту плюс интервал выпуска CRL у УЦ
     * @param maxOcspAgeMs      максимальный возраст OCSP-ответа без nextUpdate в мс
     * @param maxThisUpdateAge  необязательный предел возраста {@code thisUpdate} для всех
     *                          OCSP-ответов (Р 1323565.1.059-2024, п. 5.3) или {@code null} - не
     *                          задан. В отличие от {@code maxOcspAgeMs} (миллисекунды) это
     *                          {@link Duration}. Без {@code nextUpdate} действует меньший из двух
     *                          пределов. Должен быть больше интервала обновления ответов службы
     * @return TrustManager
     * @throws IllegalArgumentException если trustAnchors null или пуст, предел нулевой или
     *                                  отрицательный, {@code crlCacheMaxBytes} отрицательный либо предел размера ответа загрузчика CRL
     *                                  меньше {@code maxCrlSize}
     */
    public static GostX509TrustManager fromTrustAnchors(
            TrustAnchors trustAnchors,
            OcspPolicy ocspPolicy,
            OcspFetcher ocspFetcher,
            CrlPolicy crlPolicy,
            CrlFetcher crlFetcher,
            int maxCrlSize,
            int maxRevokedEntries,
            long crlCacheMaxBytes,
            Duration crlMaxAge,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge) {
        // Неверное значение должно отказывать при создании, а не при рукопожатии: политика
        // TlsPeerPolicy строится заново на каждое соединение
        OcspVerifier.requireValidMaxThisUpdateAge(maxThisUpdateAge);
        CrlCache.requireValidMaxAge(crlMaxAge);
        return new GostX509TrustManager(
                trustAnchors,
                ocspPolicy,
                ocspFetcher,
                crlPolicy,
                crlFetcher,
                maxCrlSize,
                maxRevokedEntries,
                crlCacheMaxBytes,
                crlMaxAge,
                maxOcspAgeMs,
                maxThisUpdateAge,
                false);
    }

    private GostX509TrustManager(
            TrustAnchors trustAnchors,
            OcspPolicy ocspPolicy,
            OcspFetcher ocspFetcher,
            CrlPolicy crlPolicy,
            CrlFetcher crlFetcher,
            int maxCrlSize,
            int maxRevokedEntries,
            long crlCacheMaxBytes,
            Duration crlMaxAge,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge,
            boolean insecureTrustAll) {
        CrlCache.requireValidMaxBytes(crlCacheMaxBytes);
        if (!insecureTrustAll) {
            if (trustAnchors == null || trustAnchors.isEmpty()) {
                throw new IllegalArgumentException(
                        "trustAnchors must not be null or empty;"
                                + " use GostX509TrustManager.insecureTrustAll() for explicit"
                                + " no-chain mode");
            }
            this.trustAnchors = trustAnchors;
        } else {
            this.trustAnchors = TrustAnchors.empty();
        }
        this.insecureTrustAll = insecureTrustAll;
        this.ocspPolicy = ocspPolicy;
        this.ocspFetcher = ocspFetcher;
        this.requireOcspStapling = ocspPolicy == OcspPolicy.STAPLING_REQUIRED;
        this.crlPolicy = crlPolicy;
        this.crlFetcher = crlFetcher;
        this.crlCache =
                crlPolicy != CrlPolicy.DISABLED ? new CrlCache(crlCacheMaxBytes, crlMaxAge) : null;
        // Значения не больше нуля отвергаем сразу: иначе ошибка проявилась бы фатальным отказом на
        // первом же CRL, а не при создании менеджера
        this.crlLimits = new CrlLimits(maxCrlSize, maxRevokedEntries);
        // Загрузчик без политики CRL не используется: оператор, задавший только его, считал бы
        // отзыв по CRL проверяемым. Отказ здесь, а не только в построителях: конструктор доступен
        // и напрямую
        if (crlFetcher != null && crlPolicy == CrlPolicy.DISABLED) {
            throw new IllegalArgumentException("crlFetcher requires crlPolicy other than DISABLED");
        }
        // Загрузчик с пределом меньше maxCrlSize оборвал бы большой CRL раньше разбора
        if (crlPolicy != CrlPolicy.DISABLED) {
            String fetcherProblem = CrlFetcher.limitProblem(crlFetcher, maxCrlSize);
            if (fetcherProblem != null) {
                throw new IllegalArgumentException(fetcherProblem);
            }
        }
        this.maxOcspAgeMs = maxOcspAgeMs;
        this.maxThisUpdateAge = maxThisUpdateAge;
        if (insecureTrustAll) {
            LOG.log(
                    Level.WARNING,
                    "TrustManager created with certificate chain validation DISABLED."
                            + " The identity of the peer is not verified. Use only for"
                            + " development.");
        }
    }

    /**
     * Явный небезопасный режим: не проверяет цепочку сертификатов.
     * <p>
     * Проверки срока действия, KeyUsage, EKU, hostname и OCSP сохраняются.
     * Только для тестов и отладки; в production используйте
     * {@link #fromTrustAnchors(TrustAnchors)}.
     *
     * @return TrustManager без проверки цепочки
     */
    public static GostX509TrustManager insecureTrustAll() {
        return insecureTrustAll(OcspPolicy.IF_PRESENT, null);
    }

    /**
     * Для тестов: insecure-режим с явной политикой OCSP.
     * Сетевые запросы всё равно запрещены — проверяется только присланный staple.
     */
    static GostX509TrustManager insecureTrustAll(OcspPolicy ocspPolicy, OcspFetcher ocspFetcher) {
        return new GostX509TrustManager(
                TrustAnchors.empty(),
                ocspPolicy,
                ocspFetcher,
                CrlPolicy.DISABLED,
                null,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                CrlCache.DEFAULT_MAX_BYTES,
                CrlCache.DEFAULT_MAX_AGE,
                GostOids.MAX_OCSP_AGE_MS,
                null,
                true);
    }

    /**
     * Возвращает hostname для endpoint identification или падает, если проверка
     * включена, а адрес собеседника неизвестен.
     *
     * <p>Иначе {@code createSSLEngine()} без адреса с включённым HTTPS молча
     * пропускал бы проверку имени: hostname был бы {@code null}, и валидация цепочки не
     * сравнила бы имя.</p>
     *
     * <p>Алгоритм разбирается напрямую: {@code null} и пустая строка означают «отключено»,
     * любое иное значение вне HTTPS/LDAPS отвергается, чтобы неподдерживаемый алгоритм не
     * отключал проверку молча. Ошибка алгоритма приоритетнее ошибки «peer host is missing».</p>
     *
     * @param engine SSLEngine
     * @return hostname или null, если endpoint identification выключен
     * @throws CertificateException если алгоритм не поддерживается либо проверка включена, а
     *     hostname пуст
     */
    public static String requireHostnameForEndpointId(SSLEngine engine)
            throws CertificateException {
        String alg =
                engine != null && engine.getSSLParameters() != null
                        ? engine.getSSLParameters().getEndpointIdentificationAlgorithm()
                        : null;
        return requireHostname(alg, engine != null ? engine.getPeerHost() : null);
    }

    /**
     * Аналог {@link #requireHostnameForEndpointId(SSLEngine)} для socket-перегрузки
     * {@code checkServerTrusted}.
     *
     * @param socket SSLSocket (может быть null)
     * @return hostname или null, если endpoint identification выключен
     * @throws CertificateException если алгоритм не поддерживается либо проверка включена, а
     *     hostname пуст (в том числе вызов вне рукопожатия: сессии рукопожатия нет)
     */
    public static String requireHostnameForEndpointId(Socket socket) throws CertificateException {
        if (!(socket instanceof SSLSocket sslSocket)) {
            return null;
        }
        String alg =
                sslSocket.getSSLParameters() != null
                        ? sslSocket.getSSLParameters().getEndpointIdentificationAlgorithm()
                        : null;
        if (EndpointIdentification.isDisabled(alg)) {
            return null;
        }
        if (!EndpointIdentification.isSupported(alg)) {
            throw new CertificateException(EndpointIdentification.unsupportedMessage(alg));
        }
        // Только сессия идущего рукопожатия, как в JDK: getSession() по контракту SSLSocket
        // запускает рукопожатие, а помощник проверки доверия запускать его не должен. Вне
        // рукопожатия имени пира нет, и проверка имени, которую требует алгоритм, невозможна
        SSLSession session = sslSocket.getHandshakeSession();
        return requireHostname(alg, session != null ? session.getPeerHost() : null);
    }

    /**
     * Общая логика {@code require…}: null при отключённой проверке, отказ при неподдерживаемом
     * алгоритме, непустой hostname при включённой.
     */
    public static String requireHostname(String alg, String peerHost) throws CertificateException {
        if (EndpointIdentification.isDisabled(alg)) {
            return null;
        }
        if (!EndpointIdentification.isSupported(alg)) {
            throw new CertificateException(EndpointIdentification.unsupportedMessage(alg));
        }
        if (peerHost == null || peerHost.isBlank()) {
            throw new CertificateException(
                    "Endpoint identification is enabled but peer host is missing");
        }
        return peerHost;
    }

    // ========================================================================
    // Методы контракта X509TrustManager для сторонних потребителей JSSE. Это полные реализации
    // (та же проверка цепочки, что и в handshake), но сам провайдер crypto-gost-jsse в
    // рукопожатии вызывает validateChainWithOcsp() напрямую из GostSSLEngine.
    // ========================================================================

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        checkClientTrustedImpl(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        checkClientTrustedImpl(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkClientTrustedImpl(chain);
    }

    /**
     * Не вызывается GostSSLSocket — реальная валидация серверного сертификата
     * идёт через {@link #validateChainWithOcsp} из GostSSLEngine.
     * <p>
     * Если endpoint identification включён, hostname берётся из
     * {@link SSLSocket#getHandshakeSession()}; пустой адрес — отказ.
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        checkServerTrustedImpl(chain, requireHostnameForEndpointId(socket));
    }

    /**
     * Проверка серверного сертификата по контракту JSSE. {@code GostSSLEngine} её не вызывает:
     * он идёт через {@link #validateChainWithOcsp}, где hostname берётся
     * через {@link #requireHostnameForEndpointId(SSLEngine)}.
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        checkServerTrustedImpl(chain, requireHostnameForEndpointId(engine));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        // Контракт JCA: перегрузка без соединения, адреса партнёра нет, сверять имя не с чем.
        // Так работает и JDK; имя не сверяется явно (null -> политика без сверки имени)
        checkServerTrustedImpl(chain, null);
    }

    /**
     * Возвращает пустой список принятых CA-сертификатов.
     * <p>
     * Три причины:
     * <ol>
     *   <li><b>Тактическая:</b> пустой список уменьшает размер CertificateRequest
     *       (RFC 8446 §4.3.2: список Distinguished Names опционален).</li>
     *   <li><b>Security:</b> не раскрываем список доверенных CA клиенту
     *       (защита от fingerprinting CA-инфраструктуры).</li>
     *   <li><b>Техническая:</b> валидация цепочки делается по сертификатам-якорям
     *       в {@link #validateChainWithOcsp}, не через accepted issuers.
     *       Пустой список не влияет на проверку сертификатов.</li>
     * </ol>
     *
     * @return пустой массив (длина 0)
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * Прямая валидация цепочки GostCertificate с OCSP и CRL для всей цепочки.
     * <p>
     * Поддерживает client-side OCSP fetch для leaf и intermediate сертификатов
     * по политике {@code ocspPolicy}. Поддерживает CRL-проверку по политике
     * {@code crlPolicy}. CRL проверяется только если OCSP-ответ отсутствует
     * (приоритет OCSP -> CRL, RFC 5280).
     * <p>
     * Не использует {@code ChainValidator.validateChainWithRevocation} из pkix —
     * для JSSE необходимы monotonicity CRL (minCrlNumber через {@code crlCache}),
     * настраиваемые лимиты (maxCrlSize, maxRevokedEntries), OCSP-nonce-проверка,
     * политики ({@code OcspPolicy}, {@code CrlPolicy}) и сетевой fetch —
     * всё это теряется в упрощённом convenience-методе pull-модели.
     * Для сценариев без этих требований см.
     * {@link org.rssys.gost.pkix.cert.ChainValidator#validateChainWithRevocation}.
     * <p>
     * Для серверного сертификата {@link OcspPolicy#STAPLING_OR_FETCH} делает
     * OCSP обязательным (staple или успешный fetch), кроме
     * {@code insecureTrustAll}, где сетевые запросы запрещены контрактом.
     *
     * @param hostname имя сервера для сверки с сертификатом; {@code null} - явный режим
     *         «без сверки имени» (endpoint identification выключен), пустое имя - отказ
     *         с {@link CertificateException}
     * @param requireOcsp дополнительная обязательность OCSP (помимо политики)
     * @return цепочка границы доверия: эффективная цепочка, по которой принят сервер, без
     *         локального якоря, срок которого не проверяется; наименьший {@code notAfter} по ней
     *         ограничивает срок PSK-тикета. Для {@code insecureTrustAll} это один leaf, срок
     *         которого проверен
     */
    public List<GostCertificate> validateChainWithOcsp(
            List<GostCertificate> chain, String hostname, boolean requireOcsp)
            throws CertificateException {
        if (chain == null || chain.isEmpty()) {
            throw new CertificateException("Empty certificate chain");
        }

        // STAPLING_OR_FETCH обещает fail-closed: staple или успешный fetch.
        // Ослабление до best-effort допустимо только для insecureTrustAll,
        // где контракт запрещает сетевые запросы.
        boolean needOcsp =
                requireOcsp || (!insecureTrustAll && ocspPolicy == OcspPolicy.STAPLING_OR_FETCH);
        TlsPeerPolicy policy =
                serverPolicy(hostname)
                        .requireOcspStaple(needOcsp)
                        .maxOcspAge(maxOcspAgeMs)
                        .maxThisUpdateAge(maxThisUpdateAge);

        // Сначала структура и PKIX. Сеть для отзыва — только после успешной
        // структурной проверки, иначе битая цепочка провоцирует лишние запросы.
        // Для cert-якорей структурная проверка возвращает эффективную цепочку: тогда OCSP/CRL
        // проверяются и для верхнего промежуточного CA, а issuer'ом выступает
        // локальный сертификат якоря, даже если пир не прислал корень.
        List<GostCertificate> effective = chain;
        try {
            if (insecureTrustAll) {
                TlsCertificateValidator.validateLeafOnly(chain, policy);
            } else {
                effective = TlsCertificateValidator.validateStructure(chain, policy);
            }
        } catch (TlsException e) {
            // Отказ по сертификату собеседника пишет движок на DEBUG (он знает соединение),
            // причина остаётся в исключении. Здесь записи нет: один отказ - одна запись.
            throw new CertificateException("Certificate validation failed: " + e.getMessage(), e);
        } catch (RuntimeException e) {
            // Сбой библиотеки или стороннего загрузчика: движок отличает его от отказа
            // собеседника и пишет WARNING с типом исключения
            throw e;
        } catch (Exception e) {
            // Проверяемое исключение не от TlsCertificateValidator - сбой библиотеки.
            // Текст не пишем: он может содержать данные собеседника.
            LOG.log(Level.WARNING, "Certificate validation error: {0}", e.getClass().getName());
            throw new CertificateException("Certificate validation error: " + e.getMessage(), e);
        }

        if (!insecureTrustAll) {
            // Бюджет создаётся на вызов, а не хранится в поле: менеджер общий для параллельных
            // рукопожатий
            RevocationBudget budget = new RevocationBudget(revocationBudget);
            List<PendingOcspEntry> pendingOcsp = collectRevocationEvidence(effective, budget, true);

            try {
                // Только отзыв: PKIX-валидация уже выполнена выше.
                TlsCertificateValidator.validateRevocation(effective, policy);
                // Только на успешном пути: сетевые ответы попадают в кэш после проверки.
                commitOcspCache(pendingOcsp);
            } catch (TlsException e) {
                logValidationFailure(e);
                throw new CertificateException(
                        "Certificate validation failed: " + e.getMessage(), e);
            }

            // Intermediate OCSP missing (best-effort fallthrough) — только при STAPLING_OR_FETCH
            if (ocspPolicy == OcspPolicy.STAPLING_OR_FETCH) {
                for (int i = 1; i < effective.size() - 1; i++) {
                    GostCertificate ic = effective.get(i);
                    if (!ic.hasOcspResponse()
                            && ic.getOcspUris() != null
                            && ic.getOcspUris().length > 0) {
                        // Цепочку присылает собеседник: WARNING на каждое соединение
                        // заполнялся бы внешним узлом, решение библиотеки видно на DEBUG
                        LOG.log(
                                Level.DEBUG,
                                "Intermediate cert serial=0x{0} has no OCSP response"
                                        + " (best-effort fallthrough)",
                                HEX.formatHex(ic.getSerialNumber()));
                    }
                }
            }
        }
        // Граница доверия считается по проверенной цепочке, а не по присланной: сервер мог
        // прислать корень, срок которого валидатор допускает
        return insecureTrustAll
                ? List.of(chain.get(0))
                : PeerTrustBoundary.boundaryChain(effective, trustAnchors);
    }

    /**
     * Собирает сведения об отзыве для сертификатов цепочки, кроме корня: сначала OCSP по сети
     * (если разрешён), затем CRL для сертификатов без OCSP-ответа (у OCSP приоритет). Сетевые
     * OCSP-ответы ещё не проверены: вызывающий кладёт их в кэш только после успешной проверки.
     *
     * @param fetchOcsp true - запрашивать недостающие OCSP-ответы по сети
     * @return записи для отложенного помещения в кэш OCSP
     * @throws CertificateException при отзыве по CRL или невозможности проверки CRL
     */
    private List<PendingOcspEntry> collectRevocationEvidence(
            List<GostCertificate> effective, RevocationBudget budget, boolean fetchOcsp)
            throws CertificateException {
        List<PendingOcspEntry> pendingOcsp = new ArrayList<>();
        if (fetchOcsp) {
            for (int i = 0; i < effective.size() - 1; i++) {
                addIfPresent(
                        pendingOcsp,
                        fetchOcspIfNeeded(effective.get(i), effective.get(i + 1), budget));
            }
        }
        for (int i = 0; i < effective.size() - 1; i++) {
            GostCertificate cert = effective.get(i);
            if (!cert.hasOcspResponse()) {
                checkCrl(cert, effective.get(i + 1), budget);
            }
        }
        return pendingOcsp;
    }

    /**
     * Записывает отзыв, найденный в присланном OCSP-ответе: одна WARNING с серийным номером.
     * Остальные отказы проверки сертификата пишет движок на DEBUG: он знает соединение и стадию,
     * а повторная запись в менеджере нарушила бы правило «один отказ - одна запись».
     */
    private static void logValidationFailure(TlsException e) {
        // Отзыв определяется по коду alert, а не по тексту: подстрока "revoked" есть и в
        // сообщениях об ошибках разбора, и ложно сообщила бы «сертификат отозван».
        if (e.getAlertCode() == TlsConstants.ALERT_CERTIFICATE_REVOKED) {
            // Текст собран из наших констант и серийного номера (TlsCertUtils), данных
            // собеседника в нём нет
            LOG.log(Level.WARNING, "Certificate revoked: {0}", e.getMessage());
        }
    }

    /**
     * Возвращает признак обязательного staple для серверного сертификата.
     * <p>
     * К клиентским сертификатам не применяется: их OCSP не обязателен.
     *
     * @return true, если политика {@link OcspPolicy#STAPLING_REQUIRED}
     */
    public boolean isRequireOcspStapling() {
        return requireOcspStapling;
    }

    /**
     * Возвращает случайный идентификатор этого экземпляра менеджера доверия.
     *
     * <p>Идентификатор нужен для привязки состояния, выведенного из проверки этим менеджером
     * (например, PSK-тикетов): возобновление не показывает сертификат и наследует проверку
     * исходного рукопожатия, поэтому тикет нельзя переносить в соединения, проверяемые другим
     * менеджером. Решение о принятии сервера зависит от якорей, политик, пользовательских
     * загрузчиков отзыва и будущих настроек; идентификатор экземпляра охватывает их все без
     * ведения списка полей. Тикет не переживает пересоздание менеджера: для кэша в памяти это не
     * потеря.</p>
     *
     * <p>Не секрет, но и не идентификатор пользователя: не используйте его в журналах как
     * сведения о пользователе.</p>
     *
     * @return копия идентификатора, 16 байт
     */
    public byte[] bindingId() {
        return bindingId.clone();
    }

    private static byte[] newBindingId() {
        byte[] id = new byte[BINDING_ID_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(id);
        return id;
    }

    /**
     * Политика проверки сертификата сервера. {@code null} вместо имени - явный выбор «имя не
     * сверять»: endpoint identification выключен (иначе {@code requireHostnameForEndpointId}
     * уже отказал бы) либо вызов без соединения. Пустое имя - ошибка, а не пропуск сверки.
     */
    private TlsPeerPolicy serverPolicy(String hostname) throws CertificateException {
        if (hostname == null) {
            return insecureTrustAll
                    ? TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()
                    : TlsPeerPolicy.serverWithoutHostnameVerification(trustAnchors);
        }
        if (hostname.isBlank()) {
            throw new CertificateException("Server hostname must not be blank");
        }
        return insecureTrustAll
                ? TlsPeerPolicy.serverLeafOnly(hostname)
                : TlsPeerPolicy.server(hostname, trustAnchors);
    }

    private void checkServerTrustedImpl(X509Certificate[] chain, String hostname)
            throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Empty server certificate chain");
        }
        List<GostCertificate> gostChain = CertificateBridge.toGost(chain);
        validateChainWithOcsp(gostChain, hostname, requireOcspStapling);
    }

    /**
     * JCA-путь: сертификаты пришли как {@link X509Certificate}, а конверсия через DER теряет
     * присланный staple. Поэтому он валидируется с политикой {@link ClientOcspPolicy#OFF} и
     * требовать staple не может; для политик {@code REQUEST}/{@code REQUIRE} используйте
     * {@link #validateClientChain} (его вызывает {@code GostSSLEngine}).
     */
    private void checkClientTrustedImpl(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Empty client certificate chain");
        }
        validateClientChain(CertificateBridge.toGost(chain), ClientOcspPolicy.OFF);
    }

    /**
     * Прямая валидация клиентской цепочки {@link GostCertificate} с учётом OCSP-staple,
     * присланного клиентом (RFC 8446 §4.4.2.1).
     * <p>
     * В отличие от JCA-пути {@link #checkClientTrusted(X509Certificate[], String)} не теряет
     * staple: сертификаты не проходят конверсию через DER. Присланный staple проверяется всегда.
     * <ul>
     *   <li>{@link ClientOcspPolicy#OFF}: отсутствие staple допустимо, исходящих запросов нет.</li>
     *   <li>{@link ClientOcspPolicy#REQUEST}: отсутствие staple допустимо; при
     *       {@link OcspPolicy#STAPLING_OR_FETCH} выполняется best-effort fetch. Условие fetch -
     *       конъюнкция: серверная политика {@code STAPLING_OR_FETCH} (в фасаде это
     *       {@code ocsp(true)} + {@code ocspFetcher}) и {@code ClientOcspPolicy != OFF}.</li>
     *   <li>{@link ClientOcspPolicy#REQUIRE}: staple leaf обязателен ({@code bad_certificate}).
     *       Наличие staple фиксируется до fetch, поэтому ответ, полученный по сети,
     *       обязательность не выполняет.</li>
     * </ul>
     *
     * @param chain  клиентская цепочка leaf-first, сертификаты хранят присланный staple
     * @param policy политика сервера в отношении клиентского staple (не null)
     * @throws CertificateException при отказе в доверии, в том числе при отсутствии
     *         обязательного staple
     */
    public void validateClientChain(List<GostCertificate> chain, ClientOcspPolicy policy)
            throws CertificateException {
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        if (chain == null || chain.isEmpty()) {
            throw new CertificateException("Empty client certificate chain");
        }
        boolean requireStaple = policy == ClientOcspPolicy.REQUIRE;
        // Фиксируем до fetch: fetchOcspIfNeeded кладёт сетевой ответ в сертификат, и
        // проверка после него засчитала бы fetch как присланный клиентом staple.
        boolean stapledByClient = chain.get(0).hasOcspResponse();
        TlsPeerPolicy peerPolicy =
                (insecureTrustAll
                                ? TlsPeerPolicy.clientLeafOnly()
                                : TlsPeerPolicy.client(trustAnchors))
                        .requireOcspStaple(requireStaple)
                        .maxOcspAge(maxOcspAgeMs)
                        .maxThisUpdateAge(maxThisUpdateAge);
        try {
            if (insecureTrustAll) {
                // Никакой сети: только структура leaf и уже присланный OCSP.
                TlsCertificateValidator.validateLeafOnly(chain, peerPolicy);
                warnClientOcspNotMandatoryOnce(chain.get(0), policy);
            } else {
                // Сначала структура и PKIX, затем сеть, затем только отзыв.
                List<GostCertificate> effective =
                        TlsCertificateValidator.validateStructure(chain, peerPolicy);
                if (requireStaple && !stapledByClient) {
                    throw new TlsException(
                            TlsConstants.ALERT_BAD_CERTIFICATE,
                            "Client did not provide OCSP stapling response");
                }
                // OFF: клиентские сертификаты не вызывают исходящих запросов. Fetch по AIA из
                // сертификата, присланного неаутентифицированным пиром, включается явно.
                // Бюджет нужен и при OFF: OCSP тогда не грузится, но CRL по CDP загружается
                RevocationBudget budget = new RevocationBudget(revocationBudget);
                // Предупреждение действует только при OFF, а тогда OCSP по сети не запрашивается:
                // наличие ответа у листа к сбору сведений не меняется
                warnClientOcspNotMandatoryOnce(effective.get(0), policy);
                List<PendingOcspEntry> pendingOcsp =
                        collectRevocationEvidence(
                                effective, budget, policy != ClientOcspPolicy.OFF);
                // Присланный staple проверяется внутри; при REQUIRE дополнительно нужен издатель.
                TlsCertificateValidator.validateRevocation(effective, peerPolicy);
                commitOcspCache(pendingOcsp);
            }
        } catch (TlsException e) {
            throw new CertificateException(
                    "Client certificate validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CertificateException("Certificate validation error: " + e.getMessage(), e);
        }
        GostCertificate leaf = chain.get(0);
        // DN усечён, как в остальных записях журнала; строки собираются только при включённом DEBUG
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(
                    Level.DEBUG,
                    "Client certificate accepted: subject={0}, serial=0x{1}",
                    leaf.getSubjectDnForLog(GostCertificate.DN_LOG_MAX_CHARS),
                    new BigInteger(1, leaf.getSerialNumber()).toString(16));
        }
    }

    /**
     * Один раз предупреждает, что OCSP клиентского сертификата не обязателен.
     * <p>
     * Без этого пользователь может решить, что {@code STAPLING_REQUIRED}
     * действительно требует staple от клиента, и будет искать несуществующую
     * ошибку конфигурации. Текст статический: секретов и содержимого ответа нет.
     */
    private void warnClientOcspNotMandatoryOnce(GostCertificate leaf, ClientOcspPolicy policy) {
        // При REQUEST и REQUIRE политика клиентского staple задана явно: предупреждение
        // «не обязателен» противоречило бы ей.
        if (policy != ClientOcspPolicy.OFF) {
            return;
        }
        if (ocspPolicy != OcspPolicy.STAPLING_REQUIRED
                && ocspPolicy != OcspPolicy.STAPLING_OR_FETCH) {
            return;
        }
        if (leaf.hasOcspResponse()) {
            return;
        }
        if (clientOcspSoftWarningLogged.compareAndSet(false, true)) {
            LOG.log(
                    Level.WARNING,
                    "Client certificate OCSP is not mandatory:"
                            + " OCSP policy applies to the server certificate;"
                            + " use CrlPolicy.REQUIRE for strict client revocation"
                            + " when no OCSP response is available");
        }
    }

    /**
     * Запрашивает OCSP для сертификата, если ещё нет stapled ответа и политика разрешает fetch.
     * <p>
     * Ответ кладётся в сертификат для последующей проверки, но в {@code ocspCache} не пишется:
     * сетевой ответ ещё не аутентифицирован, и подложенный ответ с далёким {@code nextUpdate} отравил бы
     * кэш для всех следующих соединений. Запись возвращается вызывающему и попадает в кэш
     * через {@link #commitOcspCache} только после успешной проверки отзыва.
     *
     * @return запись для отложенного помещения в кэш или {@code null}, если fetch не выполнялся,
     *         не удался или ответ взят из кэша
     */
    private PendingOcspEntry fetchOcspIfNeeded(
            GostCertificate cert, GostCertificate issuer, RevocationBudget budget) {
        if (ocspPolicy != OcspPolicy.STAPLING_OR_FETCH || ocspFetcher == null) {
            return null;
        }
        if (cert.hasOcspResponse()) {
            return null;
        }

        String[] ocspUris = cert.getOcspUris();
        if (ocspUris == null || ocspUris.length == 0) {
            return null;
        }

        OcspCacheKey cacheKey = buildCacheKey(cert, issuer);
        CachedOcspStatus cached = ocspCache.get(cacheKey);
        if (cached != null) {
            if (!cached.isExpired()) {
                LOG.log(Level.DEBUG, "OCSP cache hit for {0}", cacheKey.certSerial);
                cert.setOcspResponse(cached.response);
                cert.setOcspNonce(cached.nonce);
                return null;
            }
            ocspCache.remove(cacheKey);
        }

        PendingOcspEntry pending = null;
        int tried = 0;
        for (String ocspUri : ocspUris) {
            if (ocspUri == null || ocspUri.isEmpty()) continue;
            if (tried++ >= MAX_REVOCATION_URIS_PER_KIND) {
                LOG.log(
                        Level.WARNING,
                        "OCSP: only the first {0} responder addresses are tried",
                        MAX_REVOCATION_URIS_PER_KIND);
                break;
            }
            // Кэш уже проверен выше, поэтому бюджет тратится только на настоящие загрузки
            if (!budget.tryStart()) {
                LOG.log(
                        Level.WARNING,
                        "OCSP fetch skipped for {0}: revocation fetch budget is exhausted",
                        cacheKey.certSerial);
                break;
            }
            long start = System.nanoTime();
            OcspFetchResult result =
                    ocspFetcher.fetchWithNonce(cert.getEncoded(), issuer.getEncoded(), ocspUri);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            if (result.response() != null) {
                cert.setOcspResponse(result.response());
                cert.setOcspNonce(result.nonce());
                long now = System.currentTimeMillis();
                long expiresAt = ocspCacheExpiry(result.response(), cert, now);
                // Ответ, который верификатор уже отвергнет, кэшировать бессмысленно: он только
                // задержал бы повторный запрос свежего ответа.
                if (expiresAt > now) {
                    pending =
                            new PendingOcspEntry(
                                    cacheKey,
                                    new CachedOcspStatus(
                                            result.response(), result.nonce(), expiresAt));
                }
                // SafeText.uri санитизирует адрес посимвольно до проверки уровня внутри log: при
                // выключенном DEBUG это лишняя работа на каждой загрузке OCSP
                if (LOG.isLoggable(Level.DEBUG)) {
                    LOG.log(
                            Level.DEBUG,
                            "OCSP fetch success for cert={0} from {1} ({2}ms)",
                            cacheKey.certSerial,
                            SafeText.uri(ocspUri),
                            elapsedMs);
                }
                break;
            } else {
                // Загрузчик сам не пишет: одна запись на отказ здесь, где известен сертификат.
                // Причина перечисление, текст исключения HTTP-клиента в журнал не идёт
                LOG.log(
                        Level.WARNING,
                        "OCSP fetch failed for cert={0} from {1}: {2}",
                        cacheKey.certSerial,
                        SafeText.uri(ocspUri),
                        Objects.toString(result.failure(), "reason not reported"));
            }
        }
        return pending;
    }

    /**
     * Вычисляет момент, до которого OCSP-ответ можно держать в кэше.
     * <p>
     * Срок не должен превышать окно, которое принимает {@code OcspVerifier}: тот отвергает ответ
     * сразу после {@code nextUpdate} (допуск часов к {@code nextUpdate} не применяется), а без
     * {@code nextUpdate} - по истечении {@code thisUpdate + maxOcspAgeMs}; при заданном пределе возраста
     * {@code thisUpdate} - не позже {@code thisUpdate + предел}. Иначе кэш отдавал бы
     * ответ, который проверка гарантированно отклонит, и повторного запроса не было бы.
     * <p>
     * Поля {@code nextUpdate} и {@code thisUpdate} здесь ещё не проверены и приходят из сети;
     * безопасно это лишь потому, что срок ограничен {@code ocspCacheTtlMs}, а свежесть ответа
     * проверяется в {@code validateRevocation} при каждом использовании записи. Берётся
     * {@code SingleResponse} именно проверяемого сертификата: в ответе их может быть несколько.
     *
     * @param responseDer DER OCSP-ответа
     * @param cert        сертификат, для которого получен ответ
     * @param nowMs       текущее время, мс
     * @return момент истечения записи, мс; значение не позже {@code nowMs} означает «не кэшировать»
     */
    private long ocspCacheExpiry(byte[] responseDer, GostCertificate cert, long nowMs) {
        try {
            SingleOcspResponse single = findSingleResponse(responseDer, cert.getSerialNumber());
            if (single == null) {
                return nowMs;
            }
            return ocspCacheExpiry(single, nowMs, ocspCacheTtlMs, maxOcspAgeMs, maxThisUpdateAge);
        } catch (PkixException e) {
            // Не разобранный ответ верификатор всё равно отвергнет: в кэш он не нужен.
            return nowMs;
        }
    }

    static long ocspCacheExpiry(
            SingleOcspResponse single,
            long nowMs,
            long ocspCacheTtlMs,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge) {
        long expiry;
        Instant nextUpdate = single.nextUpdate();
        long thisUpdateMs = single.thisUpdate().toEpochMilli();
        long ttlLimit = nowMs + ocspCacheTtlMs;
        if (nextUpdate != null) {
            expiry = Math.min(nextUpdate.toEpochMilli(), ttlLimit);
        } else {
            expiry = Math.min(thisUpdateMs + maxOcspAgeMs, ttlLimit);
        }
        if (maxThisUpdateAge != null) {
            // Запись не должна жить дольше окна, которое примет проверка: иначе кэш отдавал бы
            // ответ, который она гарантированно отклонит, а свежий не запрашивался бы.
            // Сложение с насыщением: очень большой предел просто ничего не ограничивает и не
            // должен обрывать соединение исключением из-за настройки.
            long limitMs;
            try {
                limitMs = maxThisUpdateAge.toMillis();
            } catch (ArithmeticException tooLarge) {
                limitMs = Long.MAX_VALUE;
            }
            long limitExpiry;
            try {
                limitExpiry = Math.addExact(thisUpdateMs, limitMs);
            } catch (ArithmeticException overflow) {
                limitExpiry = Long.MAX_VALUE;
            }
            expiry = Math.min(expiry, limitExpiry);
        }
        return expiry;
    }

    static SingleOcspResponse findSingleResponse(byte[] responseDer, byte[] certSerial)
            throws PkixException {
        for (SingleOcspResponse single : new GostOcspResponse(responseDer).getResponses()) {
            if (Arrays.equals(single.certSerialNumber(), certSerial)) {
                return single;
            }
        }
        return null;
    }

    private static void addIfPresent(List<PendingOcspEntry> entries, PendingOcspEntry entry) {
        if (entry != null) {
            entries.add(entry);
        }
    }

    /**
     * Помещает в кэш OCSP-ответы, полученные по сети, после успешной проверки отзыва.
     * <p>
     * Вызывается только на успешном пути: при отказе записи отбрасываются вместе со списком.
     */
    private void commitOcspCache(List<PendingOcspEntry> entries) {
        long now = System.currentTimeMillis();
        for (PendingOcspEntry entry : entries) {
            // Между расчётом срока и проверкой отзыва запись могла истечь: просроченную в кэш
            // не кладём, иначе следующий lookup только удалит её.
            if (entry.status().expiresAt <= now) {
                continue;
            }
            ocspCache.put(entry.key(), entry.status());
            // Мягкий предел: при превышении уходит запись с ближайшим сроком (как в CrlCache), а
            // не произвольная, которая могла бы оказаться только что добавленным ответом с самым
            // долгим сроком
            if (ocspCache.size() > OCSP_CACHE_MAX_ENTRIES) {
                evictNearestExpiry(ocspCache);
            }
        }
    }

    /** Удаляет из кэша запись с ближайшим сроком истечения. */
    static void evictNearestExpiry(ConcurrentHashMap<OcspCacheKey, CachedOcspStatus> cache) {
        cache.entrySet().stream()
                .min(Comparator.comparingLong(entry -> entry.getValue().expiresAt))
                .ifPresent(entry -> cache.remove(entry.getKey(), entry.getValue()));
    }

    /**
     * Проверяет сертификат по CRL (Certificate Revocation List).
     * <p>
     * Вызывается только если OCSP-ответ отсутствует (приоритет OCSP -> CRL, RFC 5280).
     * fail-closed: при REQUIRE + нет CDP/нет fetcher/ошибка fetch — reject.
     * Сетевые ошибки (IOException) при fetch приводят к переходу к следующему CDP mirror
     * (или reject при REQUIRE). Слишком большой ответ ({@link CrlSizeLimitException} или длина
     * больше {@code maxCrlSize}) и ошибка из {@code verify} (битая подпись, expired, revoked)
     * пробрасываются немедленно — никаких fallback mirror'ов. CRL, который использовать нельзя
     * (неизвестное critical-расширение, не покрывающий сертификат), равносилен недоступному
     * адресу.
     * Кэш CRL (CrlCache) хранит уже проверенный CRL: подпись и разбор выполняются один раз на
     * адрес и издателя (одним потоком, остальные ждут), а сертификат проверяется по готовому
     * объекту на каждом соединении. Последний известный cRLNumber защищает от отката CRL
     * (RFC 5280 §5.2.3). Прерывание потока при загрузке даёт отказ, а не переход к следующему
     * зеркалу.
     *
     * @param cert   проверяемый сертификат (leaf или intermediate)
     * @param issuer issuer сертификата (cert[i+1] в цепочке)
     * @throws CertificateException при revoked CRL, REQUIRE без CDP, REQUIRE без fetcher
     */
    private void checkCrl(GostCertificate cert, GostCertificate issuer, RevocationBudget budget)
            throws CertificateException {
        if (crlPolicy == CrlPolicy.DISABLED) {
            return;
        }
        String[] cdps = cert.getCdpUris();
        if (cdps == null || cdps.length == 0) {
            if (crlPolicy == CrlPolicy.REQUIRE) {
                throw new CertificateException(
                        "CRL required but no CRLDistributionPoints in certificate");
            }
            return;
        }
        if (crlFetcher == null) {
            if (crlPolicy == CrlPolicy.REQUIRE) {
                throw new CertificateException("CRL required but no CrlFetcher configured");
            }
            return;
        }

        // Издатель опознаётся хешем его сертификата целиком (как в кэше OCSP): один адрес у двух
        // издателей не должен делить проверенный CRL.
        String issuerCertHash = issuerCertHashHex(issuer);
        int triedMirrors = 0;
        mirrors:
        for (String crlUri : cdps) {
            if (crlUri == null || crlUri.isEmpty()) continue;
            if (triedMirrors++ >= MAX_REVOCATION_URIS_PER_KIND) {
                LOG.log(
                        Level.WARNING,
                        "CRL: only the first {0} distribution points are tried",
                        MAX_REVOCATION_URIS_PER_KIND);
                break;
            }
            CrlKey key = new CrlKey(crlUri, issuerCertHash);
            try {
                for (int attempt = 0; ; attempt++) {
                    CrlCache.Loaded loaded;
                    try {
                        // Дорогая часть (загрузка, подпись, разбор) не зависит от сертификата и
                        // выполняется одним потоком на ключ; сертификат проверяется ниже по
                        // готовому объекту. Остальные соединения ждут его не дольше остатка
                        // бюджета; сдавшийся ожидающий получает DeadlineExceededException, и
                        // общая ветка IOException ниже ведёт к следующему зеркалу.
                        loaded =
                                crlCache.get(
                                        key,
                                        // Бюджет проверяется только на промахе кэша, то
                                        // есть перед настоящей загрузкой. Отказ оформлен как
                                        // пропуск: ожидающие этот же CRL потоки других
                                        // соединений повторят загрузку сами
                                        new CdpLoader(crlUri, budget, false),
                                        recheckLoader(crlUri, budget),
                                        der ->
                                                CrlVerifier.authenticate(
                                                        der, issuer, this.crlLimits),
                                        // Ожидание чужой загрузки ограничено остатком бюджета:
                                        // иначе бюджет не был бы потолком
                                        budget.remaining());
                    } catch (CrlSizeLimitException e) {
                        // Сервер ответил, но CRL слишком большой: это не «адрес недоступен».
                        // Переход к следующему адресу или пропуск проверки отзыва при
                        // IF_CDP_PRESENT молча отключили бы её для подлинного большого CRL.
                        LOG.log(
                                Level.WARNING,
                                "CRL exceeds size limit, rejecting: {0} (limit {1,number,#} bytes)",
                                SafeText.uri(crlUri),
                                e.getMaxBytes());
                        throw new CertificateException(
                                "CRL exceeds size limit (" + e.getMaxBytes() + " bytes)", e);
                    } catch (CrlCache.LoadSkippedException e) {
                        // Бюджет загрузок исчерпан: это не недоступность адреса, и сообщение не
                        // должно вводить в заблуждение при разборе журнала
                        LOG.log(
                                Level.WARNING,
                                "CRL fetch skipped for {0}: revocation fetch budget is exhausted",
                                SafeText.uri(crlUri));
                        continue mirrors;
                    } catch (IOException e) {
                        // Прерванный поток не должен молча пройти без проверки отзыва: переход к
                        // следующему зеркалу при IF_CDP_PRESENT равнялся бы пропуску проверки.
                        if (Thread.currentThread().isInterrupted()) {
                            throw new CertificateException(
                                    "CRL fetch interrupted for " + SafeText.uri(crlUri), e);
                        }
                        // Текст исключения может прийти от стороннего CrlFetcher или HTTP-клиента:
                        // в журнал идёт только перечисление причины
                        LOG.log(
                                Level.WARNING,
                                "CRL mirror unavailable, trying next: {0}: {1}",
                                SafeText.uri(crlUri),
                                crlFailureReason(e));
                        continue mirrors;
                    }
                    try {
                        // Откат номера проверен при загрузке (CrlCache.get), и в кэш попадают
                        // только прошедшие эту проверку объекты. Повторно сверять с текущим
                        // базовым номером нельзя: поток, получивший годный объект, мог
                        // отстать от другого потока, загрузившего более новый CRL после
                        // вытеснения записи, и получил бы ложный отказ.
                        loaded.crl().verifyFor(cert, issuer, null);
                        // Инвариант: в кэше лежат только CRL с проверенной подписью (кэш
                        // кладёт запись после authenticate), CRL с чужой подписью его не отравит.
                        return; // чистый CRL - прерываем цикл
                    } catch (PkixException e) {
                        // Срок объекта из кэша мог истечь после выдачи: это промах кэша, а не
                        // отказ. Один повтор: свежезагруженный просроченный CRL - ошибка.
                        if (attempt == 0
                                && loaded.fromCache()
                                && e.reason() == PkixException.Reason.EXPIRED) {
                            crlCache.invalidate(key, loaded.crl());
                            continue;
                        }
                        throw e;
                    }
                }
            } catch (PkixException e) {
                // Отзыв определяем по причине, а не по тексту: подстрока "revoked" есть и в
                // сообщениях об ошибке разбора записей, и ложно сообщила бы «сертификат отозван».
                if (e.reason() == PkixException.Reason.REVOKED) {
                    // Текст исключения при отзыве постоянный и не называет сертификат: оператору
                    // нужны серийный номер и адрес списка, по которому найден отзыв
                    LOG.log(
                            Level.WARNING,
                            "CRL: certificate revoked: serial=0x{0}, CRL {1}",
                            HEX.formatHex(cert.getSerialNumber()),
                            SafeText.uri(crlUri));
                    throw new CertificateException("Certificate is revoked per CRL", e);
                }
                if (isUnusableCrl(e)) {
                    // CRL, который RFC 5280 не позволяет использовать, равносилен недоступному
                    // зеркалу: идём к следующему. Для CRL, не покрывающего сертификат, отзыв не
                    // теряется: запись проверяется раньше области. Неизвестное critical-расширение
                    // и indirect CRL отвергаются при разборе, до проверки записей, поэтому такой
                    // CRL не используется, даже если в нём указан сертификат (RFC 5280 §5.2, §5.3).
                    LOG.log(
                            Level.WARNING,
                            "CRL mirror skipped, CRL cannot be used: {0} - {1}",
                            SafeText.uri(crlUri),
                            e.getMessage());
                    continue;
                }
                throw new CertificateException("CRL validation failed: " + e.getMessage(), e);
            }
        }
        // Все CDP-зеркала исчерпаны. Зеркало могло и ответить, но его CRL не подошёл.
        if (crlPolicy == CrlPolicy.REQUIRE) {
            throw new CertificateException("CRL required but no usable CRL from any CDP mirror");
        }
    }

    /**
     * Причина отказа загрузки CRL для журнала: перечисление, а не текст исключения. Исключение
     * кэша о пустом ответе несёт причину загрузчика, остальные определяются по типу.
     */
    private static FetchFailure crlFailureReason(IOException e) {
        if (e instanceof CrlCache.NoDataException noData && noData.failure() != null) {
            return noData.failure();
        }
        return FetchFailure.of(e);
    }

    /**
     * Загрузчик перепроверки записи кэша CRL. Перепроверка необязательна: она идёт только при
     * остатке бюджета и не берёт «первую загрузку, разрешённую всегда» ({@code tryStart} не
     * вызывается), которая нужна обязательным загрузкам цепочки. Иначе перепроверка листового CRL
     * заняла бы эту гарантию, и при {@code REQUIRE} обязательная загрузка CRL следующего УЦ
     * получала бы отказ.
     */
    CrlCache.Loader recheckLoader(String crlUri, RevocationBudget budget) {
        return new CdpLoader(crlUri, budget, true);
    }

    /**
     * Загрузчик CRL по адресу CDP для кэша: обязательный или перепроверочный. Обязательный
     * проверяет бюджет через {@code tryStart} (первая загрузка разрешена всегда), перепроверочный -
     * только остаток бюджета. Оба умеют условный запрос: обязательной загрузке кэш не даёт
     * валидатор, но она захватывает {@code Last-Modified} ответа.
     */
    private final class CdpLoader implements CrlCache.Loader {
        private final String crlUri;
        private final RevocationBudget budget;
        private final boolean recheck;

        CdpLoader(String crlUri, RevocationBudget budget, boolean recheck) {
            this.crlUri = crlUri;
            this.budget = budget;
            this.recheck = recheck;
        }

        @Override
        public byte[] fetch() throws IOException {
            return fetchConditional(null).der();
        }

        @Override
        public CrlFetchResult fetchConditional(String validator) throws IOException {
            boolean allowed = recheck ? budget.hasRemaining() : budget.tryStart();
            if (!allowed) {
                throw new CrlCache.LoadSkippedException("Revocation fetch budget is exhausted");
            }
            return fetchBounded(crlUri, validator);
        }
    }

    private CrlFetchResult fetchBounded(String crlUri, String validator) throws IOException {
        CrlFetchResult result = crlFetcher.fetchConditional(crlUri, validator);
        byte[] der = result.der();
        if (der != null && der.length > crlLimits.maxSize()) {
            throw new CrlSizeLimitException(
                    "CRL exceeds size limit (" + crlLimits.maxSize() + " bytes), got " + der.length,
                    crlLimits.maxSize(),
                    der.length);
        }
        return result;
    }

    /**
     * Признак CRL, который использовать нельзя, но который не является ошибкой проверки:
     * неизвестное critical-расширение (RFC 5280 §5.2, §5.3) и CRL, не покрывающий сертификат
     * (partial или indirect: область, которую библиотека не умеет применять, а также
     * несовпадение distributionPoint с CDP сертификата). Delta CRL по адресу CDP остаётся
     * фатальной ошибкой намеренно: это неверная настройка, а не неподходящий CRL.
     */
    private static boolean isUnusableCrl(PkixException e) {
        return e.reason() == PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION
                || e.reason() == PkixException.Reason.IDP_NOT_SUPPORTED;
    }

    /**
     * Строит ключ кэша OCSP по (хеш сертификата издателя, серийный номер сертификата).
     *
     * <p>Серийные номера у разных УЦ часто совпадают, поэтому издатель опознаётся хешем его
     * сертификата целиком (DN, открытый ключ и серийный номер входят в хеш). Ответ чужого
     * издателя тогда не подставится из кэша. Ошибку хеширования не скрываем: подмена
     * идентификатора издателя нарушила бы fail-closed.</p>
     *
     * <p>Вызывается до обращения к кэшу, поэтому копия DER и Стрибог-256 считаются на каждом
     * поиске, включая попадания; на фоне проверки подписей ГОСТ это несущественно.</p>
     */
    static OcspCacheKey buildCacheKey(GostCertificate cert, GostCertificate issuer) {
        return new OcspCacheKey(issuerCertHashHex(issuer), HEX.formatHex(cert.getSerialNumber()));
    }

    private static final HexFormat HEX = HexFormat.of();

    /** Хэш (Стрибог-256) DER издателя в hex: общая часть ключей кэшей CRL и OCSP. */
    private static String issuerCertHashHex(GostCertificate issuer) {
        return HEX.formatHex(Digest.digest256(issuer.getEncoded()));
    }

    /**
     * Ключ кэша OCSP по (issuerCertHashHex, certSerialHex).
     */
    record OcspCacheKey(String issuerCertHash, String certSerial) {
        OcspCacheKey {
            Objects.requireNonNull(issuerCertHash);
            Objects.requireNonNull(certSerial);
        }
    }

    /**
     * OCSP-ответ, полученный по сети и ещё не проверенный: ждёт помещения в кэш.
     */
    private record PendingOcspEntry(OcspCacheKey key, CachedOcspStatus status) {}

    /** Подставляет кэш CRL (например, с подменёнными часами); для тестов (публичный API не меняется). */
    void setCrlCacheForTest(CrlCache cache) {
        this.crlCache = cache;
    }

    /** Задаёт бюджет проверки; для тестов (публичный API не меняется). */
    void setRevocationBudgetForTest(Duration budget) {
        this.revocationBudget = budget;
    }

    /**
     * Бюджет времени на загрузки отзыва за одну проверку цепочки. Живёт в одном вызове и одном
     * потоке, поэтому без синхронизации. Первая загрузка разрешена всегда (одна на весь вызов):
     * иначе нулевой или малый бюджет отключал бы проверку отзыва полностью. После исчерпания новые
     * загрузки не начинаются ни для текущего, ни для следующих сертификатов цепочки.
     */
    static final class RevocationBudget {
        private final long startNanos = System.nanoTime();
        private final long limitNanos;
        private boolean started;

        RevocationBudget(Duration limit) {
            this.limitNanos = limit.toNanos();
        }

        /**
         * Остаток бюджета от создания: ожидание чужой загрузки CRL считается в том же окне, что и
         * собственные загрузки. Флаг {@code started} не учитывается: ожидание его не взводит, и
         * на каждом следующем зеркале поток получал бы полный срок заново.
         */
        Duration remaining() {
            long left = Math.max(0L, limitNanos - (System.nanoTime() - startNanos));
            return Duration.ofNanos(Math.min(left, Deadline.MAX_FETCH_TIMEOUT.toNanos()));
        }

        /** @return {@code true}, если окно бюджета ещё не исчерпано (флаг {@code started} не меняется) */
        boolean hasRemaining() {
            return !remaining().isZero();
        }

        /** @return {@code true}, если загрузку можно начинать; отмечает её начало */
        boolean tryStart() {
            if (started && System.nanoTime() - startNanos >= limitNanos) {
                return false;
            }
            started = true;
            return true;
        }
    }

    /**
     * Кэшированный OCSP-ответ. Хранит сам response, чтобы избежать повторного HTTP.
     */
    static final class CachedOcspStatus {
        final byte[] response;
        final byte[] nonce;
        final long expiresAt;

        CachedOcspStatus(byte[] response, byte[] nonce, long expiresAt) {
            this.response = response;
            this.nonce = nonce;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }
}
