package org.rssys.gost.jsse;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.engine.EndpointIdentificationMode;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * Fluent builder {@link SSLContext} для ГОСТ TLS 1.3.
 * <p>
 * Единственная реализация сборки контекста: простые статические методы {@link GostSsl}
 * делегируют сюда. Помимо источников сертификата и доверенных CA покрывает проверку отзыва
 * (OCSP, CRL), аутентификацию клиента (mTLS), кэш сессий, проверку имени сервера и совместимость
 * с чужими реализациями.
 * <p>
 * Владение данными: массивы, переданные в {@link #certificate(byte[], byte[])} и
 * {@link #certificate(byte[], char[])}, и пароль builder не копирует и не затирает. Они остаются
 * собственностью вызывающего: один builder можно использовать для серверного и клиентского
 * контекстов, а затирание после первой сборки сломало бы вторую. Вызывающий затирает пароль и
 * ключевой материал сам, когда контексты построены.
 */
public final class GostSslBuilder {

    /** Алиас единственной ключевой записи контекста. */
    private static final String DEFAULT_KEY_ALIAS = "default";

    private byte[] certDer;
    private byte[] keyDer;
    private byte[] p12Data;
    private char[] p12Password;
    private final List<GostCertificate> trustedCas = new ArrayList<>();
    private boolean ocspEnabled;
    private int sessionCacheSize = -1;
    private boolean trustAll;
    private CrlPolicy crlPolicy = CrlPolicy.DISABLED;
    private CrlFetcher crlFetcher;
    private int maxCrlSize = GostCrl.DEFAULT_MAX_CRL_SIZE;
    private int maxRevokedEntries = GostCrl.DEFAULT_MAX_REVOKED_ENTRIES;
    private long crlCacheMaxBytes = CrlCache.DEFAULT_MAX_BYTES;
    private Duration crlMaxAge = CrlCache.DEFAULT_MAX_AGE;
    private OcspFetcher ocspFetcher;
    private long maxOcspAgeMs = GostOids.MAX_OCSP_AGE_MS;
    private Duration maxThisUpdateAge;
    private boolean interopAcceptGostBaseSigScheme;
    private boolean needClientAuth;
    private boolean wantClientAuth;
    private ClientOcspPolicy clientOcspPolicy = ClientOcspPolicy.OFF;
    private boolean disableHostnameVerification;

    GostSslBuilder() {}

    /**
     * Устанавливает сертификат и ключ с авто-определением формата.
     * <p>
     * Каждый аргумент может быть в PEM или DER. PEM автоматически конвертируется
     * в DER через {@link GostCertificate#pemToDer(byte[])}: в PEM допускается ровно один блок,
     * файл с цепочкой сертификатов здесь отвергается. Массивы не копируются и не затираются
     * (см. описание класса).
     *
     * @param certData сертификат X.509 (PEM или DER)
     * @param keyData  закрытый ключ PKCS#8 (PEM или DER)
     * @return this для fluent API
     */
    public GostSslBuilder certificate(byte[] certData, byte[] keyData) {
        this.certDer =
                GostCertificate.isPem(certData) ? GostCertificate.pemToDer(certData) : certData;
        this.keyDer = GostCertificate.isPem(keyData) ? GostCertificate.pemToDer(keyData) : keyData;
        return this;
    }

    /**
     * Устанавливает сертификат и ключ из PKCS12. Массив и пароль не копируются и не затираются
     * (см. описание класса).
     *
     * @param p12Data  байты PFX-контейнера
     * @param password пароль
     */
    public GostSslBuilder certificate(byte[] p12Data, char[] password) {
        this.p12Data = p12Data;
        this.p12Password = password;
        return this;
    }

    /**
     * Добавляет доверенный CA-сертификат в trust store.
     * <p>
     * Автоматически определяет формат: PEM (одиночный или цепочка) или DER.
     * Для PEM-цепочки добавляются все сертификаты из неё.
     * Добавленные CA используются все при проверке цепочки сертификатов.
     * <p>
     * Для сервера без клиентской аутентификации якоря не нужны: он не проверяет сертификаты
     * клиентов. Клиенту и серверу с mTLS они обязательны.
     *
     * @param caData PEM- или DER-байты CA-сертификата
     * @return this для fluent API
     * @throws IllegalArgumentException если данные не содержат валидного сертификата
     */
    public GostSslBuilder trustCa(byte[] caData) {
        if (GostCertificate.isPem(caData)) {
            trustedCas.addAll(GostCertificate.listFromPem(caData));
        } else {
            trustedCas.add(new GostCertificate(caData));
        }
        return this;
    }

    /**
     * Добавляет в trust store CA-сертификаты цепочки ключа из PFX-контейнера.
     * <p>
     * Якорями становятся только CA, связанные с ключом контейнера (путь от сертификата ключа
     * вверх). Независимые сертификаты контейнера, не входящие в эту цепочку, и не-CA
     * сертификаты якорями не становятся. Для CA-бандла с несколькими независимыми корнями
     * используйте {@link #trustCaBundle(byte[], char[])}.
     * <p>
     * PFX должен содержать проверенный MAC: без него открытый SafeContents можно подменить, не
     * зная пароль.
     *
     * @param pfxData  байты PFX-контейнера
     * @param password пароль PFX
     * @return this для fluent API
     * @throws IllegalArgumentException если MAC отсутствует или в цепочке ключа нет CA
     */
    public GostSslBuilder trustCaChain(byte[] pfxData, char[] password) {
        GostPkcs12Loader.Result container = GostPkcs12Loader.load(pfxData, password, true);
        return trustCaCertificates(container.getCertificateChain(), "key chain of the PFX");
    }

    /**
     * Добавляет в trust store все сертификаты PFX-контейнера, который является CA-бандлом.
     * <p>
     * Контейнер обязан состоять только из CA-сертификатов (ключ УЦ и несколько независимых
     * корней): все они становятся якорями доверия, и защиту обеспечивает только MAC. Если в
     * контейнере есть не-CA сертификат, метод бросает исключение, а не отбрасывает его молча;
     * для контейнера со смешанным составом используйте {@link #trustCaChain(byte[], char[])}.
     * Для контейнера, прочитанного через JDK-fallback, набор сертификатов best-effort:
     * учитываются только записи, видимые через {@code KeyStore}.
     * <p>
     * PFX должен содержать проверенный MAC.
     *
     * @param pfxData  байты PFX-контейнера
     * @param password пароль PFX
     * @return this для fluent API
     * @throws IllegalArgumentException если MAC отсутствует, в контейнере нет CA или есть не-CA
     *     сертификат
     */
    public GostSslBuilder trustCaBundle(byte[] pfxData, char[] password) {
        GostPkcs12Loader.Result container = GostPkcs12Loader.load(pfxData, password, true);
        List<GostCertificate> all = container.getAllCertificates();
        if (!all.stream().allMatch(GostCertificate::isCA)) {
            throw new IllegalArgumentException(
                    "PFX is not a CA bundle: it contains a non-CA certificate;"
                            + " use trustCaChain() for a mixed container");
        }
        return trustCaCertificates(all, "PFX");
    }

    private GostSslBuilder trustCaCertificates(List<GostCertificate> source, String origin) {
        List<GostCertificate> caCerts =
                source.stream().filter(GostCertificate::isCA).collect(Collectors.toList());
        if (caCerts.isEmpty()) {
            throw new IllegalArgumentException("No CA certificate found in " + origin);
        }
        trustedCas.addAll(caCerts);
        return this;
    }

    /**
     * Включает обязательный OCSP stapling серверного сертификата.
     * <p>
     * Вместе с {@link #ocspFetcher(OcspFetcher)} staple остаётся обязательным условием, но при его
     * отсутствии статус запрашивается по сети; недоступность ответчика приводит к отказу.
     * Несовместимо с {@link #trustAll()}: без доверенных якорей проверять OCSP нечем.
     * <p>
     * <b>Только клиентская роль.</b> На серверном контексте эта политика не используется: сервер
     * не проверяет собственный сертификат. Свой staple сервер задаёт не здесь, а
     * {@code GostSSLEngine.setOcspResponse(...)} до {@code beginHandshake()}; сокеты этот способ
     * не поддерживают. Проверка staple клиентского сертификата задаётся
     * {@link #clientOcspPolicy(ClientOcspPolicy)}.
     */
    public GostSslBuilder ocsp(boolean enabled) {
        this.ocspEnabled = enabled;
        return this;
    }

    /**
     * Устанавливает fetcher для client-side OCSP-запросов (при отсутствии stapling).
     * <p>
     * Требует {@link #ocsp(boolean) ocsp(true)}: без него fetcher не используется, и сборка
     * контекста завершится {@link IllegalStateException}, а не молча проигнорирует настройку.
     * Для клиентских сертификатов (mTLS) fetch дополнительно требует
     * {@link #clientOcspPolicy(ClientOcspPolicy)}, отличную от {@link ClientOcspPolicy#OFF}:
     * по умолчанию сервер не делает исходящих запросов по AIA из клиентских сертификатов.
     * <p>
     * Внимание: при включённом запросе для клиентских сертификатов сервер обращается по AIA из
     * сертификата, присланного клиентом (выпущенного доверенным УЦ). Число URI в сертификате не
     * ограничено, а защита от SSRF ({@code SsrfGuard}) не закрывает DNS-rebinding: штатный
     * {@code HttpClient} не фиксирует адрес. Риск - отказ в обслуживании и сканирование
     * внутренней сети по времени ответа; ответ при этом должен быть подписан издателем или
     * уполномоченным им responder.
     *
     * @param fetcher реализация {@link OcspFetcher} (может быть null — отключает fetch)
     */
    public GostSslBuilder ocspFetcher(OcspFetcher fetcher) {
        this.ocspFetcher = fetcher;
        return this;
    }

    /**
     * Устанавливает максимальный возраст OCSP-ответа без {@code nextUpdate}
     * (RFC 6960 §2.4 — локальная политика свежести relying party).
     *
     * @param maxOcspAgeMs возраст в миллисекундах
     */
    public GostSslBuilder maxOcspAgeMs(long maxOcspAgeMs) {
        this.maxOcspAgeMs = maxOcspAgeMs;
        return this;
    }

    /**
     * Устанавливает необязательный предел возраста {@code thisUpdate} OCSP-ответа для всех
     * ответов, в том числе с {@code nextUpdate} (Р 1323565.1.059-2024, п. 5.3). Без него ответ со
     * старым {@code thisUpdate} и далёким {@code nextUpdate} принимается. {@link
     * #maxOcspAgeMs(long)} остаётся в миллисекундах и действует на ответы без {@code nextUpdate};
     * без {@code nextUpdate} действует меньший из двух пределов.
     *
     * <p>Предел должен быть больше интервала обновления ответов у службы, иначе служба с заранее
     * выпущенными ответами получит отказы. Устаревший приложенный ответ даёт отказ сразу, запасного
     * запроса к службе нет. Несовместим с {@link #trustAll()}: проверки отзыва там нет.</p>
     *
     * @param maxThisUpdateAge предел или {@code null} - не задан (так же сбрасывается)
     * @throws IllegalArgumentException если значение нулевое или отрицательное
     */
    public GostSslBuilder maxThisUpdateAge(Duration maxThisUpdateAge) {
        this.maxThisUpdateAge = OcspVerifier.requireValidMaxThisUpdateAge(maxThisUpdateAge);
        return this;
    }

    /**
     * Устанавливает политику проверки CRL. По умолчанию {@link CrlPolicy#DISABLED}.
     * <p>
     * CRL проверяется только для сертификатов без OCSP-ответа: при наличии OCSP-ответа
     * (присланного или полученного по сети) проверка CRL пропускается. Валидность OCSP
     * проверяется отдельно; при её ошибке соединение отклоняется, повторной проверки по CRL нет.
     * Это относится и к {@link CrlPolicy#REQUIRE}. Политика действует и для клиентских
     * сертификатов при mTLS.
     *
     * @param policy политика CRL
     */
    public GostSslBuilder crlPolicy(CrlPolicy policy) {
        this.crlPolicy = policy != null ? policy : CrlPolicy.DISABLED;
        return this;
    }

    /**
     * Устанавливает fetcher для скачивания CRL по CDP URI. Требует политику CRL, отличную от
     * {@link CrlPolicy#DISABLED} ({@link #crlPolicy(CrlPolicy)}): по умолчанию проверка CRL
     * отключена, и загрузчик без политики даёт ошибку конфигурации при сборке, а не молча не
     * используется.
     *
     * @param fetcher реализация {@link CrlFetcher} (может быть null)
     */
    public GostSslBuilder crlFetcher(CrlFetcher fetcher) {
        this.crlFetcher = fetcher;
        return this;
    }

    /**
     * Устанавливает максимальный размер CRL в байтах (защита от DoS).
     * <p>
     * Предел загрузчика {@link org.rssys.gost.jsse.crl.CrlFetcher#maxResponseSize()} должен быть
     * &ge; переданного значения: при включённой проверке CRL это проверяется при построении
     * контекста (загрузчики библиотеки сообщают свой предел, собственная реализация без
     * переопределения метода не проверяется). Слишком большой ответ даёт отказ проверки, а не
     * пропуск адреса. Значение должно быть больше нуля, иначе сборка контекста бросит
     * {@link IllegalStateException}.
     *
     * @param maxCrlSize размер в байтах
     */
    public GostSslBuilder maxCrlSize(int maxCrlSize) {
        this.maxCrlSize = maxCrlSize;
        return this;
    }

    /**
     * Устанавливает максимальное число отозванных записей в CRL (защита от DoS).
     *
     * <p>Значение должно быть больше нуля, иначе сборка контекста бросит
     * {@link IllegalStateException}.</p>
     *
     * @param maxRevokedEntries число записей
     */
    public GostSslBuilder maxRevokedEntries(int maxRevokedEntries) {
        this.maxRevokedEntries = maxRevokedEntries;
        return this;
    }

    /**
     * Устанавливает бюджет кэша проверенных CRL в байтах оценки удержания.
     *
     * <p>Разобранный CRL удерживает около шести байт кучи на байт DER (CRL ФНС: около 233 МиБ
     * при 40 МБ DER). По умолчанию {@link CrlCache#DEFAULT_MAX_BYTES} (512 МиБ). Это верхняя
     * граница, а не занятая память. Бюджет общий для разобранных и сырых записей. Если
     * разобранный CRL не помещается, но помещается его DER, хранится сырой DER: сеть
     * используется один раз, а подпись и разбор повторяются на каждом соединении. Если не
     * помещается и DER, CRL загружается заново на каждом соединении. Поэтому значение должно быть
     * не меньше оценки самого большого ожидаемого CRL. Значение 0 запрещает хранить любые CRL
     * между соединениями (для устройств с малой памятью). Кэш создаётся на каждый
     * {@code SSLContext}.
     *
     * @param crlCacheMaxBytes бюджет в байтах, не отрицательный
     */
    public GostSslBuilder crlCacheMaxBytes(long crlCacheMaxBytes) {
        this.crlCacheMaxBytes = crlCacheMaxBytes;
        return this;
    }

    /**
     * Устанавливает предельный возраст записи кэша проверенных CRL.
     *
     * <p>Запись, загруженная давнее этого срока, но ещё не истёкшая ({@code nextUpdate}),
     * перепроверяется: одно из соединений загружает CRL заново, остальные не ждут и берут
     * действующую запись. Если перепроверка не удалась, запись остаётся до {@code nextUpdate},
     * следующая попытка не раньше чем через 5 минут. По умолчанию {@link CrlCache#DEFAULT_MAX_AGE}
     * (6 часов). Это интервал перепроверки, а не срок, в течение которого отозванный сертификат
     * может приниматься: задержка равна предельному возрасту плюс интервал, с которым УЦ выпускает
     * новый CRL (при ежесуточной публикации и 6 часах худший случай около 30 часов). Для повышенных
     * требований безопасности разумны 1-6 часов, но большой CRL (около 40 МБ у ФНС) тогда
     * загружается чаще, а пока идёт перепроверка, в куче лежат старая и новая записи: бюджет
     * {@link #crlCacheMaxBytes(long)} должен вмещать две самые большие разобранные записи. Одно
     * соединение раз в предельный возраст на каждый CRL может занять до потолка проверки (около
     * 60 с) плюс срок загрузчика CRL. Перепроверка защищает от устаревшего кэша, а не от
     * подмены ответа на канале связи.
     *
     * @param crlMaxAge {@link Duration#ZERO} - перепроверка выключена, иначе от 1 минуты до 30 суток
     * @throws IllegalArgumentException если значение {@code null} или вне границ
     */
    public GostSslBuilder crlMaxAge(Duration crlMaxAge) {
        this.crlMaxAge = CrlCache.requireValidMaxAge(crlMaxAge);
        return this;
    }

    /**
     * Устанавливает размер кэша сессий. 0 = без ограничения.
     */
    public GostSslBuilder sessionCacheSize(int size) {
        this.sessionCacheSize = size;
        return this;
    }

    /**
     * Включает режим trust-all (только для разработки): сертификат сервера не проверяется.
     */
    public GostSslBuilder trustAll() {
        this.trustAll = true;
        return this;
    }

    /**
     * Включает обход openssl-gost-provider v3.6.0: сервер всегда шлёт
     * базовые signature scheme (0x0709 для 256-bit, 0x070D для 512-bit)
     * независимо от реальной кривой сертификата.
     * <p>
     * По умолчанию выключено. Включение — осознанное решение разработчика
     * для совместимости с openssl-gost-provider.
     *
     * @return this
     */
    public GostSslBuilder interopAcceptGostBaseSigScheme(boolean enabled) {
        this.interopAcceptGostBaseSigScheme = enabled;
        return this;
    }

    /**
     * Включает обязательную аутентификацию клиента (mTLS).
     * Аналог {@code SSLServerSocket.setNeedClientAuth(true)}.
     * <p>
     * Флаг устанавливается на {@code GostSSLSessionContext} и применяется
     * ко всем серверным engine, созданным через этот контекст.
     * <p>
     * Отзыв клиентского сертификата по умолчанию не проверяется: см.
     * {@link #clientOcspPolicy(ClientOcspPolicy)} и {@link #crlPolicy(CrlPolicy)}.
     *
     * @param need true — клиентский сертификат обязателен
     * @return this
     */
    public GostSslBuilder needClientAuth(boolean need) {
        this.needClientAuth = need;
        return this;
    }

    /**
     * Включает необязательную аутентификацию клиента: сертификат запрашивается, но клиент
     * вправе не предъявлять его; предъявленный сертификат проверяется в полном объёме.
     * Аналог {@code SSLServerSocket.setWantClientAuth(true)}.
     * <p>
     * Если одновременно включён {@link #needClientAuth(boolean)}, действует обязательный режим.
     * Соединение с клиентом без сертификата завершается успешно, поэтому приложение обязано
     * проверять {@code SSLSession.getPeerCertificates()}: без сертификата пира метод бросает
     * {@code SSLPeerUnverifiedException}.
     *
     * @param want true — клиентский сертификат запрашивается, но не обязателен
     * @return this
     */
    public GostSslBuilder wantClientAuth(boolean want) {
        this.wantClientAuth = want;
        return this;
    }

    /**
     * Серверная сторона: учитывается только в {@link #buildServerContext()}, для клиентского
     * контекста игнорируется.
     * <p>
     * Задаёт политику серверных engine в отношении OCSP-staple клиентского сертификата
     * (RFC 8446 §4.4.2.1): {@link ClientOcspPolicy#REQUEST} запрашивает и проверяет присланный
     * staple, {@link ClientOcspPolicy#REQUIRE} делает его обязательным для предъявленного
     * сертификата. Значение по умолчанию - {@link ClientOcspPolicy#OFF}.
     * <p>
     * Что происходит с отзывом клиентского сертификата:
     * <ul>
     *   <li>{@code OFF}: staple не запрашивается, присланный клиентом staple отклоняется на
     *       уровне протокола ({@code unsupported_extension}). OCSP клиента не проверяется и не
     *       обязателен, сетевых запросов OCSP нет.</li>
     *   <li>{@code REQUEST}, {@code REQUIRE}: присланный staple проверяется всегда
     *       (невалидный - {@code bad_certificate}); {@code REQUIRE} дополнительно требует его
     *       наличия.</li>
     *   <li>Запрос статуса по сети выполняется только при {@code ocsp(true)},
     *       {@link #ocspFetcher(OcspFetcher)} и политике, отличной от {@code OFF}.</li>
     *   <li>CRL проверяется по {@link #crlPolicy(CrlPolicy)} независимо от этой политики, для
     *       сертификатов без OCSP-ответа.</li>
     * </ul>
     * При {@code OFF} и {@code CrlPolicy.DISABLED} (значения по умолчанию) отзыв клиентского
     * сертификата не проверяется: отозванный сертификат с валидной цепочкой будет принят.
     * <p>
     * Действует при аутентификации клиента ({@link #needClientAuth(boolean)} или
     * {@code wantClientAuth} на engine); без неё engine отказывается начинать handshake.
     * Несовместимо с {@link #trustAll()}: без доверенных якорей проверять staple нечем,
     * {@link #buildServerContext()} бросает {@link IllegalStateException}.
     *
     * @param policy политика (не null)
     * @return this
     * @throws IllegalArgumentException если policy равен null
     */
    public GostSslBuilder clientOcspPolicy(ClientOcspPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("clientOcspPolicy must not be null");
        }
        this.clientOcspPolicy = policy;
        return this;
    }

    /**
     * Отключает проверку hostname в сертификате сервера (RFC 6125).
     * <p>
     * <b>Внимание: клиент перестаёт проверять, что сертификат выдан именно тому серверу, к
     * которому он подключается.</b> Используйте только для разработки и изолированных сетей.
     * <p>
     * Компонуется с {@link #trustAll()} и {@link #trustCa(byte[])}:
     * отдельный флаг, не меняющий семантику trustAll.
     * Без явного вызова hostname verification остаётся включена (safe-default).
     * <p>
     * <b>Применимо только к {@link #buildClientContext()}.</b>
     * Вызов перед {@link #buildServerContext()} приведёт к
     * {@link IllegalStateException} — на серверной стороне hostname
     * verification не имеет смысла (RFC 6125 регулирует клиентскую
     * проверку, а не серверную).
     *
     * @return this
     * @throws IllegalStateException если вызван перед buildServerContext()
     */
    public GostSslBuilder withoutHostnameVerification() {
        this.disableHostnameVerification = true;
        return this;
    }

    /**
     * Отклоняет настройки отзыва (OCSP, CRL), которые молча не сработали бы.
     * <p>
     * Fetcher OCSP используется только при обязательном staple ({@code ocsp(true)}), а режим
     * {@code trustAll()} вообще не выполняет проверок отзыва: любая политика CRL, любой fetcher и предел
     * возраста OCSP-ответа в нём бессмысленны, и оператор считал бы отзыв проверяемым.
     */
    private void validateRevocationConfiguration() {
        // Те же проверки есть в конструкторе менеджера доверия, но buildContext оборачивает любое
        // исключение в GostSslException; здесь ошибка конфигурации видна сразу
        try {
            CrlCache.requireValidMaxBytes(crlCacheMaxBytes);
            new CrlLimits(maxCrlSize, maxRevokedEntries);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
        if (ocspFetcher != null && !ocspEnabled) {
            throw new IllegalStateException("ocspFetcher() requires ocsp(true)");
        }
        // Симметрично ocspFetcher: загрузчик при отключённой проверке CRL не используется, и
        // оператор, задавший только его, считал бы отзыв по CRL проверяемым
        if (!trustAll && crlFetcher != null && crlPolicy == CrlPolicy.DISABLED) {
            throw new IllegalStateException(
                    "crlFetcher() requires crlPolicy() other than DISABLED");
        }
        if (trustAll && (ocspEnabled || ocspFetcher != null)) {
            throw new IllegalStateException(
                    "ocsp(true) and ocspFetcher() are incompatible with trustAll()");
        }
        if (trustAll && (crlPolicy != CrlPolicy.DISABLED || crlFetcher != null)) {
            throw new IllegalStateException(
                    "crlPolicy() and crlFetcher() are incompatible with trustAll()");
        }
        if (trustAll && maxThisUpdateAge != null) {
            throw new IllegalStateException("maxThisUpdateAge() is incompatible with trustAll()");
        }
        if (!trustAll && crlPolicy != CrlPolicy.DISABLED) {
            String fetcherProblem = CrlFetcher.limitProblem(crlFetcher, maxCrlSize);
            if (fetcherProblem != null) {
                throw new IllegalStateException(fetcherProblem);
            }
        }
    }

    /**
     * Строит серверный SSLContext.
     * <p>
     * Доверенные якоря нужны только при клиентской аутентификации: {@code needClientAuth},
     * {@code wantClientAuth} или {@code clientOcspPolicy}, отличная от {@code OFF}. Сервер без
     * mTLS собирается без trust store и клиентских сертификатов не запрашивает. Если
     * аутентификацию включат позже (на контексте сессий или сокете), рукопожатие будет отвергнуто,
     * а не принято без проверки.
     */
    public SSLContext buildServerContext() {
        validateRevocationConfiguration();
        if (disableHostnameVerification) {
            throw new IllegalStateException(
                    "withoutHostnameVerification() has no effect on server side. "
                            + "Call it only before buildClientContext().");
        }
        // Без доверенных якорей (trustAll) проверять присланный staple нечем: политика
        // молча не работала бы, а оператор считал бы отзыв клиентов проверяемым.
        if (trustAll && clientOcspPolicy != ClientOcspPolicy.OFF) {
            throw new IllegalStateException(
                    "clientOcspPolicy(" + clientOcspPolicy + ") is incompatible with trustAll()");
        }
        // Без якорей проверить клиентский сертификат нечем. Ошибка на сборке, а не на
        // рукопожатии: иначе настройка молча не работала бы, а оператор считал бы mTLS или
        // проверку отзыва включёнными.
        boolean noAnchors = trustedCas.isEmpty() && !trustAll;
        if (noAnchors) {
            if (needClientAuth || wantClientAuth) {
                throw new IllegalStateException(
                        "Client authentication requires trust anchors:"
                                + " call trustCa(), trustCaChain() or trustCaBundle()");
            }
            if (clientOcspPolicy != ClientOcspPolicy.OFF) {
                throw new IllegalStateException(
                        "clientOcspPolicy() requires client authentication"
                                + " (needClientAuth/wantClientAuth) and trust anchors");
            }
            if (crlPolicy != CrlPolicy.DISABLED) {
                throw new IllegalStateException(
                        "crlPolicy() verifies client certificates and requires client"
                                + " authentication with trust anchors");
            }
        }
        SSLContext ctx = buildContext(true);
        GostSSLSessionContext serverSessions =
                (GostSSLSessionContext) ctx.getServerSessionContext();
        if (interopAcceptGostBaseSigScheme) {
            serverSessions.setInteropAcceptGostBaseSigScheme(true);
        }
        if (needClientAuth) {
            serverSessions.setNeedClientAuth(true);
        }
        if (wantClientAuth) {
            serverSessions.setWantClientAuth(true);
        }
        serverSessions.setClientOcspPolicy(clientOcspPolicy);
        return ctx;
    }

    /**
     * Строит клиентский SSLContext.
     */
    public SSLContext buildClientContext() {
        validateRevocationConfiguration();
        SSLContext ctx = buildContext(false);
        GostSSLSessionContext clientSessions =
                (GostSSLSessionContext) ctx.getClientSessionContext();
        if (interopAcceptGostBaseSigScheme) {
            clientSessions.setInteropAcceptGostBaseSigScheme(true);
        }
        if (disableHostnameVerification) {
            clientSessions.setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        }
        return ctx;
    }

    /**
     * Собирает {@link SSLContext} из накопленных настроек: менеджер ключей, менеджер доверия,
     * размер кэша сессий. Настройки сторон (mTLS, проверка имени) применяют вызывающие методы.
     *
     * @param server серверный контекст: без якорей менеджер доверия не устанавливается
     */
    private SSLContext buildContext(boolean server) {
        try {
            if (Security.getProvider(GostJsseConstants.PROVIDER_NAME) == null) {
                Security.addProvider(new RssysGostJsseProvider());
            }
            GostX509KeyManager keyManager = createKeyManager();
            GostX509TrustManager trustManager =
                    server ? createServerTrustManager() : createClientTrustManager();

            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            // Массив с null-элементом SPI отвергает; отсутствие менеджера передаётся как null,
            // и движок трактует его как «не доверять никому».
            ctx.init(
                    keyManager != null ? new KeyManager[] {keyManager} : null,
                    trustManager != null ? new TrustManager[] {trustManager} : null,
                    null);

            if (sessionCacheSize >= 0) {
                ctx.getClientSessionContext().setSessionCacheSize(sessionCacheSize);
                ctx.getServerSessionContext().setSessionCacheSize(sessionCacheSize);
            }
            return ctx;
        } catch (GostSslException e) {
            throw e;
        } catch (Exception e) {
            throw new GostSslException("Failed to create SSLContext: " + e.getMessage(), e);
        }
    }

    /** Менеджер ключей из пары сертификат и ключ либо из PKCS12; {@code null}, если ключей нет. */
    private GostX509KeyManager createKeyManager() throws Exception {
        if (certDer != null && keyDer != null) {
            GostX509KeyManager keyManager = new GostX509KeyManager();
            keyManager.addKeyEntry(
                    DEFAULT_KEY_ALIAS,
                    CertificateBridge.toJca(List.of(new GostCertificate(certDer))),
                    GostDerCodec.decodePrivateKey(keyDer));
            return keyManager;
        }
        if (p12Data != null) {
            GostPkcs12Loader.Result result = GostPkcs12Loader.load(p12Data, p12Password, true);
            GostX509KeyManager keyManager = new GostX509KeyManager();
            X509Certificate[] chain = CertificateBridge.toJca(result.getCertificateChain());
            keyManager.addKeyEntry(DEFAULT_KEY_ALIAS, chain, result.getPrivateKey());
            return keyManager;
        }
        return null;
    }

    /**
     * Менеджер доверия клиента: без якорей проверить сертификат сервера нечем, поэтому ошибка.
     */
    private GostX509TrustManager createClientTrustManager() {
        if (trustAll) {
            return GostX509TrustManager.insecureTrustAll();
        }
        if (trustedCas.isEmpty()) {
            throw new GostSslException("No CA certificate provided for trust verification");
        }
        return createTrustManagerFromAnchors();
    }

    /**
     * Менеджер доверия серверного контекста. Без якорей возвращает {@code null}: сервер без
     * клиентской аутентификации никого не проверяет, а движок при {@code null} отвергает любой
     * сертификат пира — позднее включение mTLS даёт отказ, а не приём без проверки.
     */
    private GostX509TrustManager createServerTrustManager() {
        if (trustAll) {
            return GostX509TrustManager.insecureTrustAll();
        }
        if (trustedCas.isEmpty()) {
            return null;
        }
        return createTrustManagerFromAnchors();
    }

    private GostX509TrustManager createTrustManagerFromAnchors() {
        // Якоря-сертификаты: расширения pathLen/NameConstraints корня должны проверяться,
        // даже если пир не прислал корень.
        return GostX509TrustManager.fromTrustAnchors(
                TrustAnchors.ofCertificates(trustedCas),
                selectOcspPolicy(ocspEnabled, ocspFetcher),
                ocspFetcher,
                crlPolicy,
                crlFetcher,
                maxCrlSize,
                maxRevokedEntries,
                crlCacheMaxBytes,
                crlMaxAge,
                maxOcspAgeMs,
                maxThisUpdateAge);
    }

    /**
     * Выбирает политику OCSP серверного сертификата по настройкам.
     * <p>
     * Fetcher имеет смысл только при обязательном staple: {@code STAPLING_OR_FETCH} - это staple,
     * а при его отсутствии проверенный сетевой ответ (fail-closed при недоступном ответчике).
     * Без {@code ocsp(true)} fetcher не используется, поэтому такую комбинацию отклоняет
     * {@link #validateRevocationConfiguration()}.
     *
     * @param ocspEnabled включён ли обязательный OCSP
     * @param ocspFetcher fetcher для запроса статуса по сети (может быть null)
     * @return политика OCSP
     */
    static OcspPolicy selectOcspPolicy(boolean ocspEnabled, OcspFetcher ocspFetcher) {
        if (!ocspEnabled) {
            return OcspPolicy.IF_PRESENT;
        }
        return ocspFetcher != null ? OcspPolicy.STAPLING_OR_FETCH : OcspPolicy.STAPLING_REQUIRED;
    }
}
