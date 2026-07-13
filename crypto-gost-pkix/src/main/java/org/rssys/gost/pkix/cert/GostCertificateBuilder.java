package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель X.509-сертификатов ГОСТ Р 34.10-2012.
 *
 * <p>Fluent API:
 * <pre>
 * GostCertificate cert = GostCertificateBuilder.create(params, subjectDn)
 *     .publicKey(pub)
 *     .issuerDn(issuerDnDer)
 *     .notBeforeNow()
 *     .validForDays(365)
 *     .sanDns("example.com")
 *     .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
 *     .ocspResponder("http://ocsp.example.com")
 *     .caIssuer("http://ca.example.com/cert.p7c")
 *     .crlDistributionPoints("http://crl.example.com/crl.crl")
 *     .sign(issuerPriv);
 * </pre>
 *
 * <p>Альтернативно — явные даты для воспроизводимости:
 * <pre>
 *     .notBefore("20250101000000Z")
 *     .notAfter("21010101000000Z")
 * </pre>
 *
 * <p>Двухшаговый вариант (TBS отдельно):
 * <pre>
 * byte[] tbs = GostCertificateBuilder.create(params, subjectDn)
 *     .publicKey(pub)
 *     .issuerDn(issuerDnDer)
 *     .notBefore(notBefore).notAfter(notAfter)
 *     .buildTbs();
 * GostCertificate cert = GostCertificateBuilder.sign(tbs, signer);
 * </pre>
 *
 * <p>Статические строители расширений ({@link #buildSanExtension}, {@link #buildKeyUsageExtension}
 * и др.) сохранены для совместимости с кодом, собирающим расширения отдельно.</p>
 *
 * <p>Для самоподписанных сертификатов {@code .issuerDn()} можно опустить —
 * построитель автоматически подставит {@code subjectDn} в качестве issuer.</p>
 *
 * <p><b>Серийный номер:</b> обязателен — задаётся явным вызовом {@link #serial(BigInteger)}
 * или {@link #randomSerial()}. Дефолта нет: {@link #buildTbs()} отвергает сборку без serial
 * ({@link IllegalStateException}), закрывая insecure-by-default. Требование уникальности пары
 * (issuer, serial) — RFC 5280 §4.1.2.2; требование ≥64 бит энтропии для случайных значений —
 * CA/Browser Forum BR §7.1.</p>
 *
 * <p>Подписант передаётся в {@link #sign(GostSigner)} — единообразно с
 * {@link GostCrlBuilder} и {@link GostCsrBuilder}. В отличие от остальных билдеров,
 * у сертификата есть публичный двухшаговый путь {@link #buildTbs()} + {@link #sign(byte[], GostSigner)}
 * для сценариев офлайн-церемонии (shipping TBS на подпись корневого/промежуточного УЦ).</p>
 */
public final class GostCertificateBuilder {

    private final ECParameters params;
    private final byte[] subjectDn;
    private byte[] issuerDn;
    private PublicKeyParameters pub;
    private String notBefore;
    private String notAfter;
    private final ExtensionsAccumulator ext = new ExtensionsAccumulator();

    private String[] ianDnsNames;
    private String[] ianIps;
    private String[] ianRfc822Names;
    private String[] ianUris;
    private byte[][] ianDirectoryNames;
    private OtherNameEntry[] ianOtherNames;

    /** Обязателен: задаётся через {@link #serial} или {@link #randomSerial}; без него {@link #buildTbs} бросает исключение. */
    private BigInteger serial = null;

    private String ocspUri;
    private String caIssuersUri;
    private String[] crlUris;
    private String[] freshestCrlUris;
    private byte[] akiBytes;
    private String[] ncPermittedDns;
    private String[] ncPermittedIps;
    private String[] ncExcludedDns;
    private String[] ncExcludedIps;
    private boolean ocspNoCheck;

    private GostCertificateBuilder(ECParameters params, byte[] subjectDn) {
        this.params = params;
        this.subjectDn = subjectDn;
    }

    /**
     * Создаёт построитель сертификата.
     *
     * @param params    параметры кривой
     * @param subjectDn DER-кодированный subject DN (результат {@link GostDnParser#encodeDn})
     */
    public static GostCertificateBuilder create(ECParameters params, byte[] subjectDn) {
        return new GostCertificateBuilder(params, subjectDn);
    }

    /** Удобная перегрузка: DN из строки "CN=..., O=..." */
    public static GostCertificateBuilder create(ECParameters params, String subjectDn) {
        return new GostCertificateBuilder(params, GostDnParser.encodeDn(subjectDn));
    }

    /**
     * Создаёт {@link GostCertificateBuilder} из распарсенного CSR,
     * копируя subject DN (байтово-точно через {@link GostCsrParser#getSubjectDnDer()})
     * и открытый ключ заявителя.
     *
     * <p>Внутри вызывает {@link GostCsrParser#verifySelf()} — proof-of-possession
     * обязателен. При провале выбрасывается {@link PkixException}
     * с {@link PkixException.Reason#SIGNATURE_INVALID} — единственное
     * checked-исключение в этом классе, поскольку метод выполняет
     * криптографическую верификацию, а не строительный шаг билдера.</p>
     *
     * <p>Расширения из CSR <b>не копируются</b>. Оператор УЦ обязан явно
     * проверить и перенести нужные расширения через {@link GostCsrParser#getExtensions()}
     * и fluent-сеттеры билдера. См. документацию {@link GostCsrParser#getExtensions()}
     * о границе доверия extensionRequest.</p>
     *
     * @param csr    распарсенный CSR (не null);
     *               proof-of-possession проверяется внутри метода
     * @param params параметры эллиптической кривой, которой УЦ будет
     *               подписывать сертификат; не обязана совпадать с кривой
     *               ключа заявителя из CSR (не null)
     * @return предзаполненный билдер (subject DN, public key)
     * @throws PkixException если proof-of-possession не пройден
     */
    public static GostCertificateBuilder fromCsrIdentity(GostCsrParser csr, ECParameters params)
            throws PkixException {
        Objects.requireNonNull(csr, "csr must not be null");
        Objects.requireNonNull(params, "params must not be null");
        if (!csr.verifySelf()) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID,
                    "CSR proof-of-possession verification failed: "
                            + "signature does not match subject public key");
        }
        return create(params, csr.getSubjectDnDer()).publicKey(csr.getPublicKey());
    }

    /**
     * Создаёт {@link GostCertificateBuilder} из существующего сертификата,
     * копируя subject DN (байтово-точно через {@link GostCertificate#getSubjectDnBytes()})
     * и открытый ключ субъекта.
     *
     * <p>Метод не выполняет криптографическую верификацию существующего сертификата.
     * Ответственность за то, что {@code cert} получен из доверенного источника,
     * лежит на вызывающем коде. В отличие от {@link #fromCsrIdentity}, где
     * proof-of-possession проверяется через {@link GostCsrParser#verifySelf()}.</p>
     *
     * <p>Расширения из сертификата <b>не копируются</b>. Оператор УЦ обязан явно
     * проверить и перенести нужные расширения через {@link GostCertificate#getExtensions()}
     * и fluent-сеттеры билдера. Автоматическое копирование расширений при перевыпуске
     * без повторной валидации (владение доменом, полномочия на EKU, статус CA)
     * небезопасно.</p>
     *
     * @param cert   существующий сертификат (не null)
     * @param params параметры эллиптической кривой для подписи нового сертификата (не null)
     * @return предзаполненный билдер (subject DN, public key)
     */
    public static GostCertificateBuilder fromCertificate(
            GostCertificate cert, ECParameters params) {
        Objects.requireNonNull(cert, "cert must not be null");
        Objects.requireNonNull(params, "params must not be null");
        return create(params, cert.getSubjectDnBytes()).publicKey(cert.getPublicKey());
    }

    /** Открытый ключ субъекта (обязательно для buildTbs). */
    public GostCertificateBuilder publicKey(PublicKeyParameters pub) {
        this.pub = pub;
        return this;
    }

    /**
     * DER-кодированный Distinguished Name издателя.
     *
     * <p>Для самоподписанных (self-signed) сертификатов вызов необязателен —
     * библиотека автоматически подставит {@code subjectDn} в качестве issuer.
     * Для CA-подписанных сертификатов — обязателен: передаётся DN издателя.</p>
     *
     * @param der DER-кодированный DN (результат {@link GostDnParser#encodeDn})
     */
    public GostCertificateBuilder issuerDn(byte[] der) {
        this.issuerDn = der;
        return this;
    }

    /** Удобная перегрузка: DN из строки "CN=..., O=..." */
    public GostCertificateBuilder issuerDn(String dn) {
        this.issuerDn = GostDnParser.encodeDn(dn);
        return this;
    }

    /**
     * @param time GeneralizedTime в формате YYYYMMDDHHMMSSZ (UTC)
     */
    public GostCertificateBuilder notBefore(String time) {
        this.notBefore = time;
        return this;
    }

    /** @param time notBefore как Instant (UTC) */
    public GostCertificateBuilder notBefore(Instant time) {
        this.notBefore = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    /**
     * Устанавливает notBefore = текущее UTC-время минус {@link GostOids#CLOCK_SKEW_MS} (5 мин).
     *
     * <p>Откат на 5 минут назад — стандартная практика УЦ: relying party с чуть
     * отстающими часами не отвергнет свежевыпущенный сертификат как «ещё не валидный».
     * {@link GostCertificate#isExpired()} уже имеет встроенную толерантность
     * {@code CLOCK_SKEW_MS}, но сертификат должен быть валиден сразу после выпуска
     * на любом проверяющем, а не только на тех, кто реализует clock skew.
     *
     * <p>Для тестов, где нужна побайтовая воспроизводимость, используйте
     * {@link #notBefore(String)} или {@link #notBefore(Instant)} с фиксированной датой.
     */
    public GostCertificateBuilder notBeforeNow() {
        this.notBefore =
                GostSignatureHelper.formatGeneralizedTime(
                        Instant.now().minusMillis(GostOids.CLOCK_SKEW_MS));
        return this;
    }

    /**
     * Устанавливает notAfter = notBefore + days.
     * Сутки как 24 часа UTC (не календарные, без поправки на DST).
     *
     * @param days количество дней
     * @return this
     * @throws IllegalStateException если {@code notBefore} не был задан
     */
    public GostCertificateBuilder validForDays(int days) {
        if (notBefore == null) {
            throw new IllegalStateException("notBefore must be set before validForDays()");
        }
        Instant nb = GostSignatureHelper.parseAsn1Time(notBefore);
        this.notAfter =
                GostSignatureHelper.formatGeneralizedTime(
                        nb.plusSeconds((long) days * 24L * 3600L));
        return this;
    }

    /**
     * Устанавливает notAfter = notBefore + months.
     * Календарные месяцы UTC: «то же число через N месяцев».
     * 31 января + 1 месяц → 28/29 февраля.
     *
     * @param months количество календарных месяцев
     * @return this
     * @throws IllegalStateException если {@code notBefore} не был задан
     */
    public GostCertificateBuilder validForMonths(int months) {
        if (notBefore == null) {
            throw new IllegalStateException("notBefore must be set before validForMonths()");
        }
        Instant nb = GostSignatureHelper.parseAsn1Time(notBefore);
        this.notAfter =
                GostSignatureHelper.formatGeneralizedTime(
                        nb.atZone(ZoneOffset.UTC).plusMonths(months).toInstant());
        return this;
    }

    /**
     * Устанавливает notAfter = notBefore + years.
     * Календарные годы UTC: «то же число через N лет».
     * 29 февраля 2024 + 1 год → 28 февраля 2025.
     *
     * @param years количество календарных лет
     * @return this
     * @throws IllegalStateException если {@code notBefore} не был задан
     */
    public GostCertificateBuilder validForYears(int years) {
        if (notBefore == null) {
            throw new IllegalStateException("notBefore must be set before validForYears()");
        }
        Instant nb = GostSignatureHelper.parseAsn1Time(notBefore);
        this.notAfter =
                GostSignatureHelper.formatGeneralizedTime(
                        nb.atZone(ZoneOffset.UTC).plusYears(years).toInstant());
        return this;
    }

    /**
     * @param time GeneralizedTime в формате YYYYMMDDHHMMSSZ (UTC)
     */
    public GostCertificateBuilder notAfter(String time) {
        this.notAfter = time;
        return this;
    }

    /** @param time notAfter как Instant (UTC) */
    public GostCertificateBuilder notAfter(Instant time) {
        this.notAfter = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    public GostCertificateBuilder sanDns(String... names) {
        ext.sanDns(names);
        return this;
    }

    public GostCertificateBuilder sanIp(String... ips) {
        ext.sanIp(ips);
        return this;
    }

    public GostCertificateBuilder sanRfc822Name(String... emails) {
        ext.sanRfc822Name(emails);
        return this;
    }

    public GostCertificateBuilder sanUri(String... uris) {
        ext.sanUri(uris);
        return this;
    }

    /** Добавляет directoryName в SAN.
     *  @param dnDer сырой DER DN (SEQUENCE OF RDN) */
    public GostCertificateBuilder sanDirectoryName(byte[]... dnDer) {
        ext.sanDirectoryName(dnDer);
        return this;
    }

    /** Добавляет otherName общего вида в SAN.
     *  @param oid      OID типа
     *  @param valueDer DER-кодированное значение (будет обёрнуто в [0] EXPLICIT) */
    public GostCertificateBuilder sanOtherName(String oid, byte[] valueDer) {
        ext.sanOtherName(oid, valueDer);
        return this;
    }

    /** Добавляет UPN (User Principal Name) в SAN. */
    public GostCertificateBuilder sanUpn(String upn) {
        ext.sanUpn(upn);
        return this;
    }

    /** Альтернативные DNS-имена издателя (IssuerAltName, RFC 5280 §4.2.1.7).
     *  Информационное расширение — не участвует в hostname-верификации (RFC 6125). */
    public GostCertificateBuilder ianDns(String... names) {
        this.ianDnsNames = names;
        return this;
    }

    /** Альтернативные IP-адреса издателя (IssuerAltName, RFC 5280 §4.2.1.7).
     *  Информационное расширение — не участвует в hostname-верификации (RFC 6125). */
    public GostCertificateBuilder ianIp(String... ips) {
        this.ianIps = ips;
        return this;
    }

    public GostCertificateBuilder ianRfc822Name(String... emails) {
        this.ianRfc822Names = emails;
        return this;
    }

    public GostCertificateBuilder ianUri(String... uris) {
        this.ianUris = uris;
        return this;
    }

    /** Добавляет directoryName в IssuerAltName.
     *  @param dnDer сырой DER DN (SEQUENCE OF RDN) */
    public GostCertificateBuilder ianDirectoryName(byte[]... dnDer) {
        this.ianDirectoryNames = dnDer;
        return this;
    }

    /** Добавляет otherName общего вида в IssuerAltName.
     *  @param oid      OID типа
     *  @param valueDer DER-кодированное значение (будет обёрнуто в [0] EXPLICIT) */
    public GostCertificateBuilder ianOtherName(String oid, byte[] valueDer) {
        this.ianOtherNames = new OtherNameEntry[] {new OtherNameEntry(oid, valueDer)};
        return this;
    }

    /** Добавляет UPN в IssuerAltName. */
    public GostCertificateBuilder ianUpn(String upn) {
        byte[] upnValue = DerCodec.encodeUTF8String(upn);
        return ianOtherName(GostOids.ID_MS_UPN, upnValue);
    }

    public GostCertificateBuilder keyUsage(KeyUsage... usages) {
        ext.keyUsage(usages);
        return this;
    }

    /**
     * Устанавливает EKU без флага критичности (critical=false по умолчанию).
     *
     * @param oids dotted-string OID EKU (например {@link org.rssys.gost.pkix.GostOids#EXT_TIME_STAMPING})
     */
    public GostCertificateBuilder extendedKeyUsage(String... oids) {
        ext.extendedKeyUsage(oids);
        return this;
    }

    /**
     * Устанавливает EKU с явным флагом критичности (RFC 5280 §4.2.1.12).
     * Например {@code true} для TSA-сертификатов.
     */
    public GostCertificateBuilder extendedKeyUsage(boolean critical, String... oids) {
        ext.extendedKeyUsage(critical, oids);
        return this;
    }

    /**
     * @param isCA    true — субъект является CA
     * @param pathLen максимальная глубина цепочки (RFC 5280 §4.2.1.9), null — без ограничения
     * @throws IllegalArgumentException если pathLen задан при isCA=false
     */
    public GostCertificateBuilder basicConstraints(boolean isCA, Integer pathLen) {
        ext.basicConstraints(isCA, pathLen);
        return this;
    }

    /**
     * Устанавливает URI OCSP-ответчика для AIA-расширения (id-ad-ocsp, RFC 5280 §4.2.2.1).
     * Можно комбинировать с {@link #caIssuer(String)} — оба URI попадут в одно AIA-расширение.
     */
    public GostCertificateBuilder ocspResponder(String uri) {
        this.ocspUri = uri;
        return this;
    }

    /**
     * Устанавливает URI caIssuers для AIA-расширения (id-ad-caIssuers, RFC 5280 §4.2.2.1).
     * Можно комбинировать с {@link #ocspResponder(String)} — оба URI попадут в одно AIA-расширение.
     */
    public GostCertificateBuilder caIssuer(String uri) {
        this.caIssuersUri = uri;
        return this;
    }

    /**
     * Помечает сертификат расширением id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) —
     * некритичным расширением с пустым значением (DER {@code NULL}).
     *
     * <p>Расширение говорит проверяющей стороне не проверять рекурсивно отзыв самого
     * сертификата OCSP-респондера (иначе возникла бы циклическая зависимость: чтобы
     * проверить OCSP-ответ, нужен ещё один OCSP-запрос про сертификат подписанта).</p>
     *
     * <p><b>Безопасность:</b> сертификат с этим расширением фактически невозможно
     * эффективно отозвать — клиенты по определению не проверяют его отзыв. Поэтому его
     * следует ставить <b>только на короткоживущие</b> (сутки-двое) сертификаты
     * делегированного OCSP-респондера. Срок жизни библиотека не навязывает — это
     * операционная политика CA.</p>
     *
     * <p>Расширение уместно только на сертификате с EKU {@code id-kp-OCSPSigning};
     * {@link #buildTbs()} это проверяет и бросает {@link IllegalStateException},
     * если EKU не задан fluent-методом {@link #extendedKeyUsage(String...)}. Проверка
     * смотрит только на fluent-поле EKU: если EKU задаётся сырым DER через
     * {@link #additionalExtensions(byte[])}, то и nocheck ставьте сырым DER.</p>
     *
     * <p>Не дублируется в {@code GostCsrBuilder} — расширение выражает решение
     * выпускающей CA, а не запрос субъекта.</p>
     */
    public GostCertificateBuilder ocspNoCheck() {
        this.ocspNoCheck = true;
        return this;
    }

    /**
     * Устанавливает OID политик сертификата (RFC 5280 §4.2.1.4), без квалификаторов.
     *
     * @param policyOids OID политик в точечной нотации (например, {@code "1.2.643.100.113.1"})
     */
    public GostCertificateBuilder certificatePolicies(String... policyOids) {
        ext.certificatePolicies(policyOids);
        return this;
    }

    /**
     * Устанавливает политики сертификата с опциональными CPS-квалификаторами
     * (RFC 5280 §4.2.1.4).
     *
     * @param policies политики; у каждой {@code cpsUri} может быть {@code null}
     *                 если квалификатор не требуется
     */
    public GostCertificateBuilder certificatePolicyInfos(CertificatePolicy... policies) {
        ext.certificatePolicyInfos(policies);
        return this;
    }

    public GostCertificateBuilder crlDistributionPoints(String... uris) {
        this.crlUris = uris;
        return this;
    }

    /**
     * Устанавливает FreshestCRL extension (RFC 5280 §5.2.6) — точки распространения delta CRL.
     * Структура DistributionPoint идентична CDP, отличается только OID (2.5.29.46).
     *
     * @param uris URI точек распространения delta CRL
     * @return this
     */
    public GostCertificateBuilder freshestCrl(String... uris) {
        this.freshestCrlUris = uris;
        return this;
    }

    /**
     * Вычисляет SKI (Subject Key Identifier, RFC 5280 §4.2.1.2)
     * как Streebog-256(raw public key point bytes) из открытого ключа,
     * ранее установленного через {@link #publicKey(PublicKeyParameters)}.
     *
     * @throws IllegalStateException если {@link #publicKey} ещё не вызван
     */
    public GostCertificateBuilder ski() {
        if (pub == null) {
            throw new IllegalStateException("publicKey must be set before ski()");
        }
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(pub);
        ext.ski(Digest.digest256(pointBytes));
        return this;
    }

    /**
     * AKI из готовых байтов SKI издателя (результат {@link ExtensionsAccumulator#buildSkiExtension}).
     */
    public GostCertificateBuilder aki(byte[] issuerSkiBytes) {
        this.akiBytes = issuerSkiBytes.clone();
        return this;
    }

    /**
     * Вычисляет AKI (Authority Key Identifier, RFC 5280 §4.2.1.1)
     * из публичного ключа издателя — = SKI издателя.
     */
    public GostCertificateBuilder aki(PublicKeyParameters issuerPub) {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(issuerPub);
        this.akiBytes = Digest.digest256(pointBytes);
        return this;
    }

    /**
     * Устанавливает NameConstraints (RFC 5280 §4.2.1.10).
     * Расширение всегда critical (RFC 5280 §4.2.1.10 MUST be critical).
     *
     * @param permittedDns разрешённые dNSName (может быть {@code null})
     * @param permittedIps разрешённые iPAddress в CIDR-нотации (может быть {@code null})
     * @param excludedDns  запрещённые dNSName (может быть {@code null})
     * @param excludedIps  запрещённые iPAddress в CIDR-нотации (может быть {@code null})
     */
    public GostCertificateBuilder nameConstraints(
            String[] permittedDns,
            String[] permittedIps,
            String[] excludedDns,
            String[] excludedIps) {
        this.ncPermittedDns = permittedDns;
        this.ncPermittedIps = permittedIps;
        this.ncExcludedDns = excludedDns;
        this.ncExcludedIps = excludedIps;
        return this;
    }

    /** Сырые DER-байты дополнительных расширений (конкатенация). */
    public GostCertificateBuilder additionalExtensions(byte[] der) {
        ext.additionalExtensions(der);
        return this;
    }

    public GostCertificateBuilder serial(BigInteger s) {
        if (s.signum() <= 0) {
            throw new IllegalArgumentException(
                    "Serial number must be positive (RFC 5280 §4.1.2.2), got: " + s);
        }
        int valueLen = (s.bitLength() + 7) / 8;
        if (valueLen > GostOids.MAX_SERIAL_OCTETS) {
            throw new IllegalArgumentException(
                    "Serial number exceeds "
                            + GostOids.MAX_SERIAL_OCTETS
                            + " octets (RFC 5280 §4.1.2.2), value length: "
                            + valueLen
                            + ", serial: "
                            + s);
        }
        this.serial = s;
        return this;
    }

    /**
     * Генерирует криптографически случайный серийный номер сертификата.
     *
     * <p>Каждый вызов возвращает новый положительный {@link BigInteger}
     * с не менее чем 127 битами эффективной энтропии (CA/Browser Forum BR §7.1
     * требует ≥64, реализация — 128 бит CSPRNG-вывода, старший бит форсирован).
     * Результат пригоден для прямой передачи в {@link #serial(BigInteger)}.
     *
     * <p>Не заменяет управление серийниками на уровне УЦ (БД, монотонный счётчик, HSM) —
     * это низкоуровневый генератор для сертификатов, выпускаемых программно.</p>
     *
     * @return положительный BigInteger со случайным значением (bitLength == 128)
     */
    public static BigInteger generateSerial() {
        return new BigInteger(128, CryptoRandom.INSTANCE).setBit(127);
    }

    /**
     * Fluent-метод: генерирует случайный серийный номер и устанавливает его.
     * Делегат в {@link #generateSerial()}.
     *
     * @return this
     */
    public GostCertificateBuilder randomSerial() {
        return serial(generateSerial());
    }

    /**
     * Собирает TBSCertificate (DER).
     *
     * @return DER-кодированный TBSCertificate
     */
    public byte[] buildTbs() {
        if (pub == null) {
            throw new IllegalStateException("publicKey must be set");
        }
        if (notBefore == null) {
            throw new IllegalStateException("notBefore must be set");
        }
        if (notAfter == null) {
            throw new IllegalStateException("notAfter must be set");
        }
        if (serial == null) {
            throw new IllegalStateException(
                    "serial must be set explicitly via serial(...) or randomSerial()");
        }
        Instant notBeforeInstant = GostSignatureHelper.parseAsn1Time(notBefore);
        Instant notAfterInstant = GostSignatureHelper.parseAsn1Time(notAfter);
        if (!notAfterInstant.isAfter(notBeforeInstant)) {
            throw new IllegalArgumentException(
                    "notAfter must be after notBefore: notBefore="
                            + notBefore
                            + ", notAfter="
                            + notAfter);
        }
        if (ocspNoCheck
                && (ext.ekuOids == null
                        || !Arrays.asList(ext.ekuOids).contains(GostOids.EXT_OCSP_SIGNING))) {
            throw new IllegalStateException(
                    "ocspNoCheck() requires extendedKeyUsage(EXT_OCSP_SIGNING)");
        }
        ByteArrayOutputStream allExts = new ByteArrayOutputStream();
        try {
            ext.writeExtensions(allExts);
            if (hasAnyIanNames()) {
                allExts.write(
                        ExtensionsAccumulator.buildIssuerAltNameExtension(
                                ianDnsNames,
                                ianIps,
                                ianRfc822Names,
                                ianUris,
                                ianDirectoryNames,
                                ianOtherNames));
            }
            if (ocspUri != null || caIssuersUri != null) {
                allExts.write(ExtensionsAccumulator.buildAiaExtension(ocspUri, caIssuersUri));
            }
            if (ocspNoCheck) {
                allExts.write(ExtensionsAccumulator.buildOcspNoCheckExtension());
            }
            if (crlUris != null) {
                allExts.write(ExtensionsAccumulator.buildCdpExtension(crlUris));
            }
            if (freshestCrlUris != null) {
                allExts.write(ExtensionsAccumulator.buildFreshestCrlExtension(freshestCrlUris));
            }
            if (akiBytes != null) {
                allExts.write(ExtensionsAccumulator.buildAkiExtension(akiBytes));
            }
            if ((ncPermittedDns != null && ncPermittedDns.length > 0)
                    || (ncPermittedIps != null && ncPermittedIps.length > 0)
                    || (ncExcludedDns != null && ncExcludedDns.length > 0)
                    || (ncExcludedIps != null && ncExcludedIps.length > 0)) {
                allExts.write(
                        ExtensionsAccumulator.buildNameConstraintsExtension(
                                ncPermittedDns, ncPermittedIps, ncExcludedDns, ncExcludedIps));
            }
            if (ext.additionalExtensions != null) {
                allExts.write(ext.additionalExtensions);
            }
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        return assembleTbs(
                pub,
                params,
                notBefore,
                notAfter,
                allExts.size() > 0 ? allExts.toByteArray() : null,
                issuerDn,
                subjectDn,
                serial);
    }

    /**
     * Собирает и подписывает сертификат за один шаг (без отдельной TBS-сборки).
     *
     * <p>Fail-closed: проверяет согласованность {@code params} из {@code create(...)}
     * и {@code signer.getParams()} — при несовпадении алгоритма подписи в TBS и фактического
     * алгоритма выбрасывает {@link IllegalStateException}.</p>
     */
    public GostCertificate sign(PrivateKeyParameters issuerPriv) {
        return sign(GostSigner.of(issuerPriv));
    }

    /**
     * Собирает и подписывает сертификат за один шаг подписантом (например, HSM).
     *
     * <p>Fail-closed: проверяет согласованность {@code params} из {@code create(...)}
     * и {@code signer.getParams()} — при несовпадении выбрасывает {@link IllegalStateException}.
     * Это закрывает риск, задокументированный в комментариях старого API:
     * AlgorithmIdentifier в TBS и фактический алгоритм подписи обязаны совпадать.</p>
     *
     * @param signer подписант издателя
     */
    public GostCertificate sign(GostSigner signer) {
        Objects.requireNonNull(signer, "signer must not be null");
        // AlgorithmIdentifier в TBS строится из params (create-time), подпись — из signer.
        // При рассинхроне кривых сертификат оказался бы некорректным; ловим до подписи.
        if (!Arrays.equals(
                GostSignatureHelper.buildAlgId(this.params),
                GostSignatureHelper.buildAlgId(signer.getParams()))) {
            throw new IllegalStateException(
                    "Certificate AlgorithmIdentifier mismatch: "
                            + "params from create() differ from signer.getParams()");
        }
        byte[] tbs = buildTbs();
        return sign(tbs, signer);
    }

    // ========================================================================
    // Статический sign (двухшаговый режим: buildTbs отдельно)
    // ========================================================================

    /**
     * Подписывает TBSCertificate и возвращает готовый сертификат.
     *
     * <p>Подписант сам несёт параметры кривой (hlen, algId), поэтому закрытый ключ
     * издателя не требуется. Для ключа в памяти — {@link GostSigner#of(PrivateKeyParameters)}.</p>
     *
     * <p>Двухшаговый путь (офлайн-церемония): TBS собирается через {@link #buildTbs()},
     * увозится на подпись и подписывается здесь — билдер на этой стадии уже недоступен,
     * поэтому метод статический. AlgorithmIdentifier уже зафиксирован внутри TBS.</p>
     *
     * @param tbs    DER-кодированный TBSCertificate (результат {@link #buildTbs()})
     * @param signer подписант (может быть HSM-адаптером)
     * @return готовый сертификат {@link GostCertificate}
     */
    public static GostCertificate sign(byte[] tbs, GostSigner signer) {
        Objects.requireNonNull(signer, "signer must not be null");
        byte[] hash = GostSignatureHelper.doHash(tbs, signer.getParams().hlen);
        byte[] sig = GostSignatureHelper.signHashChecked(hash, signer);
        byte[] algId = GostSignatureHelper.buildAlgId(signer.getParams());
        byte[] der = DerCodec.encodeSequence(tbs, algId, DerCodec.encodeBitString(sig));
        return new GostCertificate(der);
    }

    // ========================================================================
    // Приватная сборка TBS
    // ========================================================================

    private static byte[] assembleTbs(
            PublicKeyParameters pub,
            ECParameters params,
            String notBefore,
            String notAfter,
            byte[] allExtensions,
            byte[] issuerDn,
            byte[] subjectDn,
            BigInteger serial) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(DerCodec.encodeContextConstructed(0, DerCodec.encodeInteger(2)));
            out.write(DerCodec.encodeInteger(serial));
            out.write(GostSignatureHelper.buildAlgId(params));
            out.write(
                    issuerDn != null
                            ? issuerDn
                            : (subjectDn != null
                                    ? subjectDn
                                    : DerCodec.encodeSequence(new byte[0])));
            out.write(
                    DerCodec.encodeSequence(
                            DerCodec.encodeTime(notBefore), DerCodec.encodeTime(notAfter)));
            out.write(subjectDn != null ? subjectDn : DerCodec.encodeSequence(new byte[0]));
            byte[] spki = GostDerCodec.encodePublicKey(pub);
            out.write(spki, 0, spki.length);
            if (allExtensions != null && allExtensions.length > 0) {
                byte[] extensionsSeq = DerCodec.encodeSequence(allExtensions);
                out.write(DerCodec.encodeTlv(0xA3, extensionsSeq));
            }
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        return DerCodec.encodeSequence(out.toByteArray());
    }

    // ========================================================================
    // KeyUsage enum (обратная совместимость)
    // ========================================================================

    public enum KeyUsage {
        DIGITAL_SIGNATURE(0x80),
        NON_REPUDIATION(0x40),
        KEY_ENCIPHERMENT(0x20),
        DATA_ENCIPHERMENT(0x10),
        KEY_AGREEMENT(0x08),
        KEY_CERT_SIGN(0x04),
        CRL_SIGN(0x02),
        ENCIPHER_ONLY(0x01);

        final int mask;

        KeyUsage(int mask) {
            this.mask = mask;
        }

        /**
         * Проверяет, установлен ли этот флаг KeyUsage в битовой маске.
         *
         * @param bits сырая битовая маска KeyUsage (из {@code ExtensionsResult.keyUsageBits})
         * @return true если флаг установлен
         */
        public boolean isSetIn(int bits) {
            return (bits & mask) != 0;
        }
    }

    // ========================================================================
    // Статические строители расширений — делегаты в ExtensionsAccumulator
    // ========================================================================

    public static byte[] keyUsageFlags(KeyUsage... usages) {
        return ExtensionsAccumulator.keyUsageFlags(usages);
    }

    public static byte[] buildKeyUsageExtension(KeyUsage... usages) {
        return ExtensionsAccumulator.buildKeyUsageExtension(usages);
    }

    public static byte[] buildKeyUsageExtension(boolean critical, KeyUsage... usages) {
        return ExtensionsAccumulator.buildKeyUsageExtension(
                ExtensionsAccumulator.keyUsageFlags(usages), critical);
    }

    public static byte[] buildKeyUsageExtension(byte[] kuFlags, boolean critical) {
        return ExtensionsAccumulator.buildKeyUsageExtension(kuFlags, critical);
    }

    public static byte[] buildEkuExtension(String[] oids, boolean critical) {
        return ExtensionsAccumulator.buildEkuExtension(oids, critical);
    }

    public static byte[] buildCertificatePoliciesExtension(String[] policyOids) {
        return ExtensionsAccumulator.buildCertificatePoliciesExtension(
                CertificatePolicy.fromOids(policyOids));
    }

    public static byte[] buildCertificatePoliciesExtension(CertificatePolicy[] policies) {
        return ExtensionsAccumulator.buildCertificatePoliciesExtension(policies);
    }

    public static byte[] buildBasicConstraintsExtension(boolean isCA, Integer pathLen) {
        return ExtensionsAccumulator.buildBasicConstraintsExtension(isCA, pathLen);
    }

    public static byte[] buildAiaExtension(String ocspUri, String caIssuersUri) {
        return ExtensionsAccumulator.buildAiaExtension(ocspUri, caIssuersUri);
    }

    public static byte[] buildOcspNoCheckExtension() {
        return ExtensionsAccumulator.buildOcspNoCheckExtension();
    }

    public static byte[] buildSanExtension(
            String[] dnsNames,
            String[] ipAddresses,
            String[] rfc822Names,
            String[] uris,
            byte[][] directoryNames,
            OtherNameEntry[] otherNames) {
        return ExtensionsAccumulator.buildSanExtension(
                dnsNames, ipAddresses, rfc822Names, uris, directoryNames, otherNames);
    }

    public static byte[] buildIssuerAltNameExtension(
            String[] dnsNames,
            String[] ipAddresses,
            String[] rfc822Names,
            String[] uris,
            byte[][] directoryNames,
            OtherNameEntry[] otherNames) {
        return ExtensionsAccumulator.buildIssuerAltNameExtension(
                dnsNames, ipAddresses, rfc822Names, uris, directoryNames, otherNames);
    }

    public static byte[] buildCdpExtension(String... crlUris) {
        return ExtensionsAccumulator.buildCdpExtension(crlUris);
    }

    public static byte[] buildFreshestCrlExtension(String... uris) {
        return ExtensionsAccumulator.buildFreshestCrlExtension(uris);
    }

    public static byte[] buildSkiExtension(PublicKeyParameters pub) {
        return ExtensionsAccumulator.buildSkiExtension(pub);
    }

    public static byte[] buildAkiExtension(byte[] issuerSkiBytes) {
        return ExtensionsAccumulator.buildAkiExtension(issuerSkiBytes);
    }

    public static byte[] buildAkiExtension(PublicKeyParameters issuerPub) {
        return ExtensionsAccumulator.buildAkiExtension(issuerPub);
    }

    public static byte[] buildNameConstraintsExtension(
            String[] permittedDns,
            String[] permittedIps,
            String[] excludedDns,
            String[] excludedIps) {
        return ExtensionsAccumulator.buildNameConstraintsExtension(
                permittedDns, permittedIps, excludedDns, excludedIps);
    }

    // ========================================================================
    // Приватные проверки
    // ========================================================================

    private boolean hasAnyIanNames() {
        return (ianDnsNames != null && ianDnsNames.length > 0)
                || (ianIps != null && ianIps.length > 0)
                || (ianRfc822Names != null && ianRfc822Names.length > 0)
                || (ianUris != null && ianUris.length > 0)
                || (ianDirectoryNames != null && ianDirectoryNames.length > 0)
                || (ianOtherNames != null && ianOtherNames.length > 0);
    }

    // ========================================================================
    // Валидация времени
    // ========================================================================

    // Методы parseTimeString, UTC_TIME_FORMATTER и GENERALIZED_TIME_FORMATTER
    // вынесены в GostSignatureHelper, чтобы избежать дублирования между
    // Certificate и CRL builder'ами.
}
