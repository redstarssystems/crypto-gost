package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель CRL (CertificateList, RFC 5280 §5.1) для ГОСТ Р 34.10-2012.
 *
 * <p>Fluent API:
 * <pre>
 * byte[] crl = GostCrlBuilder.create(issuerDnDer)
 *     .thisUpdateNow()
 *     .nextUpdateDays(30)
 *     .withIdpExtension()
 *     .addRevoked(serial, revocationDate)
 *     .sign(signer);
 * </pre>
 *
 * <p>Альтернативно — явные даты для воспроизводимости:
 * <pre>
 *     .thisUpdate("20250101000000Z")
 *     .nextUpdate("20260101000000Z")
 * </pre>
 *
 * <p>Симметричен {@link GostCrl} (парсинг) и {@link CrlVerifier} (проверка).</p>
 *
 * <p>{@link #sign(GostSigner)} возвращает wire-формат DER-байтов для передачи по сети.
 * Для инспекции и проверки — consumer-класс {@link GostCrl}:
 * {@code new GostCrl(bytes).verify(caPub)}. Разделение producer (CA строит CRL)
 * и consumer (валидатор проверяет) осмысленно: CRL — fail-closed объект,
 * {@link GostCrl#getRevokedCertificates()} недоступен до вызова
 * {@link GostCrl#verify verify()}.</p>
 *
 * <p>Подписант передаётся в терминальный {@link #sign(GostSigner)} — единообразно с
 * {@link GostCertificateBuilder} и {@link GostCsrBuilder}. В отличие от сертификата,
 * у CRL нет публичного двухшагового пути (сборка TBS -> внешняя офлайн-подпись):
 * CRL — рутинная частая операция против online-HSM, а офлайн-церемония (shipping TBS)
 * релевантна редким событиям выпуска корневых/промежуточных сертификатов УЦ. Разные
 * операционные модели -> у CRL только одношаговый {@code sign(...)}.</p>
 */
public final class GostCrlBuilder {

    private final byte[] issuerDnDer;
    private String thisUpdate;
    private String nextUpdate;
    private boolean nextUpdateOmitted;
    private boolean withIdpExtension;
    private boolean idpOnlyContainsUserCerts;
    private boolean idpOnlyContainsCACerts;
    private BigInteger crlNumber;
    private BigInteger baseCrlNumber;
    private String[] freshestCrlUris;
    private byte[] akiBytes;
    private final List<RevokedEntry> revokedEntries = new ArrayList<>();

    private GostCrlBuilder(byte[] issuerDnDer) {
        this.issuerDnDer = issuerDnDer;
    }

    /**
     * Создаёт построитель CRL с обязательным issuer Name.
     * Подписант задаётся позже — в терминальном {@link #sign(GostSigner)}.
     *
     * @param issuerDnDer DER-кодированный issuer Name
     */
    public static GostCrlBuilder create(byte[] issuerDnDer) {
        return new GostCrlBuilder(issuerDnDer);
    }

    /**
     * Удобная перегрузка: DN из строки "CN=..., O=...".
     *
     * <p>Для CRL уже существующего УЦ передавайте DER через
     * {@link #create(byte[])} (например, {@code caCert.getSubjectDnBytes()}):
     * строковая перегрузка кодирует DN заново и может не совпасть с issuer
     * DN старых сертификатов.</p>
     */
    public static GostCrlBuilder create(String issuerDn) {
        return new GostCrlBuilder(GostDnParser.encodeDn(issuerDn));
    }

    /** @param time thisUpdate в формате GeneralizedTime (YYYYMMDDHHMMSSZ) */
    public GostCrlBuilder thisUpdate(String time) {
        this.thisUpdate = time;
        return this;
    }

    /** @param time thisUpdate как Instant (UTC) */
    public GostCrlBuilder thisUpdate(Instant time) {
        this.thisUpdate = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    /**
     * @param time nextUpdate в формате GeneralizedTime; {@code null} сбрасывает значение,
     *     выпуск без nextUpdate разрешает только {@link #withoutNextUpdate()}
     */
    public GostCrlBuilder nextUpdate(String time) {
        this.nextUpdate = time;
        return this;
    }

    /** @param time nextUpdate как Instant (UTC) */
    public GostCrlBuilder nextUpdate(Instant time) {
        this.nextUpdate = GostSignatureHelper.formatGeneralizedTime(time);
        return this;
    }

    /**
     * Явно разрешает выпуск CRL без nextUpdate.
     *
     * <p>RFC 5280 §5.1.2.5 обязывает УЦ включать nextUpdate, а проверяющая сторона библиотеки
     * такой CRL отвергает: без nextUpdate CRL не устаревает и его можно предъявлять бесконечно.
     * Метод нужен только для негативных тестов и проверки чужих реализаций, поэтому без него
     * {@link #sign(GostSigner)} не выпустит такой CRL.</p>
     */
    public GostCrlBuilder withoutNextUpdate() {
        this.nextUpdate = null;
        this.nextUpdateOmitted = true;
        return this;
    }

    /**
     * Устанавливает thisUpdate = текущее UTC-время минус {@link GostOids#CLOCK_SKEW_MS} (5 мин).
     *
     * <p>Буфер симметричен {@link GostCertificateBuilder#notBeforeNow()}:
     * {@link GostCrl#verify()} использует ту же константу {@code CLOCK_SKEW_MS}
     * для fail-closed проверки thisUpdate-не-в-будущем
     * ({@link PkixException.Reason#THIS_UPDATE_FUTURE}).
     * Без буфера свежевыпущенный CRL от УЦ со спешащими часами был бы отклонён
     * relying party.
     *
     * <p>Для тестов — используйте {@link #thisUpdate(String)} с фиксированной датой.
     *
     * <p><b>Осторожно с CAdES-X Long.</b> Откат на 5 минут совпадает с нижней границей окна
     * свежести {@code STRICT} (thisUpdate не раньше времени подписи минус {@code CLOCK_SKEW_MS}),
     * то есть запаса нет. Время округляется до секунды, поэтому CRL, построенный до штампа времени,
     * при смене секунды между ними оказывается вне окна и отвергается. Так же отвергается CRL,
     * построенный после штампа, если штамп выдал внешний сервер с опережающими часами: время
     * штампа идёт по его часам, а thisUpdate - по локальным. Для доказательств, встраиваемых под
     * {@code STRICT}, используйте {@link #thisUpdate(Instant)} с текущим моментом.
     */
    public GostCrlBuilder thisUpdateNow() {
        this.thisUpdate =
                GostSignatureHelper.formatGeneralizedTime(
                        Instant.now().minusMillis(GostOids.CLOCK_SKEW_MS));
        return this;
    }

    /**
     * nextUpdate = thisUpdate + days (24-часовые сутки UTC).
     *
     * @throws IllegalStateException если {@code thisUpdate} не был задан
     */
    public GostCrlBuilder nextUpdateDays(int days) {
        if (thisUpdate == null) {
            throw new IllegalStateException("thisUpdate must be set before nextUpdateDays()");
        }
        Instant tu = GostSignatureHelper.parseAsn1Time(thisUpdate);
        this.nextUpdate =
                GostSignatureHelper.formatGeneralizedTime(
                        tu.plusSeconds((long) days * 24L * 3600L));
        return this;
    }

    /**
     * nextUpdate = thisUpdate + months (календарные месяцы UTC).
     * 31 января + 1 месяц → 28/29 февраля.
     *
     * @throws IllegalStateException если {@code thisUpdate} не был задан
     */
    public GostCrlBuilder nextUpdateMonths(int months) {
        if (thisUpdate == null) {
            throw new IllegalStateException("thisUpdate must be set before nextUpdateMonths()");
        }
        Instant tu = GostSignatureHelper.parseAsn1Time(thisUpdate);
        this.nextUpdate =
                GostSignatureHelper.formatGeneralizedTime(
                        tu.atZone(ZoneOffset.UTC).plusMonths(months).toInstant());
        return this;
    }

    /**
     * nextUpdate = thisUpdate + years (календарные годы UTC).
     * 29 февраля 2024 + 1 год → 28 февраля 2025.
     *
     * @throws IllegalStateException если {@code thisUpdate} не был задан
     */
    public GostCrlBuilder nextUpdateYears(int years) {
        if (thisUpdate == null) {
            throw new IllegalStateException("thisUpdate must be set before nextUpdateYears()");
        }
        Instant tu = GostSignatureHelper.parseAsn1Time(thisUpdate);
        this.nextUpdate =
                GostSignatureHelper.formatGeneralizedTime(
                        tu.atZone(ZoneOffset.UTC).plusYears(years).toInstant());
        return this;
    }

    /** Добавляет issuingDistributionPoint extension. */
    public GostCrlBuilder withIdpExtension() {
        this.withIdpExtension = true;
        return this;
    }

    /**
     * Добавляет issuingDistributionPoint extension с указанными флагами
     * (RFC 5280 §5.2.5). indirectCRL всегда false — indirect CRL не в scope.
     *
     * @param onlyContainsUserCerts флаг onlyContainsUserCerts [1]
     * @param onlyContainsCACerts   флаг onlyContainsCACerts [2]
     */
    public GostCrlBuilder withIdpExtension(
            boolean onlyContainsUserCerts, boolean onlyContainsCACerts) {
        this.withIdpExtension = true;
        this.idpOnlyContainsUserCerts = onlyContainsUserCerts;
        this.idpOnlyContainsCACerts = onlyContainsCACerts;
        return this;
    }

    /**
     * Добавляет CRL Number extension (RFC 5280 §5.2.3, non-critical).
     *
     * @param n номер CRL (монотонно возрастающее целое)
     */
    public GostCrlBuilder withCrlNumber(BigInteger n) {
        requireValidCrlNumber(n);
        this.crlNumber = n;
        return this;
    }

    /** Удобная int-перегрузка для {@link #withCrlNumber(BigInteger)}. */
    public GostCrlBuilder withCrlNumber(int n) {
        return withCrlNumber(BigInteger.valueOf(n));
    }

    /**
     * Добавляет Delta CRL Indicator extension (RFC 5280 §5.2.4, critical).
     * Требует предварительного вызова {@link #withCrlNumber}.
     *
     * @param baseCrlNumber номер базового CRL (cRLNumber из base CRL)
     * @throws IllegalStateException при вызове {@link #build()} если {@link #withCrlNumber} не вызван
     */
    public GostCrlBuilder withDeltaCrlIndicator(BigInteger baseCrlNumber) {
        requireValidCrlNumber(baseCrlNumber);
        this.baseCrlNumber = baseCrlNumber;
        return this;
    }

    /**
     * Симметрично проверке {@link GostCrl}: номер неотрицателен и не длиннее
     * {@link GostOids#MAX_CRL_NUMBER_OCTETS} октетов величины (RFC 5280 §5.2.3), иначе
     * построитель выпустил бы CRL, который собственная проверка отвергнет.
     */
    private static void requireValidCrlNumber(BigInteger number) {
        if (number == null) {
            return;
        }
        if (number.signum() < 0) {
            throw new IllegalArgumentException("CRL number must not be negative");
        }
        if ((number.bitLength() + 7) / 8 > GostOids.MAX_CRL_NUMBER_OCTETS) {
            throw new IllegalArgumentException(
                    "CRL number exceeds " + GostOids.MAX_CRL_NUMBER_OCTETS + " octets");
        }
    }

    /** Удобная int-перегрузка для {@link #withDeltaCrlIndicator(BigInteger)}. */
    public GostCrlBuilder withDeltaCrlIndicator(int baseCrlNumber) {
        return withDeltaCrlIndicator(BigInteger.valueOf(baseCrlNumber));
    }

    /**
     * Добавляет Freshest CRL extension (RFC 5280 §5.2.6).
     * Указывает URI для получения delta CRL.
     * Структура идентична CDP.
     *
     * @param uris URI точек распространения delta CRL
     */
    public GostCrlBuilder withFreshestCrl(String... uris) {
        this.freshestCrlUris = (uris != null) ? uris.clone() : null;
        return this;
    }

    /**
     * Добавляет AuthorityKeyIdentifier extension (RFC 5280 §5.2.1).
     * keyIdentifier — обычно SKI сертификата подписанта CRL.
     *
     * @param signerSkiBytes байты keyIdentifier (32 байта для ГОСТ 256-битных кривых)
     */
    public GostCrlBuilder withAki(byte[] signerSkiBytes) {
        this.akiBytes = (signerSkiBytes != null) ? signerSkiBytes.clone() : null;
        return this;
    }

    /** Удобная перегрузка: вычисляет SKI из открытого ключа подписанта. */
    public GostCrlBuilder withAki(PublicKeyParameters signerPub) {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(signerPub);
        byte[] ski = Digest.digest256(pointBytes);
        return withAki(ski);
    }

    /** Добавляет запись об отозванном сертификате. */
    public GostCrlBuilder addRevoked(RevokedEntry entry) {
        revokedEntries.add(entry);
        return this;
    }

    /** Добавляет записи об отозванных сертификатах из коллекции. */
    public GostCrlBuilder addRevoked(Collection<RevokedEntry> entries) {
        revokedEntries.addAll(entries);
        return this;
    }

    /**
     * Добавляет запись об отозванном сертификате (без расширений).
     *
     * @param serial         серийный номер (raw DER INTEGER value)
     * @param revocationDate дата отзыва (YYYYMMDDHHMMSSZ)
     */
    public GostCrlBuilder addRevoked(byte[] serial, String revocationDate) {
        revokedEntries.add(new RevokedEntry(serial, revocationDate));
        return this;
    }

    /**
     * Добавляет запись об отозванном сертификате (без расширений) —
     * удобная перегрузка с {@link BigInteger}.
     *
     * @param serial         серийный номер как BigInteger
     * @param revocationDate дата отзыва (YYYYMMDDHHMMSSZ)
     */
    public GostCrlBuilder addRevoked(BigInteger serial, String revocationDate) {
        return addRevoked(serial.toByteArray(), revocationDate);
    }

    /**
     * Собирает и подписывает CRL.
     *
     * @param signer подписант CRL (может быть HSM-адаптером); ECParameters берутся из него
     * @return DER-кодированный CertificateList
     * @throws IllegalStateException если deltaCRLIndicator задан без cRLNumber или не задан
     *     nextUpdate (выпуск без него разрешает только {@link #withoutNextUpdate()})
     */
    public byte[] sign(GostSigner signer) {
        Objects.requireNonNull(signer, "signer must not be null");
        // Собственная проверка отвергает CRL без nextUpdate: не выпускаем то, что сами не примем
        if (nextUpdate == null && !nextUpdateOmitted) {
            throw new IllegalStateException(
                    "nextUpdate must be set (RFC 5280 §5.1.2.5); use withoutNextUpdate() to omit it");
        }
        // RFC 5280 §5.2.4: deltaCRLIndicator не может присутствовать без cRLNumber
        if (baseCrlNumber != null && crlNumber == null) {
            throw new IllegalStateException(
                    "deltaCRLIndicator requires cRLNumber extension (RFC 5280 §5.2.4)");
        }
        // thisUpdate по умолчанию фиксируется в момент подписи (а не создания билдера):
        // между create() и sign() может пройти время (отложенная подпись через HSM-воркер),
        // и thisUpdate должен отражать момент выпуска CRL. Явный thisUpdate(...) имеет приоритет.
        String effectiveThisUpdate =
                (thisUpdate != null) ? thisUpdate : GostSignatureHelper.nowGeneralizedTime();
        RevokedEntry[] entries =
                revokedEntries.isEmpty() ? null : revokedEntries.toArray(new RevokedEntry[0]);
        return assembleCrlCore(
                entries,
                signer,
                issuerDnDer,
                effectiveThisUpdate,
                nextUpdate,
                false,
                crlNumber,
                baseCrlNumber,
                freshestCrlUris,
                withIdpExtension,
                idpOnlyContainsUserCerts,
                idpOnlyContainsCACerts,
                false,
                akiBytes);
    }

    /**
     * Собирает и подписывает CRL закрытым ключом в памяти.
     * Удобная обёртка через {@link GostSigner#of(PrivateKeyParameters)}.
     *
     * @param signerPriv ключ, которым подписывается CRL (ECParameters извлекаются из ключа)
     * @return DER-кодированный CertificateList
     */
    public byte[] sign(PrivateKeyParameters signerPriv) {
        return sign(GostSigner.of(signerPriv));
    }

    // ========================================================================
    // Приватные методы сборки
    // ========================================================================

    /**
     * Внутренний метод сборки CRL — прямой доступ к параметрам сборки.
     * Не предназначен для обычного использования — применяйте {@link #sign(GostSigner)}.
     * Публичен только для специальных тестовых сценариев (например, сборка CRL
     * с устаревшим форматом версии для проверки fallback-веток верификации).
     *
     * @param withIdpExtension если true — добавляет пустой IDP (все флаги false)
     */
    public static byte[] assembleCrl(
            RevokedEntry[] revokedEntries,
            PrivateKeyParameters signerPriv,
            byte[] issuerDnDer,
            String thisUpdateGeneralizedTime,
            String nextUpdateGeneralizedTime,
            boolean legacyVersion,
            BigInteger crlNumber,
            BigInteger baseCrlNumber,
            String[] freshestCrlUris,
            boolean withIdpExtension,
            byte[] akiBytes) {
        return assembleCrl(
                revokedEntries,
                signerPriv,
                issuerDnDer,
                thisUpdateGeneralizedTime,
                nextUpdateGeneralizedTime,
                legacyVersion,
                crlNumber,
                baseCrlNumber,
                freshestCrlUris,
                withIdpExtension,
                false,
                false,
                akiBytes);
    }

    /**
     * Внутренний метод сборки CRL с IDP-флагами.
     */
    public static byte[] assembleCrl(
            RevokedEntry[] revokedEntries,
            PrivateKeyParameters signerPriv,
            byte[] issuerDnDer,
            String thisUpdateGeneralizedTime,
            String nextUpdateGeneralizedTime,
            boolean legacyVersion,
            BigInteger crlNumber,
            BigInteger baseCrlNumber,
            String[] freshestCrlUris,
            boolean withIdpExtension,
            boolean idpOnlyContainsUserCerts,
            boolean idpOnlyContainsCACerts,
            byte[] akiBytes) {
        return assembleCrl(
                revokedEntries,
                signerPriv,
                issuerDnDer,
                thisUpdateGeneralizedTime,
                nextUpdateGeneralizedTime,
                legacyVersion,
                crlNumber,
                baseCrlNumber,
                freshestCrlUris,
                withIdpExtension,
                idpOnlyContainsUserCerts,
                idpOnlyContainsCACerts,
                false,
                akiBytes);
    }

    /**
     * Внутренний метод сборки CRL с полными IDP-флагами (включая indirectCRL).
     * indirectCRL — только для тестов, на генерации indirect CRL builder не разрешает.
     */
    public static byte[] assembleCrl(
            RevokedEntry[] revokedEntries,
            PrivateKeyParameters signerPriv,
            byte[] issuerDnDer,
            String thisUpdateGeneralizedTime,
            String nextUpdateGeneralizedTime,
            boolean legacyVersion,
            BigInteger crlNumber,
            BigInteger baseCrlNumber,
            String[] freshestCrlUris,
            boolean withIdpExtension,
            boolean idpOnlyContainsUserCerts,
            boolean idpOnlyContainsCACerts,
            boolean idpIndirectCrl,
            byte[] akiBytes) {
        return assembleCrlCore(
                revokedEntries,
                GostSigner.of(signerPriv),
                issuerDnDer,
                thisUpdateGeneralizedTime,
                nextUpdateGeneralizedTime,
                legacyVersion,
                crlNumber,
                baseCrlNumber,
                freshestCrlUris,
                withIdpExtension,
                idpOnlyContainsUserCerts,
                idpOnlyContainsCACerts,
                idpIndirectCrl,
                akiBytes);
    }

    private static byte[] assembleCrlCore(
            RevokedEntry[] revokedEntries,
            GostSigner signer,
            byte[] issuerDnDer,
            String thisUpdateGeneralizedTime,
            String nextUpdateGeneralizedTime,
            boolean legacyVersion,
            BigInteger crlNumber,
            BigInteger baseCrlNumber,
            String[] freshestCrlUris,
            boolean withIdpExtension,
            boolean idpOnlyContainsUserCerts,
            boolean idpOnlyContainsCACerts,
            boolean idpIndirectCrl,
            byte[] akiBytes) {
        try {
            ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
            if (legacyVersion) {
                tbsOut.write(DerCodec.encodeTlv(0xA0, new byte[] {0x02, 0x01, 0x01}));
            } else {
                tbsOut.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
            }
            tbsOut.write(GostSignatureHelper.buildAlgId(signer.getParams()));
            tbsOut.write(issuerDnDer);
            // RFC 5280 §5.1.2.4: Time кодируется UTCTime до 2049, далее GeneralizedTime.
            tbsOut.write(
                    DerCodec.encodeTime(
                            GostSignatureHelper.normalizeRfc5280Time(thisUpdateGeneralizedTime)));
            if (nextUpdateGeneralizedTime != null) {
                tbsOut.write(
                        DerCodec.encodeTime(
                                GostSignatureHelper.normalizeRfc5280Time(
                                        nextUpdateGeneralizedTime)));
            }
            if (revokedEntries != null && revokedEntries.length > 0) {
                ByteArrayOutputStream rvOut = new ByteArrayOutputStream();
                for (RevokedEntry entry : revokedEntries) {
                    byte[] entryExts = encodeEntryExtensions(entry);
                    byte[] revokedEntry;
                    if (entryExts != null) {
                        revokedEntry =
                                DerCodec.encodeSequence(
                                        DerCodec.encodeTlv(0x02, entry.serial()),
                                        DerCodec.encodeTime(
                                                GostSignatureHelper.normalizeRfc5280Time(
                                                        entry.revocationDate())),
                                        entryExts);
                    } else {
                        revokedEntry =
                                DerCodec.encodeSequence(
                                        DerCodec.encodeTlv(0x02, entry.serial()),
                                        DerCodec.encodeTime(
                                                GostSignatureHelper.normalizeRfc5280Time(
                                                        entry.revocationDate())));
                    }
                    rvOut.write(revokedEntry);
                }
                tbsOut.write(DerCodec.encodeSequence(rvOut.toByteArray()));
            }

            // Обобщённая сборка CRL-расширений (замена жёсткой привязки к IDP)
            ByteArrayOutputStream crlExts = new ByteArrayOutputStream();
            boolean hasCrlExt = false;

            if (crlNumber != null) {
                crlExts.write(
                        buildSingleExtension(
                                GostOids.EXT_CRL_NUMBER, false, DerCodec.encodeInteger(crlNumber)));
                hasCrlExt = true;
            }

            if (freshestCrlUris != null) {
                crlExts.write(
                        ExtensionsAccumulator.buildDistributionPointExtension(
                                GostOids.EXT_FRESHEST_CRL, freshestCrlUris));
                hasCrlExt = true;
            }

            if (baseCrlNumber != null) {
                crlExts.write(
                        buildSingleExtension(
                                GostOids.EXT_DELTA_CRL_INDICATOR,
                                true,
                                DerCodec.encodeInteger(baseCrlNumber)));
                hasCrlExt = true;
            }

            if (withIdpExtension) {
                byte[] idpDer =
                        buildIdpExtension(
                                idpOnlyContainsUserCerts, idpOnlyContainsCACerts, idpIndirectCrl);
                byte[] idpOid = DerCodec.encodeOid(GostOids.EXT_IDP);
                byte[] idpExt = DerCodec.encodeSequence(idpOid, DerCodec.encodeTlv(0x04, idpDer));
                crlExts.write(idpExt);
                hasCrlExt = true;
            }

            if (akiBytes != null) {
                crlExts.write(ExtensionsAccumulator.buildAkiExtension(akiBytes));
                hasCrlExt = true;
            }

            if (hasCrlExt) {
                byte[] extSeq = DerCodec.encodeSequence(crlExts.toByteArray());
                tbsOut.write(DerCodec.encodeTlv(0xA0, extSeq));
            }

            byte[] tbsCertList = DerCodec.encodeSequence(tbsOut.toByteArray());
            int hlen = signer.getParams().hlen;
            byte[] hash = GostSignatureHelper.doHash(tbsCertList, hlen);
            byte[] sig = GostSignatureHelper.signHashChecked(hash, signer);
            byte[] sigAlg = GostSignatureHelper.buildAlgId(signer.getParams());
            return DerCodec.encodeSequence(tbsCertList, sigAlg, DerCodec.encodeBitString(sig));
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
    }

    /**
     * Кодирует IssuingDistributionPoint SEQUENCE (RFC 5280 §5.2.5, Appendix A —
     * DEFINITIONS IMPLICIT TAGS). Флаги кодируются как IMPLICIT BOOLEAN:
     * тег 0x81/0x82/0x84, значение — байт 0xFF напрямую.
     * indirectCRL всегда false при генерации через builder — indirect CRL вне scope.
     * Неиспользуемые поля ([0] distributionPoint, [3] onlySomeReasons,
     * [5] onlyContainsAttributeCerts) опускаются.
     * Флаги BOOLEAN DEFAULT FALSE — кодируются только true.
     */
    public static byte[] buildIdpExtension(
            boolean onlyContainsUserCerts, boolean onlyContainsCACerts, boolean indirectCRL) {
        ByteArrayOutputStream idpOut = new ByteArrayOutputStream();
        try {
            if (onlyContainsUserCerts) {
                idpOut.write(DerCodec.encodeTlv(0x81, new byte[] {(byte) 0xFF}));
            }
            if (onlyContainsCACerts) {
                idpOut.write(DerCodec.encodeTlv(0x82, new byte[] {(byte) 0xFF}));
            }
            if (indirectCRL) {
                idpOut.write(DerCodec.encodeTlv(0x84, new byte[] {(byte) 0xFF}));
            }
            return DerCodec.encodeSequence(idpOut.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
    }

    /**
     * Кодирует одно CRL-расширение с INTEGER-значением внутри OCTET STRING.
     *
     * @param oid      OID расширения (строка)
     * @param critical true если расширение critical
     * @param intValue DER-кодированный INTEGER
     */
    private static byte[] buildSingleExtension(String oid, boolean critical, byte[] intValue) {
        byte[] extValue = DerCodec.encodeOctetString(intValue);
        if (critical) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(oid), DerCodec.encodeBoolean(true), extValue);
        }
        return DerCodec.encodeSequence(DerCodec.encodeOid(oid), extValue);
    }

    private static byte[] encodeEntryExtensions(RevokedEntry entry) {
        ByteArrayOutputStream exts = new ByteArrayOutputStream();
        boolean hasExtensions = false;

        try {
            if (entry.reason() != null) {
                byte[] enumerated =
                        DerCodec.encodeTlv(
                                DerCodec.TAG_ENUMERATED,
                                new byte[] {(byte) entry.reason().value()});
                byte[] extValue = DerCodec.encodeOctetString(enumerated);
                byte[] ext =
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.EXT_CRL_REASON), extValue);
                exts.write(ext);
                hasExtensions = true;
            }

            if (entry.invalidityDate() != null) {
                byte[] invDate =
                        DerCodec.encodeTime(
                                GostSignatureHelper.normalizeRfc5280Time(entry.invalidityDate()));
                byte[] extValue = DerCodec.encodeOctetString(invDate);
                byte[] ext =
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.EXT_INVALIDITY_DATE), extValue);
                exts.write(ext);
                hasExtensions = true;
            }

            if (entry.certificateIssuer() != null) {
                byte[] extValue = DerCodec.encodeOctetString(entry.certificateIssuer());
                byte[] ext =
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.EXT_CERTIFICATE_ISSUER), extValue);
                exts.write(ext);
                hasExtensions = true;
            }

        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }

        if (!hasExtensions) {
            return null;
        }
        return DerCodec.encodeSequence(exts.toByteArray());
    }
}
