package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель X.509-сертификатов ГОСТ Р 34.10-2012.
 *
 * <p>Fluent API:
 * <pre>
 * GostCertificate cert = GostCertificateBuilder.create(params, subjectDn)
 *     .publicKey(pub)
 *     .issuerDn(issuerDnDer)
 *     .notBefore("20250101000000Z")
 *     .notAfter("21010101000000Z")
 *     .sanDns("example.com")
 *     .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
 *     .assembleCert(issuerPriv);
 * </pre>
 *
 * <p>Двухшаговый вариант (TBS отдельно):
 * <pre>
 * byte[] tbs = GostCertificateBuilder.create(params, subjectDn)
 *     .publicKey(pub)
 *     .issuerDn(issuerDnDer)
 *     .notBefore(notBefore).notAfter(notAfter)
 *     .buildTbs();
 * GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, issuerPriv, params);
 * </pre>
 *
 * <p>Статические строители расширений ({@link #buildSanExtension}, {@link #buildKeyUsageExtension}
 * и др.) сохранены для совместимости с кодом, собирающим расширения отдельно.</p>
 *
 * <p>Для самоподписанных сертификатов {@code .issuerDn()} можно опустить —
 * построитель автоматически подставит {@code subjectDn} в качестве issuer.</p>
 */
public final class GostCertificateBuilder {

    private final ECParameters params;
    private final byte[] subjectDn;
    private byte[] issuerDn;
    private PublicKeyParameters pub;
    private String notBefore;
    private String notAfter;
    private String[] sanDnsNames;
    private String[] sanIps;
    private byte[] additionalExtensions;
    private BigInteger serial = BigInteger.ONE;
    private byte[] keyUsageFlags;
    private String[] ekuOids;
    private boolean ekuCritical;
    private Boolean isCA;
    private Integer pathLen;
    private String ocspUri;
    private String[] crlUris;
    private byte[] skiBytes;
    private byte[] akiBytes;

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
        this.notBefore = GENERALIZED_TIME_FORMATTER.format(time);
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
        this.notAfter = GENERALIZED_TIME_FORMATTER.format(time);
        return this;
    }

    public GostCertificateBuilder sanDns(String... names) {
        this.sanDnsNames = names;
        return this;
    }

    public GostCertificateBuilder sanIp(String... ips) {
        this.sanIps = ips;
        return this;
    }

    public GostCertificateBuilder keyUsage(KeyUsage... usages) {
        this.keyUsageFlags = keyUsageFlags(usages);
        return this;
    }

    /**
     * Устанавливает EKU без флага критичности (critical=false по умолчанию).
     *
     * @param oids dotted-string OID EKU (например {@link org.rssys.gost.pkix.GostOids#EXT_TIME_STAMPING})
     */
    public GostCertificateBuilder extendedKeyUsage(String... oids) {
        this.ekuOids = oids;
        this.ekuCritical = false;
        return this;
    }

    /**
     * Устанавливает EKU с явным флагом критичности (RFC 5280 §4.2.1.12).
     * Например {@code true} для TSA-сертификатов.
     */
    public GostCertificateBuilder extendedKeyUsage(boolean critical, String... oids) {
        this.ekuOids = oids;
        this.ekuCritical = critical;
        return this;
    }

    /**
     * @param isCA    true — субъект является CA
     * @param pathLen максимальная глубина цепочки (RFC 5280 §4.2.1.9), null — без ограничения
     * @throws IllegalArgumentException если pathLen задан при isCA=false
     */
    public GostCertificateBuilder basicConstraints(boolean isCA, Integer pathLen) {
        if (pathLen != null && !isCA) {
            throw new IllegalArgumentException("pathLen requires isCA=true");
        }
        this.isCA = isCA;
        this.pathLen = pathLen;
        return this;
    }

    public GostCertificateBuilder ocspResponder(String uri) {
        this.ocspUri = uri;
        return this;
    }

    public GostCertificateBuilder crlDistributionPoints(String... uris) {
        this.crlUris = uris;
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
        this.skiBytes = Digest.digest256(pointBytes);
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
     * AKI из готовых байтов SKI издателя (результат {@link #buildSkiExtension}).
     */
    public GostCertificateBuilder aki(byte[] issuerSkiBytes) {
        this.akiBytes = issuerSkiBytes.clone();
        return this;
    }

    /** Сырые DER-байты дополнительных расширений (конкатенация). */
    public GostCertificateBuilder additionalExtensions(byte[] der) {
        this.additionalExtensions = der;
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
                    "Serial number exceeds " + GostOids.MAX_SERIAL_OCTETS
                    + " octets (RFC 5280 §4.1.2.2), value length: " + valueLen
                    + ", serial: " + s);
        }
        this.serial = s;
        return this;
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
        Instant notBeforeInstant = parseTimeString(notBefore);
        Instant notAfterInstant = parseTimeString(notAfter);
        if (!notAfterInstant.isAfter(notBeforeInstant)) {
            throw new IllegalArgumentException(
                    "notAfter must be after notBefore: notBefore="
                            + notBefore
                            + ", notAfter="
                            + notAfter);
        }
        // Собираем все расширения
        ByteArrayOutputStream allExts = new ByteArrayOutputStream();
        try {
            if ((sanDnsNames != null && sanDnsNames.length > 0)
                    || (sanIps != null && sanIps.length > 0)) {
                allExts.write(buildSanExtension(sanDnsNames, sanIps));
            }
            if (keyUsageFlags != null) {
                allExts.write(buildKeyUsageExtension(keyUsageFlags, true));
            }
            if (ekuOids != null) {
                allExts.write(buildEkuExtension(ekuOids, ekuCritical));
            }
            if (isCA != null) {
                allExts.write(buildBasicConstraintsExtension(isCA, pathLen));
            }
            if (ocspUri != null) {
                allExts.write(buildAiaOcspExtension(ocspUri));
            }
            if (crlUris != null) {
                allExts.write(buildCdpExtension(crlUris));
            }
            if (skiBytes != null) {
                allExts.write(buildSkiExtensionBytes(skiBytes));
            }
            if (akiBytes != null) {
                allExts.write(buildAkiExtensionBytes(akiBytes));
            }
            if (additionalExtensions != null) {
                allExts.write(additionalExtensions);
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
     */
    public GostCertificate assembleCert(PrivateKeyParameters issuerPriv) {
        byte[] tbs = buildTbs();
        return assembleCert(tbs, issuerPriv, params);
    }

    // ========================================================================
    // Статический assembleCert (двухшаговый режим: buildTbs отдельно)
    // ========================================================================

    /**
     * Подписывает TBSCertificate и возвращает готовый сертификат.
     *
     * <p>Для одношагового варианта — экземплярный {@link #assembleCert(PrivateKeyParameters)}.</p>
     *
     * @param tbs       DER-кодированный TBSCertificate (результат {@link #buildTbs()})
     * @param issuerPriv закрытый ключ издателя
     * @param params    параметры эллиптической кривой
     * @return готовый сертификат {@link GostCertificate}
     */
    public static GostCertificate assembleCert(
            byte[] tbs, PrivateKeyParameters issuerPriv, ECParameters params) {
        byte[] hash = GostSignatureHelper.doHash(tbs, params.hlen);
        byte[] sig = Signature.signHash(hash, issuerPriv);
        byte[] algId = GostSignatureHelper.buildAlgId(params);
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
    // Статические строители расширений (независимы от fluent-состояния)
    // ========================================================================

    /**
     * Биты KeyUsage extension (RFC 5280 §4.2.1.3).
     */
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
    }

    /** Собирает однобайтовую битовую маску KeyUsage. */
    public static byte[] keyUsageFlags(KeyUsage... usages) {
        int mask = 0;
        for (KeyUsage u : usages) {
            mask |= u.mask;
        }
        return new byte[] {(byte) mask};
    }

    /**
     * Кодирует расширение KeyUsage (OID 2.5.29.15, RFC 5280 §4.2.1.3).
     * Non-critical по умолчанию. Для critical используйте
     * {@link #buildKeyUsageExtension(boolean, KeyUsage...)}.
     */
    public static byte[] buildKeyUsageExtension(KeyUsage... usages) {
        return buildKeyUsageExtension(keyUsageFlags(usages), false);
    }

    /**
     * Строит Extension keyUsage с явным флагом критичности (RFC 5280 §4.2.1.3 SHOULD critical).
     *
     * @param usages   перечисление KeyUsage
     * @param critical {@code true} — расширение критическое
     */
    public static byte[] buildKeyUsageExtension(boolean critical, KeyUsage... usages) {
        return buildKeyUsageExtension(keyUsageFlags(usages), critical);
    }

    /**
     * Строит Extension keyUsage с явным флагом критичности (RFC 5280 §4.2.1.3 SHOULD critical).
     *
     * @param kuFlags  битовая маска KeyUsage
     * @param critical {@code true} — расширение критическое
     */
    public static byte[] buildKeyUsageExtension(byte[] kuFlags, boolean critical) {
        byte[] extValue = DerCodec.encodeOctetString(DerCodec.encodeBitString(kuFlags));
        if (critical) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.EXT_KU),
                    DerCodec.encodeBoolean(true),
                    extValue);
        }
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_KU), extValue);
    }

    /**
     * Кодирует расширение KeyUsage (OID 2.5.29.15, RFC 5280 §4.2.1.3).
     *
     * <p><b>Контракт:</b> через {@link #buildTbs()} (fluent API) KeyUsage всегда
     * critical. Через этот static-метод — non-critical по умолчанию.
     * Для critical-варианта используйте {@link #buildKeyUsageExtension(byte[], boolean)}.
     *
     * @param kuFlags битовая маска KeyUsage
     * @return DER-кодированное расширение без critical flag
     */
    public static byte[] buildKeyUsageExtension(byte[] kuFlags) {
        return buildKeyUsageExtension(kuFlags, false);
    }

    public static byte[] buildEkuExtension(String[] oids) {
        return buildEkuExtension(oids, false);
    }

    /**
     * Строит Extension extKeyUsage с явным флагом критичности.
     *
     * @param oids     dotted-string OID EKU
     * @param critical {@code true} — расширение критическое (RFC 5280 §4.2.1.12)
     */
    public static byte[] buildEkuExtension(String[] oids, boolean critical) {
        ByteArrayOutputStream ekuSeq = new ByteArrayOutputStream();
        for (String oid : oids) {
            try {
                ekuSeq.write(DerCodec.encodeOid(oid));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        if (critical) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.EXT_EKU),
                    DerCodec.encodeBoolean(true),
                    DerCodec.encodeOctetString(DerCodec.encodeSequence(ekuSeq.toByteArray())));
        }
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.EXT_EKU),
                DerCodec.encodeOctetString(DerCodec.encodeSequence(ekuSeq.toByteArray())));
    }

    public static byte[] buildCertificatePoliciesExtension(String[] policyOids) {
        ByteArrayOutputStream cpSeq = new ByteArrayOutputStream();
        for (String oid : policyOids) {
            try {
                byte[] policyInfoSeq = DerCodec.encodeSequence(DerCodec.encodeOid(oid));
                cpSeq.write(policyInfoSeq);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.EXT_CP),
                DerCodec.encodeOctetString(DerCodec.encodeSequence(cpSeq.toByteArray())));
    }

    /**
     * Строит DER-кодированное расширение Basic Constraints (RFC 5280 §4.2.1.9).
     *
     * @param isCA    true — субъект является CA (добавляется BOOLEAN DEFAULT TRUE)
     * @param pathLen максимальная глубина цепочки, null — без ограничения
     * @throws IllegalArgumentException если pathLen задан при isCA=false
     */
    public static byte[] buildBasicConstraintsExtension(boolean isCA, Integer pathLen) {
        if (pathLen != null && !isCA) {
            throw new IllegalArgumentException("pathLen requires isCA=true");
        }
        ByteArrayOutputStream bcSeq = new ByteArrayOutputStream();
        try {
            if (isCA) {
                bcSeq.write(new byte[] {0x01, 0x01, (byte) 0xFF});
            }
            if (pathLen != null) {
                bcSeq.write(DerCodec.encodeInteger(pathLen));
            }
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        byte[] bcContent = DerCodec.encodeSequence(bcSeq.toByteArray());
        byte[] extValue = DerCodec.encodeOctetString(bcContent);
        if (isCA) {
            // RFC 5280 §4.2.1.9: MUST critical для CA-сертификатов
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.EXT_BC),
                    DerCodec.encodeBoolean(true),
                    extValue);
        }
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_BC), extValue);
    }

    public static byte[] buildAiaOcspExtension(String ocspUri) {
        byte[] uriBytes = ocspUri.getBytes(StandardCharsets.US_ASCII);
        byte[] accessDesc =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.OCSP_AD), DerCodec.encodeTlv(0x86, uriBytes));
        byte[] aiaSeq = DerCodec.encodeSequence(accessDesc);
        byte[] extValue = DerCodec.encodeOctetString(aiaSeq);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_AIA), extValue);
    }

    public static byte[] buildSanExtension(String[] dnsNames, String[] ipAddresses) {
        byte[] gnSeq = GeneralNameCodec.encodeGeneralNames(dnsNames, ipAddresses);
        byte[] extValue = DerCodec.encodeOctetString(gnSeq);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_SAN), extValue);
    }

    public static byte[] buildCdpExtension(String... crlUris) {
        return buildDistributionPointExtension(GostOids.EXT_CDP, crlUris);
    }

    /**
     * Кодирует extension типа DistributionPoint (CDP / Freshest CRL).
     * Структура идентична для CDP (RFC 5280 §4.2.1.13) и
     * Freshest CRL (RFC 5280 §5.2.6), отличается только OID.
     */
    static byte[] buildDistributionPointExtension(String oid, String... uris) {
        ByteArrayOutputStream dps = new ByteArrayOutputStream();
        for (String uri : uris) {
            byte[] uriBytes = uri.getBytes(StandardCharsets.US_ASCII);
            byte[] gnUri = DerCodec.encodeTlv(0x86, uriBytes);
            byte[] fullName = DerCodec.encodeTlv(0xA0, gnUri);
            byte[] distPointContent = DerCodec.encodeTlv(0xA0, fullName);
            byte[] distPointSeq = DerCodec.encodeSequence(distPointContent);
            try {
                dps.write(distPointSeq);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        byte[] distributionPoints = DerCodec.encodeSequence(dps.toByteArray());
        byte[] extValue = DerCodec.encodeOctetString(distributionPoints);
        return DerCodec.encodeSequence(DerCodec.encodeOid(oid), extValue);
    }

    public static byte[] buildSkiExtension(PublicKeyParameters pub) {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(pub);
        byte[] ski = Digest.digest256(pointBytes);
        byte[] skiOctet = DerCodec.encodeOctetString(ski);
        byte[] extValue = DerCodec.encodeOctetString(skiOctet);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_SKI), extValue);
    }

    public static byte[] buildAkiExtension(byte[] issuerSkiBytes) {
        byte[] keyIdentifier = DerCodec.encodeTlv(0x80, issuerSkiBytes);
        byte[] akiValue = DerCodec.encodeSequence(keyIdentifier);
        byte[] extValue = DerCodec.encodeOctetString(akiValue);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_AKI), extValue);
    }

    public static byte[] buildAkiExtension(PublicKeyParameters issuerPub) {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(issuerPub);
        byte[] ski = Digest.digest256(pointBytes);
        return buildAkiExtension(ski);
    }

    // ========================================================================
    // Приватные обёртки SKI/AKI (из готовых байтов, без повторного хеширования)
    // ========================================================================

    private static byte[] buildSkiExtensionBytes(byte[] ski) {
        byte[] skiOctet = DerCodec.encodeOctetString(ski);
        byte[] extValue = DerCodec.encodeOctetString(skiOctet);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_SKI), extValue);
    }

    private static byte[] buildAkiExtensionBytes(byte[] aki) {
        byte[] keyIdentifier = DerCodec.encodeTlv(0x80, aki);
        byte[] akiValue = DerCodec.encodeSequence(keyIdentifier);
        byte[] extValue = DerCodec.encodeOctetString(akiValue);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_AKI), extValue);
    }

    // ========================================================================
    // Валидация времени
    // ========================================================================

    /** Форматтер UTCTime: YYMMDDHHMMSSZ (RFC 5280 §4.1.2.5.1) */
    private static final DateTimeFormatter UTC_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyMMddHHmmssX").withZone(ZoneOffset.UTC);

    /** Форматтер GeneralizedTime: YYYYMMDDHHMMSSZ (RFC 5280 §4.1.2.5.2) */
    private static final DateTimeFormatter GENERALIZED_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmssX").withZone(ZoneOffset.UTC);

    /**
     * Валидирует и парсит строку времени в формате UTCTime (13 символов) или
     * GeneralizedTime (15 символов). Оба формата оканчиваются на 'Z' (UTC).
     *
     * @param timeStr строка в формате YYMMDDHHMMSSZ или YYYYMMDDHHMMSSZ
     * @return Instant времени в UTC
     * @throws IllegalArgumentException если формат неверен
     */
    static Instant parseTimeString(String timeStr) {
        if (timeStr == null || !timeStr.endsWith("Z")) {
            throw new IllegalArgumentException("Time string must end with 'Z': " + timeStr);
        }
        int len = timeStr.length();
        DateTimeFormatter fmt;
        if (len == 13) {
            fmt = UTC_TIME_FORMATTER;
        } else if (len == 15) {
            fmt = GENERALIZED_TIME_FORMATTER;
        } else {
            throw new IllegalArgumentException(
                    "Time string must be 13 or 15 chars (UTCTime or GeneralizedTime): " + timeStr);
        }
        try {
            return Instant.from(fmt.parse(timeStr));
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("Invalid time string: " + timeStr, e);
        }
    }
}
