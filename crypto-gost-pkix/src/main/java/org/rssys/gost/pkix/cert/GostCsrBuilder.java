package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель PKCS#10 CSR (Certificate Signing Request, RFC 2986 §4.1).
 *
 * <p>Строит CertificationRequest: TBS-запрос + AlgorithmIdentifier подписи + подпись.
 * DN строится через {@link GostDnParser#encodeDn}.</p>
 *
 * <p>Поддерживает атрибут {@code extensionRequest} (PKCS#9 §5.4.2) — подписчик может
 * запросить конкретные расширения X.509v3 (SAN, KeyUsage, ExtendedKeyUsage,
 * BasicConstraints, SubjectKeyIdentifier) через fluent-сеттеры, а также произвольные атрибуты
 * PKCS#10 через {@link #attribute(String, byte[]...)} и {@code challengePassword}
 * (PKCS#9 §5.4.1) через {@link #sign(GostSigner, char[])}. Без них блок атрибутов пустой, что
 * разрешено RFC 2986 §4.1.</p>
 *
 * <p>Блок атрибутов {@code [0] IMPLICIT SET OF Attribute} кодируется по DER: элементы
 * отсортированы по своему кодированию, поэтому порядок вызовов на результат не влияет.</p>
 *
 * <h3>Пример с расширениями</h3>
 * <pre>{@code
 * GostCsrBuilder.create("CN=example.com", pubKey)
 *     .sanDns("example.com", "www.example.com")
 *     .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
 *     .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
 *     .sign(signer);
 * }</pre>
 *
 * <p>Подписант передаётся в терминальный {@link #sign(GostSigner)} — единообразно с
 * {@link GostCertificateBuilder} и {@link GostCrlBuilder}.</p>
 *
 * <p>{@link #sign(GostSigner)} возвращает wire-формат DER-байтов CSR для передачи в УЦ.
 * Для инспекции и проверки — consumer-класс {@link GostCsrParser}. Разделение producer
 * (запрашивающая сторона строит и подписывает CSR своим ключом) и consumer (УЦ парсит
 * и проверяет подпись/PoP) намеренное.</p>
 *
 * <p><b>Proof-of-possession:</b> CSR подписывается закрытым ключом, соответствующим
 * открытому ключу из {@code create(...)}. {@link #sign(GostSigner)} fail-closed проверяет,
 * что {@code signer.getPublicKey()} совпадает с этим открытым ключом, — иначе несостыковка
 * всплыла бы лишь у потребителя при проверке подписи.</p>
 *
 * @see GostCsrParser
 * @see GostCertificateBuilder
 */
public final class GostCsrBuilder {

    private final byte[] subjectDnDer;
    private final PublicKeyParameters pubKey;
    private final ExtensionsAccumulator ext = new ExtensionsAccumulator();

    /** Готовые DER-кодировки произвольных атрибутов; ключ — кодирование OID. */
    private final Map<String, byte[]> attributes = new LinkedHashMap<>();

    private GostCsrBuilder(byte[] subjectDnDer, PublicKeyParameters pubKey) {
        this.subjectDnDer = subjectDnDer;
        this.pubKey = pubKey;
    }

    public static GostCsrBuilder create(String subjectDn, PublicKeyParameters pubKey) {
        return new GostCsrBuilder(GostDnParser.encodeDn(subjectDn), pubKey);
    }

    public static GostCsrBuilder create(byte[] subjectDnDer, PublicKeyParameters pubKey) {
        return new GostCsrBuilder(subjectDnDer, pubKey);
    }

    // ========================================================================
    // Fluent-сеттеры расширений (каждый делегирует в ExtensionsAccumulator)
    // ========================================================================

    public GostCsrBuilder sanDns(String... names) {
        ext.sanDns(names);
        return this;
    }

    public GostCsrBuilder sanIp(String... ips) {
        ext.sanIp(ips);
        return this;
    }

    public GostCsrBuilder sanRfc822Name(String... emails) {
        ext.sanRfc822Name(emails);
        return this;
    }

    public GostCsrBuilder sanUri(String... uris) {
        ext.sanUri(uris);
        return this;
    }

    public GostCsrBuilder sanDirectoryName(byte[]... dnDer) {
        ext.sanDirectoryName(dnDer);
        return this;
    }

    public GostCsrBuilder sanOtherName(String oid, byte[] valueDer) {
        ext.sanOtherName(oid, valueDer);
        return this;
    }

    public GostCsrBuilder sanUpn(String upn) {
        ext.sanUpn(upn);
        return this;
    }

    public GostCsrBuilder keyUsage(GostCertificateBuilder.KeyUsage... usages) {
        ext.keyUsage(usages);
        return this;
    }

    public GostCsrBuilder extendedKeyUsage(String... oids) {
        ext.extendedKeyUsage(oids);
        return this;
    }

    public GostCsrBuilder extendedKeyUsage(boolean critical, String... oids) {
        ext.extendedKeyUsage(critical, oids);
        return this;
    }

    public GostCsrBuilder basicConstraints(boolean isCA, Integer pathLen) {
        ext.basicConstraints(isCA, pathLen);
        return this;
    }

    /**
     * Добавляет расширение SubjectKeyIdentifier (RFC 5280 §4.2.1.2),
     * вычисленное как Streebog-256 от точки открытого ключа.
     */
    public GostCsrBuilder ski() {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(pubKey);
        ext.ski(org.rssys.gost.api.Digest.digest256(pointBytes));
        return this;
    }

    public GostCsrBuilder additionalExtensions(byte[] derExtensions) {
        ext.additionalExtensions(derExtensions);
        return this;
    }

    public GostCsrBuilder certificatePolicies(String... policyOids) {
        ext.certificatePolicies(policyOids);
        return this;
    }

    public GostCsrBuilder certificatePolicyInfos(CertificatePolicy... policies) {
        ext.certificatePolicyInfos(policies);
        return this;
    }

    /**
     * Добавляет произвольный атрибут PKCS#10 (RFC 2986 §4.1).
     *
     * <p>Значения передаются готовыми DER-элементами. В CSR они упорядочиваются по DER
     * ({@code SET OF}), порядок аргументов на результат не влияет. Массивы копируются:
     * последующее изменение массива вызывающим на уже принятый атрибут не влияет.</p>
     *
     * <p>Атрибуты {@code extensionRequest} и {@code challengePassword} добавляются своими
     * путями (сеттеры расширений и {@link #sign(GostSigner, char[])}): иначе у одного атрибута
     * было бы два источника.</p>
     *
     * @param oid       OID атрибута в точечной нотации
     * @param valuesDer значения: один и более, каждое — ровно один целый DER-элемент
     * @return this
     * @throws IllegalArgumentException если OID некорректен, значений нет, значение не является
     *     одним целым DER-элементом, OID уже добавлен либо это {@code extensionRequest} или
     *     {@code challengePassword}
     */
    public GostCsrBuilder attribute(String oid, byte[]... valuesDer) {
        Objects.requireNonNull(oid, "oid must not be null");
        Objects.requireNonNull(valuesDer, "valuesDer must not be null");
        // OID проверяется сразу, а не отложенно в sign(): опечатка должна всплыть у вызывающего
        byte[] oidDer = DerCodec.encodeOid(oid);
        if (Arrays.equals(oidDer, DerCodec.encodeOid(GostOids.ATTR_EXTENSION_REQUEST))
                || Arrays.equals(oidDer, DerCodec.encodeOid(GostOids.ATTR_CHALLENGE_PASSWORD))) {
            throw new IllegalArgumentException(
                    "Attribute " + oid + " has a dedicated API and cannot be added generically");
        }
        // Ключ - DER-кодировка OID, чтобы "1.2" и "01.2" считались одним атрибутом
        String key = new String(oidDer, StandardCharsets.ISO_8859_1);
        if (attributes.containsKey(key)) {
            throw new IllegalArgumentException("Duplicate attribute OID: " + oid);
        }
        if (valuesDer.length == 0) {
            throw new IllegalArgumentException("Attribute must have at least one value");
        }
        byte[][] copies = new byte[valuesDer.length][];
        for (int i = 0; i < valuesDer.length; i++) {
            copies[i] = requireSingleDerElement(valuesDer[i]);
        }
        attributes.put(key, DerCodec.encodeSequence(oidDer, DerCodec.encodeSetOf(copies)));
        return this;
    }

    private static byte[] requireSingleDerElement(byte[] value) {
        Objects.requireNonNull(value, "attribute value must not be null");
        // Теги 0x00 (конец содержимого BER) и 0xFF (зарезервирован) не бывают элементом DER
        if (value.length > 0 && (value[0] == 0x00 || value[0] == (byte) 0xFF)) {
            throw new IllegalArgumentException("Attribute value has a reserved DER tag");
        }
        int[] tlv = GostDerParser.readTlv(value, 0);
        if (tlv[1] != value.length) {
            throw new IllegalArgumentException(
                    "Attribute value must be exactly one DER element without trailing bytes");
        }
        return value.clone();
    }

    // ========================================================================
    // Sign-методы
    // ========================================================================

    /**
     * Подписывает CSR закрытым ключом, соответствующим открытому ключу из {@code create(...)}.
     * Proof-of-possession: проверяет, что {@code signer.getPublicKey()} совпадает с pubKey
     * из {@code create(...)} — иначе CSR не является доказательством владения ключом.
     *
     * @param signer подписант (может быть HSM-адаптером)
     * @return DER-кодированный CertificationRequest
     * @throws IllegalStateException если signer.getPublicKey() не совпадает с pubKey из create()
     */
    public byte[] sign(GostSigner signer) {
        return signInternal(signer, null);
    }

    /**
     * Подписывает CSR закрытым ключом в памяти.
     * Удобная обёртка через {@link GostSigner#of(PrivateKeyParameters)}.
     *
     * @param privKey ключ, соответствующий открытому ключу из {@code create(...)}
     * @return DER-кодированный CertificationRequest
     */
    public byte[] sign(PrivateKeyParameters privKey) {
        return sign(GostSigner.of(privKey));
    }

    /**
     * Подписывает CSR с атрибутом {@code challengePassword} (RFC 2985 §5.4.1).
     *
     * <p>Пароль передаётся на терминальной операции, а не хранится в сборщике: в EST он привязан
     * к моменту подписи в конкретной TLS-сессии (RFC 7030 §3.5), а не к структуре запроса.
     * Поэтому сборщик остаётся повторно используемым, а секрет живёт только на время вызова.</p>
     *
     * <p>Значение кодируется как {@code PrintableString}, если все знаки входят в алфавит
     * X.680 (при записи он проверяется строго), иначе как {@code UTF8String}. Требования: от 1
     * до 255 знаков (code points), содержимое не более 255 байт (RFC 7030 §3.5), никаких
     * управляющих знаков ({@link Character#CONTROL}) и одиночных суррогатов. Пароль не
     * превращается в {@code String}.</p>
     *
     * <p><b>Гигиена, а не гарантия:</b> промежуточные байты пароля, TBS и хеш затираются при
     * любом исходе вызова. Переданный {@code password} библиотека не затирает и не изменяет:
     * им владеет вызывающий. Готовый DER содержит пароль всегда (это wire-формат), поэтому
     * сам CSR нужно хранить как секрет до выпуска сертификата.</p>
     *
     * @param signer   подписант (может быть HSM-адаптером)
     * @param password пароль, не {@code null}
     * @return DER-кодированный CertificationRequest
     * @throws IllegalArgumentException если пароль {@code null}, пуст или нарушает требования
     * @throws IllegalStateException если signer.getPublicKey() не совпадает с pubKey из create();
     *     эта проверка идёт раньше проверки содержимого пароля (но после проверки на {@code null}),
     *     поэтому при неверном ключе и плохом пароле выбрасывается именно она
     */
    public byte[] sign(GostSigner signer, char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("challengePassword must not be null");
        }
        return signInternal(signer, password);
    }

    /**
     * Подписывает CSR с {@code challengePassword} закрытым ключом в памяти.
     *
     * @param privKey  ключ, соответствующий открытому ключу из {@code create(...)}
     * @param password пароль, см. {@link #sign(GostSigner, char[])}
     * @return DER-кодированный CertificationRequest
     */
    public byte[] sign(PrivateKeyParameters privKey, char[] password) {
        return sign(GostSigner.of(privKey), password);
    }

    // ========================================================================
    // Приватные методы
    // ========================================================================

    private byte[] signInternal(GostSigner signer, char[] password) {
        Objects.requireNonNull(signer, "signer must not be null");
        ECParameters params = signer.getParams();
        if (!Arrays.equals(
                GostDerCodec.subjectPublicKeyPointBytes(pubKey),
                GostDerCodec.subjectPublicKeyPointBytes(signer.getPublicKey()))) {
            throw new IllegalStateException(
                    "CSR proof-of-possession mismatch: signer public key does not "
                            + "match the subject public key from create()");
        }
        // Все промежуточные буферы, в которых мог оказаться пароль, затираются в finally
        // при любом исходе: иначе после ошибки подписи они остались бы в куче до сборки мусора.
        List<byte[]> scratch = new ArrayList<>();
        byte[] tbs = null;
        byte[] hash = null;
        try {
            byte[] passwordAttribute = null;
            if (password != null) {
                byte[] passwordValue = ChallengePasswordCodec.encode(password);
                scratch.add(passwordValue);
                byte[] valueSet = DerCodec.encodeSet(passwordValue);
                scratch.add(valueSet);
                passwordAttribute =
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.ATTR_CHALLENGE_PASSWORD), valueSet);
                scratch.add(passwordAttribute);
            }
            tbs = buildTbsCertRequest(passwordAttribute, scratch);
            hash = GostSignatureHelper.doHash(tbs, params.hlen);
            byte[] sigValue = GostSignatureHelper.signHashChecked(hash, signer);
            return DerCodec.encodeSequence(
                    tbs,
                    GostSignatureHelper.buildAlgId(params),
                    DerCodec.encodeBitString(sigValue));
        } finally {
            for (byte[] buffer : scratch) {
                Arrays.fill(buffer, (byte) 0);
            }
            if (tbs != null) {
                Arrays.fill(tbs, (byte) 0);
            }
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    private byte[] buildTbsCertRequest(byte[] passwordAttribute, List<byte[]> scratch) {
        byte[] attributesBlock = buildAttributesBlock(passwordAttribute, scratch);
        scratch.add(attributesBlock);
        return DerCodec.encodeSequence(
                DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {0x00}),
                subjectDnDer,
                GostDerCodec.encodePublicKey(pubKey),
                attributesBlock);
    }

    /**
     * Собирает {@code [0] IMPLICIT SET OF Attribute}. Тег SET замещается тегом {@code [0]}
     * (RFC 2986, IMPLICIT TAGS), поэтому содержимое — конкатенация атрибутов без внешнего SET,
     * а DER-порядок SET OF обеспечивается сортировкой самих элементов.
     */
    private byte[] buildAttributesBlock(byte[] passwordAttribute, List<byte[]> scratch) {
        List<byte[]> all = new ArrayList<>();
        if (ext.hasAnyExtensions()) {
            all.add(buildExtensionRequestAttribute());
        }
        all.addAll(attributes.values());
        if (passwordAttribute != null) {
            all.add(passwordAttribute);
        }
        if (all.isEmpty()) {
            return DerCodec.encodeContextConstructed(0, new byte[0]);
        }
        byte[][] sorted = all.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        byte[] content = DerCodec.concat(sorted);
        scratch.add(content);
        return DerCodec.encodeContextConstructed(0, content);
    }

    private byte[] buildExtensionRequestAttribute() {
        try {
            ByteArrayOutputStream extStream = new ByteArrayOutputStream();
            ext.writeExtensions(extStream);
            if (ext.additionalExtensions != null) {
                extStream.write(ext.additionalExtensions);
            }

            byte[] extensions = DerCodec.encodeSequence(extStream.toByteArray());
            byte[] attrValues = DerCodec.encodeSet(extensions);
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.ATTR_EXTENSION_REQUEST), attrValues);
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
    }
}
