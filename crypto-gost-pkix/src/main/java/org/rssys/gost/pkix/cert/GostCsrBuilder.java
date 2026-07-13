package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
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
 * <p>Поддерживает атрибут {@code extensionRequest} (PKCS#9 §5.4.1) — подписчик может
 * запросить конкретные расширения X.509v3 (SAN, KeyUsage, ExtendedKeyUsage,
 * BasicConstraints, SubjectKeyIdentifier) через fluent-сеттеры. Без вызова
 * fluent-сеттеров атрибутный блок пустой, что разрешено RFC 2986 §4.1.</p>
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
        Objects.requireNonNull(signer, "signer must not be null");
        ECParameters params = signer.getParams();
        if (!Arrays.equals(
                GostDerCodec.subjectPublicKeyPointBytes(pubKey),
                GostDerCodec.subjectPublicKeyPointBytes(signer.getPublicKey()))) {
            throw new IllegalStateException(
                    "CSR proof-of-possession mismatch: signer public key does not "
                            + "match the subject public key from create()");
        }
        byte[] tbs = buildTbsCertRequest();
        byte[] hash = GostSignatureHelper.doHash(tbs, params.hlen);
        byte[] sigValue = GostSignatureHelper.signHashChecked(hash, signer);
        return DerCodec.encodeSequence(
                tbs, GostSignatureHelper.buildAlgId(params), DerCodec.encodeBitString(sigValue));
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

    // ========================================================================
    // Приватные методы
    // ========================================================================

    private byte[] buildTbsCertRequest() {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] spki = GostDerCodec.encodePublicKey(pubKey);
            out.write(DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {0x00}));
            out.write(subjectDnDer);
            out.write(spki);
            if (ext.hasAnyExtensions()) {
                out.write(buildExtensionRequestAttribute());
            } else {
                out.write(DerCodec.encodeContextConstructed(0, new byte[0]));
            }
            return DerCodec.encodeSequence(out.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
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
            byte[] extensionRequestAttr =
                    DerCodec.encodeSequence(
                            DerCodec.encodeOid(GostOids.ATTR_EXTENSION_REQUEST), attrValues);

            return DerCodec.encodeContextConstructed(0, extensionRequestAttr);
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
    }
}
