package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Вспомогательные методы для примеров — построение сертификатов X.509
 * и DER-кодирование вручную.
 * <p>
 * Единственная точка сборки сертификатов в модуле examples/tls.
 * Использует {@link DerCodec} для DER-примитивов, {@link KeyGenerator}
 * для генерации ключей, {@link Signature} для подписи TBSCertificate.
 */
public final class ExampleUtils {

    private static final AtomicInteger certCounter = new AtomicInteger(0);

    private ExampleUtils() {}

    /**
     * Результат создания сертификата — сам сертификат и связанные с ним ключи.
     * <p>
     * В отличие от {@link #createRootCA()} / {@link #createServerCert(TlsCertificate, PrivateKeyParameters, PublicKeyParameters)},
     * возвращает ключи (нужны для JSSE-примеров, где ключи подставляются в KeyManager).
     */
    public record CertBundle(
            TlsCertificate cert,
            PrivateKeyParameters priv,
            PublicKeyParameters pub
    ) {}

    // ---- DER ----

    static byte[] derTlv(int tag, byte[] content) {
        return DerCodec.encodeTlv(tag, content);
    }

    static byte[] derSequence(byte[]... elements) {
        return DerCodec.encodeSequence(elements);
    }

    static byte[] derOid(String oidStr) {
        return DerCodec.encodeOid(oidStr);
    }

    static byte[] derBitString(byte[] content) {
        return DerCodec.encodeBitString(content);
    }

    static byte[] derTime(String time) {
        int tag = time.length() == 13 ? DerCodec.TAG_UTC_TIME : DerCodec.TAG_GENERALIZED_TIME;
        return derTlv(tag, time.getBytes(StandardCharsets.US_ASCII));
    }

    // ---- DN ----

    /**
     * Строит DER-encoded Distinguished Name из CN.
     * <p>
     * Формат: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String(cn) } } }
     * Одно RDN (CommonName) — достаточно для демо-сертификатов.
     */
    public static byte[] buildDN(String cn) {
        byte[] attr = derSequence(derOid(GostOids.ATTR_CN),
                derTlv(DerCodec.TAG_UTF8_STRING, cn.getBytes(StandardCharsets.UTF_8)));
        return derSequence(derTlv(DerCodec.TAG_SET, attr));
    }

    // ---- Подпись ----

    /**
     * Хэширует данные через Streebog (256 или 512 бит).
     * Выбор дайджеста определяется hlen — длиной хэша в байтах.
     */
    static byte[] doHash(byte[] data, int hlen) {
        if (hlen == TlsConstants.STREEBOG_256_HASH_LEN) return Digest.digest256(data);
        if (hlen == TlsConstants.STREEBOG_512_HASH_LEN) return Digest.digest512(data);
        throw new IllegalArgumentException("Unsupported hash length: " + hlen);
    }

    /**
     * AlgorithmIdentifier для ГОСТ-подписи.
     * <p>
     * Формат: SEQUENCE { signwithdigest OID } — без parameters (RFC 9215 §4.2).
     * signOid выбирается по hlen (32 → SIGN_ALG_256, 64 → SIGN_ALG_512).
     */
    public static byte[] buildAlgId(ECParameters params) {
        String signOid = params.hlen == TlsConstants.STREEBOG_256_HASH_LEN ? GostOids.SIGN_ALG_256 : GostOids.SIGN_ALG_512;
        return derSequence(derOid(signOid));
    }

    // ---- Сертификаты ----

    /**
     * AlgorithmIdentifier с фиксированным Streebog256/256A.
     * Используется в {@link #buildTbs(PublicKeyParameters, ECParameters, byte[], byte[], byte[])}
     * когда нужно переиспользовать подпись и у нас нет params.
     */
    static byte[] buildAlgIdStreebog256() {
        return derSequence(derOid(GostOids.SIGN_ALG_256));
    }

    /**
     * Строит TBSCertificate (RFC 5280 §4.1.2).
     * <p>
     * SerialNumber фиксирован (1) — для демо-сертификатов уникальность не нужна.
     * Validity: 2025-01-01 — 2106-01-01 (широкое окно, не протухнет).
     * Расширения передаются сырыми DER-байтами — {@code buildTbs} уже оборачивает их
     * в контейнер extensions [3].
     */
    public static byte[] buildTbs(PublicKeyParameters pub, ECParameters params,
                           byte[] issuerDn, byte[] subjectDn,
                           byte[] additionalExtensions) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // v3 — обязательный контейнер [0] EXPLICIT INTEGER
        out.write(DerCodec.encodeContextConstructed(0, DerCodec.encodeInteger(2)));
        out.write(DerCodec.encodeInteger(1));
        out.write(buildAlgId(params));
        out.write(issuerDn);
        out.write(derSequence(derTime("20250101120000Z"), derTime("21060101120000Z")));
        out.write(subjectDn);
        byte[] spki = GostDerCodec.encodePublicKey(pub);
        out.write(spki, 0, spki.length);
        if (additionalExtensions != null) {
            byte[] extensionsSeq = DerCodec.encodeSequence(additionalExtensions);
            out.write(DerCodec.encodeContextConstructed(3, extensionsSeq));
        }
        return derSequence(out.toByteArray());
    }

    /**
     * Собирает подписанный сертификат X.509: TBS → хэш → подпись → обёртка.
     * <p>
     * Схема: SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING signature }
     * Подпись ставится по схеме signHash (не sign) — хэшируем TBS отдельно.
     */
    public static TlsCertificate createCert(PrivateKeyParameters issuerPriv,
                                      PublicKeyParameters issuerPub,
                                      PublicKeyParameters subjectPub,
                                      ECParameters params,
                                      byte[] issuerDn, byte[] subjectDn,
                                      byte[] exts) throws Exception {
        byte[] tbs = buildTbs(subjectPub, params, issuerDn, subjectDn, exts);
        int hlen = params.hlen;
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, issuerPriv);
        byte[] certDer = derSequence(tbs, buildAlgId(params), derBitString(sig));
        return new TlsCertificate(certDer);
    }

    /**
     * Создаёт самоподписанный корневой CA (BasicConstraints: cA=TRUE).
     * <p>
     * Возвращает только сертификат, ключ отбрасывается — в TLS-примерах
     * CA-ключ больше не нужен после подписания дочерних сертификатов.
     * Если нужны ключи — используй {@link #createRootCABundle()}.
     */
    public static TlsCertificate createRootCA() throws Exception {
        return createRootCABundle().cert();
    }

    /**
     * Создаёт корневой CA и возвращает его вместе с ключами.
     * <p>
     * В отличие от {@link #createRootCA()} не теряет закрытый ключ —
     * нужен для JSSE-примеров, где ключ подставляется в KeyManager.
     */
    public static CertBundle createRootCABundle() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = buildDN("Example Root CA " + (certCounter.incrementAndGet()));
        byte[] bcExt = buildBasicConstraintsExt(true, null);
        TlsCertificate cert = createCert(kp.getPrivate(), kp.getPublic(),
                kp.getPublic(), params, dn, dn, bcExt);
        return new CertBundle(cert, kp.getPrivate(), kp.getPublic());
    }

    /**
     * Создаёт серверный сертификат (SAN localhost, KU digitalSignature),
     * подписанный переданным CA.
     * <p>
     * Возвращает только сертификат — ключ не возвращается.
     * Для получения ключа используй {@link #createServerCertBundle(CertBundle)}.
     */
    public static TlsCertificate createServerCert(TlsCertificate ca, PrivateKeyParameters caPriv,
                                                    PublicKeyParameters caPub) throws Exception {
        return createServerCertBundle(ca, caPriv, caPub).cert();
    }

    /**
     * Создаёт серверный сертификат и возвращает его вместе с ключами.
     * <p>
     * Сертификат содержит SAN localhost и KU digitalSignature.
     * Issuer DN берётся из CA-сертификата (ca.getSubjectDnBytes()).
     * Ключи сервера генерируются и возвращаются — нужны для JSSE KeyManager.
     */
    public static CertBundle createServerCertBundle(TlsCertificate ca, PrivateKeyParameters caPriv,
                                                     PublicKeyParameters caPub) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = buildDN("Example Server " + (certCounter.incrementAndGet()));
        byte[] sanExt = buildSanExt(new String[]{"localhost"}, null);
        byte[] kuExt = buildKeyUsageExt(new byte[]{(byte) 0x80});
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write(sanExt);
        buf.write(kuExt);
        TlsCertificate cert = createCert(caPriv, caPub, kp.getPublic(), params,
                ca.getSubjectDnBytes(), subjectDn, buf.toByteArray());
        return new CertBundle(cert, kp.getPrivate(), kp.getPublic());
    }

    /** Удобная перегрузка, принимающая {@link CertBundle} вместо отдельных ключей. */
    public static CertBundle createServerCertBundle(CertBundle ca) throws Exception {
        return createServerCertBundle(ca.cert(), ca.priv(), ca.pub());
    }

    /**
     * Создаёт клиентский сертификат (KU digitalSignature, EKU clientAuth),
     * подписанный переданным CA.
     */
    public static TlsCertificate createClientCert(TlsCertificate ca, PrivateKeyParameters caPriv,
                                                    PublicKeyParameters caPub) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = buildDN("Example Client " + (certCounter.incrementAndGet()));
        byte[] kuExt = buildKeyUsageExt(new byte[]{(byte) 0x80});
        byte[] ekuExt = buildEkuExt(GostOids.EXT_CLIENT_AUTH);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write(kuExt);
        buf.write(ekuExt);
        return createCert(caPriv, caPub, kp.getPublic(), params,
                ca.getSubjectDnBytes(), subjectDn, buf.toByteArray());
    }

    // ---- Расширения ----

    /**
     * BasicConstraints (2.5.29.19).
     * <p>
     * critical-флаг выставляется только для CA-сертификатов — не-CA
     * сертификаты не получают critical, чтобы не ломать старые парсеры,
     * которые не знают X.509 v3 расширений (RFC 5280 §4.2.1.9).
     */
    public static byte[] buildBasicConstraintsExt(boolean isCA, Integer pathLen) throws IOException {
        ByteArrayOutputStream bc = new ByteArrayOutputStream();
        if (isCA) bc.write(derTlv(0x01, new byte[]{(byte) 0xFF}));
        if (pathLen != null) bc.write(derTlv(0x02, new byte[]{pathLen.byteValue()}));
        byte[] extValue = derOctetString(derSequence(bc.toByteArray()));
        // critical выставляем только если isCA — не-CA сертификаты без critical
        return derSequence(derOid(GostOids.EXT_BC), isCA ? derTlv(0x01, new byte[]{(byte) 0xFF}) : new byte[0], extValue);
    }

    /**
     * KeyUsage (2.5.29.15).
     * <p>
     * Всегда critical — RFC 5280 требует для всех сертификатов, содержащих
     * открытый ключ, используемый для проверки подписи.
     */
    public static byte[] buildKeyUsageExt(byte[] kuBits) {
        byte[] extValue = derOctetString(derBitString(kuBits));
        return derSequence(derOid(GostOids.EXT_KU), derTlv(0x01, new byte[]{(byte) 0xFF}), extValue);
    }

    /**
     * ExtendedKeyUsage (2.5.29.37).
     * <p>
     * Принимает массив OID (serverAuth, clientAuth) — для серверных
     * и клиентских сертификатов. Non-critical по RFC 5280.
     */
    public static byte[] buildEkuExt(String... oids) throws IOException {
        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        for (String oid : oids) seq.write(derOid(oid));
        byte[] extValue = derOctetString(derSequence(seq.toByteArray()));
        return derSequence(derOid(GostOids.EXT_EKU), extValue);
    }

    /**
     * SubjectAltName (2.5.29.17).
     * <p>
     * Принимает DNS-имена (тег 0x82) и IP-адреса (тег 0x87).
     * DNS-имена передаются как ASCII — так требует RFC 5280 §4.2.1.6.
     * IP-адреса конвертируются через InetAddress.getByName() для поддержки IPv4 и IPv6.
     */
    public static byte[] buildSanExt(String[] dnsNames, String[] ipAddresses) throws IOException {
        ByteArrayOutputStream gn = new ByteArrayOutputStream();
        if (dnsNames != null) {
            for (String name : dnsNames) {
                gn.write(derTlv(0x82, name.getBytes(StandardCharsets.US_ASCII)));
            }
        }
        if (ipAddresses != null) {
            for (String ip : ipAddresses) {
                gn.write(derTlv(0x87, java.net.InetAddress.getByName(ip).getAddress()));
            }
        }
        byte[] extValue = derOctetString(derSequence(gn.toByteArray()));
        return derSequence(derOid(GostOids.EXT_SAN), extValue);
    }

    static byte[] derOctetString(byte[] data) {
        return DerCodec.encodeOctetString(data);
    }

    static byte[] buildOcspExt() throws IOException {
        return derSequence(derOid(GostOids.EXT_AIA), derOid(GostOids.OCSP_AD));
    }
}
