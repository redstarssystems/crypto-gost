package org.rssys.gost.tls13.examples;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Вспомогательные методы для примеров — тонкие делегаты в {@link GostCertificateBuilder}.
 *
 * <p>После плана 084: вся логика построения сертификатов и расширений
 * вынесена в {@code pkix.cert}. Здесь остались только делегаты
 * для обратной совместимости примеров.</p>
 */
public final class ExampleUtils {

    private static final AtomicInteger certCounter = new AtomicInteger(0);

    private ExampleUtils() {}

    public record CertBundle(
            GostCertificate cert, PrivateKeyParameters priv, PublicKeyParameters pub) {}

    // ---- DN ----

    public static byte[] buildDN(String cn) {
        return GostDnParser.encodeDn("CN=" + cn);
    }

    // ---- Сертификаты ----

    public static GostCertificate createCert(
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters subjectPub,
            ECParameters params,
            byte[] issuerDn,
            byte[] subjectDn,
            byte[] exts)
            throws Exception {
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(subjectPub)
                        .notBefore("20250101120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(exts)
                        .issuerDn(issuerDn)
                        .buildTbs();
        return GostCertificateBuilder.assembleCert(tbs, issuerPriv, params);
    }

    public static CertBundle createRootCABundle() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = buildDN("Example Root CA " + (certCounter.incrementAndGet()));
        byte[] bcExt = buildBasicConstraintsExt(true, null);
        GostCertificate cert = createCert(kp.getPrivate(), kp.getPublic(), params, dn, dn, bcExt);
        return new CertBundle(cert, kp.getPrivate(), kp.getPublic());
    }

    public static CertBundle createServerCertBundle(
            GostCertificate ca, PrivateKeyParameters caPriv, PublicKeyParameters caPub)
            throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = buildDN("Example Server " + (certCounter.incrementAndGet()));
        byte[] sanExt = buildSanExt(new String[] {"localhost"}, null);
        byte[] kuExt = buildKeyUsageExt(new byte[] {(byte) 0x80});
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write(sanExt);
        buf.write(kuExt);
        GostCertificate cert =
                createCert(
                        caPriv,
                        kp.getPublic(),
                        params,
                        ca.getSubjectDnBytes(),
                        subjectDn,
                        buf.toByteArray());
        return new CertBundle(cert, kp.getPrivate(), kp.getPublic());
    }

    public static CertBundle createServerCertBundle(CertBundle ca) throws Exception {
        return createServerCertBundle(ca.cert(), ca.priv(), ca.pub());
    }

    /**
     * Сертификат клиента + приватный ключ (подписан CA).
     */
    public static CertBundle createClientCertBundle(
            GostCertificate ca, PrivateKeyParameters caPriv, PublicKeyParameters caPub)
            throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = buildDN("Example Client " + (certCounter.incrementAndGet()));
        byte[] kuExt = buildKeyUsageExt(new byte[] {(byte) 0x80});
        byte[] ekuExt = buildEkuExt(GostOids.EXT_CLIENT_AUTH);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write(kuExt);
        buf.write(ekuExt);
        GostCertificate cert =
                createCert(
                        caPriv,
                        kp.getPublic(),
                        params,
                        ca.getSubjectDnBytes(),
                        subjectDn,
                        buf.toByteArray());
        return new CertBundle(cert, kp.getPrivate(), kp.getPublic());
    }

    public static CertBundle createClientCertBundle(CertBundle ca) throws Exception {
        return createClientCertBundle(ca.cert(), ca.priv(), ca.pub());
    }

    // ---- TBS ----

    public static byte[] buildTbs(
            PublicKeyParameters pub,
            ECParameters params,
            byte[] issuerDn,
            byte[] subjectDn,
            byte[] additionalExtensions)
            throws IOException {
        return GostCertificateBuilder.create(params, subjectDn)
                .publicKey(pub)
                .notBefore("20250101120000Z")
                .notAfter("21060101120000Z")
                .additionalExtensions(additionalExtensions)
                .issuerDn(issuerDn)
                .buildTbs();
    }

    // ---- Расширения (делегаты) ----

    public static byte[] buildBasicConstraintsExt(boolean isCA, Integer pathLen)
            throws IOException {
        return GostCertificateBuilder.buildBasicConstraintsExtension(isCA, pathLen);
    }

    public static byte[] buildKeyUsageExt(byte[] kuBits) {
        return GostCertificateBuilder.buildKeyUsageExtension(kuBits);
    }

    public static byte[] buildEkuExt(String... oids) throws IOException {
        return GostCertificateBuilder.buildEkuExtension(oids);
    }

    public static byte[] buildSanExt(String[] dnsNames, String[] ipAddresses) throws IOException {
        return GostCertificateBuilder.buildSanExtension(dnsNames, ipAddresses);
    }
}
