package org.rssys.gost.crossval.cms;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.GostPkcs7;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Кросс-валидация записи certs-only {@code .p7b} (SignedData без подписантов),
 * формируемого {@link GostPkcs7#buildCertsOnly}.
 *
 * <p>Контейнер, порождённый библиотекой, должен читаться сторонними стеками:
 * <ul>
 *   <li>OpenSSL — {@code pkcs7 -print_certs} (разбор X.509-обёртки не требует
 *       GOST-engine, поэтому проходит и на ванильном OpenSSL);</li>
 *   <li>BouncyCastle — {@code CMSSignedData.getCertificates()} (структурный разбор
 *       CMS без криптографической верификации подписи).</li>
 * </ul>
 * Подписи в certs-only контейнере нет, поэтому обе стороны проверяют лишь то, что
 * все вложенные сертификаты корректно извлекаются и совпадают с исходными.
 */
@DisplayName("certs-only .p7b: кросс-валидация записи с OpenSSL и BouncyCastle")
class GostP7bCertsOnlyCrossValidationTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate certAlpha;
    private static GostCertificate certBeta;
    private static GostCertificate certGamma;
    private static GostCrl testCrl;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        certAlpha = newCert("P7B Alpha", 2001);
        certBeta = newCert("P7B Beta", 2002);
        certGamma = newCert("P7B Gamma", 2003);

        KeyPair crlKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] crlIssuerDn = GostDnParser.encodeDn("CN=CRL Issuer");
        byte[] crlDer =
                GostCrlBuilder.create(crlIssuerDn)
                        .nextUpdate("270601120000Z")
                        .sign(crlKp.getPrivate());
        testCrl = GostCrl.fromDer(crlDer);
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("OpenSSL pkcs7 -print_certs читает все сертификаты из certs-only .p7b")
    void opensslReadsCertsOnly() throws Exception {
        byte[] p7b = GostPkcs7.buildCertsOnly(certAlpha, certBeta, certGamma);
        Path dir = Files.createTempDirectory("p7b-openssl");
        Path p7bPath = dir.resolve("bundle.p7b");
        Files.write(p7bPath, p7b);

        // -print_certs разбирает только X.509-обёртку контейнера, GOST-engine не нужен
        String out =
                run(
                        opensslBinary(),
                        "pkcs7",
                        "-inform",
                        "DER",
                        "-in",
                        p7bPath.toString(),
                        "-print_certs",
                        "-noout");

        assertTrue(out.contains("P7B Alpha"), "OpenSSL должен показать subject Alpha, вывод: " + out);
        assertTrue(out.contains("P7B Beta"), "OpenSSL должен показать subject Beta, вывод: " + out);
        assertTrue(out.contains("P7B Gamma"), "OpenSSL должен показать subject Gamma, вывод: " + out);
    }

    @Test
    @DisplayName("BouncyCastle CMSSignedData извлекает те же сертификаты (по множеству серийников)")
    void bouncyCastleReadsCertsOnly() throws Exception {
        byte[] p7b = GostPkcs7.buildCertsOnly(certAlpha, certBeta, certGamma);

        CMSSignedData sd = new CMSSignedData(p7b);

        assertTrue(
                sd.getSignerInfos().getSigners().isEmpty(),
                "certs-only контейнер не должен содержать подписантов");

        Store<X509CertificateHolder> store = sd.getCertificates();
        Set<BigInteger> serials = new HashSet<>();
        for (X509CertificateHolder holder : store.getMatches((Selector<X509CertificateHolder>) null)) {
            serials.add(holder.getSerialNumber());
        }

        assertEquals(
                Set.of(
                        certAlpha.getSerialNumberBigInt(),
                        certBeta.getSerialNumberBigInt(),
                        certGamma.getSerialNumberBigInt()),
                serials,
                "BC должен извлечь ровно исходное множество серийников");
    }

    @Test
    @DisplayName("BouncyCastle читает certs-only .p7b с одним сертификатом")
    void bouncyCastleReadsSingleCert() throws Exception {
        byte[] p7b = GostPkcs7.buildCertsOnly(certAlpha);

        CMSSignedData sd = new CMSSignedData(p7b);

        Store<X509CertificateHolder> store = sd.getCertificates();
        var matches = store.getMatches((Selector<X509CertificateHolder>) null);
        assertEquals(1, matches.size(), "ровно один сертификат");
        assertEquals(
                certAlpha.getSerialNumberBigInt(),
                matches.iterator().next().getSerialNumber(),
                "серийник должен совпасть");
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("OpenSSL pkcs7 -print_certs читает certs-only .p7b с CRL (crls [1] не мешает разбору)")
    void opensslReadsCertsOnlyWithCrl() throws Exception {
        byte[] p7b = GostPkcs7.buildCertsOnly(List.of(testCrl), certAlpha, certBeta, certGamma);
        Path dir = Files.createTempDirectory("p7b-openssl-crl");
        Path p7bPath = dir.resolve("bundle_crl.p7b");
        Files.write(p7bPath, p7b);

        String out =
                run(
                        opensslBinary(),
                        "pkcs7",
                        "-inform",
                        "DER",
                        "-in",
                        p7bPath.toString(),
                        "-print_certs",
                        "-noout");

        assertTrue(out.contains("P7B Alpha"), "OpenSSL должен показать subject Alpha, вывод: " + out);
        assertTrue(out.contains("P7B Beta"), "OpenSSL должен показать subject Beta, вывод: " + out);
        assertTrue(out.contains("P7B Gamma"), "OpenSSL должен показать subject Gamma, вывод: " + out);
    }

    @Test
    @DisplayName("GostPkcs7.extractCertificates не ломается при наличии crls [1]")
    void extractCertificatesWithCrl() throws Exception {
        byte[] p7b = GostPkcs7.buildCertsOnly(List.of(testCrl), certAlpha, certBeta);

        List<GostCertificate> certs = GostPkcs7.extractCertificates(p7b);
        Set<BigInteger> serials = new HashSet<>();
        for (GostCertificate c : certs) {
            serials.add(c.getSerialNumberBigInt());
        }
        assertEquals(
                Set.of(certAlpha.getSerialNumberBigInt(), certBeta.getSerialNumberBigInt()),
                serials,
                "Сертификаты должны корректно извлечься при наличии crls [1]");
    }

    private static GostCertificate newCert(String cn, int serial) {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        return GostCertificateBuilder.create(PARAMS, "CN=" + cn + ",O=Test Org,C=RU")
                .publicKey(kp.getPublic())
                .serial(BigInteger.valueOf(serial))
                .notBefore("20250101000000Z")
                .notAfter("21250101000000Z")
                .sign(kp.getPrivate());
    }

    static boolean opensslAvailable() {
        return Files.exists(Path.of(opensslBinary()));
    }

    static String opensslBinary() {
        return System.getProperty("openssl.binary", "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    static String run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String o = new String(p.getInputStream().readAllBytes());
        p.waitFor();
        return o;
    }
}
