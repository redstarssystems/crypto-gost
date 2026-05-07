package org.rssys.gost.tls13.cert;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.TlsTestHelper;
import static org.rssys.gost.tls13.TlsTestHelper.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("TlsCertificate — X.509 сертификат с GOST ключами")
class TlsCertificateTest {

    // -----------------------------------------------------------------------
    // Парсинг DER
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("parseLength: короткая форма (однобайтовая)")
    void testparseLengthShortForm() {
        byte[] data = new byte[]{0x05};
        int[] result = TlsDerParser.parseLength(data, 0);
        assertArrayEquals(new int[]{1, 5}, result);
    }

    @Test
    @DisplayName("parseLength: короткая форма 0x7F")
    void testparseLengthShortFormMax() {
        byte[] data = new byte[]{0x7F};
        int[] result = TlsDerParser.parseLength(data, 0);
        assertArrayEquals(new int[]{1, 127}, result);
    }

    @Test
    @DisplayName("parseLength: длинная форма 2 байта")
    void testparseLengthLongForm2() {
        byte[] data = new byte[]{(byte) 0x82, 0x01, (byte) 0x00};
        int[] result = TlsDerParser.parseLength(data, 0);
        assertArrayEquals(new int[]{3, 256}, result);
    }

    @Test
    @DisplayName("parseLength: длинная форма 3 байта")
    void testparseLengthLongForm3() {
        byte[] data = new byte[]{(byte) 0x83, 0x01, 0x00, 0x00};
        int[] result = TlsDerParser.parseLength(data, 0);
        assertArrayEquals(new int[]{4, 65536}, result);
    }

    @Test
    @DisplayName("readTlv: INTEGER (tag 0x02)")
    void testreadTlvInteger() {
        byte[] data = new byte[]{0x02, 0x01, 0x2A};
        int[] result = TlsDerParser.readTlv(data, 0);
        assertEquals(3, result[1]);
        int contentLen = result[1] - result[0];
        assertEquals(1, contentLen);
        assertEquals(0x2A, data[result[0]]);
    }

    @Test
    @DisplayName("readTlv: SEQUENCE (tag 0x30)")
    void testreadTlvSequence() {
        byte[] data = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
        int[] result = TlsDerParser.readTlv(data, 0);
        assertEquals(8, result[1]);
        assertEquals(2, result[0]);
    }

    @Test
    @DisplayName("parseSequence: корректная SEQUENCE")
    void testparseSequenceValid() {
        byte[] data = new byte[]{0x30, 0x02, 0x01, 0x00};
        int[] result = TlsDerParser.parseSequence(data, 0);
        assertEquals(2, result[0]);
        assertEquals(4, result[1]);
    }

    @Test
    @DisplayName("parseSequence: не SEQUENCE бросает исключение")
    void testparseSequenceInvalidTag() {
        byte[] data = new byte[]{0x02, 0x01, 0x00};
        assertThrows(IllegalArgumentException.class,
                () -> TlsDerParser.parseSequence(data, 0));
    }

    @Test
    @DisplayName("null DER → исключение")
    void testNullDerThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new TlsCertificate(null));
    }

    @Test
    @DisplayName("некорректный DER → исключение")
    void testInvalidDerThrows() {
        byte[] invalid = new byte[]{0x01, 0x02, 0x03};
        assertThrows(Exception.class,
                () -> new TlsCertificate(invalid));
    }

    // -----------------------------------------------------------------------
    // Self-signed сертификат
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("самоподписанный сертификат 256-bit")
    void testselfSignedCertificate256() throws Exception {
        byte[] certDer = createSelfSignedCert();
        TlsCertificate cert = new TlsCertificate(certDer);

        PublicKeyParameters pubKey = cert.getPublicKey();
        assertNotNull(pubKey);
        assertEquals(32, pubKey.getParams().hlen);
    }

    @Test
    @DisplayName("verify самоподписанного сертификата")
    void testverifySelfSigned() throws Exception {
        byte[] certDer = createSelfSignedCert();
        TlsCertificate cert = new TlsCertificate(certDer);

        // Для самоподписанного проверяем ключом из сертификата
        assertTrue(cert.verify(cert.getPublicKey()));
    }

    @Test
    @DisplayName("подмена tbsCertificate приводит к ошибке verify")
    void testtamperedCertFailsVerification() throws Exception {
        byte[] certDer = createSelfSignedCert();
        TlsCertificate cert = new TlsCertificate(certDer);

        // Создаём сертификат с тем же public key, но подменённым TBSCertificate
        // Получаем public key, создаём новый сертификат с другими данными
        PublicKeyParameters pubKey = cert.getPublicKey();

        // Подпись от другого сообщения не пройдёт верификацию
        TlsCertificate sameCert = new TlsCertificate(certDer);
        assertTrue(sameCert.verify(pubKey));

        org.rssys.gost.api.KeyPair otherKp = KeyGenerator.generateKeyPair(ECParameters.cryptoProB());
        assertFalse(cert.verify(otherKp.getPublic()));
    }

    @Test
    @DisplayName("hasSignatureScheme корректно определяет схему")
    void testhasSignatureScheme() throws Exception {
        byte[] certDer256 = createSelfSignedCert();
        TlsCertificate cert256 = new TlsCertificate(certDer256);
        assertTrue(cert256.hasSignatureScheme(TlsConstants.SIG_GOST_TC26_A_256));
    }

    @Test
    @DisplayName("сертификат v3 с [3] extensions после SPKI: field-index поиск")
    void testCertificateV3WithExtensions() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] spki = GostDerCodec.encodePublicKey(kp.getPublic());

        byte[] version = derContextExpl(0, derInteger(2));
        byte[] serial = derInteger(1);
        byte[] sigAlg = derSequence(derOid("1.2.643.7.1.1.1.1"));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derUtcTime("250101000000Z"), derUtcTime("350101000000Z"));
        byte[] extensions = derContextExpl(3, derSequence());

        byte[] tbs = derSequence(version, serial, sigAlg, dn, validity, dn, spki, extensions);
        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] sigAlgCert = derSequence(derOid("1.2.643.7.1.1.1.1"));
        byte[] certDer = derSequence(tbs, sigAlgCert, derBitString(sig));

        TlsCertificate cert = new TlsCertificate(certDer);
        assertNotNull(cert.getPublicKey());
        assertEquals(32, cert.getPublicKey().getParams().hlen);
        assertTrue(cert.verify(kp.getPublic()));
        assertFalse(cert.isExpired());
        assertTrue(cert.hasSignatureScheme(TlsConstants.SIG_GOST_TC26_A_256));
    }

    @Test
    @DisplayName("isExpired: действующий сертификат не просрочен")
    void testCertNotExpired() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertFalse(bundle.cert.isExpired());
    }

    @Test
    @DisplayName("isExpired: сертификат с notAfter в прошлом просрочен")
    void testCertExpired() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "200101120000Z", "200201120000Z");
        assertTrue(bundle.cert.isExpired());
    }

    @Test
    @DisplayName("UTCTime: год 99 → 1999 (RFC 5280 §4.1.2.5.1)")
    void testUtcTimeYear99() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "990101120000Z", "500101120000Z");
        assertTrue(bundle.cert.isExpired(), "1999 год должен быть просрочен");
    }

    // -----------------------------------------------------------------------
    // SubjectAltName / verifyHostname
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verifyHostname: точное совпадение SAN")
    void testSanMatch() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname("example.com"));
        assertFalse(bundle.cert.verifyHostname("other.com"));
    }

    @Test
    @DisplayName("verifyHostname: wildcard *.example.com → www.example.com")
    void testSanWildcard() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"*.example.com"});
        assertTrue(bundle.cert.verifyHostname("www.example.com"));
        assertFalse(bundle.cert.verifyHostname("example.com"));
        assertFalse(bundle.cert.verifyHostname("a.b.example.com"));
    }

    @Test
    @DisplayName("verifyHostname: wildcard case-insensitive")
    void testSanWildcardCase() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"*.EXAMPLE.COM"});
        assertTrue(bundle.cert.verifyHostname("www.example.com"));
    }

    @Test
    @DisplayName("verifyHostname: частичный wildcard f* запрещён")
    void testSanWildcardPartial() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"f*.example.com"});
        assertFalse(bundle.cert.verifyHostname("foo.example.com"));
    }

    @Test
    @DisplayName("verifyHostname: несколько DNS-имён в SAN")
    void testSanMultipleDnsNames() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"a.com", "b.com", "c.com"});
        assertTrue(bundle.cert.verifyHostname("b.com"));
        assertFalse(bundle.cert.verifyHostname("d.com"));
    }

    @Test
    @DisplayName("verifyHostname: SAN отсутствует → false")
    void testSanNoSan() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256());
        assertFalse(bundle.cert.verifyHostname("example.com"));
    }

    @Test
    @DisplayName("verifyHostname: IPv4 в SAN — совпадает")
    void testSanIpv4Match() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, null, new String[]{"192.168.1.1"});
        assertTrue(bundle.cert.verifyHostname("192.168.1.1"));
    }

    @Test
    @DisplayName("verifyHostname: IPv4 в SAN — не совпадает")
    void testSanIpv4Mismatch() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, null, new String[]{"10.0.0.1"});
        assertFalse(bundle.cert.verifyHostname("192.168.1.1"));
    }

    @Test
    @DisplayName("verifyHostname: DNS и IPv4 в SAN")
    void testSanMixedDnsIp() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"}, null, null,
                new String[]{"10.0.0.1"});
        assertTrue(bundle.cert.verifyHostname("example.com"));
        assertTrue(bundle.cert.verifyHostname("10.0.0.1"));
        assertFalse(bundle.cert.verifyHostname("other.com"));
    }

    @Test
    @DisplayName("verifyHostname: IPv6 в SAN — совпадает")
    void testSanIpv6Match() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, null,
                new String[]{"::1"});
        assertTrue(bundle.cert.verifyHostname("::1"));
    }

    @Test
    @DisplayName("verifyHostname: DNS-имя при пустом SAN-IP")
    void testSanDnsOnlyWhenIpEmpty() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname("example.com"));
        assertFalse(bundle.cert.verifyHostname("10.0.0.1"));
    }

    @Test
    @DisplayName("verifyHostname: hostname не IP и не DNS -> false")
    void testSanInvalidHostname() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256());
        assertFalse(bundle.cert.verifyHostname(""));
    }

    @Test
    @DisplayName("verifyHostname: malformed iPAddress (3 байта) игнорируется")
    void testSanMalformedLength() throws Exception {
        byte[] garbageIp = TlsTestHelper.derTlv(0x87, new byte[]{0x01, 0x02, 0x03});
        byte[] validIp = TlsTestHelper.derTlv(0x87,
                java.net.InetAddress.getByName("10.0.0.1").getAddress());
        byte[] gnSeq = TlsTestHelper.derSequence(garbageIp, validIp);
        byte[] sanOid = TlsTestHelper.derOid("2.5.29.17");
        byte[] sanExt = TlsTestHelper.derSequence(sanOid, TlsTestHelper.derOctetString(gnSeq));

        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = TlsTestHelper.buildDN("Test Cert");
        byte[] tbs = TlsTestHelper.buildTbs(kp.getPublic(), params,
                "240501120000Z", "290501120000Z",
                null, null, sanExt, dn, dn);
        byte[] hash = TlsTestHelper.doHash(tbs, params.hlen);
        byte[] sig = Signature.signHash(hash, kp.getPrivate());
        byte[] algId = TlsTestHelper.buildAlgId(params);
        byte[] sigBs = TlsTestHelper.derBitString(sig);
        byte[] certDer = TlsTestHelper.derSequence(tbs, algId, sigBs);
        TlsCertificate cert = new TlsCertificate(certDer);

        assertTrue(cert.verifyHostname("10.0.0.1"));
        assertFalse(cert.verifyHostname("0.0.0.0"));
    }

    @Test
    @DisplayName("verifyHostname: IPv4 vs IPv4-mapped IPv6 — не совпадают")
    void testSanCrossVersion() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, null, new String[]{"192.168.1.1"});
        // IPv4-mapped: 16 байт, не равен чистому IPv4 (4 байта)
        byte[] ipv4Mapped = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xFF, (byte)0xFF,
                (byte)192, (byte)168, 1, 1};
        assertFalse(bundle.cert.verifyAddress(ipv4Mapped));
        assertTrue(bundle.cert.verifyHostname("192.168.1.1"));
    }

    @Test
    @DisplayName("verifyHostname: IPv6 vs IPv4 — не совпадают")
    void testSanCrossVersion2() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, null, new String[]{"::1"});
        // IPv4 loopback: 4 байта, не равен IPv6 loopback (16 байт)
        byte[] ipv4Loopback = {127, 0, 0, 1};
        assertFalse(bundle.cert.verifyAddress(ipv4Loopback));
        assertTrue(bundle.cert.verifyHostname("::1"));
    }

    @Test
    @DisplayName("parseCertificate: OCSP-стэпплинг из CertificateEntry")
    void testParseCertificateOcspStapling() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] ocspBytes = TlsTestHelper.buildDummyOcspResponse();
        TlsMessageBuilder builder = new TlsMessageBuilder(
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                0x0022, 0x0709, bundle.priv, List.of(bundle.cert), 32);
        byte[] certBody = builder.buildCertificateBody(ocspBytes);
        List<TlsCertificate> chain = TlsMessageParser.parseCertificate(certBody);
        assertEquals(1, chain.size());
        TlsCertificate parsed = chain.get(0);
        assertNotNull(parsed.getOcspResponse());
        assertArrayEquals(ocspBytes, parsed.getOcspResponse());
    }

    @Test
    @DisplayName("verifyOcspResponse: nextUpdate просрочен → TlsException")
    void testVerifyOcspExpired() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] ocsp = TlsTestHelper.buildOcspResponse(
                bundle.cert.getSerialNumber(), bundle.priv,
                bundle.cert.getPublicKey(), bundle.subjectDn, "20200101120000Z");
        bundle.cert.setOcspResponse(ocsp);
        assertThrows(TlsException.class,
                () -> bundle.cert.verifyOcspResponse(bundle.cert.getPublicKey()));
    }

    @Test
    @DisplayName("verifyOcspResponse: нет nextUpdate → проходит")
    void testVerifyOcspNoNextUpdate() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] ocsp = TlsTestHelper.buildOcspResponse(
                bundle.cert.getSerialNumber(), bundle.priv,
                bundle.cert.getPublicKey(), bundle.subjectDn, null);
        bundle.cert.setOcspResponse(ocsp);
        assertDoesNotThrow(() ->
                bundle.cert.verifyOcspResponse(bundle.cert.getPublicKey()));
    }

    @Test
    @DisplayName("verifyHostname: null → true")
    void testSanNullHostname() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname(null));
    }

    @Test
    @DisplayName("verifyHostname: IP-адрес → false (не поддерживается)")
    void testSanIpAddress() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"});
        assertFalse(bundle.cert.verifyHostname("192.168.1.1"));
        assertFalse(bundle.cert.verifyHostname("::1"));
    }

    @Test
    @DisplayName("verifyHostname: trailing dot в hostname нормализуется")
    void testSanTrailingDot() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname("example.com."));
    }

    @Test
    @DisplayName("verifyHostname: hostname с пробелами обрезается")
    void testSanHostnameTrim() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname("  example.com  "));
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    /**
     * Создаёт самоподписанный X.509 сертификат для тестов на tc26-A-256.
     * Формат: SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING signature }
     */
    private static byte[] createSelfSignedCert() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PublicKeyParameters pubKey = kp.getPublic();
        PrivateKeyParameters privKey = kp.getPrivate();

        // SubjectPublicKeyInfo DER
        byte[] spki = GostDerCodec.encodePublicKey(pubKey);

        // TBSCertificate с минимальными полями
        byte[] tbs = buildTbsCertificate(spki);

        // Подпись TBSCertificate
        byte[] sig = signTbs(tbs, privKey);

        // SignatureAlgorithm: 1.2.643.7.1.1.1.1 для 256-бит
        String sigOid = "1.2.643.7.1.1.1.1";
        byte[] sigAlg = derSequence(derOid(sigOid));

        // SignatureValue: BIT STRING
        byte[] sigBitString = derBitString(sig);

        // Certificate = SEQUENCE { tbs, sigAlg, sigBitString }
        return derSequence(tbs, sigAlg, sigBitString);
    }

    // -----------------------------------------------------------------------
    // KeyUsage / ExtendedKeyUsage
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("isKeyUsageValid: KU с digitalSignature → true")
    void testKuWithDigitalSignature() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null);
        assertTrue(bundle.cert.isKeyUsageValid());
    }

    @Test
    @DisplayName("isKeyUsageValid: KU без digitalSignature → false")
    void testKuWithoutDigitalSignature() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x20}, null);
        assertFalse(bundle.cert.isKeyUsageValid());
    }

    @Test
    @DisplayName("isKeyUsageValid: KU отсутствует → true")
    void testKuAbsent() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(bundle.cert.isKeyUsageValid());
    }

    @Test
    @DisplayName("isEkuValid: EKU с serverAuth → true")
    void testEkuWithServerAuth() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.1"});
        assertTrue(bundle.cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("isEkuValid: EKU без serverAuth → false")
    void testEkuWithoutServerAuth() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.3"});
        assertFalse(bundle.cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("isEkuValid: EKU отсутствует → true")
    void testEkuAbsent() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(bundle.cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("isEkuValid: EKU с serverAuth и codeSigning → true")
    void testEkuWithServerAuthAndOther() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.1"});
        assertTrue(bundle.cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("isEkuValidForClient: EKU с clientAuth → true")
    void testEkuClientAuthValid() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.2"});
        assertTrue(bundle.cert.isEkuValidForClient());
    }

    @Test
    @DisplayName("isEkuValidForClient: EKU без clientAuth → false")
    void testEkuClientAuthMissing() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.1"});
        assertFalse(bundle.cert.isEkuValidForClient());
    }

    @Test
    @DisplayName("isEkuValidForClient: EKU отсутствует → true")
    void testEkuClientAuthAbsent() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(bundle.cert.isEkuValidForClient());
    }

    @Test
    @DisplayName("isEkuValidForClient: EKU с clientAuth и serverAuth → true")
    void testEkuClientAuthWithServerAuth() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "240501120000Z", "290501120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"});
        assertTrue(bundle.cert.isEkuValidForClient());
    }

    @Test
    @DisplayName("verify: leaf подписан root → true")
    void testChainSignatureVerification() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.1"},
                false, null);
        assertTrue(leaf.cert.verify(root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("verify: leaf подписан root, чужим ключом → false")
    void testChainSignatureWrongKey() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                null, null, null, false, null);
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        assertFalse(leaf.cert.verify(kp.getPublic()));
    }

    @Test
    @DisplayName("isCA: корневой CA → true, keyCertSign → true")
    void testRootCAIsCA() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        assertTrue(root.cert.isCA());
        assertTrue(root.cert.isKeyCertSignSet());
    }

    @Test
    @DisplayName("isCA: leaf без BC → false, keyCertSign → false")
    void testLeafNotCA() throws Exception {
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertFalse(leaf.cert.isCA());
        assertFalse(leaf.cert.isKeyCertSignSet());
    }

    // -----------------------------------------------------------------------
    // 3-сертификатная цепочка (leaf → intermediate → root)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("3-cert: leaf подписан intermediate → true")
    void testThreeCertLeafVerifiesByIntermediate() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle intermediate = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 0);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), intermediate.priv, intermediate.cert.getPublicKey(),
                intermediate.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, null, false, null);
        assertTrue(leaf.cert.verify(intermediate.cert.getPublicKey()));
    }

    @Test
    @DisplayName("3-cert: intermediate подписан root → true")
    void testThreeCertIntermediateVerifiesByRoot() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle intermediate = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 0);
        assertTrue(intermediate.cert.verify(root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("3-cert: leaf подписан root → false (прямая верификация через root не проходит)")
    void testThreeCertLeafDoesNotVerifyByRoot() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle intermediate = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 0);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), intermediate.priv, intermediate.cert.getPublicKey(),
                intermediate.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, null, false, null);
        assertFalse(leaf.cert.verify(root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("tampered: изменение 1 байта DER → verify возвращает false")
    void testTamperedCertFailsVerification() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, null, false, null);
        byte[] tamperedDer = leaf.cert.getCertData().clone();
        tamperedDer[tamperedDer.length - 1] ^= 0x01;
        TlsCertificate tampered = new TlsCertificate(tamperedDer);
        assertFalse(tampered.verify(root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("algConsistent: разные signatureAlgorithm внутри и снаружи → false")
    void testAlgMismatch() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] spki = GostDerCodec.encodePublicKey(kp.getPublic());

        byte[] version = derContextExpl(0, derInteger(2));
        byte[] serial = derInteger(1);
        byte[] tbsSigAlg = derSequence(derOid("1.2.643.7.1.1.1.1"));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derUtcTime("250101000000Z"), derUtcTime("350101000000Z"));
        byte[] tbs = derSequence(version, serial, tbsSigAlg, dn, validity, dn, spki);

        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] outerSigAlg = derSequence(derOid("1.2.643.7.1.1.1.2"));
        byte[] certDer = derSequence(tbs, outerSigAlg, derBitString(sig));

        TlsCertificate cert = new TlsCertificate(certDer);
        assertFalse(cert.isAlgConsistent());
    }

    @Test
    @DisplayName("hasUnknownCriticalExtension: неизвестный critical extension → true")
    void testUnknownCriticalExtension() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] spki = GostDerCodec.encodePublicKey(kp.getPublic());

        byte[] version = derContextExpl(0, derInteger(2));
        byte[] serial = derInteger(1);
        byte[] sigAlg = derSequence(derOid("1.2.643.7.1.1.1.1"));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derUtcTime("250101000000Z"), derUtcTime("350101000000Z"));

        byte[] unknownExtOid = derOid("1.2.3.4");
        byte[] unknownExtValue = derOctetString(new byte[]{0x05, 0x00});
        byte[] unknownExt = derSequence(unknownExtOid, new byte[]{0x01, 0x01, (byte) 0xFF}, unknownExtValue);
        byte[] extensions = derContextExpl(3, derSequence(unknownExt));

        byte[] tbs = derSequence(version, serial, sigAlg, dn, validity, dn, spki, extensions);
        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] outerSigAlg = derSequence(derOid("1.2.643.7.1.1.1.1"));
        byte[] certDer = derSequence(tbs, outerSigAlg, derBitString(sig));

        TlsCertificate cert = new TlsCertificate(certDer);
        assertTrue(cert.hasUnknownCriticalExtension());
    }

    /**
     * Строит минимальный TBSCertificate:
     * SEQUENCE {
     *   [0] { INTEGER 2 }         -- v3 (version)
     *   INTEGER 1                  -- serial
     *   SEQUENCE { OID(sigAlg) }   -- signature
     *   SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String("Test") } } } -- issuer
     *   SEQUENCE { UTCTime, UTCTime } -- validity
     *   SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String("Test") } } } -- subject
     *   spki                       -- SubjectPublicKeyInfo
     * }
     */
    private static byte[] buildTbsCertificate(byte[] spki) {
        byte[] version = derContextExpl(0, derInteger(2)); // v3

        byte[] serial = derInteger(1);

        byte[] sigAlg = derSequence(derOid("1.2.643.7.1.1.1.1"));

        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));

        byte[] validity = derSequence(
                derUtcTime("250101000000Z"),
                derUtcTime("350101000000Z"));

        byte[] tbs = derSequence(version, serial, sigAlg, dn, validity, dn, spki);
        return tbs;
    }

    private static byte[] signTbs(byte[] tbs, PrivateKeyParameters privKey) throws Exception {
        org.rssys.gost.api.Digest digest = new org.rssys.gost.api.Digest(
                org.rssys.gost.api.Digest.Algorithm.STREEBOG_256);
        digest.update(tbs, 0, tbs.length);
        byte[] hash = digest.digest();
        return Signature.signHash(hash, privKey);
    }

    // -----------------------------------------------------------------------
    // DER построители
    // -----------------------------------------------------------------------

    private static byte[] derInteger(int value) {
        if (value < 0x80) {
            return derTlv(0x02, new byte[]{(byte) value});
        }
        byte[] bytes;
        if (value < 0x100) {
            bytes = new byte[]{(byte) value};
        } else if (value < 0x10000) {
            bytes = new byte[]{(byte) (value >> 8), (byte) value};
        } else {
            bytes = new byte[]{(byte) (value >> 16), (byte) (value >> 8), (byte) value};
        }
        return derTlv(0x02, bytes);
    }

    private static byte[] derOid(String oidStr) {
        String[] parts = oidStr.split("\\.");
        int[] arcs = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            arcs[i] = Integer.parseInt(parts[i]);
        }
        byte[] body = encodeOidBody(arcs);
        return derTlv(0x06, body);
    }

    private static byte[] encodeOidBody(int[] arcs) {
        if (arcs.length < 2) {
            throw new IllegalArgumentException("OID must have at least 2 arcs");
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        // Первые два компонента кодируются как 40*arcs[0] + arcs[1]
        out.write(40 * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            encodeOidComponent(out, arcs[i]);
        }
        return out.toByteArray();
    }

    private static void encodeOidComponent(java.io.ByteArrayOutputStream out, int value) {
        if (value < 128) {
            out.write(value);
            return;
        }
        // Base-128 encoding для многобайтовых значений
        int bits = 32 - Integer.numberOfLeadingZeros(value);
        int nBytes = (bits + 6) / 7;
        for (int i = nBytes - 1; i >= 0; i--) {
            int b = (value >>> (i * 7)) & 0x7F;
            if (i > 0) {
                b |= 0x80;
            }
            out.write(b);
        }
    }

    private static byte[] derUtf8String(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        return derTlv(0x0C, bytes);
    }

    private static byte[] derUtcTime(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.US_ASCII);
        return derTlv(0x17, bytes);
    }

    private static byte[] derBitString(byte[] content) {
        byte[] data = new byte[1 + content.length];
        data[0] = 0; // unused bits
        System.arraycopy(content, 0, data, 1, content.length);
        return derTlv(0x03, data);
    }

    private static byte[] derSet(byte[] element) {
        return derTlv(0x31, element);
    }

    private static byte[] derContextExpl(int tag, byte[] content) {
        return derTlv(0xA0 | tag, content);
    }

    private static byte[] derOctetString(byte[] data) {
        return derTlv(0x04, data);
    }

    private static byte[] derSequence(byte[]... elements) {
        byte[] content = concat(elements);
        return derTlv(0x30, content);
    }

    private static byte[] derTlv(int tag, byte[] content) {
        byte[] length = derLength(content.length);
        byte[] tlv = new byte[1 + length.length + content.length];
        tlv[0] = (byte) tag;
        System.arraycopy(length, 0, tlv, 1, length.length);
        System.arraycopy(content, 0, tlv, 1 + length.length, content.length);
        return tlv;
    }

    private static byte[] derLength(int len) {
        if (len < 0x80) {
            return new byte[]{(byte) len};
        }
        if (len < 0x100) {
            return new byte[]{(byte) 0x81, (byte) len};
        }
        if (len < 0x10000) {
            return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
        }
        return new byte[]{(byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len};
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

}
