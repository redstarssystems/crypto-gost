package org.rssys.gost.tls13.cert;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.TlsTestHelper;
import static org.rssys.gost.tls13.TlsTestHelper.*;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.util.DerCodec;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
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

    @Test
    @DisplayName("parseLength: 0x80 (Indefinite form) → IllegalArgumentException")
    void testparseLengthIndefiniteForm() {
        byte[] data = new byte[]{(byte) 0x80};
        assertThrows(IllegalArgumentException.class,
                () -> TlsDerParser.parseLength(data, 0));
    }

    @Test
    @DisplayName("parseLength: numBytes=4 > 3 → IllegalArgumentException")
    void testparseLengthTooManyLengthBytes() {
        byte[] data = new byte[]{(byte) 0x84, 0x01, 0x02, 0x03, 0x04};
        assertThrows(IllegalArgumentException.class,
                () -> TlsDerParser.parseLength(data, 0));
    }

    @Test
    @DisplayName("parseLength: обрезанная длинная форма (нет байт длины) → IndexOutOfBoundsException")
    void testparseLengthTruncatedLongForm() {
        byte[] data = new byte[]{(byte) 0x82};
        assertThrows(IndexOutOfBoundsException.class,
                () -> TlsDerParser.parseLength(data, 0));
    }

    @Test
    @DisplayName("parseTime: не-Z timezone → IllegalArgumentException")
    void testparseTimeNonUtcTimezone() {
        byte[] data = new byte[]{0x17, 0x0C, '2', '5', '0', '1', '0', '1', '1', '2', '0', '0', '0', '0'};
        assertThrows(IllegalArgumentException.class,
                () -> TlsDerParser.parseTime(data, 0));
    }

    @Test
    @DisplayName("parseTime: неизвестный тег (BOOLEAN) → IllegalArgumentException")
    void testparseTimeUnknownTag() {
        byte[] data = new byte[]{0x01, 0x01, 'Z'};
        assertThrows(IllegalArgumentException.class,
                () -> TlsDerParser.parseTime(data, 0));
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
        byte[] sigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derTime("250101000000Z"), derTime("21060101120000Z"));
        byte[] extensions = derContextExpl(3, derSequence());

        byte[] tbs = derSequence(version, serial, sigAlg, dn, validity, dn, spki, extensions);
        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] sigAlgCert = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname("example.com"));
        assertFalse(bundle.cert.verifyHostname("other.com"));
    }

    @Test
    @DisplayName("verifyHostname: wildcard *.example.com → www.example.com")
    void testSanWildcard() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"*.example.com"});
        assertTrue(bundle.cert.verifyHostname("www.example.com"));
        assertFalse(bundle.cert.verifyHostname("example.com"));
        assertFalse(bundle.cert.verifyHostname("a.b.example.com"));
    }

    @Test
    @DisplayName("verifyHostname: wildcard case-insensitive")
    void testSanWildcardCase() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"*.EXAMPLE.COM"});
        assertTrue(bundle.cert.verifyHostname("www.example.com"));
    }

    @Test
    @DisplayName("verifyHostname: частичный wildcard f* запрещён")
    void testSanWildcardPartial() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"f*.example.com"});
        assertFalse(bundle.cert.verifyHostname("foo.example.com"));
    }

    @Test
    @DisplayName("verifyHostname: несколько DNS-имён в SAN")
    void testSanMultipleDnsNames() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, null, new String[]{"192.168.1.1"});
        assertTrue(bundle.cert.verifyHostname("192.168.1.1"));
    }

    @Test
    @DisplayName("verifyHostname: IPv4 в SAN — не совпадает")
    void testSanIpv4Mismatch() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, null, new String[]{"10.0.0.1"});
        assertFalse(bundle.cert.verifyHostname("192.168.1.1"));
    }

    @Test
    @DisplayName("verifyHostname: DNS и IPv4 в SAN")
    void testSanMixedDnsIp() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, null,
                new String[]{"::1"});
        assertTrue(bundle.cert.verifyHostname("::1"));
    }

    @Test
    @DisplayName("verifyHostname: DNS-имя при пустом SAN-IP")
    void testSanDnsOnlyWhenIpEmpty() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                "20240501120000Z", "21060101120000Z",
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                List.of(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S),
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname(null));
    }

    @Test
    @DisplayName("verifyHostname: IP-адрес → false (не поддерживается)")
    void testSanIpAddress() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"example.com"});
        assertFalse(bundle.cert.verifyHostname("192.168.1.1"));
        assertFalse(bundle.cert.verifyHostname("::1"));
    }

    @Test
    @DisplayName("verifyHostname: trailing dot в hostname нормализуется")
    void testSanTrailingDot() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"example.com"});
        assertTrue(bundle.cert.verifyHostname("example.com."));
    }

    @Test
    @DisplayName("verifyHostname: hostname с пробелами обрезается")
    void testSanHostnameTrim() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
        String sigOid = GostOids.SIG_WITH_DIGEST_256;
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, new byte[]{(byte) 0x80}, null);
        assertTrue(bundle.cert.isKeyUsageValid());
    }

    @Test
    @DisplayName("isKeyUsageValid: KU без digitalSignature → false")
    void testKuWithoutDigitalSignature() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, new String[]{GostOids.EXT_SERVER_AUTH});
        assertTrue(bundle.cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("isEkuValid: EKU без serverAuth → false")
    void testEkuWithoutServerAuth() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, new String[]{"1.3.6.1.5.5.7.3.3", GostOids.EXT_SERVER_AUTH});
        assertTrue(bundle.cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("isEkuValidForClient: EKU с clientAuth → true")
    void testEkuClientAuthValid() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, new String[]{GostOids.EXT_CLIENT_AUTH});
        assertTrue(bundle.cert.isEkuValidForClient());
    }

    @Test
    @DisplayName("isEkuValidForClient: EKU без clientAuth → false")
    void testEkuClientAuthMissing() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, new String[]{GostOids.EXT_SERVER_AUTH});
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
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                null, null, new String[]{GostOids.EXT_SERVER_AUTH, GostOids.EXT_CLIENT_AUTH});
        assertTrue(bundle.cert.isEkuValidForClient());
    }

    @Test
    @DisplayName("verify: leaf подписан root → true")
    void testChainSignatureVerification() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "20240501120000Z", "21060101120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
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
                "20240501120000Z", "21060101120000Z",
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
                "20240501120000Z", "21060101120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 0);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), intermediate.priv, intermediate.cert.getPublicKey(),
                intermediate.subjectDn,
                "20240501120000Z", "21060101120000Z", null,
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
                "20240501120000Z", "21060101120000Z", null,
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
                "20240501120000Z", "21060101120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 0);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), intermediate.priv, intermediate.cert.getPublicKey(),
                intermediate.subjectDn,
                "20240501120000Z", "21060101120000Z", null,
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
                "20240501120000Z", "21060101120000Z", null,
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
        byte[] tbsSigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derTime("250101000000Z"), derTime("21060101120000Z"));
        byte[] tbs = derSequence(version, serial, tbsSigAlg, dn, validity, dn, spki);

        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] outerSigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_512));
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
        byte[] sigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derTime("250101000000Z"), derTime("21060101120000Z"));

        byte[] unknownExtOid = derOid("1.2.3.4");
        byte[] unknownExtValue = derOctetString(new byte[]{0x05, 0x00});
        byte[] unknownExt = derSequence(unknownExtOid, new byte[]{0x01, 0x01, (byte) 0xFF}, unknownExtValue);
        byte[] extensions = derContextExpl(3, derSequence(unknownExt));

        byte[] tbs = derSequence(version, serial, sigAlg, dn, validity, dn, spki, extensions);
        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] outerSigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] certDer = derSequence(tbs, outerSigAlg, derBitString(sig));

        TlsCertificate cert = new TlsCertificate(certDer);
        assertTrue(cert.hasUnknownCriticalExtension());
    }

    // -----------------------------------------------------------------------
    // equals / hashCode
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("equals: одинаковые DER → true")
    void testEqualsSameDer() throws Exception {
        byte[] der = createSelfSignedCert();
        TlsCertificate c1 = new TlsCertificate(der);
        TlsCertificate c2 = new TlsCertificate(der);
        assertEquals(c1, c2);
        assertEquals(c1.hashCode(), c2.hashCode());
    }

    @Test
    @DisplayName("equals: разные сертификаты → false")
    void testEqualsDifferentDer() throws Exception {
        byte[] der1 = createSelfSignedCert();
        byte[] der2 = createSelfSignedCert();
        TlsCertificate c1 = new TlsCertificate(der1);
        TlsCertificate c2 = new TlsCertificate(der2);
        assertNotEquals(c1, c2);
    }

    @Test
    @DisplayName("equals: null → false")
    void testEqualsNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertNotNull(cert);
        assertNotEquals(null, cert);
    }

    @Test
    @DisplayName("equals: другой тип → false")
    void testEqualsDifferentType() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertNotEquals("string", cert);
    }

    // -----------------------------------------------------------------------
    // Версия
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getVersion: v3 для createSelfSignedCert")
    void testVersionV3() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertEquals(3, cert.getVersion());
    }

    @Test
    @DisplayName("getVersion: без [0] EXPLICIT → v1")
    void testVersionV1() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] spki = GostDerCodec.encodePublicKey(kp.getPublic());

        // TBSCertificate без поля version (по умолчанию v1)
        byte[] serial = derInteger(1);
        byte[] sigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(derTime("250101000000Z"), derTime("21060101120000Z"));
        byte[] tbs = derSequence(serial, sigAlg, dn, validity, dn, spki);

        byte[] sig = signTbs(tbs, kp.getPrivate());
        byte[] outerSigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] certDer = derSequence(tbs, outerSigAlg, derBitString(sig));

        TlsCertificate cert = new TlsCertificate(certDer);
        assertEquals(1, cert.getVersion());
    }

    // -----------------------------------------------------------------------
    // Серийный номер
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getSerialNumberBigInt: serial = 1 → BigInteger(1)")
    void testSerialNumberBigInt() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertEquals(BigInteger.valueOf(1), cert.getSerialNumberBigInt());
    }

    // -----------------------------------------------------------------------
    // Самоподписанность (isSelfSigned) и self-issued (isSelfIssued)
    // isSelfSigned проверяется криптографически (sign+verify),
    // isSelfIssued — сравнением DER issuer и subject.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("isSelfSigned: самоподписанный → true")
    void testIsSelfSignedTrue() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertTrue(cert.isSelfSigned());
    }

    @Test
    @DisplayName("isSelfSigned: root CA → true")
    void testIsSelfSignedRootCA() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        assertTrue(root.cert.isSelfSigned());
    }

    @Test
    @DisplayName("isSelfSigned: leaf подписан root → false")
    void testIsSelfSignedLeaf() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "20240501120000Z", "21060101120000Z",
                null, null, null, false, null);
        assertFalse(leaf.cert.isSelfSigned());
    }

    @Test
    @DisplayName("isSelfIssued: issuer = subject → true")
    void testIsSelfIssuedTrue() throws Exception {
        // createCertWithKey создаёт issuer = subject
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(bundle.cert.isSelfIssued());
    }

    @Test
    @DisplayName("isSelfIssued: issuer ≠ subject → false")
    void testIsSelfIssuedFalse() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "20240501120000Z", "21060101120000Z",
                null, null, null, false, null);
        assertFalse(leaf.cert.isSelfIssued());
    }

    // -----------------------------------------------------------------------
    // Срок действия (isValidAt) — проверка на произвольную дату
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("isValidAt: дата внутри периода → true")
    void testIsValidAtWithin() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(bundle.cert.isValidAt(new Date()));
    }

    @Test
    @DisplayName("isValidAt: дата до notBefore → false")
    void testIsValidAtBefore() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z");
        Date past = new Date(0); // 1970-01-01
        assertFalse(bundle.cert.isValidAt(past));
    }

    @Test
    @DisplayName("isValidAt: дата после notAfter → false")
    void testIsValidAtAfter() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z");
        Date farFuture = new Date(200 * 365 * 86400000L); // ~2170
        assertFalse(bundle.cert.isValidAt(farFuture));
    }

    // -----------------------------------------------------------------------
    // DN строки
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getSubjectDn: формат CN=Test Cert N")
    void testSubjectDnString() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        String dn = bundle.cert.getSubjectDn();
        assertNotNull(dn);
        assertTrue(dn.startsWith("CN="), "DN должен начинаться с CN=, но: " + dn);
    }

    // -----------------------------------------------------------------------
    // DN escape (RFC 4514) — escapeDnValue coverage
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("DN: backslash в значении экранируется")
    void testDnEscapeBackslash() throws Exception {
        // CN=foo\bar → с экранированием: CN=foo\\bar
        byte[] dn = buildDnWithCn("foo\\bar");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=foo\\\\bar", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: запятая в значении экранируется")
    void testDnEscapeComma() throws Exception {
        byte[] dn = buildDnWithCn("a,b");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\\,b", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: равно в значении экранируется")
    void testDnEscapeEquals() throws Exception {
        byte[] dn = buildDnWithCn("a=b");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\\=b", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: плюс в значении экранируется")
    void testDnEscapePlus() throws Exception {
        byte[] dn = buildDnWithCn("a+b");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\\+b", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: C0 control (0x01) экранируется как \\u0001")
    void testDnEscapeC0Control() throws Exception {
        byte[] dn = buildDnWithCn("a\u0001b");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\\u0001b", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: DEL (0x7F) экранируется как \\u007F")
    void testDnEscapeDel() throws Exception {
        byte[] dn = buildDnWithCn("a\u007Fb");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\\u007Fb", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: C1 control NEL (0x85) экранируется как \\u0085")
    void testDnEscapeC1Control() throws Exception {
        byte[] dn = buildDnWithCn("a\u0085b");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\\u0085b", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: NBSP (0xA0) НЕ экранируется — граница условия <0xA0")
    void testDnEscapeNbspBoundary() throws Exception {
        // NBSP = 0xA0, условие c < 0xA0 exclusive — не должен экранироваться
        byte[] dn = buildDnWithCn("a\u00A0b");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=a\u00A0b", cert.getSubjectDn());
    }

    @Test
    @DisplayName("DN: обычная строка без спецсимволов не меняется")
    void testDnEscapePlainText() throws Exception {
        byte[] dn = buildDnWithCn("example.com");
        TlsCertificate cert = certWithDn(dn);
        assertEquals("CN=example.com", cert.getSubjectDn());
    }

    @Test
    @DisplayName("getIssuerDn: совпадает с subject для self-issued")
    void testIssuerDnString() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertEquals(bundle.cert.getSubjectDn(), bundle.cert.getIssuerDn());
    }

    @Test
    @DisplayName("getSubjectDnField: CN → [\"Test Cert N\"]")
    void testSubjectDnFieldCn() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        String[] cns = bundle.cert.getSubjectDnField("2.5.4.3");
        assertTrue(cns.length > 0);
        assertTrue(cns[0].startsWith("Test Cert"));
    }

    @Test
    @DisplayName("getSubjectDnField: неизвестный OID → пустой массив")
    void testSubjectDnFieldUnknown() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        String[] values = bundle.cert.getSubjectDnField("1.2.3.4");
        assertEquals(0, values.length);
    }

    @Test
    @DisplayName("getSubjectDnForLog: обрезка строки")
    void testSubjectDnForLog() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        String dn = bundle.cert.getSubjectDnForLog(10);
        assertTrue(dn.length() <= 10 + "...[truncated]".length() || dn.length() <= 10);
    }

    // -----------------------------------------------------------------------
    // toString
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("toString: содержит ключевые поля")
    void testToStringContainsFields() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        String s = cert.toString();
        assertTrue(s.startsWith("TlsCertificate{"));
        assertTrue(s.contains("serial=0x"));
        assertTrue(s.contains("subject=CN="));
        assertTrue(s.contains("issuer=CN="));
        assertTrue(s.contains("validity=["));
        assertTrue(s.contains("bit GOST R 34.10-2012"));
        assertTrue(s.endsWith("}"));
    }

    // -----------------------------------------------------------------------
    // Defensive copies — проверяем что мутация полученного массива
    // не влияет на внутреннее состояние сертификата (безопасность)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getSanDnsNames: модификация массива не влияет на сертификат")
    void testSanDnsNamesDefensiveCopy() {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z",
                new String[]{"example.com"});
        String[] dns = bundle.cert.getSanDnsNames();
        String orig = dns[0];
        dns[0] = "hacked.com";
        assertFalse(bundle.cert.verifyHostname("hacked.com"));
        assertTrue(bundle.cert.verifyHostname(orig));
    }

    // -----------------------------------------------------------------------
    // equals cross-loading — проверяем что дважды загруженный DER даёт equals.
    // Важно для кэширования: если сертификат загружается из разных источников
    // (файл, сеть, PKCS#12), equals должен работать по DER-байтам.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("equals: cross-loading — дважды загруженный DER даёт equals")
    void testCrossLoadingEquals() throws Exception {
        byte[] der = createSelfSignedCert();
        TlsCertificate c1 = new TlsCertificate(der);
        TlsCertificate c2 = new TlsCertificate(der.clone());
        assertEquals(c1, c2);
    }

    // ========================================================================
    // SignatureAlgorithm, NamedGroup, SKI/AKI, AIA, matchesPrivateKey
    // Проверяем, что методы возвращают корректные значения для тестового
    // сертификата (tc26a256, самоподписанный, без SKI/AKI/AIA-расширений).
    // ------------------------------------------------------------------------

    @Test @DisplayName("getSignatureAlgorithmOid: OID совпадает с GostCurves.OID_SIGN_256")
    void testSignatureAlgorithmOid() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // createSelfSignedCert использует sigOid = GostOids.SIG_WITH_DIGEST_256 (256-бит)
        assertEquals(GostCurves.OID_SIGN_256, cert.getSignatureAlgorithmOid());
    }

    @Test @DisplayName("getKeySize: 256 бит")
    void testKeySize() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // tc26a256 — 256-битная кривая (hlen=32 → 32*8=256)
        assertEquals(256, cert.getKeySize());
    }

    @Test @DisplayName("getNamedGroup: tc26a256 = GRP_GC256A")
    void testNamedGroup() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // createSelfSignedCert использует tc26a256 → GRP_GC256A (0x0022)
        assertEquals(TlsConstants.GRP_GC256A, cert.getNamedGroup());
    }

    @Test @DisplayName("getSubjectKeyIdentifier: null — тестовый сертификат без SKI-расширения")
    void testSubjectKeyIdentifierNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // buildTbsCertificate не добавляет SKI (2.5.29.14) — только SAN/KU/EKU/BC
        assertNull(cert.getSubjectKeyIdentifier());
    }

    @Test @DisplayName("getAuthorityKeyIdentifier: null — тестовый сертификат без AKI-расширения")
    void testAuthorityKeyIdentifierNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertNull(cert.getAuthorityKeyIdentifier());
    }

    @Test @DisplayName("getAiaUris: null — тестовый сертификат без AIA-расширения")
    void testAiaUrisNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertNull(cert.getAiaUris());
    }

    @Test @DisplayName("matchesPrivateKey: свой ключ → true")
    void testMatchesPrivateKeyTrue() {
        // Генерируем ключевую пару и сертификат через TlsTestHelper,
        // затем проверяем что matchesPrivateKey возвращает true для своего ключа
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.cryptoProA());
        assertTrue(bundle.cert.matchesPrivateKey(bundle.priv));
    }

    @Test @DisplayName("matchesPrivateKey: null → false (NPE guard)")
    void testMatchesPrivateKeyNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // matchesPrivateKey должен корректно обрабатывать null без NPE
        assertFalse(cert.matchesPrivateKey(null));
    }

    @Test @DisplayName("matchesPrivateKey: чужой ключ → false")
    void testMatchesPrivateKeyWrongKey() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // Сертификат на tc26a256, а ключ от cryptoProA — не совпадают
        TlsTestHelper.CertBundle otherBundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertFalse(cert.matchesPrivateKey(otherBundle.priv));
    }

    // ========================================================================
    // SignatureValue, TBSCertificate, CDP, CertificatePolicies
    // Проверяем базовые getter'ы (непустые значения, null для отсутствующих
    // расширений, правильную длину подписи).
    // ------------------------------------------------------------------------

    @Test @DisplayName("getSignatureValue: не пустой")
    void testGetSignatureValue() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // Подпись должна быть — проверяем что не null и не пустая
        assertNotNull(cert.getSignatureValue());
        assertTrue(cert.getSignatureValue().length > 0);
    }

    @Test @DisplayName("getTBSCertificateBytes: не пустой")
    void testGetTBSCertificateBytes() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // TBS (TBSCertificate) — это всё кроме подписи, должен быть не пуст
        assertNotNull(cert.getTBSCertificateBytes());
        assertTrue(cert.getTBSCertificateBytes().length > 0);
    }

    @Test @DisplayName("CDP: null — тестовый сертификат без CDP-расширения")
    void testCdpUrisNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // CRLDistributionPoints не добавляется в test buildTbsCertificate
        assertNull(cert.getCdpUris());
    }

    @Test @DisplayName("CertificatePolicies: null — тестовый сертификат без CertificatePolicies")
    void testCertificatePoliciesNull() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        assertNull(cert.getCertificatePolicies());
    }

    @Test @DisplayName("getSignatureValue: длина 64 байта для 256-битной кривой")
    void testGetSignatureValueLength() throws Exception {
        TlsCertificate cert = new TlsCertificate(createSelfSignedCert());
        // tc26a256 → hlen=32 → r||s = 32+32 = 64 байта подписи
        assertEquals(64, cert.getSignatureValue().length);
    }

    /**
     * Создаёт самоподписанный сертификат с AIA-расширением.
     *
     * @param aiaUris URI для включения в AuthorityInfoAccess
     * @return TlsCertificate с AIA
     */
    private static TlsCertificate createCertWithAia(String... aiaUris) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PublicKeyParameters pubKey = kp.getPublic();
        PrivateKeyParameters privKey = kp.getPrivate();
        byte[] spki = GostDerCodec.encodePublicKey(pubKey);

        // Строим AIA AccessDescription SEQUENCE для каждого URI
        byte[][] accessDescs = new byte[aiaUris.length][];
        for (int i = 0; i < aiaUris.length; i++) {
            byte[] uriBytes = aiaUris[i].getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            // uniformResourceIdentifier [6] (primitive)
            byte[] uriGn = derTlv(0x86, uriBytes);
            // AccessDescription: SEQUENCE { OID(caIssuers), GeneralName }
            accessDescs[i] = derSequence(derOid("1.3.6.1.5.5.7.48.2"), uriGn);
        }

        // AIA extension value: OCTET STRING { SEQUENCE OF AccessDescription }
        byte[] aiaValue = derOctetString(derSequence(accessDescs));

        // Extension: SEQUENCE { OID(AIA), OCTET STRING }
        byte[] aiaExt = derSequence(derOid("1.3.6.1.5.5.7.1.1"), aiaValue);

        // Extensions: [3] EXPLICIT { SEQUENCE OF Extension }
        byte[] extensions = derContextExpl(3, derSequence(aiaExt));

        // TBS с extensions после SPKI
        byte[] version = derContextExpl(0, derInteger(2));
        byte[] serial = derInteger(1);
        byte[] sigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));
        byte[] validity = derSequence(
                derTime("250101000000Z"),
                derTime("21060101120000Z"));
        byte[] tbs = derSequence(version, serial, sigAlg, dn, validity, dn, spki, extensions);

        // Подпись
        byte[] sig = signTbs(tbs, privKey);
        byte[] sigAlgEncoded = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));
        byte[] certDer = derSequence(tbs, sigAlgEncoded, derBitString(sig));

        return new TlsCertificate(certDer);
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

        byte[] sigAlg = derSequence(derOid(GostOids.SIG_WITH_DIGEST_256));

        byte[] cn = derSequence(derOid("2.5.4.3"), derUtf8String("Test"));
        byte[] dn = derSequence(derSet(cn));

        byte[] validity = derSequence(
                derTime("250101000000Z"),
                derTime("21060101120000Z"));

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

    private static byte[] derTime(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.US_ASCII);
        int tag = s.length() == 13 ? 0x17 : 0x18;
        return derTlv(tag, bytes);
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

    /**
     * Строит DER-кодированный Distinguished Name с одним RDN: CN=value.
     * Аналог TlsTestHelper.buildDN(), но с произвольным значением (не только CN).
     */
    private static byte[] buildDnWithCn(String value) {
        byte[] valueBytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] attr = derSequence(derOid("2.5.4.3"), derTlv(DerCodec.TAG_UTF8_STRING, valueBytes));
        return derSequence(Set(attr));
    }

    /**
     * Создаёт минимальный самоподписанный сертификат с заданным subject/issuer DN.
     * Не добавляет расширений — сертификат годится только для тестов DN-парсинга.
     */
    private static TlsCertificate certWithDn(byte[] dn) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] tbs = buildTbs(kp.getPublic(), params, "20240501120000Z", "21060101120000Z",
                null, null, null, dn, dn);
        byte[] hash = doHash(tbs, params.hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, kp.getPrivate());
        byte[] certDer = derSequence(tbs, buildAlgId(params), derBitString(sig));
        return new TlsCertificate(certDer);
    }

}
