package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsTestHelper.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;

@DisplayName("TlsCertificateFactory — фабричные методы DER/PEM")
class TlsCertificateFactoryTest {

    private static GostCertificate createTestCert() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        return TlsTestHelper.createCertWithKey(params).cert;
    }

    @Test
    @DisplayName("fromDer: DER-байты -> TlsCertificate")
    void testFromDer() throws Exception {
        GostCertificate cert = createTestCert();
        byte[] der = cert.getEncoded();
        GostCertificate fromDer = new GostCertificate(der);
        assertNotNull(fromDer, "fromDer должен вернуть не-null сертификат");
        assertTrue(
                fromDer.verifySignature(fromDer.getPublicKey()),
                "Сертификат через fromDer должен самоподписываться");
    }

    @Test
    @DisplayName("fromPemOrDer: DER-байты (автоопределение)")
    void testFromPemOrDerWithDer() throws Exception {
        GostCertificate cert = createTestCert();
        byte[] der = cert.getEncoded();
        GostCertificate result = GostCertificate.fromPemOrDer(der);
        assertNotNull(result, "fromPemOrDer(DER) должен вернуть сертификат");
        assertTrue(
                result.verifySignature(result.getPublicKey()),
                "Сертификат должен самоподписываться");
    }

    @Test
    @DisplayName("fromPemOrDer: PEM-байты (автоопределение)")
    void testFromPemOrDerWithPem() throws Exception {
        GostCertificate cert = createTestCert();
        String pem = cert.toPem();
        byte[] pemBytes = pem.getBytes(StandardCharsets.US_ASCII);
        GostCertificate result = GostCertificate.fromPemOrDer(pemBytes);
        assertNotNull(result, "fromPemOrDer(PEM) должен вернуть сертификат");
        assertTrue(
                result.verifySignature(result.getPublicKey()),
                "Сертификат через PEM roundtrip должен самоподписываться");
    }

    @Test
    @DisplayName("toPem: формат PEM-заголовков")
    void testToPemFormat() throws Exception {
        GostCertificate cert = createTestCert();
        String pem = cert.toPem();
        assertTrue(
                pem.startsWith("-----BEGIN CERTIFICATE-----"),
                "PEM должен начинаться с BEGIN CERTIFICATE");
        assertTrue(
                pem.contains("-----END CERTIFICATE-----"), "PEM должен содержать END CERTIFICATE");
        // Каждая строка Base64 ≤ 64 символа (кроме заголовков)
        for (String line : pem.split("\n")) {
            if (line.startsWith("-----")) continue;
            assertTrue(
                    line.length() <= 64,
                    "Строка Base64 не должна превышать 64 символа: " + line.length());
        }
    }

    @Test
    @DisplayName("toPem -> fromPemOrDer: roundtrip с валидацией подписи")
    void testToPemFromPemOrDerRoundtrip() throws Exception {
        GostCertificate cert = createTestCert();
        String pem = cert.toPem();
        GostCertificate roundtrip =
                GostCertificate.fromPemOrDer(pem.getBytes(StandardCharsets.US_ASCII));
        assertTrue(
                roundtrip.verifySignature(roundtrip.getPublicKey()),
                "toPem->fromPemOrDer roundtrip: подпись должна быть валидна");
    }

    @Test
    @DisplayName("listFromPem: один сертификат")
    void testListFromPemSingle() throws Exception {
        GostCertificate cert = createTestCert();
        List<GostCertificate> list =
                GostCertificate.listFromPem(cert.toPem().getBytes(StandardCharsets.US_ASCII));
        assertEquals(1, list.size(), "Один PEM-блок -> один сертификат");
        assertTrue(
                list.get(0).verifySignature(list.get(0).getPublicKey()),
                "Подпись сертификата должна быть валидна");
    }

    @Test
    @DisplayName("listFromPem: цепочка из двух сертификатов")
    void testListFromPemChain() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        // Создаём корневой и подчинённый сертификаты
        CertBundle rootBundle = TlsTestHelper.createRootCA(params);
        PrivateKeyParameters rootPriv = rootBundle.priv;
        PublicKeyParameters rootPub = rootBundle.cert.getPublicKey();
        CertBundle leafBundle =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootPriv,
                        rootPub,
                        rootBundle.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        false,
                        null);
        String chainPem = leafBundle.cert.toPem() + rootBundle.cert.toPem();
        List<GostCertificate> chain =
                GostCertificate.listFromPem(chainPem.getBytes(StandardCharsets.US_ASCII));
        assertEquals(2, chain.size(), "Два PEM-блока -> два сертификата");
        // leaf подписан root
        assertTrue(
                chain.get(0).verifySignature(chain.get(1).getPublicKey()),
                "Leaf сертификат должен быть подписан root-ом");
        // root самоподписан
        assertTrue(
                chain.get(1).verifySignature(chain.get(1).getPublicKey()),
                "Root сертификат должен быть самоподписан");
    }

    @Test
    @DisplayName("chainToPem: roundtrip через listFromPem")
    void testChainToPemRoundtrip() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        CertBundle rootBundle = TlsTestHelper.createRootCA(params);
        PrivateKeyParameters rootPriv = rootBundle.priv;
        PublicKeyParameters rootPub = rootBundle.cert.getPublicKey();
        CertBundle leafBundle =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootPriv,
                        rootPub,
                        rootBundle.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        false,
                        null);
        List<GostCertificate> original = Arrays.asList(leafBundle.cert, rootBundle.cert);
        String pem = GostCertificate.chainToPem(original);
        List<GostCertificate> restored =
                GostCertificate.listFromPem(pem.getBytes(StandardCharsets.US_ASCII));
        assertEquals(
                original.size(),
                restored.size(),
                "chainToPem->listFromPem: размер цепочки должен совпадать");
        assertTrue(
                restored.get(0).verifySignature(restored.get(1).getPublicKey()),
                "chainToPem->listFromPem: подпись leaf должна быть валидна");
    }

    // -----------------------------------------------------------------------
    // Обработка ошибок
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("fromPemOrDer: null-вход -> исключение")
    void testFromPemOrDerNull() {
        assertThrows(IllegalArgumentException.class, () -> GostCertificate.fromPemOrDer(null));
    }

    @Test
    @DisplayName("fromPemOrDer: пустой массив -> IllegalArgumentException")
    void testFromPemOrDerEmpty() {
        assertThrows(
                IllegalArgumentException.class, () -> GostCertificate.fromPemOrDer(new byte[0]));
    }

    @Test
    @DisplayName("fromPemOrDer: мусор -> IllegalArgumentException")
    void testFromPemOrDerInvalid() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificate.fromPemOrDer(new byte[] {0x00}));
    }

    @Test
    @DisplayName("listFromPem: пустая строка -> IllegalArgumentException")
    void testListFromPemEmpty() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificate.listFromPem("".getBytes(StandardCharsets.US_ASCII)));
    }
}
