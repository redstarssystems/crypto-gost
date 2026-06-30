package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;

/**
 * Модульные тесты {@link CertIdHasher}: issuerNameHash и issuerKeyHash.
 */
@DisplayName("CertIdHasher: хеши CertID")
class CertIdHasherTest {

    // ---------------------------------------------------------------
    // Вспомогательный метод
    // ---------------------------------------------------------------

    /** Создаёт самоподписанный сертификат для тестов. */
    private static GostCertificate createSelfSignedCert() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Issuer");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .buildTbs();
        return GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);
    }

    // ---------------------------------------------------------------
    // Существующий тест
    // ---------------------------------------------------------------

    @Test
    @DisplayName("hashIssuerPublicKey: перегрузки byte[] и GostCertificate дают одинаковый хеш")
    void testHashIssuerPublicKeyOverloadsMatch() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hashFromDer = CertIdHasher.hashIssuerPublicKey(certDer);
        byte[] hashFromCert = CertIdHasher.hashIssuerPublicKey(cert);

        assertArrayEquals(
                hashFromDer,
                hashFromCert,
                "Перегрузки hashIssuerPublicKey(byte[]) и hashIssuerPublicKey(GostCertificate) должны давать одинаковый хеш");
    }

    // ---------------------------------------------------------------
    // hashIssuerName(byte[], int hlen) — 2 теста
    // ---------------------------------------------------------------

    @Test
    @DisplayName("hashIssuerName: перегрузка (byte[], 32) совпадает с одноаргументной")
    void testHashIssuerNameByteArrayHlen32() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hashDefault = CertIdHasher.hashIssuerName(certDer);
        byte[] hashExplicit = CertIdHasher.hashIssuerName(certDer, GostOids.STREEBOG_256_HASH_LEN);

        assertArrayEquals(
                hashDefault,
                hashExplicit,
                "hashIssuerName(byte[]) должен совпадать с hashIssuerName(byte[], 32)");
        assertEquals(32, hashExplicit.length, "длина хеша Streebog-256 = 32 байта");
    }

    @Test
    @DisplayName("hashIssuerName: (byte[], 64) -> длина 64 байта")
    void testHashIssuerNameByteArrayHlen64() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hash = CertIdHasher.hashIssuerName(certDer, GostOids.STREEBOG_512_HASH_LEN);

        assertEquals(64, hash.length, "длина хеша Streebog-512 = 64 байта");

        byte[] hash32 = CertIdHasher.hashIssuerName(certDer, GostOids.STREEBOG_256_HASH_LEN);
        assertFalse(java.util.Arrays.equals(hash, hash32), "хеши 256 и 512 различаются");
    }

    // ---------------------------------------------------------------
    // hashIssuerName(GostCertificate) — 1 тест
    // ---------------------------------------------------------------

    @Test
    @DisplayName("hashIssuerName(GostCertificate) совпадает с hashIssuerName(byte[], 32)")
    void testHashIssuerNameGostCert() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hashFromCert = CertIdHasher.hashIssuerName(cert);
        byte[] hashFromDer = CertIdHasher.hashIssuerName(certDer, GostOids.STREEBOG_256_HASH_LEN);

        assertArrayEquals(
                hashFromDer,
                hashFromCert,
                "hashIssuerName(GostCertificate) должен давать тот же хеш что и hashIssuerName(byte[], 32)");
    }

    // ---------------------------------------------------------------
    // hashIssuerName(GostCertificate, int hlen) — 2 теста
    // ---------------------------------------------------------------

    @Test
    @DisplayName("hashIssuerName: (GostCertificate, 32) совпадает с одноаргументной")
    void testHashIssuerNameGostCertHlen32() {
        GostCertificate cert = createSelfSignedCert();

        byte[] hashDefault = CertIdHasher.hashIssuerName(cert);
        byte[] hashExplicit = CertIdHasher.hashIssuerName(cert, GostOids.STREEBOG_256_HASH_LEN);

        assertArrayEquals(
                hashDefault,
                hashExplicit,
                "hashIssuerName(GostCertificate) должен совпадать с hashIssuerName(GostCertificate, 32)");
    }

    @Test
    @DisplayName("hashIssuerName: (GostCertificate, 64) -> Streebog-512")
    void testHashIssuerNameGostCertHlen64() {
        GostCertificate cert = createSelfSignedCert();

        byte[] hash = CertIdHasher.hashIssuerName(cert, GostOids.STREEBOG_512_HASH_LEN);

        assertEquals(64, hash.length, "длина хеша = 64");
    }

    // ---------------------------------------------------------------
    // hashIssuerPublicKey(byte[], int hlen) — 2 теста
    // ---------------------------------------------------------------

    @Test
    @DisplayName("hashIssuerPublicKey: (byte[], 32) совпадает с одноаргументной")
    void testHashIssuerPublicKeyByteArrayHlen32() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hashDefault = CertIdHasher.hashIssuerPublicKey(certDer);
        byte[] hashExplicit =
                CertIdHasher.hashIssuerPublicKey(certDer, GostOids.STREEBOG_256_HASH_LEN);

        assertArrayEquals(
                hashDefault,
                hashExplicit,
                "hashIssuerPublicKey(byte[]) должен совпадать с hashIssuerPublicKey(byte[], 32)");
        assertEquals(32, hashExplicit.length);
    }

    @Test
    @DisplayName("hashIssuerPublicKey: (byte[], 64) -> Streebog-512")
    void testHashIssuerPublicKeyByteArrayHlen64() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hash = CertIdHasher.hashIssuerPublicKey(certDer, GostOids.STREEBOG_512_HASH_LEN);

        assertEquals(64, hash.length, "длина хеша = 64");
    }

    // ---------------------------------------------------------------
    // hashIssuerPublicKey(GostCertificate, int hlen) — 2 теста
    // ---------------------------------------------------------------

    @Test
    @DisplayName("hashIssuerPublicKey: (GostCertificate, 32) совпадает с (byte[], 32)")
    void testHashIssuerPublicKeyGostCertHlen32() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hashFromCert =
                CertIdHasher.hashIssuerPublicKey(cert, GostOids.STREEBOG_256_HASH_LEN);
        byte[] hashFromDer =
                CertIdHasher.hashIssuerPublicKey(certDer, GostOids.STREEBOG_256_HASH_LEN);

        assertArrayEquals(
                hashFromDer,
                hashFromCert,
                "hashIssuerPublicKey(GostCertificate, 32) должен совпадать с hashIssuerPublicKey(byte[], 32)");
    }

    @Test
    @DisplayName("hashIssuerPublicKey: (GostCertificate, 64) -> Streebog-512")
    void testHashIssuerPublicKeyGostCertHlen64() {
        GostCertificate cert = createSelfSignedCert();
        byte[] certDer = cert.getEncoded();

        byte[] hashFromCert =
                CertIdHasher.hashIssuerPublicKey(cert, GostOids.STREEBOG_512_HASH_LEN);
        byte[] hashFromDer =
                CertIdHasher.hashIssuerPublicKey(certDer, GostOids.STREEBOG_512_HASH_LEN);

        assertArrayEquals(
                hashFromDer,
                hashFromCert,
                "hashIssuerPublicKey(GostCertificate, 64) должен совпадать с hashIssuerPublicKey(byte[], 64)");
        assertEquals(64, hashFromCert.length);
    }
}
