package org.rssys.gost.tls13.cert;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsTestHelper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit-тесты для TlsOcspVerifier.verify() — CertID matching negative paths.
 */
class TlsOcspVerifierTest {

    private static ECParameters params;
    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
        leaf = TlsTestHelper.createCertSignedBy(params, root.priv,
                root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, (byte[]) null, (String[]) null,
                false, null);
    }

    @Test
    @DisplayName("CertID: неверный issuer DN → issuerNameHash mismatch")
    void testCertIdNameHashMismatch() throws Exception {
        byte[] ocsp = TlsTestHelper.buildOcspResponse(
                leaf.cert.getSerialNumber(), root.priv,
                root.cert.getPublicKey(), root.subjectDn);
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsOcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(),
                        root.cert.getPublicKey(),
                        new byte[]{0x30, 0x00}, root.cert.getEncoded()));
        assertTrue(ex.getMessage().contains("issuerNameHash mismatch"));
    }

    @Test
    @DisplayName("CertID: чужой issuer с другим ключом → issuerKeyHash mismatch")
    void testCertIdKeyHashMismatch() throws Exception {
        TlsTestHelper.CertBundle otherRoot = TlsTestHelper.createRootCA(params);
        byte[] ocsp = TlsTestHelper.buildOcspResponse(
                leaf.cert.getSerialNumber(), root.priv,
                root.cert.getPublicKey(), root.subjectDn);
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsOcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(),
                        root.cert.getPublicKey(),
                        root.subjectDn, otherRoot.cert.getEncoded()));
        assertTrue(ex.getMessage().contains("issuerKeyHash mismatch"));
    }

    @Test
    @DisplayName("CertID: OID алгоритма хеширования не Streebog-256 → отказ")
    void testCertIdHashAlgorithmMismatch() throws Exception {
        byte[] ocsp = TlsTestHelper.buildOcspResponse(
                leaf.cert.getSerialNumber(), root.priv,
                root.cert.getPublicKey(), root.subjectDn);
        // Мутируем OID с Streebog-256 (0x06,0x08,0x2A,0x85,...) на SHA-1 (0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A)
        byte[] mutated = ocsp.clone();
        byte[] streebogOid = {0x06, 0x08, 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
        byte[] sha1Oid     = {0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A};
        int idx = indexOf(mutated, streebogOid);
        assertTrue(idx >= 0, "Streebog-256 OID should be found in OCSP response");
        System.arraycopy(sha1Oid, 0, mutated, idx, sha1Oid.length);

        TlsException ex = assertThrows(TlsException.class, () ->
                TlsOcspVerifier.verify(mutated, leaf.cert.getSerialNumber(),
                        root.cert.getPublicKey(),
                        root.subjectDn, root.cert.getEncoded()));
        assertTrue(ex.getMessage().contains("not Streebog-256"),
                "Expected hashAlgorithm error, got: " + ex.getMessage());
    }

    @Test
    @DisplayName("thisUpdate в будущем → отказ (RFC 6960 §3.2)")
    void testThisUpdateInFuture() throws Exception {
        byte[] ocsp = TlsTestHelper.buildOcspResponse(
                leaf.cert.getSerialNumber(), root.priv,
                root.cert.getPublicKey(), root.subjectDn);
        byte[] mutated = ocsp.clone();
        // Ищем полный TLV UTCTime (0x17) со значением "250501120000Z"
        // producedAt (0x18 GeneralizedTime) не содержит подстроку-совпадение с тегом 0x17
        byte[] needle = {0x17, 0x0D, 0x32, 0x35, 0x30, 0x35, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A};
        byte[] replacement = {0x17, 0x0D, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A};
        int idx = indexOf(mutated, needle);
        assertTrue(idx >= 0, "thisUpdate TLV должен быть найден в OCSP-ответе");
        System.arraycopy(replacement, 0, mutated, idx, replacement.length);

        TlsException ex = assertThrows(TlsException.class, () ->
                TlsOcspVerifier.verify(mutated, leaf.cert.getSerialNumber(),
                        root.cert.getPublicKey()));
        assertTrue(ex.getMessage().contains("future"),
                "Ожидалось thisUpdate future, получено: " + ex.getMessage());
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
