package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Тесты расширения id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1): выпуск, кодировка,
 * guard от неправильного использования, чтение и предикат аномалии verifier'а.
 */
@DisplayName("id-pkix-ocsp-nocheck: выпуск, кодировка, guard, чтение")
class OcspNoCheckExtensionTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    // Каноническая DER-кодировка расширения (RFC 6960 §4.2.2.2.1):
    // SEQUENCE { OID 1.3.6.1.5.5.7.48.1.5, OCTET STRING { NULL } }, non-critical.
    // extnValue = 04 02 05 00 (OCTET STRING, оборачивающий DER NULL), НЕ пустой 04 00.
    private static final byte[] EXPECTED_EXTENSION = {
        0x30, 0x0F, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05, 0x04, 0x02,
        0x05, 0x00
    };

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
    }

    private static byte[] dn(String cn) {
        return GostDnParser.encodeDn("CN=" + cn);
    }

    @Test
    @DisplayName("buildOcspNoCheckExtension() кодирует ровно 04 02 05 00 (не 04 00)")
    void staticBuilder_exactBytes() {
        byte[] ext = GostCertificateBuilder.buildOcspNoCheckExtension();
        assertArrayEquals(
                EXPECTED_EXTENSION,
                ext,
                "DER-кодировка nocheck должна быть канонической (extnValue = 04 02 05 00)");
        // Байт сразу после OID — тег OCTET STRING (0x04), а не BOOLEAN (0x01):
        // расширение обязано быть non-critical.
        int afterOidTag = ext[13] & 0xFF;
        assertEquals(0x04, afterOidTag, "nocheck должно быть non-critical (без BOOLEAN critical)");
    }

    @Test
    @DisplayName("Выпуск responder-сертификата с .ocspNoCheck() — round-trip чтения")
    void issueAndRead_roundTrip() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();
        byte[] subject = dn("OCSP Responder");

        GostCertificate cert =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(pub)
                        .issuerDn(subject)
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)
                        .ocspNoCheck()
                        .randomSerial()
                        .sign(priv);

        assertTrue(cert.hasOcspNoCheck(), "hasOcspNoCheck() должен вернуть true");
        assertTrue(
                cert.getPresentExtensionOids().contains(GostOids.EXT_OCSP_NOCHECK),
                "OID nocheck должен присутствовать в presentExtensionOids");
        assertTrue(
                indexOf(cert.getEncoded(), EXPECTED_EXTENSION) >= 0,
                "DER сертификата должен содержать каноническое расширение nocheck");
    }

    @Test
    @DisplayName("Без .ocspNoCheck() — hasOcspNoCheck() == false")
    void withoutNoCheck_absent() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subject = dn("Plain Responder");

        GostCertificate cert =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(kp.getPublic())
                        .issuerDn(subject)
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)
                        .randomSerial()
                        .sign(kp.getPrivate());

        assertFalse(cert.hasOcspNoCheck(), "без вызова .ocspNoCheck() расширения быть не должно");
    }

    @Test
    @DisplayName("Guard: .ocspNoCheck() без EKU OCSPSigning -> IllegalStateException")
    void guard_requiresOcspSigningEku() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subject = dn("Wrong Usage");

        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(kp.getPublic())
                        .issuerDn(subject)
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .randomSerial()
                        .ocspNoCheck();

        IllegalStateException ex =
                assertThrows(
                        IllegalStateException.class,
                        builder::buildTbs,
                        "nocheck без EKU OCSPSigning должен быть отвергнут");
        assertTrue(
                ex.getMessage().contains("EXT_OCSP_SIGNING"),
                "сообщение должно указывать на требование EKU OCSPSigning");
    }

    @Test
    @DisplayName("Guard: EKU serverAuth (без OCSPSigning) + nocheck -> IllegalStateException")
    void guard_wrongEku() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subject = dn("Server Cert");

        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(kp.getPublic())
                        .issuerDn(subject)
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .randomSerial()
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .ocspNoCheck();

        assertThrows(
                IllegalStateException.class,
                builder::buildTbs,
                "nocheck на не-responder сертификате должен быть отвергнут");
    }

    // ------------------------------------------------------------------------
    // Матрица предиката аномалии verifier'а (RFC 6960 §4.2.2.2.1) — все 4 угла.
    // Проверяем именно AND/! логику: перепутанный ||/&& ловится строкой 2.
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Матрица аномалии: nocheck=есть, revocation=нет -> норма (DEBUG)")
    void matrix_noCheckPresent_noPointer_normal() {
        GostCertificate dc = buildResponder(true, false);
        assertFalse(OcspVerifier.isMissingNoCheckAnomaly(dc), "case 1: аномалии быть не должно");
    }

    @Test
    @DisplayName("Матрица аномалии: nocheck=есть, revocation=есть -> норма (DEBUG, НЕ WARNING)")
    void matrix_noCheckPresent_withPointer_normal() {
        GostCertificate dc = buildResponder(true, true);
        assertFalse(
                OcspVerifier.isMissingNoCheckAnomaly(dc),
                "CA подстраховался с обеих сторон — это не аномалия");
    }

    @Test
    @DisplayName("Матрица аномалии: nocheck=нет, revocation=нет -> норма (DEBUG, case 3)")
    void matrix_noCheckAbsent_noPointer_normal() {
        GostCertificate dc = buildResponder(false, false);
        assertFalse(
                OcspVerifier.isMissingNoCheckAnomaly(dc),
                "case 3 (ничего не указано) легален — не аномалия");
    }

    @Test
    @DisplayName("Матрица аномалии: nocheck=нет, revocation=есть -> АНОМАЛИЯ (WARNING, case 2)")
    void matrix_noCheckAbsent_withPointer_anomaly() {
        GostCertificate dc = buildResponder(false, true);
        assertTrue(
                OcspVerifier.isMissingNoCheckAnomaly(dc),
                "case 2: точка отзыва есть, а nocheck нет — аномалия");
    }

    /** Строит responder-сертификат с заданными флагами nocheck и наличия точки отзыва. */
    private static GostCertificate buildResponder(boolean noCheck, boolean revocationPointer) {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subject = dn("Matrix Responder " + noCheck + "-" + revocationPointer);
        GostCertificateBuilder b =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(kp.getPublic())
                        .issuerDn(subject)
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)
                        .randomSerial();
        if (revocationPointer) {
            b.crlDistributionPoints("http://crl.example.com/r.crl");
        }
        if (noCheck) {
            b.ocspNoCheck();
        }
        return b.sign(kp.getPrivate());
    }

    /** Индекс первого вхождения needle в haystack, либо -1. */
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
