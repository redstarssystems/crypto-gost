package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Тесты EKU-проверки делегированных OCSP-responder сертификатов (RFC 6960 §4.2.2.2).
 */
@DisplayName("OcspVerifier: EKU проверка делегированных responder-сертификатов")
class OcspVerifierDelegatedCertTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static PkixCertTestHelper.CertBundle ca;
    private static PkixCertTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ca = PkixCertTestHelper.createRootCA(PARAMS);
        leaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);
    }

    @Test
    @DisplayName("Прямое подписание CA — успех (EKU не проверяется для CA)")
    void directCaSigning_success() throws Exception {
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(ca.subjectDn)
                        .sign(ca.priv);

        OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert);
    }

    @Test
    @DisplayName("Делегированный responder с EKU id-kp-OCSPSigning — успех")
    void delegatedWithEkuOcspSigning_success() throws Exception {
        byte[] ku =
                GostCertificateBuilder.keyUsageFlags(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        PkixCertTestHelper.CertBundle responder =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        ku,
                        new String[] {GostOids.EXT_OCSP_SIGNING},
                        false,
                        null);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .withDelegatedCerts(responder.cert.getEncoded())
                        .sign(responder.priv);

        OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert);
    }

    @Test
    @DisplayName("Делегированный responder БЕЗ id-kp-OCSPSigning — PkixException")
    void delegatedWithoutOcspEku_throws() throws Exception {
        byte[] ku =
                GostCertificateBuilder.keyUsageFlags(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        PkixCertTestHelper.CertBundle responder =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        ku,
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .withDelegatedCerts(responder.cert.getEncoded())
                        .sign(responder.priv);

        PkixException ex;
        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            ex =
                    assertThrows(
                            PkixException.class,
                            () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                            "Делегированный responder без id-kp-OCSPSigning должен быть отвергнут");
            // Итоговое исключение не называет причину отказа кандидата: она пишется на DEBUG
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(
                                    m ->
                                            m.contains("candidate")
                                                    && m.contains("skipped: no id-kp-OCSPSigning")),
                    "причина пропуска кандидата на DEBUG: " + log.messages(Level.FINE));
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отказ несёт исключение, WARNING не нужен");
        }
        assertTrue(
                ex.getMessage().contains("signature verification failed"),
                "Ожидалась ошибка подписи, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Делегированный responder БЕЗ EKU вовсе — PkixException (restrictive)")
    void delegatedWithoutAnyEku_throws() throws Exception {
        // ekuOids=null -> расширения EKU нет вовсе (ekuPresent=false). Ранее permissive-формула
        // давала isOcspSigning()=true и принимала такой cert как responder — теперь fail-closed
        // по RFC 6960 §4.2.2.2.
        byte[] ku =
                GostCertificateBuilder.keyUsageFlags(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        PkixCertTestHelper.CertBundle responder =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        ku,
                        null,
                        false,
                        null);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .withDelegatedCerts(responder.cert.getEncoded())
                        .sign(responder.priv);

        PkixException ex;
        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            ex =
                    assertThrows(
                            PkixException.class,
                            () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                            "Делегированный responder без EKU должен быть отвергнут (fail-closed)");
            // Итоговое исключение не называет причину отказа кандидата: она пишется на DEBUG
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(
                                    m ->
                                            m.contains("candidate")
                                                    && m.contains("skipped: no id-kp-OCSPSigning")),
                    "причина пропуска кандидата на DEBUG: " + log.messages(Level.FINE));
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отказ несёт исключение, WARNING не нужен");
        }
        assertTrue(
                ex.getMessage().contains("signature verification failed"),
                "Ожидалась ошибка подписи, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Делегированный responder просрочен — PkixException")
    void delegatedExpiredResponder_throws() throws Exception {
        byte[] ku =
                GostCertificateBuilder.keyUsageFlags(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        PkixCertTestHelper.CertBundle responder =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20000101120000Z",
                        "20010101120000Z",
                        null,
                        null,
                        ku,
                        new String[] {GostOids.EXT_OCSP_SIGNING},
                        false,
                        null);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .withDelegatedCerts(responder.cert.getEncoded())
                        .sign(responder.priv);

        PkixException ex;
        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            ex =
                    assertThrows(
                            PkixException.class,
                            () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                            "Просроченный delegated responder должен быть отвергнут");
            // Итоговое исключение не называет причину отказа кандидата: она пишется на DEBUG
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(
                                    m ->
                                            m.contains("candidate")
                                                    && m.contains(
                                                            "skipped: expired or not yet valid")),
                    "причина пропуска кандидата на DEBUG: " + log.messages(Level.FINE));
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отказ несёт исключение, WARNING не нужен");
        }
        assertTrue(
                ex.getMessage().contains("signature verification failed"),
                "Ожидалась ошибка подписи, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CertID: несовпадение issuerNameHash при одинаковом ключе — PkixException")
    void certIdNameHashMismatch_throws() throws Exception {
        org.rssys.gost.api.KeyPair kpSame = KeyGenerator.generateKeyPair(PARAMS);
        PrivateKeyParameters samePriv = kpSame.getPrivate();
        PublicKeyParameters samePub = kpSame.getPublic();

        byte[] kuCa =
                GostCertificateBuilder.keyUsageFlags(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        ByteArrayOutputStream ca1Ext = new ByteArrayOutputStream();
        ca1Ext.write(GostCertificateBuilder.buildBasicConstraintsExtension(true, null));
        ca1Ext.write(GostCertificateBuilder.buildKeyUsageExtension(kuCa, false));

        byte[] dn1 = GostDnParser.encodeDn("CN=CA One");
        byte[] tbs1 =
                GostCertificateBuilder.create(PARAMS, dn1)
                        .publicKey(samePub)
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .additionalExtensions(ca1Ext.toByteArray())
                        .issuerDn(dn1)
                        .randomSerial()
                        .buildTbs();
        GostCertificate ca1 = GostCertificateBuilder.sign(tbs1, GostSigner.of(samePriv));

        byte[] dn2 = GostDnParser.encodeDn("CN=CA Two");
        byte[] tbs2 =
                GostCertificateBuilder.create(PARAMS, dn2)
                        .publicKey(samePub)
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .additionalExtensions(ca1Ext.toByteArray())
                        .issuerDn(dn2)
                        .randomSerial()
                        .buildTbs();
        GostCertificate ca2 = GostCertificateBuilder.sign(tbs2, GostSigner.of(samePriv));

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(dn1)
                        .sign(samePriv);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca2),
                        "CertID nameHash mismatch должен быть обнаружен");
        assertTrue(
                ex.getMessage().contains("issuerNameHash mismatch"),
                "Ожидался issuerNameHash mismatch, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CertID: несовпадение issuerKeyHash через caPublicKey — PkixException")
    void certIdKeyHashMismatch_throws() throws Exception {
        // caPublicKey builder-а задаёт ключ для CertID независимо от ключа подписи.
        // Используем dummy-ключ — CertID.issuerKeyHash = hash(dummyPub),
        // а подпись — CA-ключом (совпадает с issuerCert).
        var dummyKp = KeyGenerator.generateKeyPair(PARAMS);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(dummyKp.getPublic())
                        .issuerDn(ca.subjectDn)
                        .sign(ca.priv);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                        "CertID issuerKeyHash mismatch должен быть обнаружен");
        assertTrue(
                ex.getMessage().contains("issuerKeyHash mismatch"),
                "Ожидался issuerKeyHash mismatch, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CertID: hashAlgorithm не Streebog — PkixException при парсинге")
    void certIdHashAlgorithmMismatch_throws() throws Exception {
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(ca.subjectDn)
                        .sign(ca.priv);

        // Подменяем OID Streebog-256 в CertID на SHA-1
        byte[] streebog256Oid = {0x06, 0x08, 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
        byte[] sha1Oid = {0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A};
        byte[] mutated = ocsp.clone();
        int idx = -1;
        outer:
        for (int i = 0; i <= mutated.length - streebog256Oid.length; i++) {
            for (int j = 0; j < streebog256Oid.length; j++) {
                if (mutated[i + j] != streebog256Oid[j]) continue outer;
            }
            idx = i;
            break;
        }
        assertTrue(idx >= 0, "OID Streebog-256 должен быть найден в OCSP-ответе");
        System.arraycopy(sha1Oid, 0, mutated, idx, sha1Oid.length);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(mutated, leaf.cert.getSerialNumber(), ca.cert),
                        "Неверный hashAlgorithm должен быть отвергнут при парсинге");
        assertTrue(
                ex.getMessage().contains("must be Streebog-256 or Streebog-512"),
                "Ожидалась ошибка hashAlgorithm, получено: " + ex.getMessage());
    }

    // ========================================================================
    // Раздельные роли RFC 6960: certIdIssuer vs responderAuthority
    // ========================================================================

    @Test
    @DisplayName(
            "Раздельные роли: ответ подписан authority, CertID — от истинного издателя — успех")
    void splitRoles_directAuthoritySigning_success() throws Exception {
        // authority — независимый CA, чьим ключом подписан ответ; CertID при этом
        // считается от истинного издателя листа (ca). Легитимный аналог rollover.
        PkixCertTestHelper.CertBundle authority = PkixCertTestHelper.createRootCA(PARAMS);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .sign(authority.priv);

        OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert, authority.cert, null);
    }

    @Test
    @DisplayName("Раздельные роли: неверный responderAuthority — отказ подписи")
    void splitRoles_wrongAuthority_signatureFails() throws Exception {
        PkixCertTestHelper.CertBundle authority = PkixCertTestHelper.createRootCA(PARAMS);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .sign(authority.priv);

        // authority правильный по CertID (ca), но как authority подписи передан сам ca,
        // чьим ключом ответ не подписан -> fail-closed по подписи.
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        ocsp, leaf.cert.getSerialNumber(), ca.cert, ca.cert, null),
                        "Неверный responderAuthority должен приводить к отказу подписи");
        assertTrue(
                ex.getMessage().contains("signature verification failed"),
                "Ожидалась ошибка подписи, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Раздельные роли: неверный certIdIssuer — issuerNameHash mismatch")
    void splitRoles_wrongCertIdIssuer_hashMismatch() throws Exception {
        PkixCertTestHelper.CertBundle authority = PkixCertTestHelper.createRootCA(PARAMS);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .sign(authority.priv);

        // Подпись валидна (authority), но CertID считается не от того издателя.
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        ocsp,
                                        leaf.cert.getSerialNumber(),
                                        authority.cert,
                                        authority.cert,
                                        null),
                        "Неверный certIdIssuer должен ловиться проверкой CertID");
        assertTrue(
                ex.getMessage().contains("issuerNameHash mismatch"),
                "Ожидался issuerNameHash mismatch, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Раздельные роли: оба параметра = CA эквивалентно однопараметрической перегрузке")
    void splitRoles_bothSameAsSingleArg_equivalent() throws Exception {
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(ca.subjectDn)
                        .sign(ca.priv);

        // Не должно бросать: поведение совпадает с verify(ocsp, serial, ca).
        OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert, ca.cert, null);
    }
}
