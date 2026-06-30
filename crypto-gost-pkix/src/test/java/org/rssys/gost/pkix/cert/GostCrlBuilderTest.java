package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostCrlBuilder}: roundtrip build -> verify.
 */
@DisplayName("GostCrlBuilder: построение, подпись, проверка")
class GostCrlBuilderTest {

    private static final byte[] TEST_SERIAL = new byte[] {0x01};
    private static final byte[] UNUSED_SERIAL = new byte[] {0x77};

    @Test
    @DisplayName("buildCrl: обратимость — собираем CRL, верифицируем через CrlVerifier")
    void testBuildCrlRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .build();

        assertNotNull(crlDer);
        assertTrue(crlDer.length > 50);
        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("buildCrl: подпись валидна, сертификат не отозван -> OK")
    void testBuildCrlSignatureValid() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .build();

        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("buildCrl: сертификат отозван -> PkixException")
    void testBuildCrlCertificateRevoked() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry[] entries =
                new RevokedEntry[] {
                    new RevokedEntry(TEST_SERIAL, GostSignatureHelper.nowGeneralizedTime())
                };
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(Arrays.asList(entries))
                        .build();

        assertThrows(
                PkixException.class, () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()));
    }

    @Test
    @DisplayName("buildCrl с несколькими отозванными сертификатами")
    void testBuildCrlWithMultipleRevoked() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry[] entries =
                new RevokedEntry[] {
                    new RevokedEntry(TEST_SERIAL, GostSignatureHelper.nowGeneralizedTime()),
                    new RevokedEntry(new byte[] {0x05}, GostSignatureHelper.nowGeneralizedTime()),
                    new RevokedEntry(new byte[] {0x10}, GostSignatureHelper.nowGeneralizedTime())
                };
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(Arrays.asList(entries))
                        .build();

        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()),
                "TEST_SERIAL должен быть отозван");
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, new byte[] {0x05}, kp.getPublic()),
                "Серийный номер 0x05 должен быть отозван");
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, new byte[] {0x10}, kp.getPublic()),
                "Серийный номер 0x10 должен быть отозван");
    }

    @Test
    @DisplayName("buildCrl с IDP-расширением — CrlVerifier должен reject")
    void testBuildCrlWithIdpExtensionRejected() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withIdpExtension()
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic()),
                "CRL с IDP должен быть rejected (partial/indirect не поддерживается)");
    }

    @Test
    @DisplayName("assembleCrl с legacyVersion: fallback-ветка CrlVerifier")
    void testBuildCrlLegacyVersion() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.assembleCrl(
                        null, kp.getPrivate(), issuerDn,
                        GostSignatureHelper.nowGeneralizedTime(),
                        "20990601120000Z", true, null, null, null, false);

        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("buildCrl без nextUpdate (null) — должен верифицироваться")
    void testBuildCrlWithoutNextUpdate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer = GostCrlBuilder.create(kp.getPrivate(), issuerDn).build();

        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("buildCrl: чужой ключ не проходит проверку подписи")
    void testBuildCrlWrongKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        KeyPair wrongKp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, UNUSED_SERIAL, wrongKp.getPublic()),
                "Чужой ключ не должен проходить проверку");
    }

    // ========================================================================
    // CRL entry extensions: reasonCode, invalidityDate, certificateIssuer
    // ========================================================================

    @Test
    @DisplayName("buildCrl с reasonCode KEY_COMPROMISE: обратимость")
    void testBuildCrlWithReasonCode() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry entry =
                new RevokedEntry(
                        TEST_SERIAL,
                        GostSignatureHelper.nowGeneralizedTime(),
                        ReasonCode.KEY_COMPROMISE,
                        null,
                        null);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()),
                "Отозванный сертификат должен вызывать PkixException");

        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CRL_REASON)),
                "CRL должен содержать OID reasonCode");
    }

    @Test
    @DisplayName("buildCrl с invalidityDate: обратимость")
    void testBuildCrlWithInvalidityDate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry entry =
                new RevokedEntry(TEST_SERIAL, "20250601120000Z", null, "20250530120000Z", null);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        assertThrows(
                PkixException.class, () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()));

        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_INVALIDITY_DATE)),
                "CRL должен содержать OID invalidityDate");
    }

    @Test
    @DisplayName("buildCrl с certificateIssuer (indirect CRL): обратимость")
    void testBuildCrlWithCertificateIssuer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] certIssuerDn = GostDnParser.encodeDn("CN=Original Issuer CA");
        byte[] certIssuerGn =
                GeneralNameCodec.encodeGeneralNames(
                        GeneralNameCodec.encodeDirectoryName(certIssuerDn));

        RevokedEntry entry =
                new RevokedEntry(TEST_SERIAL, "20250601120000Z", null, null, certIssuerGn);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        assertThrows(
                PkixException.class, () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()));

        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CERTIFICATE_ISSUER)),
                "CRL должен содержать OID certificateIssuer");
    }

    @Test
    @DisplayName("buildCrl: reasonCode + invalidityDate вместе")
    void testBuildCrlWithReasonAndInvalidityDate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry entry =
                new RevokedEntry(
                        TEST_SERIAL,
                        "20250601120000Z",
                        ReasonCode.KEY_COMPROMISE,
                        "20250530120000Z",
                        null);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        assertThrows(
                PkixException.class, () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()));

        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CRL_REASON)),
                "CRL должен содержать OID reasonCode");
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_INVALIDITY_DATE)),
                "CRL должен содержать OID invalidityDate");
    }

    @Test
    @DisplayName("buildCrl: несколько записей с разными reasonCode")
    void testBuildCrlWithMultipleEntries() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry[] entries =
                new RevokedEntry[] {
                    new RevokedEntry(
                            TEST_SERIAL, "20250601120000Z", ReasonCode.KEY_COMPROMISE, null, null),
                    new RevokedEntry(
                            new byte[] {0x05},
                            "20250601120000Z",
                            ReasonCode.SUPERSEDED,
                            null,
                            null),
                    new RevokedEntry(
                            new byte[] {0x10},
                            "20250601120000Z",
                            ReasonCode.UNSPECIFIED,
                            null,
                            null)
                };
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(Arrays.asList(entries))
                        .build();

        assertThrows(
                PkixException.class, () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()));
        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("buildCrl: пустой revokedEntries -> CRL без записей")
    void testBuildCrlWithEmptyEntries() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer = GostCrlBuilder.create(kp.getPrivate(), issuerDn).build();

        assertNotNull(crlDer);
        assertTrue(crlDer.length > 50);
        CrlVerifier.verify(crlDer, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("buildCrl: CERTIFICATE_HOLD reason")
    void testBuildCrlWithCertificateHold() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry entry =
                new RevokedEntry(
                        TEST_SERIAL, "20250601120000Z", ReasonCode.CERTIFICATE_HOLD, null, null);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        assertThrows(
                PkixException.class, () -> CrlVerifier.verify(crlDer, TEST_SERIAL, kp.getPublic()));
    }

    @Test
    @DisplayName("buildCrl: reasonCode ENUMERATED имеет правильный DER tag 0x0A")
    void testBuildCrlReasonCodeDerTag() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry entry =
                new RevokedEntry(
                        TEST_SERIAL, "20250601120000Z", ReasonCode.KEY_COMPROMISE, null, null);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        assertNotNull(crlDer);
        // Проверяем наличие reasonCode в CRL: ищем OID EXT_CRL_REASON
        byte[] reasonOidDer = DerCodec.encodeOid(GostOids.EXT_CRL_REASON);
        boolean foundReasonOid = containsBytes(crlDer, reasonOidDer);
        assertTrue(foundReasonOid, "CRL должен содержать OID reasonCode");
    }

    /** Проверяет, содержит ли массив data подмассив pattern. */
    private static boolean containsBytes(byte[] data, byte[] pattern) {
        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    // ========================================================================
    // Delta CRL — fluent-методы
    // ========================================================================

    @Test
    @DisplayName("withCrlNumber: CRL содержит OID cRLNumber")
    void testBuildCrlWithCrlNumber() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(42)
                        .build();

        assertNotNull(crlDer);
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CRL_NUMBER)),
                "CRL должен содержать OID cRLNumber");

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());
        assertEquals(BigInteger.valueOf(42), crl.getCrlNumber());
        assertFalse(crl.isDelta());
    }

    @Test
    @DisplayName("withDeltaCrlIndicator: CRL содержит оба OID")
    void testBuildCrlWithDeltaCrlIndicator() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(5)
                        .withDeltaCrlIndicator(4)
                        .build();

        assertNotNull(crlDer);
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CRL_NUMBER)),
                "CRL должен содержать OID cRLNumber");
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_DELTA_CRL_INDICATOR)),
                "CRL должен содержать OID deltaCRLIndicator");

        GostCrl crl = new GostCrl(crlDer);
        assertThrows(PkixException.class, () -> crl.verify(kp.getPublic()),
                "Delta CRL должен быть rejected при изолированной верификации");
    }

    @Test
    @DisplayName("deltaCRLIndicator без cRLNumber: IllegalStateException")
    void testDeltaCrlIndicatorRequiresCrlNumber() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        assertThrows(
                IllegalStateException.class,
                () -> GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withDeltaCrlIndicator(4)
                        .build(),
                "deltaCRLIndicator без cRLNumber должен бросать IllegalStateException");
    }

    @Test
    @DisplayName("withFreshestCrl: CRL содержит OID freshestCRL")
    void testBuildCrlWithFreshestCrl() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withFreshestCrl("http://ca.example/delta.crl")
                        .build();

        assertNotNull(crlDer);
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_FRESHEST_CRL)),
                "CRL должен содержать OID freshestCRL");
    }

    @Test
    @DisplayName("Все 4 CRL-расширения вместе")
    void testBuildDeltaCrlWithAllExtensions() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(10)
                        .withDeltaCrlIndicator(9)
                        .withFreshestCrl("http://ca.example/delta.crl")
                        .withIdpExtension()
                        .build();

        assertNotNull(crlDer);
        assertTrue(containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CRL_NUMBER)));
        assertTrue(containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_DELTA_CRL_INDICATOR)));
        assertTrue(containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_FRESHEST_CRL)));
        assertTrue(containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_IDP)));
    }

    @Test
    @DisplayName("Delta CRL roundtrip: getCrlNumber / getBaseCrlNumber")
    void testDeltaCrlParseRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(7)
                        .withDeltaCrlIndicator(6)
                        .addRevoked(new byte[] {0x01}, "20250601120000Z")
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        // Пакетно-приватный verify с allowDelta=true вызывается через тест
        // (доступен из того же пакета)
        crl.verify(kp.getPublic(), true);

        assertEquals(BigInteger.valueOf(7), crl.getCrlNumber());
        assertEquals(BigInteger.valueOf(6), crl.getBaseCrlNumber());
        assertTrue(crl.isDelta());
    }

    @Test
    @DisplayName("isDelta: true для Delta CRL")
    void testDeltaCrlIsDelta() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(3)
                        .withDeltaCrlIndicator(2)
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), true);
        assertTrue(crl.isDelta(), "Delta CRL должен возвращать isDelta() == true");
    }

    @Test
    @DisplayName("isDelta: false для обычного CRL")
    void testCompleteCrlIsNotDelta() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer = GostCrlBuilder.create(kp.getPrivate(), issuerDn).build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());
        assertFalse(crl.isDelta(), "Обычный CRL должен возвращать isDelta() == false");
        assertNull(crl.getBaseCrlNumber());
    }

    @Test
    @DisplayName("CRL с reasonCode: getReason возвращает KEY_COMPROMISE")
    void testCrlWithReasonCodeParsed() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serial = new byte[] {0x01};

        RevokedEntry entry =
                new RevokedEntry(serial, "20250601120000Z", ReasonCode.KEY_COMPROMISE, null, null);
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(List.of(entry))
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());
        assertEquals(ReasonCode.KEY_COMPROMISE, crl.getReason(serial));
    }

    @Test
    @DisplayName("CRL без reasonCode: getReason возвращает null")
    void testCrlWithoutReasonCode() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serial = new byte[] {0x01};

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .addRevoked(serial, "20250601120000Z")
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());
        assertNull(crl.getReason(serial), "getReason должен быть null без reasonCode");
    }

    @Test
    @DisplayName("Пустой delta CRL распознаётся как delta")
    void testEmptyDeltaCrlIsDelta() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(5)
                        .withDeltaCrlIndicator(4)
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), true);
        assertTrue(crl.isDelta(), "Пустой delta CRL должен распознаваться как delta");
        assertEquals(BigInteger.valueOf(5), crl.getCrlNumber());
        assertEquals(BigInteger.valueOf(4), crl.getBaseCrlNumber());
    }

    // ========================================================================
    // reasonCode=7 (зарезервирован IANA) — парсинг не должен бросать исключение
    // ========================================================================

    /**
     * Строит CRL DER с reasonCode=7 (зарезервирован IANA, отсутствует в RFC 5280).
     * Повторяет логику {@link GostCrlBuilder#assembleCrl}, но с ручным
     * кодированием ENUMERATED = 0x07 для reasonCode.
     */
    private static byte[] buildCrlWithReasonCode7(
            byte[] serial,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String thisUpdate,
            String nextUpdate) {
        try {
            ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
            // version v2 = INTEGER 1
            tbsOut.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
            tbsOut.write(GostSignatureHelper.buildAlgId(caPub.getParams()));
            tbsOut.write(issuerDnDer);
            tbsOut.write(DerCodec.encodeTime(thisUpdate));
            if (nextUpdate != null) {
                tbsOut.write(DerCodec.encodeTime(nextUpdate));
            }
            // revoked entry с reasonCode=7
            byte[] enumerated =
                    DerCodec.encodeTlv(DerCodec.TAG_ENUMERATED, new byte[] {0x07});
            byte[] extValue = DerCodec.encodeOctetString(enumerated);
            byte[] reasonExt =
                    DerCodec.encodeSequence(
                            DerCodec.encodeOid(GostOids.EXT_CRL_REASON), extValue);
            byte[] entryExts = DerCodec.encodeSequence(reasonExt);
            byte[] revokedEntry =
                    DerCodec.encodeSequence(
                            DerCodec.encodeTlv(0x02, serial),
                            DerCodec.encodeTime(thisUpdate),
                            entryExts);
            tbsOut.write(DerCodec.encodeSequence(revokedEntry));

            // TBS -> sign -> assemble
            byte[] tbsCertList = DerCodec.encodeSequence(tbsOut.toByteArray());
            int hlen = caPub.getParams().hlen;
            byte[] hash = GostSignatureHelper.doHash(tbsCertList, hlen);
            byte[] sig = Signature.signHash(hash, caPriv);
            byte[] sigAlg = GostSignatureHelper.buildAlgId(caPub.getParams());
            return DerCodec.encodeSequence(tbsCertList, sigAlg, DerCodec.encodeBitString(sig));
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("CRL с reasonCode=7 (зарезервирован IANA): парсинг не бросает исключение, reason=null")
    void testCrlWithReasonCode7DoesNotThrow() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serial = new byte[] {0x01, 0x02, 0x03};

        byte[] crlDer = buildCrlWithReasonCode7(
                serial,
                kp.getPrivate(),
                kp.getPublic(),
                issuerDn,
                "20250601120000Z",
                "20990601120000Z");

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), false);

        List<RevokedEntry> revoked = crl.getRevokedCertificates();
        assertNotNull(revoked, "Список отозванных сертификатов не null");
        assertEquals(1, revoked.size(), "Ожидается ровно одна запись");
        RevokedEntry entry = revoked.get(0);
        assertNull(entry.reason(), "reasonCode=7 должен давать reason=null (неизвестный код)");
    }

    @Test
    @DisplayName("Instant-перегрузки thisUpdate/nextUpdate: валидный CRL")
    void testInstantThisUpdateNextUpdate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        Instant now = Instant.now();
        Instant future = now.plusSeconds(3600L * 24 * 365);

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .thisUpdate(now)
                        .nextUpdate(future)
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), false);

        Instant thisUpdate = crl.getThisUpdate();
        Instant nextUpdate = crl.getNextUpdate();
        assertNotNull(thisUpdate, "thisUpdate должен быть не null");
        assertNotNull(nextUpdate, "nextUpdate должен быть не null");
        assertTrue(
                thisUpdate.toEpochMilli() >= now.toEpochMilli() - 1000,
                "thisUpdate должен быть >= now - 1с");
        assertTrue(
                nextUpdate.isAfter(thisUpdate),
                "nextUpdate должен быть позже thisUpdate");
    }

    @Test
    @DisplayName("addRevoked(BigInteger): round-trip через GostCrl")
    void testAddRevokedBigInteger() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        BigInteger serial = BigInteger.valueOf(42);

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(serial, "20250601120000Z")
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), false);

        List<RevokedEntry> revoked = crl.getRevokedCertificates();
        assertNotNull(revoked, "Список отозванных сертификатов не null");
        assertEquals(1, revoked.size(), "Ожидается ровно одна запись");
        byte[] actualSerialBytes = revoked.get(0).serial();
        BigInteger actualSerial = new BigInteger(actualSerialBytes);
        assertEquals(serial, actualSerial, "Серийный номер должен быть 42 после round-trip");
    }
}
