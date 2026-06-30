package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Тесты merge-логики {@link CrlVerifier#verify(byte[], byte[], byte[],
 * org.rssys.gost.signature.PublicKeyParameters)}: base + delta CRL.
 */
@DisplayName("CrlVerifier: base+delta merge-логика")
class CrlVerifierTest {

    private static final byte[] TEST_SERIAL = new byte[] {0x01};
    private static final byte[] OTHER_SERIAL = new byte[] {0x02};
    private static final byte[] UNUSED_SERIAL = new byte[] {0x77};

    @Test
    @DisplayName("base+delta: сертификат ни в одном списке -> OK")
    void testBaseDeltaMergeCertNotRevoked() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();

        CrlVerifier.verify(baseCrl, deltaCrl, UNUSED_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("base+delta: сертификат отозван в base -> PkixException")
    void testBaseDeltaMergeRevokedInBase() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .addRevoked(TEST_SERIAL, "20250601120000Z")
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "Сертификат отозван в base CRL");
    }

    @Test
    @DisplayName("base+delta: сертификат отозван в delta -> PkixException")
    void testBaseDeltaMergeRevokedInDelta() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .addRevoked(TEST_SERIAL, "20250601120000Z")
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "Сертификат отозван в delta CRL");
    }

    @Test
    @DisplayName("base+delta: removeFromCRL в delta — сертификат не отозван")
    void testBaseDeltaMergeRemoveFromCrl() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry baseEntry =
                new RevokedEntry(TEST_SERIAL, "20250601120000Z",
                        ReasonCode.KEY_COMPROMISE, null, null);
        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .addRevoked(List.of(baseEntry))
                        .build();

        RevokedEntry deltaEntry =
                new RevokedEntry(TEST_SERIAL, "20250602120000Z",
                        ReasonCode.REMOVE_FROM_CRL, null, null);
        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .addRevoked(List.of(deltaEntry))
                        .build();

        // REMOVE_FROM_CRL — сертификат удалён из base, не отозван
        CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic());
    }

    @Test
    @DisplayName("base+delta: SUPERSEDED в delta перекрывает base")
    void testBaseDeltaMergeSupersededInDelta() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        RevokedEntry baseEntry =
                new RevokedEntry(TEST_SERIAL, "20250601120000Z",
                        ReasonCode.KEY_COMPROMISE, null, null);
        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .addRevoked(List.of(baseEntry))
                        .build();

        RevokedEntry deltaEntry =
                new RevokedEntry(TEST_SERIAL, "20250602120000Z",
                        ReasonCode.SUPERSEDED, null, null);
        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .addRevoked(List.of(deltaEntry))
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "SUPERSEDED в delta должен перекрыть base");
    }

    @Test
    @DisplayName("base+delta: delta без deltaCRLIndicator -> PkixException")
    void testBaseDeltaMergeDeltaNotDelta() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();

        byte[] notDeltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, notDeltaCrl, TEST_SERIAL, kp.getPublic()),
                "CRL без deltaCRLIndicator — не delta");
    }

    @Test
    @DisplayName("base+delta: delta.baseCrlNumber != base.crlNumber -> PkixException")
    void testBaseDeltaMergeCrlNumberMismatch() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(99)
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "Номера CRL не совпадают");
    }

    @Test
    @DisplayName("base+delta: base без cRLNumber -> PkixException")
    void testBaseDeltaMergeBaseWithoutCrlNumber() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "base без cRLNumber должен вызывать ошибку");
    }

    @Test
    @DisplayName("base+delta: delta.thisUpdate < base.thisUpdate -> PkixException")
    void testBaseDeltaMergeThisUpdateBefore() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .thisUpdate("20900101000000Z")
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .thisUpdate("20890101000000Z")
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "delta.thisUpdate раньше base.thisUpdate");
    }

    @Test
    @DisplayName("base+delta: разные issuer DN -> PkixException")
    void testBaseDeltaMergeIssuerMismatch() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn1 = GostDnParser.encodeDn("CN=Test CA 1");
        byte[] issuerDn2 = GostDnParser.encodeDn("CN=Test CA 2");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn1)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn2)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();

        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "Разные issuer DN");
    }

    @Test
    @DisplayName("base+delta: пустой delta CRL (gap fix)")
    void testEmptyDeltaCrlMerge() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .addRevoked(TEST_SERIAL, "20250601120000Z")
                        .build();

        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();

        // Пустой delta CRL — сертификат всё ещё отозван в base
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, TEST_SERIAL, kp.getPublic()),
                "Сертификат отозван в base CRL, пустой delta не удаляет");
    }

    @Test
    @DisplayName("null certSerial в 3-param verify -> PkixException, не NPE")
    void testVerify_nullCertSerial_throwsPkixException() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .build();
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crlDer, (byte[]) null, kp.getPublic()),
                "certSerial=null должен давать PkixException, а не NPE");
    }

    @Test
    @DisplayName("null certSerial в base+delta verify -> PkixException, не NPE")
    void testVerifyDelta_nullCertSerial_throwsPkixException() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] baseCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .build();
        byte[] deltaCrl =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .build();
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(baseCrl, deltaCrl, (byte[]) null, kp.getPublic()),
                "certSerial=null должен давать PkixException, а не NPE");
    }

    // ========================================================================
    // Нормализация серийных номеров (leading-zero DER)
    // ========================================================================

    /**
     * Неканонический DER INTEGER: {0x00, 0x01} (число 1 с leading zero)
     * должен распознаваться как тот же серийный номер, что {0x01}.
     */
    @Test
    @DisplayName("isRevoked с leading-zero serial {0x00,0x01} == {0x01}")
    void testIsRevoked_leadingZeroSerial() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] nonCanonicalSerial = new byte[] {0x00, 0x01};
        byte[] canonicalSerial = new byte[] {0x01};

        byte[] crlDer =
                GostCrlBuilder.create(kp.getPrivate(), issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(nonCanonicalSerial, "20250601120000Z")
                        .build();

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        assertTrue(
                crl.isRevoked(canonicalSerial),
                "Сериный номер {0x01} должен быть найден в CRL с leading-zero {0x00, 0x01}");
    }
}
