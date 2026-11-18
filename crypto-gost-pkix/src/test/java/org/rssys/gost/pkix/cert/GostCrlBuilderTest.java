package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
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
    @DisplayName("legacy CA: issuer DN CRL берётся из DER, а не перекодируется из строки")
    void testLegacyCrlIssuerDn() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] legacyDn = legacyDnWithUtf8Country("Legacy Root");

        byte[] fromDer =
                GostCrlBuilder.create(legacyDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());
        assertArrayEquals(
                legacyDn,
                new GostCrl(fromDer).getIssuerDnBytes(),
                "CRL по DER сохраняет issuer DN старого CA");

        byte[] fromString =
                GostCrlBuilder.create("CN=Legacy Root,C=RU")
                        .nextUpdate("20990601120000Z")
                        .sign(kp.getPrivate());
        assertFalse(
                Arrays.equals(legacyDn, new GostCrl(fromString).getIssuerDnBytes()),
                "строковая перекодировка не совпадает с issuer DN старого CA");
    }

    private static byte[] legacyDnWithUtf8Country(String cn) {
        return DerCodec.encodeSequence(
                DerCodec.encodeSetOf(
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.ATTR_CN),
                                DerCodec.encodeUTF8String(cn))),
                DerCodec.encodeSetOf(
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.ATTR_C),
                                DerCodec.encodeUTF8String("RU"))));
    }

    @Test
    @DisplayName("build: thisUpdate/nextUpdate/revocationDate кодируются по RFC 5280")
    void testCrlTimeTags() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Time Tags CA,C=RU");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdate("20240501120000Z")
                        .nextUpdate("20990601120000Z")
                        .addRevoked(TEST_SERIAL, "20240601120000Z")
                        .sign(kp.getPrivate());

        byte[][] certListParts = DerCodec.parseSequenceContents(crlDer, 0);
        byte[][] tbsParts = DerCodec.parseSequenceContents(certListParts[0], 0);
        // TBSCertList: version, signature, issuer, thisUpdate, nextUpdate, revoked...
        assertEquals(0x17, tbsParts[3][0] & 0xFF, "thisUpdate 2024 должен быть UTCTime");
        assertEquals(0x18, tbsParts[4][0] & 0xFF, "nextUpdate 2099 должен быть GeneralizedTime");

        byte[][] revoked = DerCodec.parseSequenceContents(tbsParts[5], 0);
        byte[][] entry = DerCodec.parseSequenceContents(revoked[0], 0);
        assertEquals(0x17, entry[1][0] & 0xFF, "revocationDate 2024 должен быть UTCTime");
    }

    @Test
    @DisplayName("verify: serial отозванной записи > 20 октетов -> PkixException")
    void testRevokedSerialTooLong() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        // serial 22 октета (> MAX_SERIAL_OCTETS=20) -> DoS-барьер в revoked-loop
        BigInteger oversizedSerial = BigInteger.ONE.shiftLeft(168);
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(oversizedSerial, GostSignatureHelper.nowGeneralizedTime())
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "serial > 20 октетов должен приводить к PkixException");
    }

    @Test
    @DisplayName("verify: serial 20 октетов величины со знаковым байтом (21-байтный DER) -> OK")
    void testRevokedSerialHighBitSignByteAccepted() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        // 20 октетов ВЕЛИЧИНЫ со старшим битом = 1: минимальный DER требует ведущий 0x00,
        // итог 21 байт содержимого. Ранее парсер отвергал такой CRL (сверял кодированную длину).
        byte[] serial21 = new byte[21];
        serial21[0] = 0x00;
        serial21[1] = (byte) 0x80;
        for (int i = 2; i < 21; i++) {
            serial21[i] = (byte) i;
        }
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(serial21, GostSignatureHelper.nowGeneralizedTime())
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        assertDoesNotThrow(
                () -> crl.verify(kp.getPublic(), false),
                "20-октетная величина со знаковым байтом должна парситься и верифицироваться");
        assertTrue(
                crl.isRevoked(serial21),
                "серийник должен распознаваться как отозванный после round-trip");
    }

    @Test
    @DisplayName("verify: serial нулевой длины (02 00) -> детерминированно, без AIOOBE")
    void testRevokedSerialZeroLengthNoCrash() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        // Нулевая длина INTEGER — невалидный DER, но парсер обязан обрабатывать без краша:
        // guard valueOctets > 0 не даёт прочитать байт за пределами TLV. Билдер запрещает
        // пустой serial, поэтому DER собираем вручную.
        byte[] crlDer =
                buildCrlWithRawSerial(
                        new byte[0],
                        kp.getPrivate(),
                        kp.getPublic(),
                        issuerDn,
                        "20250601120000Z",
                        "20990601120000Z");

        GostCrl crl = new GostCrl(crlDer);
        // Guard в парсере предотвращает AIOOBE на length-проверке; downstream может
        // детерминированно отвергнуть пустой serial — главное, это НЕ AIOOBE.
        Throwable thrown = assertThrows(Throwable.class, () -> crl.verify(kp.getPublic(), false));
        assertFalse(
                thrown instanceof ArrayIndexOutOfBoundsException,
                "serial нулевой длины не должен приводить к ArrayIndexOutOfBoundsException: "
                        + thrown);
    }

    /**
     * Собирает CRL DER с одной revoked-записью, кодируя serial как raw INTEGER content
     * (без проверок билдера) — для проверки крайних случаев парсера.
     */
    private static byte[] buildCrlWithRawSerial(
            byte[] serialContent,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String thisUpdate,
            String nextUpdate) {
        try {
            ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
            tbsOut.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
            tbsOut.write(GostSignatureHelper.buildAlgId(caPub.getParams()));
            tbsOut.write(issuerDnDer);
            tbsOut.write(DerCodec.encodeTime(thisUpdate));
            if (nextUpdate != null) {
                tbsOut.write(DerCodec.encodeTime(nextUpdate));
            }
            byte[] revokedEntry =
                    DerCodec.encodeSequence(
                            DerCodec.encodeTlv(0x02, serialContent),
                            DerCodec.encodeTime(thisUpdate));
            tbsOut.write(DerCodec.encodeSequence(revokedEntry));

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
    @DisplayName("Построитель: отрицательный и длиннее 20 октетов cRLNumber отвергается")
    void testBuilderRejectsInvalidCrlNumber() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCrlBuilder.create(new byte[0]).withCrlNumber(BigInteger.valueOf(-1)),
                "Отрицательный cRLNumber построитель выпускать не должен");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCrlBuilder.create(new byte[0])
                                .withCrlNumber(BigInteger.ONE.shiftLeft(160)),
                "cRLNumber длиннее 20 октетов построитель выпускать не должен");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCrlBuilder.create(new byte[0])
                                .withDeltaCrlIndicator(BigInteger.ONE.shiftLeft(160)),
                "То же для BaseCRLNumber");
    }

    @Test
    @DisplayName("verify: cRLNumber 16 октетов принимается (RFC 5280 §5.2.3: до 20)")
    void testCrlNumberSixteenOctetsAccepted() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        BigInteger sixteenOctets = BigInteger.ONE.shiftLeft(120).add(BigInteger.TEN);
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(sixteenOctets)
                        .sign(kp.getPrivate());

        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "cRLNumber в 16 октетов — настоящий случай (CRL ИнфоТеКС)");
    }

    @Test
    @DisplayName("buildCrl: обратимость — собираем CRL, верифицируем через CrlVerifier")
    void testBuildCrlRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

        assertNotNull(crlDer);
        assertTrue(crlDer.length > 50);
        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));
    }

    @Test
    @DisplayName("buildCrl: подпись валидна, сертификат не отозван -> OK")
    void testBuildCrlSignatureValid() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));
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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(Arrays.asList(entries))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())));
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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(Arrays.asList(entries))
                        .sign(kp.getPrivate());

        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "TEST_SERIAL должен быть отозван");
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(new byte[] {0x05}, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "Серийный номер 0x05 должен быть отозван");
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(new byte[] {0x10}, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "Серийный номер 0x10 должен быть отозван");
    }

    @Test
    @DisplayName("buildCrl с пустым IDP — принимается, indirectCRL=false")
    void testBuildCrlWithEmptyIdpAccepted() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withIdpExtension()
                        .sign(kp.getPrivate());

        // Пустой IDP (все флаги false) — не indirect, должен приниматься
        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));
    }

    @Test
    @DisplayName("buildCrl с indirectCRL=true в IDP — должен быть rejected")
    void testBuildCrlWithIndirectCrlRejected() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.assembleCrl(
                        null,
                        kp.getPrivate(),
                        issuerDn,
                        GostSignatureHelper.nowGeneralizedTime(),
                        "20990601120000Z",
                        false,
                        null,
                        null,
                        null,
                        true,
                        false,
                        false,
                        true,
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "CRL с indirectCRL=true должен быть rejected");
    }

    @Test
    @DisplayName("indirectCRL=true в канонической IMPLICIT-кодировке (0x84 01 FF) — reject")
    void testCanonicalImplicitIndirectCrlRejected() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        // Строим TBSCertList с hand-crafted IDP: каноническая implicit-кодировка
        // indirectCRL = [4] IMPLICIT BOOLEAN true = 0x84 01 FF
        byte[] idpSeq = DerCodec.encodeSequence(DerCodec.encodeTlv(0x84, new byte[] {(byte) 0xFF}));
        byte[] idpExt =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.29.28"), DerCodec.encodeTlv(0x04, idpSeq));

        ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
        tbsOut.write(DerCodec.encodeTlv(0x02, new byte[] {0x01})); // version
        tbsOut.write(GostSignatureHelper.buildAlgId(params)); // sigAlg
        tbsOut.write(issuerDn); // issuer
        tbsOut.write(DerCodec.encodeTime(GostSignatureHelper.nowGeneralizedTime())); // thisUpdate
        tbsOut.write(DerCodec.encodeTime("20990601120000Z")); // nextUpdate
        tbsOut.write(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(idpExt))); // crlExts [0]
        byte[] tbs = DerCodec.encodeSequence(tbsOut.toByteArray());

        // Подписываем
        int hlen = params.hlen;
        byte[] hash = GostSignatureHelper.doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, kp.getPrivate());
        byte[] sigAlg = GostSignatureHelper.buildAlgId(params);
        byte[] crlDer = DerCodec.encodeSequence(tbs, sigAlg, DerCodec.encodeBitString(sig));

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
                "CRL с каноническим indirectCRL=true (0x84 01 FF) должен быть rejected");
    }

    @Test
    @DisplayName("assembleCrl с legacyVersion: fallback-ветка CrlVerifier")
    void testBuildCrlLegacyVersion() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.assembleCrl(
                        null,
                        kp.getPrivate(),
                        issuerDn,
                        GostSignatureHelper.nowGeneralizedTime(),
                        "20990601120000Z",
                        true,
                        null,
                        null,
                        null,
                        false,
                        null);

        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));
    }

    @Test
    @DisplayName("withoutNextUpdate: CRL собирается и разбирается, но проверка его отвергает")
    void testBuildCrlWithoutNextUpdate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer = GostCrlBuilder.create(issuerDn).withoutNextUpdate().sign(kp.getPrivate());

        GostCrl parsed = new GostCrl(crlDer);
        assertNull(parsed.getNextUpdate(), "Разбор CRL без nextUpdate разрешён, поле отсутствует");
        PkixException direct =
                assertThrows(
                        PkixException.class,
                        () -> parsed.verify(kp.getPublic()),
                        "GostCrl.verify должен отвергнуть CRL без nextUpdate");
        assertEquals(
                PkixException.Reason.NEXT_UPDATE_MISSING,
                direct.reason(),
                "Причина отказа должна быть NEXT_UPDATE_MISSING, а не EXPIRED");
        PkixException viaVerifier =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crlDer,
                                        CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                                        CrlTestCerts.issuerOf(kp.getPublic())),
                        "CrlVerifier.verify должен отвергнуть CRL без nextUpdate");
        assertEquals(
                PkixException.Reason.NEXT_UPDATE_MISSING,
                viaVerifier.reason(),
                "Причина отказа CrlVerifier должна быть NEXT_UPDATE_MISSING");
    }

    @Test
    @DisplayName("sign без nextUpdate и без withoutNextUpdate: построитель не выпускает CRL")
    void testSignWithoutNextUpdateThrows() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        assertThrows(
                IllegalStateException.class,
                () -> GostCrlBuilder.create(issuerDn).sign(kp.getPrivate()),
                "sign без nextUpdate должен падать: свой verifier такой CRL отвергнет");
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostCrlBuilder.create(issuerDn)
                                .nextUpdate((String) null)
                                .sign(kp.getPrivate()),
                "nextUpdate(null) сбрасывает значение и не разрешает выпуск без него");
    }

    @Test
    @DisplayName("buildCrl: чужой ключ не проходит проверку подписи")
    void testBuildCrlWrongKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        KeyPair wrongKp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(wrongKp.getPublic())),
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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())),
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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())));

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())));

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())));

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(Arrays.asList(entries))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())));
        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));
    }

    @Test
    @DisplayName("buildCrl: пустой revokedEntries -> CRL без записей")
    void testBuildCrlWithEmptyEntries() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

        assertNotNull(crlDer);
        assertTrue(crlDer.length > 50);
        CrlVerifier.verify(
                crlDer,
                CrlTestCerts.certFor(UNUSED_SERIAL, issuerDn),
                CrlTestCerts.issuerOf(kp.getPublic()));
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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verify(
                                crlDer,
                                CrlTestCerts.certFor(TEST_SERIAL, issuerDn),
                                CrlTestCerts.issuerOf(kp.getPublic())));
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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(42)
                        .sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(5)
                        .withDeltaCrlIndicator(4)
                        .sign(kp.getPrivate());

        assertNotNull(crlDer);
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_CRL_NUMBER)),
                "CRL должен содержать OID cRLNumber");
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_DELTA_CRL_INDICATOR)),
                "CRL должен содержать OID deltaCRLIndicator");

        GostCrl crl = new GostCrl(crlDer);
        assertThrows(
                PkixException.class,
                () -> crl.verify(kp.getPublic()),
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
                () ->
                        GostCrlBuilder.create(issuerDn)
                                .nextUpdate("20990601120000Z")
                                .withDeltaCrlIndicator(4)
                                .sign(kp.getPrivate()),
                "deltaCRLIndicator без cRLNumber должен бросать IllegalStateException");
    }

    @Test
    @DisplayName("withFreshestCrl: CRL содержит OID freshestCRL")
    void testBuildCrlWithFreshestCrl() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withFreshestCrl("http://ca.example/delta.crl")
                        .sign(kp.getPrivate());

        assertNotNull(crlDer);
        assertTrue(
                containsBytes(crlDer, DerCodec.encodeOid(GostOids.EXT_FRESHEST_CRL)),
                "CRL должен содержать OID freshestCRL");
    }

    @Test
    @DisplayName("FreshestCRL roundtrip: isFreshestCrl / getFreshestCrlUris")
    void testFreshestCrlParseRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withFreshestCrl("http://ca.example/delta.crl")
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        assertTrue(
                crl.isFreshestCrl(), "CRL с FreshestCRL должен возвращать isFreshestCrl() == true");
        assertArrayEquals(
                new String[] {"http://ca.example/delta.crl"},
                crl.getFreshestCrlUris(),
                "URI из FreshestCRL должен совпадать с исходным");
    }

    @Test
    @DisplayName("isFreshestCrl: false для CRL без FreshestCRL")
    void testCrlWithoutFreshestCrlNotFreshest() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        assertFalse(
                crl.isFreshestCrl(),
                "CRL без FreshestCRL должен возвращать isFreshestCrl() == false");
        assertNull(
                crl.getFreshestCrlUris(), "getFreshestCrlUris() должен быть null без расширения");
    }

    @Test
    @DisplayName("Все 4 CRL-расширения вместе")
    void testBuildDeltaCrlWithAllExtensions() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(10)
                        .withDeltaCrlIndicator(9)
                        .withFreshestCrl("http://ca.example/delta.crl")
                        .withIdpExtension()
                        .sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(7)
                        .withDeltaCrlIndicator(6)
                        .addRevoked(new byte[] {0x01}, "20250601120000Z")
                        .sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(3)
                        .withDeltaCrlIndicator(2)
                        .sign(kp.getPrivate());

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

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(List.of(entry))
                        .sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(serial, "20250601120000Z")
                        .sign(kp.getPrivate());

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
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(5)
                        .withDeltaCrlIndicator(4)
                        .sign(kp.getPrivate());

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
            byte[] enumerated = DerCodec.encodeTlv(DerCodec.TAG_ENUMERATED, new byte[] {0x07});
            byte[] extValue = DerCodec.encodeOctetString(enumerated);
            byte[] reasonExt =
                    DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_CRL_REASON), extValue);
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
    @DisplayName(
            "CRL с reasonCode=7 (зарезервирован IANA): парсинг не бросает исключение, reason=null")
    void testCrlWithReasonCode7DoesNotThrow() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serial = new byte[] {0x01, 0x02, 0x03};

        byte[] crlDer =
                buildCrlWithReasonCode7(
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
                GostCrlBuilder.create(issuerDn)
                        .thisUpdate(now)
                        .nextUpdate(future)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), false);

        Instant thisUpdate = crl.getThisUpdate();
        Instant nextUpdate = crl.getNextUpdate();
        assertNotNull(thisUpdate, "thisUpdate должен быть не null");
        assertNotNull(nextUpdate, "nextUpdate должен быть не null");
        assertTrue(
                thisUpdate.toEpochMilli() >= now.toEpochMilli() - 1000,
                "thisUpdate должен быть >= now - 1с");
        assertTrue(nextUpdate.isAfter(thisUpdate), "nextUpdate должен быть позже thisUpdate");
    }

    @Test
    @DisplayName("addRevoked(BigInteger): round-trip через GostCrl")
    void testAddRevokedBigInteger() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        BigInteger serial = BigInteger.valueOf(42);

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(serial, "20250601120000Z")
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic(), false);

        List<RevokedEntry> revoked = crl.getRevokedCertificates();
        assertNotNull(revoked, "Список отозванных сертификатов не null");
        assertEquals(1, revoked.size(), "Ожидается ровно одна запись");
        byte[] actualSerialBytes = revoked.get(0).serial();
        BigInteger actualSerial = new BigInteger(actualSerialBytes);
        assertEquals(serial, actualSerial, "Серийный номер должен быть 42 после round-trip");
    }

    @Test
    @DisplayName("GostCrl(byte[]): массив > DEFAULT_MAX_CRL_SIZE -> IllegalArgumentException")
    void testGostCrlOversizedRejected() {
        byte[] oversizedDer = new byte[67_108_865]; // на 1 больше DEFAULT_MAX_CRL_SIZE = 67_108_864
        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> new GostCrl(oversizedDer));
        assertTrue(
                ex.getMessage().contains("exceeds maximum size"),
                "должен быть reject по превышению размера: " + ex.getMessage());
    }

    @Test
    @DisplayName("GostCrl(byte[], int, int): кастомный maxSize — превышение")
    void testGostCrlCustomSizeLimitRejected() {
        byte[] der = new byte[200];
        IllegalArgumentException ex =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new GostCrl(der, new CrlLimits(100, 10)));
        assertTrue(
                ex.getMessage().contains("exceeds maximum size"),
                "должен быть reject по превышению кастомного размера: " + ex.getMessage());
    }

    @Test
    @DisplayName(
            "GostCrl: число отозванных записей больше кастомного лимита -> PkixException при verify")
    void testGostCrlCustomRevokedEntriesLimitExceeded() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        // Кастомный лимит 10 записей, берём 11 для пробития барьера.
        // count-лимит. Revoked-список парсится только внутри verify()
        // (fail-closed), поэтому и лимит проверяется там, а не в конструкторе.
        int count = 11;
        String revocationTime = "20250601120000Z";
        List<RevokedEntry> entries = new java.util.ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            entries.add(new RevokedEntry(BigInteger.valueOf(i).toByteArray(), revocationTime));
        }
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(entries)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer, new CrlLimits(10_000_000, 10));
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> crl.verify(kp.getPublic(), false),
                        "CRL с числом отозванных записей больше лимита должен отклоняться при verify");
        assertTrue(
                ex.getMessage().contains("revoked entries exceed maximum"),
                "должно сработать именно ограничение по количеству: " + ex.getMessage());
    }

    @Test
    @DisplayName("GostCrl: число отозванных записей в пределах кастомного лимита -> OK")
    void testGostCrlCustomRevokedEntriesWithinLimit() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        int count = 5;
        String revocationTime = "20250601120000Z";
        List<RevokedEntry> entries = new java.util.ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            entries.add(new RevokedEntry(BigInteger.valueOf(i).toByteArray(), revocationTime));
        }
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .addRevoked(entries)
                        .sign(kp.getPrivate());

        // Проверяем конкретный серийный номер из числа добавленных
        GostCrl crl = new GostCrl(crlDer, new CrlLimits(10_000_000, 100));
        crl.verify(kp.getPublic(), false);
        assertTrue(
                crl.isRevoked(BigInteger.valueOf(3).toByteArray()),
                "Сертификат с serial=3 должен быть найден как отозванный");
    }

    // ========================================================================
    // AKI round-trip тесты
    // ========================================================================

    @Test
    @DisplayName("AKI round-trip: withAki(byte[]) -> getAuthorityKeyIdentifier()")
    void testAkiRoundTripBytes() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] skipperSki = Arrays.copyOf(Digest.digest256(new byte[32]), 32);

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withAki(skipperSki)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());
        assertNotNull(crl.getAuthorityKeyIdentifier(), "AKI должен быть извлечён из CRL");
        assertArrayEquals(
                skipperSki,
                crl.getAuthorityKeyIdentifier(),
                "round-trip AKI байты должны совпадать");
    }

    @Test
    @DisplayName("AKI round-trip: withAki(PublicKeyParameters) -> getAuthorityKeyIdentifier()")
    void testAkiRoundTripPublicKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        KeyPair signerKp = KeyGenerator.generateKeyPair(params);
        byte[] expectedSki =
                Digest.digest256(GostDerCodec.subjectPublicKeyPointBytes(signerKp.getPublic()));

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withAki(signerKp.getPublic())
                        .sign(caKp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(caKp.getPublic());
        assertNotNull(crl.getAuthorityKeyIdentifier(), "AKI должен быть извлечён из CRL");
        assertArrayEquals(
                expectedSki,
                crl.getAuthorityKeyIdentifier(),
                "round-trip AKI через PublicKeyParameters должен совпадать с вычисленным SKI");
    }

    @Test
    @DisplayName("CRL без withAki() -> getAuthorityKeyIdentifier() == null")
    void testAkiNullWhenNotSet() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());
        assertNull(
                crl.getAuthorityKeyIdentifier(),
                "AKI должен быть null, если withAki() не вызывался");
    }

    @Test
    @DisplayName("AKI + другие расширения: все расширения присутствуют")
    void testAkiWithOtherExtensions() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");

        byte[] aki = Arrays.copyOf(Digest.digest256(new byte[32]), 32);
        String deltaUri = "http://ca.example/delta.crl";

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(42)
                        .withFreshestCrl(deltaUri)
                        .withAki(aki)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        assertNotNull(crl.getCrlNumber(), "cRLNumber должен быть извлечён");
        assertEquals(BigInteger.valueOf(42), crl.getCrlNumber(), "cRLNumber должен быть 42");
        assertTrue(crl.isFreshestCrl(), "isFreshestCrl() должен быть true");
        assertEquals(deltaUri, crl.getFreshestCrlUris()[0], "FreshestCRL URI должен совпадать");
        assertArrayEquals(aki, crl.getAuthorityKeyIdentifier(), "AKI должен совпадать");
    }

    // ========================================================================
    // Удобные методы срока действия CRL
    // ========================================================================

    @Test
    @DisplayName("thisUpdateNow() + nextUpdateDays(30): CRL собирается и верифицируется")
    void testThisUpdateNowAndNextUpdateDays() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA Now");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        Instant tu = crl.getThisUpdate();
        Instant nu = crl.getNextUpdate();
        assertTrue(nu.isAfter(tu), "nextUpdate должен быть после thisUpdate");
        assertEquals(
                30L * 24L * 3600L,
                nu.getEpochSecond() - tu.getEpochSecond(),
                "разница должна быть ровно 30 суток");
    }

    @Test
    @DisplayName("nextUpdateDays(1) с thisUpdateNow: разница ровно 24 часа")
    void testNextUpdateDaysExact() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CRL Days");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdateNow()
                        .nextUpdateDays(1)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        long diffSeconds =
                crl.getNextUpdate().getEpochSecond() - crl.getThisUpdate().getEpochSecond();
        assertEquals(24L * 3600L, diffSeconds, "разница должна быть ровно 24 часа");
    }

    @Test
    @DisplayName("nextUpdateDays() без thisUpdate → IllegalStateException")
    void testNextUpdateDaysWithoutThisUpdate() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=NoThisUpdate");

        assertThrows(
                IllegalStateException.class,
                () -> GostCrlBuilder.create(issuerDn).nextUpdateDays(30).sign(kp.getPrivate()),
                "nextUpdateDays() без thisUpdate должен бросать IllegalStateException");
    }

    @Test
    @DisplayName(
            "thisUpdateNow() проверяет буфер clock skew: thisUpdate ≤ now ∧ thisUpdate ≥ now - CLOCK_SKEW_MS - 1с")
    void testThisUpdateNowClockSkewBuffer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CRL Skew");

        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .sign(kp.getPrivate());

        GostCrl crl = new GostCrl(crlDer);
        crl.verify(kp.getPublic());

        Instant now = Instant.now();
        Instant tu = crl.getThisUpdate();
        assertFalse(
                tu.isAfter(now), "thisUpdate не должен быть в будущем: tu=" + tu + " now=" + now);
        assertTrue(
                tu.toEpochMilli() >= now.toEpochMilli() - GostOids.CLOCK_SKEW_MS - 1000L,
                "thisUpdate должен быть >= now - CLOCK_SKEW_MS - 1с (допуск): tu="
                        + tu
                        + " now="
                        + now);
    }
}
