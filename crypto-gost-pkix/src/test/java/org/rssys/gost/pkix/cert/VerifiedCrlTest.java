package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_CRL_NUMBER;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_DELTA_CRL_INDICATOR;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_IDP;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.concat;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crl;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crlExtensions;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.extension;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.integerValue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedEntry;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedList;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * {@link VerifiedCrl}: подпись и разбор выполняются один раз, а сертификат проверяется по
 * готовому объекту.
 */
@DisplayName("VerifiedCrl: проверенный CRL, привязанный к издателю")
class VerifiedCrlTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String CDP = "http://crl.example.test/a.crl";
    private static final BigInteger REVOKED_SERIAL = BigInteger.valueOf(6000);
    private static final BigInteger CLEAN_SERIAL = BigInteger.valueOf(6001);
    private static final BigInteger CA_SERIAL = BigInteger.valueOf(6002);

    private static KeyPair caKp;
    private static byte[] caDn;
    private static GostCertificate revokedLeaf;
    private static GostCertificate cleanLeaf;
    private static GostCertificate subCa;

    @BeforeAll
    static void setUp() {
        caKp = KeyGenerator.generateKeyPair(PARAMS);
        caDn = GostDnParser.encodeDn("CN=Verified CA,O=Test,C=RU");
        KeyPair subjectKp = KeyGenerator.generateKeyPair(PARAMS);
        revokedLeaf = issue("CN=Revoked,O=Test,C=RU", subjectKp, REVOKED_SERIAL, false);
        cleanLeaf = issue("CN=Clean,O=Test,C=RU", subjectKp, CLEAN_SERIAL, false);
        subCa = issue("CN=Sub CA,O=Test,C=RU", subjectKp, CA_SERIAL, true);
    }

    private static GostCertificate issue(
            String subject, KeyPair subjectKp, BigInteger serial, boolean ca) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(subjectKp.getPublic())
                        .issuerDn(caDn)
                        .notBefore("250101000000Z")
                        .notAfter("350101000000Z")
                        .serial(serial)
                        .crlDistributionPoints(CDP);
        if (ca) {
            builder.basicConstraints(true, null);
        }
        return GostCertificateBuilder.sign(builder.buildTbs(), GostSigner.of(caKp.getPrivate()));
    }

    private static byte[] number(int value) {
        return extension(OID_CRL_NUMBER, false, integerValue(BigInteger.valueOf(value)));
    }

    /** CRL издателя теста: записи об отзыве REVOKED_SERIAL и расширения. */
    private static byte[] signedCrl(byte[]... extensions) {
        return crl(
                caKp.getPrivate(),
                PARAMS,
                caDn,
                concat(revokedList(revokedEntry(REVOKED_SERIAL, null)), crlExtensions(extensions)));
    }

    private static VerifiedCrl authenticate(byte[] crlDer) throws PkixException {
        return CrlVerifier.authenticate(
                crlDer,
                CrlTestCerts.issuerOf(caKp.getPublic()),
                new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, GostCrl.DEFAULT_MAX_REVOKED_ENTRIES));
    }

    // ------------------------------------------------------------------------
    // Один объект - много сертификатов
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Один проверенный CRL: отозванный сертификат отвергается, чистый проходит")
    void oneCrlManyCertificates() throws Exception {
        VerifiedCrl verified = authenticate(signedCrl(number(5)));

        PkixException revoked =
                assertThrows(
                        PkixException.class,
                        () ->
                                verified.verifyFor(
                                        revokedLeaf, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                        "Сертификат из списка отозванных должен давать REVOKED");
        assertEquals(PkixException.Reason.REVOKED, revoked.reason(), "Причина - отзыв");
        assertDoesNotThrow(
                () -> verified.verifyFor(cleanLeaf, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                "Чистый сертификат проходит по тому же объекту");
        assertDoesNotThrow(
                () -> verified.verifyFor(subCa, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                "Повторные проверки не портят объект");
    }

    @Test
    @DisplayName("Значения доступа: cRLNumber, nextUpdate, оценка удержания")
    void accessors() throws Exception {
        byte[] der = signedCrl(number(7));
        VerifiedCrl verified = authenticate(der);

        assertEquals(BigInteger.valueOf(7), verified.getCrlNumber(), "cRLNumber");
        assertNotNull(verified.getNextUpdate(), "nextUpdate задан помощником");
        assertEquals(
                der.length + GostOids.CRL_RETAINED_BYTES_PER_ENTRY,
                verified.getEstimatedBytes(),
                "Оценка: длина DER плюс одна запись");
    }

    @Test
    @DisplayName("CRL без cRLNumber: getCrlNumber() = null")
    void noCrlNumber() throws Exception {
        assertNull(authenticate(signedCrl()).getCrlNumber(), "Номера в CRL нет");
    }

    // ------------------------------------------------------------------------
    // Проверки при каждом использовании
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Другой ключ издателя в verifyFor отвергается")
    void differentIssuerKeyRejected() throws Exception {
        VerifiedCrl verified = authenticate(signedCrl(number(1)));
        KeyPair other = KeyGenerator.generateKeyPair(PARAMS);

        assertThrows(
                PkixException.class,
                () -> verified.verifyFor(cleanLeaf, CrlTestCerts.issuerOf(other.getPublic()), null),
                "Объект привязан к ключу, которым проверена подпись");
    }

    @Test
    @DisplayName("minCrlNumber выше номера CRL -> откат отвергается")
    void rollbackRejected() throws Exception {
        VerifiedCrl verified = authenticate(signedCrl(number(5)));

        assertThrows(
                PkixException.class,
                () ->
                        verified.verifyFor(
                                cleanLeaf,
                                CrlTestCerts.issuerOf(caKp.getPublic()),
                                BigInteger.valueOf(6)),
                "Номер 5 ниже ожидаемого минимума 6");
        assertDoesNotThrow(
                () ->
                        verified.verifyFor(
                                cleanLeaf,
                                CrlTestCerts.issuerOf(caKp.getPublic()),
                                BigInteger.valueOf(5)),
                "Номер равен минимуму - допустимо");
    }

    @Test
    @DisplayName("Сертификат другого издателя (issuer DN) отвергается")
    void foreignIssuerDnRejected() throws Exception {
        KeyPair otherCa = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate foreign =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=Foreign,O=Test,C=RU")
                                .publicKey(otherCa.getPublic())
                                .issuerDn(GostDnParser.encodeDn("CN=Other CA,O=Test,C=RU"))
                                .notBefore("250101000000Z")
                                .notAfter("350101000000Z")
                                .serial(BigInteger.valueOf(77))
                                .buildTbs(),
                        GostSigner.of(otherCa.getPrivate()));
        VerifiedCrl verified = authenticate(signedCrl(number(1)));

        assertThrows(
                PkixException.class,
                () -> verified.verifyFor(foreign, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                "issuer DN сертификата не совпадает с издателем CRL");
    }

    @Test
    @DisplayName("Null-аргументы verifyFor -> PkixException")
    void nullArguments() throws Exception {
        VerifiedCrl verified = authenticate(signedCrl(number(1)));
        assertThrows(
                PkixException.class,
                () -> verified.verifyFor(null, CrlTestCerts.issuerOf(caKp.getPublic()), null));
        assertThrows(PkixException.class, () -> verified.verifyFor(cleanLeaf, null, null));
    }

    // ------------------------------------------------------------------------
    // Область CRL применяется к каждому сертификату отдельно
    // ------------------------------------------------------------------------

    private static byte[] onlyCaCertsIdp() {
        return extension(
                OID_IDP,
                true,
                DerCodec.encodeSequence(DerCodec.encodeTlv(0x82, new byte[] {(byte) 0xFF})));
    }

    @Test
    @DisplayName(
            "CRL onlyContainsCACerts: для УЦ годится, для листа - IDP_NOT_SUPPORTED, отзыв виден")
    void scopeAppliedPerCertificate() throws Exception {
        VerifiedCrl verified = authenticate(signedCrl(number(1), onlyCaCertsIdp()));

        assertDoesNotThrow(
                () -> verified.verifyFor(subCa, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                "CRL покрывает сертификат УЦ");
        PkixException notCovered =
                assertThrows(
                        PkixException.class,
                        () ->
                                verified.verifyFor(
                                        cleanLeaf, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                        "CRL только для УЦ не покрывает конечный сертификат");
        assertEquals(
                PkixException.Reason.IDP_NOT_SUPPORTED,
                notCovered.reason(),
                "Не покрытый областью сертификат - IDP_NOT_SUPPORTED");
        PkixException revoked =
                assertThrows(
                        PkixException.class,
                        () ->
                                verified.verifyFor(
                                        revokedLeaf, CrlTestCerts.issuerOf(caKp.getPublic()), null),
                        "Запись об отзыве важнее области");
        assertEquals(PkixException.Reason.REVOKED, revoked.reason(), "Отзыв определяется раньше");
    }

    // ------------------------------------------------------------------------
    // authenticate
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("authenticate: неверная подпись -> SIGNATURE_INVALID")
    void forgedSignatureRejected() {
        KeyPair other = KeyGenerator.generateKeyPair(PARAMS);
        byte[] forged =
                crl(
                        other.getPrivate(),
                        PARAMS,
                        caDn,
                        revokedList(revokedEntry(REVOKED_SERIAL, null)));

        PkixException e = assertThrows(PkixException.class, () -> authenticate(forged));
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, e.reason(), "Подпись не сходится");
    }

    @Test
    @DisplayName("authenticate: delta CRL не принимается")
    void deltaCrlRejected() {
        byte[] delta =
                signedCrl(
                        number(2),
                        extension(
                                OID_DELTA_CRL_INDICATOR,
                                true,
                                integerValue(BigInteger.valueOf(1))));

        assertThrows(PkixException.class, () -> authenticate(delta), "delta CRL не для этого типа");
    }

    @Test
    @DisplayName("authenticate: null и непригодный ввод -> PkixException")
    void invalidInputsRejected() {
        assertThrows(PkixException.class, () -> authenticate(null));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.authenticate(
                                signedCrl(),
                                null,
                                new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, 1000)));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.authenticate(
                                new byte[] {0x30, 0x00},
                                CrlTestCerts.issuerOf(caKp.getPublic()),
                                new CrlLimits(1000, 1000)));
    }

    @Test
    @DisplayName("authenticate: превышение предела записей -> CRL_LIMIT_EXCEEDED")
    void entryLimitEnforced() {
        byte[] der =
                crl(
                        caKp.getPrivate(),
                        PARAMS,
                        caDn,
                        revokedList(
                                revokedEntry(REVOKED_SERIAL, null),
                                revokedEntry(BigInteger.valueOf(6001), null)));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.authenticate(
                                        der,
                                        CrlTestCerts.issuerOf(caKp.getPublic()),
                                        new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, 1)));
        assertEquals(
                PkixException.Reason.CRL_LIMIT_EXCEEDED,
                e.reason(),
                "Предел записей нарушен, причина - превышение предела, а не " + e.reason());
    }
}
