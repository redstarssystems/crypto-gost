package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostPemUtils;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("GostPkcs7: извлечение сертификатов из PKCS#7/.p7b")
class GostPkcs7Test {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate cert1;
    private static GostCertificate cert2;
    private static GostCertificate cert3;
    private static GostCrl testCrl;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        cert1 = newCert("Cert One", 1001);
        cert2 = newCert("Cert Two", 1002);
        cert3 = newCert("Cert Three", 1003);

        KeyPair crlKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] crlIssuerDn = GostDnParser.encodeDn("CN=Test CRL Issuer");
        byte[] crlDer =
                GostCrlBuilder.create(crlKp.getPrivate(), crlIssuerDn)
                        .nextUpdate("270601120000Z")
                        .build();
        testCrl = GostCrl.fromDer(crlDer);
    }

    @Test
    @DisplayName("DER .p7b с одним сертификатом -> список из одного")
    void extractSingleFromDer() throws PkixException {
        byte[] p7b = buildP7b(cert1);

        List<GostCertificate> certs = GostPkcs7.extractCertificates(p7b);

        assertEquals(1, certs.size(), "должен извлечься ровно один сертификат");
        assertEquals(
                cert1.getSerialNumberBigInt(),
                certs.get(0).getSerialNumberBigInt(),
                "серийный номер должен совпасть с исходным");
    }

    @Test
    @DisplayName("DER .p7b с несколькими сертификатами -> все, в порядке следования")
    void extractMultipleFromDer() throws PkixException {
        byte[] p7b = buildP7b(cert1, cert2, cert3);

        List<GostCertificate> certs = GostPkcs7.extractCertificates(p7b);

        assertEquals(3, certs.size(), "должны извлечься все три сертификата");
        assertEquals(cert1.getSerialNumberBigInt(), certs.get(0).getSerialNumberBigInt());
        assertEquals(cert2.getSerialNumberBigInt(), certs.get(1).getSerialNumberBigInt());
        assertEquals(cert3.getSerialNumberBigInt(), certs.get(2).getSerialNumberBigInt());
    }

    @Test
    @DisplayName("PEM .p7b (-----BEGIN PKCS7-----) даёт тот же результат, что DER")
    void extractFromPem() throws PkixException {
        byte[] der = buildP7b(cert1, cert2);
        byte[] pem = GostPemUtils.toPem(der, "PKCS7").getBytes();

        List<GostCertificate> fromPem = GostPkcs7.extractCertificates(pem);
        List<GostCertificate> fromDer = GostPkcs7.extractCertificates(der);

        assertEquals(fromDer.size(), fromPem.size(), "PEM и DER должны дать одинаковое число");
        assertEquals(
                fromDer.get(0).getSerialNumberBigInt(), fromPem.get(0).getSerialNumberBigInt());
        assertEquals(
                fromDer.get(1).getSerialNumberBigInt(), fromPem.get(1).getSerialNumberBigInt());
    }

    @Test
    @DisplayName("SignedData с пустым полем [0] certificates -> пустой список")
    void emptyCertificatesField() throws PkixException {
        byte[] emptyField = DerCodec.encodeContextConstructed(0, new byte[0]);
        byte[] p7b = buildP7bWithRawCertsField(emptyField);

        assertTrue(
                GostPkcs7.extractCertificates(p7b).isEmpty(),
                "пустое поле certificates -> пустой список без ошибки");
    }

    @Test
    @DisplayName("SignedData вообще без поля [0] certificates -> пустой список")
    void noCertificatesField() throws PkixException {
        byte[] p7b = buildP7bWithRawCertsField(null);

        assertTrue(
                GostPkcs7.extractCertificates(p7b).isEmpty(),
                "отсутствие поля certificates -> пустой список без ошибки");
    }

    @Test
    @DisplayName("Неверный contentType (id-data вместо id-signedData) -> PkixException")
    void wrongContentType() {
        byte[] notSignedData =
                CmsContentInfo.encode(GostOids.PKCS7_DATA, DerCodec.encodeInteger(1));

        assertThrows(
                PkixException.class,
                () -> GostPkcs7.extractCertificates(notSignedData),
                "не-SignedData contentType должен отклоняться");
    }

    @Test
    @DisplayName("Битый сертификат в бандле -> PkixException (fail-closed)")
    void corruptedCertFailsClosed() {
        // Корректный TLV (SEQUENCE{INTEGER}), но не валидный X.509 -> parseCert упадёт.
        byte[] bogus = DerCodec.encodeSequence(DerCodec.encodeInteger(1));
        byte[] certsField =
                DerCodec.encodeContextConstructed(
                        0, DerCodec.concat(new byte[][] {cert1.getEncoded(), bogus}));
        byte[] p7b = buildP7bWithRawCertsField(certsField);

        assertThrows(
                PkixException.class,
                () -> GostPkcs7.extractCertificates(p7b),
                "битый сертификат в бандле не должен молча пропускаться");
    }

    @Test
    @DisplayName("buildCertsOnly -> extractCertificates: round-trip по множеству серийников")
    void buildCertsOnlyRoundTrip() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(cert1, cert2, cert3);

        List<GostCertificate> certs = GostPkcs7.extractCertificates(p7b);

        // Порядок не гарантирован: certificates[0] есть SET OF, DER требует
        // лексикографическую сортировку (X.690 §11.6), поэтому сверяем как множество.
        java.util.Set<BigInteger> serials = new java.util.HashSet<>();
        for (GostCertificate c : certs) {
            serials.add(c.getSerialNumberBigInt());
        }
        assertEquals(3, certs.size(), "должны извлечься все три сертификата");
        assertEquals(
                java.util.Set.of(
                        cert1.getSerialNumberBigInt(),
                        cert2.getSerialNumberBigInt(),
                        cert3.getSerialNumberBigInt()),
                serials,
                "множество серийников должно совпасть с исходным");
    }

    @Test
    @DisplayName("buildCertsOnly с одним сертификатом -> корректный контейнер")
    void buildCertsOnlySingle() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(cert1);

        List<GostCertificate> certs = GostPkcs7.extractCertificates(p7b);

        assertEquals(1, certs.size(), "ровно один сертификат");
        assertEquals(cert1.getSerialNumberBigInt(), certs.get(0).getSerialNumberBigInt());
    }

    @Test
    @DisplayName("buildCertsOnly формирует certs-only структуру SignedData (version=1, пустые SET)")
    void buildCertsOnlyStructure() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(cert1);

        CmsContentInfo contentInfo = CmsContentInfo.decode(p7b);
        assertEquals(
                GostOids.CMS_SIGNED_DATA,
                contentInfo.contentType(),
                "contentType должен быть id-signedData");

        byte[][] parts = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        // version, digestAlgorithms, encapContentInfo, certificates[0], signerInfos
        assertEquals(5, parts.length, "certs-only SignedData: ровно пять полей");

        BigInteger version = DerCodec.parseInteger(parts[0], 0);
        assertEquals(
                BigInteger.valueOf(CmsConstants.SIGNED_DATA_V1),
                version,
                "version должен быть 1 (eContentType=id-data, нет signerInfos v3)");

        // digestAlgorithms — пустой SET OF (0x31 0x00)
        assertArrayEquals(
                DerCodec.encodeSetOf(new byte[0][]),
                parts[1],
                "digestAlgorithms должен быть пустым SET OF");

        // encapContentInfo — SEQUENCE { id-data } без content
        assertArrayEquals(
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.PKCS7_DATA)),
                parts[2],
                "encapContentInfo без content: SEQUENCE{id-data}");

        assertTrue(DerCodec.isContextTag(parts[3], 0), "четвёртое поле — certificates [0]");

        // signerInfos — пустой SET OF
        assertArrayEquals(
                DerCodec.encodeSetOf(new byte[0][]),
                parts[4],
                "signerInfos должен быть пустым SET OF");
    }

    @Test
    @DisplayName("buildCertsOnly эквивалентен эталонному ручному построению (по множеству)")
    void buildCertsOnlyEqualsReference() throws PkixException {
        byte[] fromApi = GostPkcs7.buildCertsOnly(cert1, cert2);
        byte[] reference =
                buildP7bWithRawCertsField(
                        DerCodec.encodeContextConstructed(
                                0,
                                DerCodec.concat(
                                        new byte[][] {cert1.getEncoded(), cert2.getEncoded()})));

        java.util.Set<BigInteger> apiSerials = serialsOf(GostPkcs7.extractCertificates(fromApi));
        java.util.Set<BigInteger> refSerials = serialsOf(GostPkcs7.extractCertificates(reference));
        assertEquals(refSerials, apiSerials, "оба пути дают одно множество серийников");
    }

    @Test
    @DisplayName("buildCertsOnly с пустым/некорректным вводом -> IllegalArgumentException")
    void buildCertsOnlyRejectsEmpty() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs7.buildCertsOnly(),
                "без сертификатов -> IllegalArgumentException");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs7.buildCertsOnly((GostCertificate[]) null),
                "null-массив -> IllegalArgumentException");
    }

    @Test
    @DisplayName(
            "buildCertsOnly с CRL: certs-only контейнер содержит crls [1] и extractCertificates не падает")
    void buildCertsOnlyWithCrl() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(List.of(testCrl), cert1, cert2);

        GostPkcs7.extractCertificates(p7b);

        CmsContentInfo ci = CmsContentInfo.decode(p7b);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        boolean foundCrls = false;
        for (byte[] part : sdParts) {
            if (DerCodec.isContextTag(part, 1)) {
                foundCrls = true;
                break;
            }
        }
        assertTrue(foundCrls, "crls [1] должен присутствовать в certs-only с CRL");
    }

    @Test
    @DisplayName("buildCertsOnly с null-CRL эквивалентно buildCertsOnly без CRL")
    void buildCertsOnlyWithNullCrls() throws PkixException {
        byte[] withNull = GostPkcs7.buildCertsOnly((List<GostCrl>) null, cert1, cert2);
        byte[] without = GostPkcs7.buildCertsOnly(cert1, cert2);

        java.util.Set<BigInteger> serialsNull = serialsOf(GostPkcs7.extractCertificates(withNull));
        java.util.Set<BigInteger> serialsWithout =
                serialsOf(GostPkcs7.extractCertificates(without));

        assertEquals(serialsWithout, serialsNull);
    }

    @Test
    @DisplayName("buildCertsOnly с пустым списком CRL эквивалентно без CRL")
    void buildCertsOnlyWithEmptyCrls() throws PkixException {
        byte[] withEmpty = GostPkcs7.buildCertsOnly(List.of(), cert1, cert2);
        byte[] without = GostPkcs7.buildCertsOnly(cert1, cert2);

        java.util.Set<BigInteger> serialsEmpty =
                serialsOf(GostPkcs7.extractCertificates(withEmpty));
        java.util.Set<BigInteger> serialsWithout =
                serialsOf(GostPkcs7.extractCertificates(without));

        assertEquals(serialsWithout, serialsEmpty);
    }

    private static java.util.Set<BigInteger> serialsOf(List<GostCertificate> certs) {
        java.util.Set<BigInteger> serials = new java.util.HashSet<>();
        for (GostCertificate c : certs) {
            serials.add(c.getSerialNumberBigInt());
        }
        return serials;
    }

    @Test
    @DisplayName("Превышение maxCerts -> PkixException")
    void exceedMaxCerts() {
        byte[] p7b = buildP7b(cert1, cert2, cert3);

        assertThrows(
                PkixException.class,
                () -> GostPkcs7.extractCertificates(p7b, 2),
                "3 сертификата при потолке 2 должны вызвать отказ");
    }

    @Test
    @DisplayName("maxCerts равный числу сертификатов -> успех (граница включительна)")
    void maxCertsBoundaryInclusive() throws PkixException {
        byte[] p7b = buildP7b(cert1, cert2, cert3);

        assertEquals(3, GostPkcs7.extractCertificates(p7b, 3).size(), "ровно потолок допустим");
    }

    @Test
    @DisplayName("null / пустой / неположительный maxCerts / мусор -> PkixException")
    void invalidInputs() {
        assertThrows(PkixException.class, () -> GostPkcs7.extractCertificates(null));
        assertThrows(PkixException.class, () -> GostPkcs7.extractCertificates(new byte[0]));
        assertThrows(PkixException.class, () -> GostPkcs7.extractCertificates(buildP7b(cert1), 0));
        assertThrows(
                PkixException.class,
                () -> GostPkcs7.extractCertificates(new byte[] {0x01, 0x02, 0x03, 0x04}),
                "случайные байты (не DER) -> PkixException, не unchecked-исключение");
    }

    // ========================================================================
    // Построение тестовых .p7b
    // ========================================================================

    private static GostCertificate newCert(String cn, int serial) {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        return CmsTestUtils.createSelfSignedCertWithDn(
                kp.getPrivate(), kp.getPublic(), BigInteger.valueOf(serial), cn);
    }

    /** Строит certs-only .p7b (SignedData без подписантов) с заданными сертификатами. */
    private static byte[] buildP7b(GostCertificate... certs) {
        byte[][] certDers = new byte[certs.length][];
        for (int i = 0; i < certs.length; i++) {
            certDers[i] = certs[i].getEncoded();
        }
        byte[] certsField = DerCodec.encodeContextConstructed(0, DerCodec.concat(certDers));
        return buildP7bWithRawCertsField(certsField);
    }

    /**
     * Строит SignedData с произвольным (или отсутствующим) полем certificates.
     *
     * @param certsField готовое DER-поле {@code [0]} или {@code null}, чтобы опустить его
     */
    private static byte[] buildP7bWithRawCertsField(byte[] certsField) {
        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgs = DerCodec.encodeSetOf(new byte[0][]);
        byte[] encapContent = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.PKCS7_DATA));
        byte[] emptySignerInfos = DerCodec.encodeSetOf(new byte[0][]);

        byte[] signedData =
                certsField != null
                        ? DerCodec.encodeSequence(
                                version, digestAlgs, encapContent, certsField, emptySignerInfos)
                        : DerCodec.encodeSequence(
                                version, digestAlgs, encapContent, emptySignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedData);
    }
}
