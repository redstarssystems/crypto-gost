package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.signature.ECParameters;

/**
 * Право издателя подписывать CRL: если у его сертификата есть KeyUsage, в нём обязан быть
 * {@code cRLSign} (RFC 5280 §4.2.1.3, §6.3.3 f). Отсутствие KeyUsage разрешением считается.
 */
@DisplayName("CrlVerifier: право издателя CRL подписывать CRL (KeyUsage cRLSign)")
class CrlIssuerKeyUsageTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] LEAF_SERIAL = {0x7F};

    private static KeyPair issuerKp;
    private static byte[] issuerDn;
    private static byte[] baseCrl;
    private static byte[] deltaCrl;
    private static GostCertificate leaf;

    /** Издатель без KeyUsage, с cRLSign и без cRLSign: один и тот же ключ. */
    private static GostCertificate noKeyUsage;

    private static GostCertificate withCrlSign;
    private static GostCertificate keyCertSignOnly;
    private static GostCertificate digitalSignatureOnly;

    @BeforeAll
    static void setUp() throws Exception {
        issuerKp = KeyGenerator.generateKeyPair(PARAMS);
        issuerDn = GostDnParser.encodeDn("CN=CRL Test Issuer,O=Test,C=RU");
        baseCrl =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .sign(issuerKp.getPrivate());
        deltaCrl =
                GostCrlBuilder.create(issuerDn)
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .sign(issuerKp.getPrivate());
        leaf = CrlTestCerts.certFor(LEAF_SERIAL, issuerDn);

        noKeyUsage = CrlTestCerts.issuerOf(issuerKp.getPublic());
        withCrlSign =
                CrlTestCerts.issuerOf(
                        issuerKp.getPublic(), KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
        keyCertSignOnly = CrlTestCerts.issuerOf(issuerKp.getPublic(), KeyUsage.KEY_CERT_SIGN);
        digitalSignatureOnly =
                CrlTestCerts.issuerOf(issuerKp.getPublic(), KeyUsage.DIGITAL_SIGNATURE);
    }

    private static void assertMissingCrlSign(ThrowingCall call, String message) {
        PkixException e = assertThrows(PkixException.class, call::run, message);
        assertEquals(PkixException.Reason.MISSING_CRL_SIGN, e.reason(), message);
    }

    @FunctionalInterface
    private interface ThrowingCall {
        void run() throws Exception;
    }

    // ========================================================================
    // Прямой путь
    // ========================================================================

    @Test
    @DisplayName("Издатель без KeyUsage: CRL принимается (RFC 5280 §4.2.1.3)")
    void issuerWithoutKeyUsageIsAccepted() {
        assertDoesNotThrow(() -> CrlVerifier.verify(baseCrl, leaf, noKeyUsage));
    }

    @Test
    @DisplayName("Издатель с KeyUsage cRLSign: CRL принимается")
    void issuerWithCrlSignIsAccepted() {
        assertDoesNotThrow(() -> CrlVerifier.verify(baseCrl, leaf, withCrlSign));
    }

    @Test
    @DisplayName("Издатель с KeyUsage без cRLSign: MISSING_CRL_SIGN, подпись при этом верна")
    void issuerWithKeyUsageWithoutCrlSignIsRejected() {
        assertMissingCrlSign(
                () -> CrlVerifier.verify(baseCrl, leaf, keyCertSignOnly),
                "Только keyCertSign: CRL подписывать нельзя");
        assertMissingCrlSign(
                () -> CrlVerifier.verify(baseCrl, leaf, digitalSignatureOnly),
                "Только digitalSignature: CRL подписывать нельзя");
    }

    @Test
    @DisplayName("Отказ по cRLSign не зависит от перегрузки: minCrlNumber и пределы")
    void rejectionHoldsForAllDirectOverloads() {
        assertMissingCrlSign(
                () -> CrlVerifier.verify(baseCrl, leaf, keyCertSignOnly, BigInteger.ONE),
                "Перегрузка с minCrlNumber");
        assertMissingCrlSign(
                () -> CrlVerifier.verify(baseCrl, leaf, keyCertSignOnly, null, CrlLimits.DEFAULT),
                "Перегрузка с пределами");
    }

    @Test
    @DisplayName("Пара base+delta: издатель без cRLSign отвергается, с cRLSign принимается")
    void baseDeltaRequiresCrlSign() {
        assertDoesNotThrow(() -> CrlVerifier.verify(baseCrl, deltaCrl, leaf, withCrlSign));
        assertMissingCrlSign(
                () -> CrlVerifier.verify(baseCrl, deltaCrl, leaf, keyCertSignOnly),
                "base+delta: нет cRLSign");
    }

    @Test
    @DisplayName("Доказательство CAdES-X Long: издатель без cRLSign отвергается")
    void evidenceRequiresCrlSign() {
        RevocationEvidenceWindow window =
                new RevocationEvidenceWindow(
                        Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verifyEvidence(
                                baseCrl,
                                leaf,
                                withCrlSign,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
        assertMissingCrlSign(
                () ->
                        CrlVerifier.verifyEvidence(
                                baseCrl,
                                leaf,
                                keyCertSignOnly,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT),
                "Доказательство: нет cRLSign");
    }

    @Test
    @DisplayName("Не заданный сертификат издателя: PkixException, а не NullPointerException")
    void nullIssuerIsRejected() {
        assertThrows(PkixException.class, () -> CrlVerifier.verify(baseCrl, leaf, null));
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.authenticate(baseCrl, null, CrlLimits.DEFAULT));
    }

    // ========================================================================
    // Проверенный CRL и кэш
    // ========================================================================

    @Test
    @DisplayName("authenticate: издатель без cRLSign отвергается до выдачи VerifiedCrl")
    void authenticateRequiresCrlSign() {
        assertMissingCrlSign(
                () -> CrlVerifier.authenticate(baseCrl, keyCertSignOnly, CrlLimits.DEFAULT),
                "authenticate: нет cRLSign");
    }

    @Test
    @DisplayName("Попадание в кэш не обходит cRLSign: тот же ключ, но сертификат без бита")
    void cachedCrlIsRecheckedAgainstIssuerCertificate() throws Exception {
        VerifiedCrl verified = CrlVerifier.authenticate(baseCrl, withCrlSign, CrlLimits.DEFAULT);

        assertDoesNotThrow(() -> verified.verifyFor(leaf, withCrlSign, null));
        assertDoesNotThrow(
                () -> verified.verifyFor(leaf, noKeyUsage, null),
                "Сертификат без KeyUsage вправе подписывать CRL");
        assertMissingCrlSign(
                () -> verified.verifyFor(leaf, keyCertSignOnly, null),
                "Объект из кэша не должен действовать для издателя без cRLSign");
    }

    // ========================================================================
    // Делегированный путь
    // ========================================================================

    private static GostCertificate caWith(KeyPair caKp, KeyUsage... usages) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, "CN=CRL Test Issuer,O=Test,C=RU")
                        .publicKey(caKp.getPublic())
                        .notBefore("250101000000Z")
                        .notAfter("350101000000Z")
                        .serial(BigInteger.ONE)
                        .basicConstraints(true, null);
        if (usages.length > 0) {
            builder.keyUsage(usages);
        }
        return GostCertificateBuilder.sign(builder.buildTbs(), GostSigner.of(caKp.getPrivate()));
    }

    @Test
    @DisplayName("verifyDelegated: CRL подписан самим CA без cRLSign - отказ, а не предупреждение")
    void delegatedCaSignedCrlRequiresCrlSign() {
        assertDoesNotThrow(
                () -> CrlVerifier.verifyDelegated(baseCrl, leaf, withCrlSign, List.of()));
        assertMissingCrlSign(
                () -> CrlVerifier.verifyDelegated(baseCrl, leaf, keyCertSignOnly, List.of()),
                "CA подписал CRL сам и не вправе это делать");
    }

    @Test
    @DisplayName("verifyDelegated: подписант с cRLSign принят, даже если у CA нет cRLSign")
    void delegatedSignerPathDoesNotNeedCaCrlSign() throws Exception {
        KeyPair caKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate caWithoutCrlSign = caWith(caKp, KeyUsage.KEY_CERT_SIGN);

        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signer =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=CRL Signer,O=Test,C=RU")
                                .publicKey(signerKp.getPublic())
                                .issuerDn(caWithoutCrlSign.getSubjectDnBytes())
                                .notBefore("250101000000Z")
                                .notAfter("350101000000Z")
                                .serial(BigInteger.TWO)
                                .keyUsage(KeyUsage.CRL_SIGN)
                                .buildTbs(),
                        GostSigner.of(caKp.getPrivate()));
        byte[] crl =
                GostCrlBuilder.create(caWithoutCrlSign.getSubjectDnBytes())
                        .nextUpdate("20990601120000Z")
                        .withCrlNumber(1)
                        .sign(signerKp.getPrivate());
        GostCertificate delegatedLeaf =
                CrlTestCerts.certFor(LEAF_SERIAL, caWithoutCrlSign.getSubjectDnBytes());

        assertDoesNotThrow(
                () ->
                        CrlVerifier.verifyDelegated(
                                crl, delegatedLeaf, caWithoutCrlSign, List.of(signer.getEncoded())),
                "CRL подписан делегированным подписантом, право CA на подпись не требуется");
    }

    // ========================================================================
    // Путь проверки цепочки
    // ========================================================================

    @Test
    @DisplayName("Цепочка: CRL корня без cRLSign отвергается, с cRLSign принимается")
    void chainValidationRequiresCrlSign() throws Exception {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate rootWithBit = caWith(rootKp, KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
        GostCertificate rootWithoutBit = caWith(rootKp, KeyUsage.KEY_CERT_SIGN);
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate chainLeaf =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=Chain Leaf,O=Test,C=RU")
                                .publicKey(leafKp.getPublic())
                                .issuerDn(rootWithBit.getSubjectDnBytes())
                                .randomSerial()
                                .notBeforeNow()
                                .validForDays(30)
                                .buildTbs(),
                        GostSigner.of(rootKp.getPrivate()));
        byte[] crl =
                GostCrlBuilder.create(rootWithBit.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(7)
                        .withCrlNumber(1)
                        .sign(rootKp.getPrivate());
        List<CertRevocationData> revocation =
                java.util.Arrays.asList(new CertRevocationData(null, crl), null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChainWithRevocation(
                                List.of(chainLeaf, rootWithBit),
                                TrustAnchors.ofCertificate(rootWithBit),
                                revocation,
                                CrlLimits.DEFAULT));
        assertMissingCrlSign(
                () ->
                        ChainValidator.validateChainWithRevocation(
                                List.of(chainLeaf, rootWithoutBit),
                                TrustAnchors.ofCertificate(rootWithoutBit),
                                revocation,
                                CrlLimits.DEFAULT),
                "Цепочка: корень без cRLSign не вправе подписывать CRL");
    }
}
