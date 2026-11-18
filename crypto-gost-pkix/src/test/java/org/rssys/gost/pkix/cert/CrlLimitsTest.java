package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crl;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedEntry;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedList;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;

@DisplayName("CrlLimits: пределы CRL одинаковы на всех путях проверки")
class CrlLimitsTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String CDP = "http://crl.example.com/leaf.crl";
    private static final int ENTRIES = 11;
    private static final int ENTRIES_LIMIT = 10;

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static GostCertificate leaf;
    private static byte[] crlDer;
    private static byte[] deltaDer;

    @BeforeAll
    static void setup() throws Exception {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        root =
                GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn("CN=Root CA"))
                        .publicKey(rootKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(3650)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leaf =
                GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn("CN=Leaf"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .crlDistributionPoints(CDP)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());
        crlDer = crlWithEntries(ENTRIES);
        // Delta CRL без записей к базовому CRL с cRLNumber = 1: для пути «base+delta»
        deltaDer =
                GostCrlBuilder.create(root.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(7)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .sign(rootKp.getPrivate());
    }

    /** Подписанный CRL корня с заданным числом записей; сертификат leaf среди них не значится. */
    private static byte[] crlWithEntries(int count) throws Exception {
        List<RevokedEntry> entries = new ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            entries.add(new RevokedEntry(BigInteger.valueOf(i).toByteArray(), "20250601120000Z"));
        }
        return GostCrlBuilder.create(root.getSubjectDnBytes())
                .thisUpdateNow()
                .nextUpdateDays(7)
                .withCrlNumber(1)
                .addRevoked(entries)
                .sign(rootKp.getPrivate());
    }

    private static RevocationEvidenceWindow window() {
        return new RevocationEvidenceWindow(
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));
    }

    /** Путь проверки CRL: все они принимают один и тот же объект пределов. */
    @FunctionalInterface
    private interface Path {
        void run(byte[] crl, CrlLimits limits) throws Exception;
    }

    private static Stream<Arguments> paths() {
        Path direct = (crl, limits) -> CrlVerifier.verify(crl, leaf, root, null, limits);
        Path baseDelta = (crl, limits) -> CrlVerifier.verify(crl, deltaDer, leaf, root, limits);
        Path delegated =
                (crl, limits) -> CrlVerifier.verifyDelegated(crl, leaf, root, null, null, limits);
        Path authenticate = (crl, limits) -> CrlVerifier.authenticate(crl, root, limits);
        Path evidence =
                (crl, limits) ->
                        CrlVerifier.verifyEvidence(
                                crl,
                                leaf,
                                root,
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                limits);
        Path chain =
                (crl, limits) ->
                        ChainValidator.validateChainWithRevocation(
                                List.of(leaf, root),
                                TrustAnchors.ofCertificate(root),
                                Arrays.asList(new CertRevocationData(null, crl), null),
                                limits);
        Path chainEvidence =
                (crl, limits) ->
                        ChainValidator.validateChainWithRevocationEvidence(
                                List.of(leaf, root),
                                TrustAnchors.ofCertificate(root),
                                List.of(
                                        new CertRevocationEvidence(List.of(crl), List.of()),
                                        new CertRevocationEvidence(List.of(), List.of())),
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                List.of(),
                                limits);
        Path revocationEvidence =
                (crl, limits) ->
                        ChainValidator.validateRevocationEvidence(
                                List.of(leaf, root),
                                List.of(
                                        new CertRevocationEvidence(List.of(crl), List.of()),
                                        new CertRevocationEvidence(List.of(), List.of())),
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                limits);
        return Stream.of(
                Arguments.of("CrlVerifier.verify", direct),
                Arguments.of("CrlVerifier.verify (base+delta)", baseDelta),
                Arguments.of("CrlVerifier.verifyDelegated", delegated),
                Arguments.of("CrlVerifier.authenticate", authenticate),
                Arguments.of("CrlVerifier.verifyEvidence", evidence),
                Arguments.of("ChainValidator.validateChainWithRevocation", chain),
                Arguments.of("ChainValidator.validateChainWithRevocationEvidence", chainEvidence),
                Arguments.of("ChainValidator.validateRevocationEvidence", revocationEvidence));
    }

    // ------------------------------------------------------------------------
    // Объект пределов
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("DEFAULT: значения по умолчанию не изменились")
    void defaultValuesUnchanged() {
        assertEquals(67_108_864, CrlLimits.DEFAULT.maxSize(), "предел размера по умолчанию");
        assertEquals(
                1_000_000, CrlLimits.DEFAULT.maxRevokedEntries(), "предел записей по умолчанию");
        assertEquals(CrlLimits.DEFAULT.maxSize(), GostCrl.DEFAULT_MAX_CRL_SIZE);
        assertEquals(CrlLimits.DEFAULT.maxRevokedEntries(), GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
    }

    @Test
    @DisplayName("Значения не больше нуля отвергаются при создании")
    void nonPositiveValuesRejected() {
        assertThrows(IllegalArgumentException.class, () -> new CrlLimits(0, 1));
        assertThrows(IllegalArgumentException.class, () -> new CrlLimits(-1, 1));
        assertThrows(IllegalArgumentException.class, () -> new CrlLimits(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new CrlLimits(1, -1));
        assertThrows(IllegalArgumentException.class, () -> CrlLimits.DEFAULT.withMaxSize(0));
        assertThrows(
                IllegalArgumentException.class, () -> CrlLimits.DEFAULT.withMaxRevokedEntries(0));
    }

    @Test
    @DisplayName("withMaxSize и withMaxRevokedEntries меняют только своё значение")
    void withersChangeOnlyOwnField() {
        CrlLimits limits = new CrlLimits(100, 10);
        assertEquals(new CrlLimits(200, 10), limits.withMaxSize(200));
        assertEquals(new CrlLimits(100, 20), limits.withMaxRevokedEntries(20));
    }

    @Test
    @DisplayName("requireSize: ровно предел принимается, предел плюс 1 даёт CRL_LIMIT_EXCEEDED")
    void requireSizeBoundary() throws Exception {
        CrlLimits limits = new CrlLimits(crlDer.length, ENTRIES);
        limits.requireSize(crlDer);
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> limits.withMaxSize(crlDer.length - 1).requireSize(crlDer));
        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertTrue(e.getMessage().contains("size"), "сообщение называет размер: " + e.getMessage());
        assertTrue(
                e.getMessage().contains(String.valueOf(crlDer.length)),
                "сообщение содержит фактический размер: " + e.getMessage());
    }

    // ------------------------------------------------------------------------
    // GostCrl: сообщение о превышении числа записей
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("GostCrl.verify: сообщение называет предел записей и фактическое число")
    void gostCrlMessageNamesLimitAndCount() {
        GostCrl crl = new GostCrl(crlDer, new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, 10));
        PkixException e =
                assertThrows(PkixException.class, () -> crl.verify(rootKp.getPublic(), false));
        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertTrue(
                e.getMessage().contains("revoked entries exceed maximum 10, got 11"),
                "сообщение: " + e.getMessage());
    }

    @Test
    @DisplayName("GostCrl.verify: испорченный хвост после предела не подменяет ошибку")
    void corruptedTailAfterLimitKeepsLimitReason() {
        // Предел 10: одиннадцатая запись корректна, дальше мусор, который нельзя разобрать
        byte[][] entries = new byte[ENTRIES_LIMIT + 2][];
        for (int i = 0; i <= ENTRIES_LIMIT; i++) {
            entries[i] = revokedEntry(BigInteger.valueOf(i + 1), null);
        }
        entries[ENTRIES_LIMIT + 1] = new byte[] {0x30, 0x7F, 0x01};
        byte[] der =
                crl(rootKp.getPrivate(), PARAMS, root.getSubjectDnBytes(), revokedList(entries));
        GostCrl crl = new GostCrl(der, new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, ENTRIES_LIMIT));

        PkixException e =
                assertThrows(PkixException.class, () -> crl.verify(rootKp.getPublic(), false));

        assertEquals(
                PkixException.Reason.CRL_LIMIT_EXCEEDED,
                e.reason(),
                "сбой подсчёта не должен давать другую причину");
        assertTrue(
                e.getMessage().contains("at least"),
                "при сбое подсчёта сообщение даёт нижнюю границу: " + e.getMessage());
    }

    // ------------------------------------------------------------------------
    // Одинаковое поведение на всех путях
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}: превышение числа записей")
    @MethodSource("paths")
    @DisplayName("Превышение числа записей даёт CRL_LIMIT_EXCEEDED на каждом пути")
    void entriesLimitExceededOnEveryPath(String name, Path path) {
        CrlLimits limits = CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES_LIMIT);

        PkixException e = assertThrows(PkixException.class, () -> path.run(crlDer, limits), name);

        assertEquals(
                PkixException.Reason.CRL_LIMIT_EXCEEDED,
                e.reason(),
                name + ": причина должна называть превышение предела, а не ошибку разбора");
        assertTrue(
                e.getMessage().contains("revoked entries exceed maximum"),
                name + ": сообщение называет предел записей: " + e.getMessage());
    }

    @ParameterizedTest(name = "{0}: превышение размера")
    @MethodSource("paths")
    @DisplayName("Превышение размера даёт CRL_LIMIT_EXCEEDED на каждом пути")
    void sizeLimitExceededOnEveryPath(String name, Path path) {
        CrlLimits limits = CrlLimits.DEFAULT.withMaxSize(crlDer.length - 1);

        PkixException e = assertThrows(PkixException.class, () -> path.run(crlDer, limits), name);

        assertEquals(
                PkixException.Reason.CRL_LIMIT_EXCEEDED,
                e.reason(),
                name + ": размер сверх предела не должен выглядеть как битый CRL");
        assertTrue(
                e.getMessage().contains("size"),
                name + ": сообщение называет размер: " + e.getMessage());
    }

    @ParameterizedTest(name = "{0}: пределы ровно по CRL")
    @MethodSource("paths")
    @DisplayName("Ровно на пределе (размер и число записей) CRL принимается на каждом пути")
    void exactlyAtLimitsAccepted(String name, Path path) {
        CrlLimits limits = new CrlLimits(crlDer.length, ENTRIES);

        assertDoesNotThrow(() -> path.run(crlDer, limits), name);
    }

    @ParameterizedTest(name = "{0}: значения по умолчанию")
    @MethodSource("paths")
    @DisplayName("Значения по умолчанию пропускают обычный CRL на каждом пути")
    void defaultLimitsAcceptRegularCrl(String name, Path path) {
        assertDoesNotThrow(() -> path.run(crlDer, CrlLimits.DEFAULT), name);
    }

    @Test
    @DisplayName("Короткие перегрузки применяют значения по умолчанию")
    void shortOverloadsUseDefaults() {
        assertDoesNotThrow(() -> CrlVerifier.verify(crlDer, leaf, root));
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChainWithRevocation(
                                List.of(leaf, root),
                                TrustAnchors.ofCertificate(root),
                                Arrays.asList(new CertRevocationData(null, crlDer), null)));
    }

    @Test
    @DisplayName("null вместо пределов отвергается")
    void nullLimitsRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CrlVerifier.verify(crlDer, leaf, root, null, null));
        assertThrows(IllegalArgumentException.class, () -> new GostCrl(crlDer, null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ChainValidator.validateChainWithRevocation(
                                List.of(leaf, root),
                                TrustAnchors.ofCertificate(root),
                                Arrays.asList(new CertRevocationData(null, crlDer), null),
                                null));
    }

    @Test
    @DisplayName(
            "Конструктор GostCrl остаётся низкоуровневым: размер даёт IllegalArgumentException")
    void gostCrlConstructorKeepsIllegalArgument() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new GostCrl(new byte[200], new CrlLimits(100, 10)));
    }
}
