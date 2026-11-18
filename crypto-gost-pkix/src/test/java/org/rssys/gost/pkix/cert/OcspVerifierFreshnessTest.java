package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;

/**
 * Тесты локальной политики свежести OCSP-ответа без {@code nextUpdate}
 * (RFC 6960 §2.4), настраиваемого порога {@code maxOcspAgeMs} и необязательного
 * предела возраста {@code thisUpdate} для всех ответов (Р 1323565.1.059-2024, п. 5.3).
 */
@DisplayName("OcspVerifier: свежесть (maxOcspAgeMs и предел возраста thisUpdate)")
class OcspVerifierFreshnessTest {

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
    @DisplayName("thisUpdate в будущем -> отказ (RFC 6960 §3.2)")
    void thisUpdateInFuture_rejected() {
        // Ответ строится через builder, а не правкой готового DER: байт-хакинг тега времени
        // даёт ложные совпадения со случайными байтами хэшей issuerNameHash/issuerKeyHash
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(ca.subjectDn)
                        .producedAt("20250101000000Z")
                        .thisUpdate("21010101000000Z")
                        .nextUpdate("21010101000000Z")
                        .sign(ca.priv);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                        "Ответ с thisUpdate в далёком будущем должен отвергаться");
        assertTrue(
                ex.getMessage().contains("future"),
                "Ожидался отказ из-за thisUpdate в будущем, получено: " + ex.getMessage());
    }

    private byte[] ocspNoNextUpdate(Instant thisUpdate) throws Exception {
        return GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                .issuerDn(ca.subjectDn)
                .thisUpdate(thisUpdate)
                .noNextUpdate()
                .sign(ca.priv);
    }

    @Test
    @DisplayName("Без nextUpdate, старше кастомного maxOcspAgeMs -> response too old")
    void noNextUpdate_olderThanCustomMaxAge_throws() throws Exception {
        // thisUpdate 2 часа назад, порог 1 час -> ответ считается протухшим
        byte[] ocsp = ocspNoNextUpdate(Instant.now().minus(2, ChronoUnit.HOURS));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        ocsp,
                                        leaf.cert.getSerialNumber(),
                                        ca.cert,
                                        null,
                                        ChronoUnit.HOURS.getDuration().toMillis(),
                                        null),
                        "Ответ старше кастомного maxOcspAgeMs должен быть отвергнут");
        assertTrue(
                ex.getMessage().contains("too old"),
                "Ожидалось 'response too old', получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Без nextUpdate, в пределах кастомного maxOcspAgeMs -> OK")
    void noNextUpdate_withinCustomMaxAge_ok() throws Exception {
        // thisUpdate 2 часа назад, порог 3 часа -> ответ ещё свежий
        byte[] ocsp = ocspNoNextUpdate(Instant.now().minus(2, ChronoUnit.HOURS));

        OcspVerifier.verify(
                ocsp,
                leaf.cert.getSerialNumber(),
                ca.cert,
                null,
                3 * ChronoUnit.HOURS.getDuration().toMillis(),
                null);
    }

    @Test
    @DisplayName("Регресс: дефолтная перегрузка (24ч) принимает 2-часовой ответ без nextUpdate")
    void noNextUpdate_defaultOverload_within24h_ok() throws Exception {
        byte[] ocsp = ocspNoNextUpdate(Instant.now().minus(2, ChronoUnit.HOURS));

        OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert);
    }

    @Test
    @DisplayName("Регресс: дефолтная перегрузка (24ч) отвергает ответ без nextUpdate старше суток")
    void noNextUpdate_defaultOverload_olderThan24h_throws() throws Exception {
        // 25 часов назад > MAX_OCSP_AGE_MS (24ч) -> протух по дефолтной политике
        byte[] ocsp = ocspNoNextUpdate(Instant.now().minus(25, ChronoUnit.HOURS));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                        "Ответ старше дефолтных 24ч должен быть отвергнут");
        assertTrue(
                ex.getMessage().contains("too old"),
                "Ожидалось 'response too old', получено: " + ex.getMessage());
        assertEquals(
                24 * 60 * 60 * 1000L,
                GostOids.MAX_OCSP_AGE_MS,
                "Дефолтный порог должен оставаться 24ч");
    }

    // ------------------------------------------------------------------
    // Предел возраста thisUpdate для всех ответов
    // ------------------------------------------------------------------

    private static final Duration TWO_HOURS = Duration.ofHours(2);

    /** Ответ с далёким {@code nextUpdate}: {@code maxOcspAgeMs} к нему не применяется. */
    private byte[] ocspWithFarNextUpdate(Instant thisUpdate) {
        return GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                .issuerDn(ca.subjectDn)
                .thisUpdate(thisUpdate)
                .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                .sign(ca.priv);
    }

    private void verifyWithLimit(byte[] ocsp, Duration limit) throws PkixException {
        OcspVerifier.verify(
                ocsp, leaf.cert.getSerialNumber(), ca.cert, null, GostOids.MAX_OCSP_AGE_MS, limit);
    }

    @Test
    @DisplayName("Предел: старый thisUpdate при далёком nextUpdate -> отказ")
    void limit_oldThisUpdateWithFarNextUpdate_throws() {
        byte[] ocsp = ocspWithFarNextUpdate(Instant.now().minus(5, ChronoUnit.HOURS));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> verifyWithLimit(ocsp, TWO_HOURS),
                        "Ответ старше предела должен отвергаться, даже если nextUpdate далеко");
        assertTrue(
                ex.getMessage().contains("older than allowed thisUpdate age"),
                "Ожидался отказ по пределу возраста, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Без предела тот же ответ принимается (поведение по умолчанию не меняется)")
    void noLimit_sameResponseAccepted() {
        byte[] ocsp = ocspWithFarNextUpdate(Instant.now().minus(5, ChronoUnit.HOURS));

        assertDoesNotThrow(
                () -> verifyWithLimit(ocsp, null), "Без предела ответ с далёким nextUpdate нужен");
        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, leaf.cert.getSerialNumber(), ca.cert),
                "Перегрузка без настроек предела не вводит");
    }

    @Test
    @DisplayName("Предел больше возраста ответа -> принят")
    void limit_largerThanAge_ok() {
        byte[] ocsp = ocspWithFarNextUpdate(Instant.now().minus(1, ChronoUnit.HOURS));

        assertDoesNotThrow(() -> verifyWithLimit(ocsp, TWO_HOURS));
    }

    @Test
    @DisplayName("Без nextUpdate: возраст 3 ч, maxOcspAgeMs 24 ч, предел 2 ч -> отказ по пределу")
    void limit_noNextUpdate_youngerThanMaxAgeButOlderThanLimit_throws() throws Exception {
        byte[] ocsp = ocspNoNextUpdate(Instant.now().minus(3, ChronoUnit.HOURS));

        PkixException ex =
                assertThrows(PkixException.class, () -> verifyWithLimit(ocsp, TWO_HOURS));
        assertTrue(
                ex.getMessage().contains("older than allowed thisUpdate age"),
                "Действует меньший из двух пределов, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Отозванный ответ старше предела -> REVOKED, а не отказ по возрасту")
    void limit_revokedOlderThanLimit_reasonRevoked() {
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(ca.subjectDn)
                        .revoked("20250101000000Z")
                        .thisUpdate(Instant.now().minus(5, ChronoUnit.HOURS))
                        .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                        .sign(ca.priv);

        PkixException ex =
                assertThrows(PkixException.class, () -> verifyWithLimit(ocsp, TWO_HOURS));
        assertEquals(
                PkixException.Reason.REVOKED,
                ex.reason(),
                "Статус проверяется первым: отзыв важнее возраста");
    }

    @Test
    @DisplayName("Очень большой предел не ломает проверку (нет переполнения)")
    void limit_hugeDuration_noOverflow() {
        byte[] ocsp = ocspWithFarNextUpdate(Instant.now().minus(5, ChronoUnit.HOURS));
        Duration huge = Duration.ofSeconds(Long.MAX_VALUE);

        assertDoesNotThrow(
                () -> verifyWithLimit(ocsp, huge),
                "Огромный предел просто ничего не ограничивает, исключений быть не должно");
    }

    @Test
    @DisplayName("Ноль и отрицательный предел -> IllegalArgumentException до разбора ответа")
    void limit_nonPositive_rejectedBeforeParsing() {
        byte[] garbage = {0x01, 0x02, 0x03};
        for (Duration bad : new Duration[] {Duration.ZERO, Duration.ofSeconds(-1)}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> verifyWithLimit(garbage, bad),
                    "Ошибка настройки не должна зависеть от содержимого ответа: " + bad);
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            OcspVerifier.verify(
                                    garbage,
                                    leaf.cert.getSerialNumber(),
                                    ca.cert,
                                    ca.cert,
                                    null,
                                    GostOids.MAX_OCSP_AGE_MS,
                                    bad),
                    "Перегрузка с раздельными ролями проверяет предел так же: " + bad);
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> OcspVerifier.requireValidMaxThisUpdateAge(Duration.ZERO));
        assertNull(OcspVerifier.requireValidMaxThisUpdateAge(null), "null — предел не задан");
    }

    @Test
    @DisplayName("Раздельные роли: предел действует и в этой перегрузке")
    void limit_splitRolesOverload_enforced() {
        byte[] ocsp = ocspWithFarNextUpdate(Instant.now().minus(5, ChronoUnit.HOURS));

        assertThrows(
                PkixException.class,
                () ->
                        OcspVerifier.verify(
                                ocsp,
                                leaf.cert.getSerialNumber(),
                                ca.cert,
                                ca.cert,
                                null,
                                GostOids.MAX_OCSP_AGE_MS,
                                TWO_HOURS));
        assertDoesNotThrow(
                () ->
                        OcspVerifier.verify(
                                ocsp,
                                leaf.cert.getSerialNumber(),
                                ca.cert,
                                ca.cert,
                                null,
                                GostOids.MAX_OCSP_AGE_MS,
                                null));
    }
}
