package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;

/**
 * Тесты локальной политики свежести OCSP-ответа без {@code nextUpdate}
 * (RFC 6960 §2.4) и настраиваемого порога {@code maxOcspAgeMs}.
 */
@DisplayName("OcspVerifier: свежесть при отсутствии nextUpdate (maxOcspAgeMs)")
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

    private byte[] ocspNoNextUpdate(Instant thisUpdate) throws Exception {
        return GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                .signer(ca.priv, ca.cert.getPublicKey())
                .issuerDn(ca.subjectDn)
                .thisUpdate(thisUpdate)
                .noNextUpdate()
                .build();
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
                                        ChronoUnit.HOURS.getDuration().toMillis()),
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
                3 * ChronoUnit.HOURS.getDuration().toMillis());
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
}
