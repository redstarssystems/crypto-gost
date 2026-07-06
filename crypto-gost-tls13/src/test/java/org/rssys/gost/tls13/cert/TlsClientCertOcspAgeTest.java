package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsTestHelper;

/**
 * Проверяет проброс {@code maxOcspAgeMs} в mTLS-пути (проверка клиентского
 * сертификата), симметрично серверному пути. Раньше клиентский путь жёстко шёл
 * по дефолтной политике свежести — конфигурируемый порог до него не доходил.
 */
@DisplayName("checkClientCertificateChain: настраиваемый maxOcspAgeMs для stapled-OCSP клиента")
class TlsClientCertOcspAgeTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    private static TlsTestHelper.CertBundle root;

    @BeforeAll
    static void setUp() throws Exception {
        root = TlsTestHelper.createRootCA(PARAMS);
    }

    /** Клиентский leaf с KU digitalSignature + EKU clientAuth и приложенным OCSP-staple. */
    private static List<GostCertificate> clientChainWithStaple(Instant ocspThisUpdate)
            throws Exception {
        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        GostCertificateBuilder.keyUsageFlags(
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE),
                        new String[] {EKU_CLIENT_AUTH},
                        false,
                        null,
                        null);

        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .signer(root.priv, root.cert.getPublicKey())
                        .issuerDn(root.subjectDn)
                        .thisUpdate(ocspThisUpdate)
                        .noNextUpdate()
                        .build();

        GostCertificate leafWithStaple = new GostCertificate(leaf.cert.getEncoded());
        leafWithStaple.setOcspResponse(ocsp);
        return List.of(leafWithStaple, root.cert);
    }

    @Test
    @DisplayName("OCSP-staple без nextUpdate старше кастомного maxOcspAgeMs -> отказ")
    void staleBeyondCustomMaxAge_rejected() throws Exception {
        List<GostCertificate> chain =
                clientChainWithStaple(Instant.now().minus(2, ChronoUnit.HOURS));

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.checkClientCertificateChain(
                                        chain, null, ChronoUnit.HOURS.getDuration().toMillis()),
                        "2-часовой staple при пороге 1ч должен отвергаться на mTLS-пути");
        assertTrue(
                ex.getMessage().contains("too old"),
                "Ожидалось 'response too old', получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Тот же staple в пределах дефолтного порога (24ч) -> принимается")
    void withinDefaultMaxAge_accepted() throws Exception {
        List<GostCertificate> chain =
                clientChainWithStaple(Instant.now().minus(2, ChronoUnit.HOURS));

        // Дефолтная 2-арг перегрузка = GostOids.MAX_OCSP_AGE_MS (24ч) — 2ч свежести проходят.
        assertDoesNotThrow(
                () -> TlsCertificateValidator.checkClientCertificateChain(chain, null),
                "2-часовой staple при дефолтном пороге 24ч не должен отвергаться");
        assertEquals(
                24 * 60 * 60 * 1000L,
                GostOids.MAX_OCSP_AGE_MS,
                "Дефолтный порог должен оставаться 24ч");
    }
}
