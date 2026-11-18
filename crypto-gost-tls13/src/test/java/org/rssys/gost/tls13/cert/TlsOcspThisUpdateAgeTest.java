package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsException;

/**
 * Необязательный предел возраста {@code thisUpdate} (Р 1323565.1.059-2024, п. 5.3) доходит до
 * проверки приложенного OCSP-ответа на серверной и клиентской ветках и не теряется в копиях
 * неизменяемой политики.
 */
@DisplayName("TlsPeerPolicy.maxThisUpdateAge: предел возраста thisUpdate приложенного OCSP-ответа")
class TlsOcspThisUpdateAgeTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final Duration TWO_HOURS = Duration.ofHours(2);

    private static PkixCertTestHelper.CertBundle root;
    private static TrustAnchors anchors;

    @BeforeAll
    static void setUp() throws Exception {
        root = PkixCertTestHelper.createRootCA(PARAMS);
        anchors = TrustAnchors.ofCertificates(root.cert);
    }

    /** Цепочка: лист с приложенным ответом, thisUpdate 5 ч назад, nextUpdate через 30 суток. */
    private static List<GostCertificate> chainWithOldStaple() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        null,
                        null,
                        false,
                        null,
                        null);
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(root.subjectDn)
                        .thisUpdate(Instant.now().minus(5, ChronoUnit.HOURS))
                        .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                        .sign(root.priv);
        GostCertificate leafWithStaple = new GostCertificate(leaf.cert.getEncoded());
        leafWithStaple.setOcspResponse(ocsp);
        return List.of(leafWithStaple, root.cert);
    }

    /**
     * Цепочка лист - промежуточный - корень: у листа staple нет, у промежуточного сертификата
     * приложен старый ответ (thisUpdate 5 ч назад, nextUpdate +30 суток), подписанный корнем.
     * Так выполняются циклы проверки промежуточных сертификатов, которых нет в цепочке из двух.
     */
    private static List<GostCertificate> chainWithOldIntermediateStaple() throws Exception {
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x04},
                        (String[]) null,
                        true,
                        null);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
        GostCertificate intermediateWithStaple =
                new GostCertificate(intermediate.cert.getEncoded());
        intermediateWithStaple.setOcspResponse(
                GostOcspResponseBuilder.create(intermediate.cert.getSerialNumber())
                        .issuerDn(root.subjectDn)
                        .thisUpdate(Instant.now().minus(5, ChronoUnit.HOURS))
                        .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                        .sign(root.priv));
        return List.of(leaf.cert, intermediateWithStaple, root.cert);
    }

    @Test
    @DisplayName("Сервер: старый ответ при пределе -> bad_certificate, без предела -> принят")
    void serverBranch_limitEnforced() throws Exception {
        List<GostCertificate> chain = chainWithOldStaple();
        TlsPeerPolicy base = TlsPeerPolicy.server("example.test", anchors);

        assertDoesNotThrow(
                () -> TlsCertificateValidator.validateRevocation(chain, base),
                "Без предела ответ с далёким nextUpdate принимается");
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateRevocation(
                                        chain, base.maxThisUpdateAge(TWO_HOURS)),
                        "Ответ старше предела должен отвергаться на серверной ветке");
        assertTrue(
                ex.getMessage().contains("older than allowed thisUpdate age"),
                "Ожидался отказ по пределу, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Клиент (mTLS): старый ответ при пределе -> bad_certificate")
    void clientBranch_limitEnforced() throws Exception {
        List<GostCertificate> chain = chainWithOldStaple();
        TlsPeerPolicy base = TlsPeerPolicy.client(anchors);

        assertDoesNotThrow(() -> TlsCertificateValidator.validateRevocation(chain, base));
        assertThrows(
                TlsException.class,
                () ->
                        TlsCertificateValidator.validateRevocation(
                                chain, base.maxThisUpdateAge(TWO_HOURS)),
                "Ответ старше предела должен отвергаться на клиентской ветке");
    }

    @Test
    @DisplayName("Сервер: старый staple промежуточного сертификата при пределе -> отказ")
    void serverBranch_intermediateStapleLimitEnforced() throws Exception {
        List<GostCertificate> chain = chainWithOldIntermediateStaple();
        TlsPeerPolicy base = TlsPeerPolicy.server("example.test", anchors);

        assertDoesNotThrow(
                () -> TlsCertificateValidator.validateRevocation(chain, base),
                "Контроль: без предела ответ промежуточного сертификата принимается");
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateRevocation(
                                        chain, base.maxThisUpdateAge(TWO_HOURS)),
                        "Предел должен действовать и на промежуточные сертификаты (сервер)");
        assertTrue(
                ex.getMessage().contains("older than allowed thisUpdate age"),
                "Ожидался отказ по пределу, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Клиент (mTLS): старый staple промежуточного сертификата при пределе -> отказ")
    void clientBranch_intermediateStapleLimitEnforced() throws Exception {
        List<GostCertificate> chain = chainWithOldIntermediateStaple();
        TlsPeerPolicy base = TlsPeerPolicy.client(anchors);

        assertDoesNotThrow(() -> TlsCertificateValidator.validateRevocation(chain, base));
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateRevocation(
                                        chain, base.maxThisUpdateAge(TWO_HOURS)),
                        "Предел должен действовать и на промежуточные сертификаты (клиент)");
        assertTrue(
                ex.getMessage().contains("older than allowed thisUpdate age"),
                "Ожидался отказ по пределу, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Копии политики сохраняют предел: requireOcspStaple и maxOcspAge его не теряют")
    void copies_keepLimit() {
        TlsPeerPolicy policy = TlsPeerPolicy.server("example.test", anchors);

        assertNull(policy.maxThisUpdateAge(), "По умолчанию предел не задан");
        TlsPeerPolicy limited = policy.maxThisUpdateAge(TWO_HOURS);
        assertEquals(TWO_HOURS, limited.maxThisUpdateAge());
        assertEquals(
                TWO_HOURS,
                limited.requireOcspStaple(true).maxThisUpdateAge(),
                "requireOcspStaple создаёт копию и не должен терять предел");
        assertEquals(
                TWO_HOURS,
                limited.maxOcspAge(60_000L).maxThisUpdateAge(),
                "maxOcspAge создаёт копию и не должен терять предел");
        TlsPeerPolicy afterOtherSettings = limited.requireOcspStaple(true).maxOcspAge(60_000L);
        assertEquals(60_000L, afterOtherSettings.maxOcspAgeMs(), "maxOcspAge не потерян");
        assertTrue(afterOtherSettings.requiresOcspStaple(), "requireOcspStaple не потерян");
        assertEquals(GostOids.MAX_OCSP_AGE_MS, limited.maxOcspAgeMs(), "maxOcspAge не затронут");
    }

    @Test
    @DisplayName("null сбрасывает предел и допустим; ноль и отрицательное отвергаются")
    void nullResetsAndNonPositiveRejected() {
        TlsPeerPolicy limited = TlsPeerPolicy.client(anchors).maxThisUpdateAge(TWO_HOURS);

        assertNull(limited.maxThisUpdateAge(null).maxThisUpdateAge(), "null сбрасывает предел");
        assertThrows(IllegalArgumentException.class, () -> limited.maxThisUpdateAge(Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class,
                () -> limited.maxThisUpdateAge(Duration.ofSeconds(-1)));
    }

    @Test
    @DisplayName("Очень большой предел не оборвал бы проверку: ответ принимается")
    void hugeLimit_noOverflow() throws Exception {
        List<GostCertificate> chain = chainWithOldStaple();
        TlsPeerPolicy policy =
                TlsPeerPolicy.server("example.test", anchors)
                        .maxThisUpdateAge(Duration.ofSeconds(Long.MAX_VALUE));

        assertDoesNotThrow(() -> TlsCertificateValidator.validateRevocation(chain, policy));
    }
}
