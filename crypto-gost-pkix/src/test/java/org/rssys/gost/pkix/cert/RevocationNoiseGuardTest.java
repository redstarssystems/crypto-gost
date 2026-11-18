package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.signature.ECParameters;

/**
 * Страж шума: штатная проверка цепочки с данными отзыва (CRL или OCSP) не пишет WARNING и выше.
 * Успешная проверка не событие, а WARNING на каждую проверку попадал бы в журнал сервера на
 * каждое соединение.
 */
@DisplayName("Проверка цепочки с отзывом: штатный путь без WARNING")
class RevocationNoiseGuardTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String NEXT_UPDATE = "21000101000000Z";

    private static PkixCertTestHelper.CertBundle ca;
    private static PkixCertTestHelper.CertBundle leaf;
    private static TrustAnchors anchors;
    private static List<GostCertificate> chain;

    @BeforeAll
    static void setUp() throws Exception {
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
        anchors = TrustAnchors.ofCertificate(ca.cert);
        chain = List.of(leaf.cert, ca.cert);
    }

    @Test
    @DisplayName("CRL: лист не отозван -> WARNING нет, ход проверки виден на DEBUG")
    void crlCheckIsQuietAtWarning() throws Exception {
        byte[] crl = GostCrlBuilder.create(ca.subjectDn).nextUpdate(NEXT_UPDATE).sign(ca.priv);
        List<CertRevocationData> data =
                Arrays.asList(new CertRevocationData(null, crl), null); // корень не проверяется

        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            assertDoesNotThrow(
                    () -> ChainValidator.validateChainWithRevocation(chain, anchors, data));

            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "штатная проверка по CRL не должна писать WARNING");
            assertTrue(
                    log.messages(Level.FINE).stream().anyMatch(m -> m.contains("CRL verification")),
                    "ход проверки на DEBUG: " + log.messages(Level.FINE));
        }
    }

    @Test
    @DisplayName("OCSP: статус good -> WARNING нет, ход проверки виден на DEBUG")
    void ocspCheckIsQuietAtWarning() throws Exception {
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(ca.subjectDn)
                        .sign(ca.priv);
        List<CertRevocationData> data =
                Arrays.asList(new CertRevocationData(ocsp, null), null); // корень не проверяется

        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            assertDoesNotThrow(
                    () -> ChainValidator.validateChainWithRevocation(chain, anchors, data));

            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "штатная проверка по OCSP не должна писать WARNING");
            assertTrue(
                    log.messages(Level.FINE).stream().anyMatch(m -> m.contains("OCSP")),
                    "ход проверки на DEBUG: " + log.messages(Level.FINE));
        }
    }
}
