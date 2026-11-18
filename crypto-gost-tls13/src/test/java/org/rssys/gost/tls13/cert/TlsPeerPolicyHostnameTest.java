package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper.CertBundle;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Имя сервера в {@link TlsPeerPolicy}: отсутствие имени не должно отключать сверку молча. Имя
 * обязательно, а проверку без сверки имени выбирают явными фабриками.
 */
@DisplayName("TlsPeerPolicy: имя сервера обязательно, отключение сверки явное")
class TlsPeerPolicyHostnameTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String CERT_HOST = "host.example.com";
    private static final String OTHER_HOST = "other.example.com";

    private static CertBundle root;
    private static CertBundle leaf;
    private static TrustAnchors anchors;

    @BeforeAll
    static void setUp() throws Exception {
        root = PkixCertTestHelper.createRootCA(PARAMS);
        leaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {CERT_HOST},
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        anchors = TrustAnchors.ofCertificate(root.cert);
    }

    @Test
    @DisplayName("server(null, ...) -> IllegalArgumentException")
    void serverNullHostnameRejected() {
        assertThrows(IllegalArgumentException.class, () -> TlsPeerPolicy.server(null, anchors));
    }

    @ParameterizedTest(name = "пустое имя \"{0}\" -> IllegalArgumentException")
    @ValueSource(strings = {"", " ", "   \t"})
    @DisplayName("пустое или из пробелов имя отвергается во всех фабриках с именем")
    void blankHostnameRejected(String hostname) {
        assertThrows(IllegalArgumentException.class, () -> TlsPeerPolicy.server(hostname, anchors));
        assertThrows(IllegalArgumentException.class, () -> TlsPeerPolicy.serverLeafOnly(hostname));
    }

    @Test
    @DisplayName("serverLeafOnly(null) -> IllegalArgumentException")
    void serverLeafOnlyNullHostnameRejected() {
        assertThrows(IllegalArgumentException.class, () -> TlsPeerPolicy.serverLeafOnly(null));
    }

    @Test
    @DisplayName("с именем сверка работает: чужое имя -> bad_certificate")
    void namedPolicyStillVerifiesHostname() {
        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validate(
                                List.of(leaf.cert), TlsPeerPolicy.server(CERT_HOST, anchors)));
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        List.of(leaf.cert),
                                        TlsPeerPolicy.server(OTHER_HOST, anchors)));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName("явные фабрики без сверки имени: сертификат с чужим именем проходит")
    void explicitFactoriesSkipHostnameVerification() {
        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validate(
                                List.of(leaf.cert),
                                TlsPeerPolicy.serverWithoutHostnameVerification(anchors)),
                "имя сертификата не сверяется, остальное проверяется как обычно");
        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validateLeafOnly(
                                List.of(leaf.cert),
                                TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()));
    }

    @Test
    @DisplayName("явные фабрики не отключают остальные проверки: срок и якоря действуют")
    void explicitFactoriesStillVerifyTheRest() throws Exception {
        CertBundle foreignRoot = PkixCertTestHelper.createRootCA(PARAMS);
        TrustAnchors foreignAnchors = TrustAnchors.ofCertificate(foreignRoot.cert);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        List.of(leaf.cert),
                                        TlsPeerPolicy.serverWithoutHostnameVerification(
                                                foreignAnchors)),
                        "сертификат не от доверенного якоря отвергается и без сверки имени");
        assertEquals(TlsConstants.ALERT_UNKNOWN_CA, ex.getAlertCode());
        assertThrows(
                IllegalArgumentException.class,
                () -> TlsPeerPolicy.serverWithoutHostnameVerification(null),
                "якоря по-прежнему обязательны");
    }

    @Test
    @DisplayName("явные фабрики не отключают проверку срока: просроченный сертификат отвергается")
    void explicitFactoriesStillCheckValidity() throws Exception {
        CertBundle expired =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20200101000000Z",
                        "20200102000000Z",
                        new String[] {CERT_HOST},
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        List.of(expired.cert),
                                        TlsPeerPolicy.serverWithoutHostnameVerification(anchors)),
                        "просроченный сертификат отвергается и без сверки имени");
        assertEquals(TlsConstants.ALERT_CERTIFICATE_EXPIRED, ex.getAlertCode());
    }
}
