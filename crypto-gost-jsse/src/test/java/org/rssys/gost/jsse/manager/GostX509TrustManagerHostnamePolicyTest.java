package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Имя сервера при проверке цепочки: {@code null} - явный выбор «имя не сверять» (endpoint
 * identification выключен или вызов без соединения), пустое имя - ошибка, а не пропуск сверки.
 */
@DisplayName("GostX509TrustManager: имя сервера и политика сверки")
class GostX509TrustManagerHostnamePolicyTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String CERT_HOST = "gost.example.com";
    private static final String OTHER_HOST = "other.example.com";

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        root = PkixCertTestHelper.createRootCA(PARAMS);
        leaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {CERT_HOST},
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
    }

    private static GostX509TrustManager anchored() {
        return GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(root.cert));
    }

    private static List<org.rssys.gost.pkix.cert.GostCertificate> chain() {
        return List.of(leaf.cert, root.cert);
    }

    @Test
    @DisplayName("с якорями: совпавшее имя проходит, чужое отвергается")
    void anchoredNamedHostnameVerified() {
        GostX509TrustManager trustManager = anchored();

        assertDoesNotThrow(() -> trustManager.validateChainWithOcsp(chain(), CERT_HOST, false));
        assertThrows(
                CertificateException.class,
                () -> trustManager.validateChainWithOcsp(chain(), OTHER_HOST, false));
    }

    @Test
    @DisplayName("с якорями: null вместо имени - явный режим без сверки имени")
    void anchoredNullHostnameSkipsVerificationExplicitly() {
        assertDoesNotThrow(() -> anchored().validateChainWithOcsp(chain(), null, false));
    }

    @ParameterizedTest(name = "пустое имя \"{0}\" -> CertificateException")
    @ValueSource(strings = {"", " ", "  \t"})
    @DisplayName("пустое имя - ошибка, а не пропуск сверки (с якорями и insecureTrustAll)")
    void blankHostnameRejected(String hostname) {
        GostX509TrustManager anchored = anchored();
        GostX509TrustManager insecure = GostX509TrustManager.insecureTrustAll();

        assertThrows(
                CertificateException.class,
                () -> anchored.validateChainWithOcsp(chain(), hostname, false));
        assertThrows(
                CertificateException.class,
                () -> insecure.validateChainWithOcsp(List.of(leaf.cert), hostname, false));
    }

    @Test
    @DisplayName("insecureTrustAll: имя проверяется, если задано, и не проверяется при null")
    void insecureTrustAllHostnameBehaviour() {
        GostX509TrustManager insecure = GostX509TrustManager.insecureTrustAll();

        assertDoesNotThrow(
                () -> insecure.validateChainWithOcsp(List.of(leaf.cert), CERT_HOST, false));
        assertThrows(
                CertificateException.class,
                () -> insecure.validateChainWithOcsp(List.of(leaf.cert), OTHER_HOST, false));
        assertDoesNotThrow(() -> insecure.validateChainWithOcsp(List.of(leaf.cert), null, false));
    }

    @Test
    @DisplayName("checkServerTrusted(chain, authType) без соединения работает без сверки имени")
    void checkServerTrustedWithoutConnectionWorks() throws Exception {
        X509Certificate[] jcaChain = CertificateBridge.toJca(chain());

        assertDoesNotThrow(() -> anchored().checkServerTrusted(jcaChain, "GOST"));
    }
}
