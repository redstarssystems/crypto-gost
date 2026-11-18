package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.testkit.GostTestCerts;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * PEM в {@link GostSsl}: доверенные CA принимаются набором корней, а собственный сертификат
 * ровно одним блоком (файл цепочки там отвергается, а не читается как одиночный сертификат).
 */
@DisplayName("GostSsl: набор CA в PEM и один блок для сертификата")
class GostSslPemCaSetTest {

    private static String rootOne;
    private static String rootTwo;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        GostCertificate first = PkixCertTestHelper.createRootCA(params).cert;
        GostCertificate second = PkixCertTestHelper.createRootCA(params).cert;
        rootOne = first.toPem();
        rootTwo = second.toPem();
    }

    @Test
    @DisplayName("clientContext(caPem): набор из двух корней принимается целиком")
    void caPemMayContainSeveralRoots() {
        SSLContext context = GostSsl.clientContext(rootOne + rootTwo);
        assertNotNull(context, "контекст с двумя доверенными корнями должен собираться");
    }

    @Test
    @DisplayName("Набор корней: сервер, выпущенный вторым корнем, принимается клиентом")
    void serverIssuedBySecondRootIsTrusted() throws Exception {
        GostTestCerts.CertChain first = GostTestCerts.createServerCert();
        GostTestCerts.CertChain second = GostTestCerts.createServerCert();
        String roots = first.caCert().toPem() + second.caCert().toPem();
        String keyPem = pemEncode(GostDerCodec.encodePrivateKey(second.key()));

        // loopback-рукопожатие: клиент доверяет обоим корням, сервер выпущен вторым
        assertDoesNotThrow(
                () -> GostSsl.verifyServer(second.chain().get(0).toPem(), keyPem, roots),
                "второй корень набора не должен теряться при разборе PEM");
    }

    @Test
    @DisplayName("builder.trustCa: данные без сертификата отвергаются сразу, а не при сборке")
    void builderRejectsGarbageImmediately() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSsl.builder().trustCa(new byte[0]),
                "пустые данные не сертификат");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSsl.builder().trustCa("не сертификат".getBytes(StandardCharsets.UTF_8)),
                "произвольные байты не сертификат");
    }

    private static String pemEncode(byte[] der) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    @DisplayName("clientContext(caPem): один корень по-прежнему принимается")
    void caPemSingleRootStillAccepted() {
        assertNotNull(GostSsl.clientContext(rootOne));
    }

    @Test
    @DisplayName("PEM без сертификатов отвергается")
    void caPemWithoutCertificatesRejected() {
        assertThrows(IllegalArgumentException.class, () -> GostSsl.clientContext("не PEM"));
    }
}
