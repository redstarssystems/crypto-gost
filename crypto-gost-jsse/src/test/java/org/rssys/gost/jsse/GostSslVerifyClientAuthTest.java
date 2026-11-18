package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Security;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * {@link GostSsl#verify}: проверка mTLS обязана проверять и сертификат клиента. Без запроса
 * сертификата сервером цепочка клиента не проверялась бы, и verify() подтверждал бы mTLS с любым
 * клиентским сертификатом.
 */
@DisplayName("GostSsl.verify: сервер проверяет сертификат клиента")
class GostSslVerifyClientAuthTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle foreignRoot;
    private static PkixCertTestHelper.CertBundle server;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        foreignRoot = PkixCertTestHelper.createRootCA(PARAMS);
        server = leaf(root, new String[] {"localhost"});
    }

    private static PkixCertTestHelper.CertBundle leaf(
            PkixCertTestHelper.CertBundle issuer, String[] dns) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                dns,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static String keyPem(PrivateKeyParameters key) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(GostDerCodec.encodePrivateKey(key))
                + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    @DisplayName("Сертификат клиента выпущен доверенным корнем: проверка проходит")
    void trustedClientCertificatePasses() throws Exception {
        PkixCertTestHelper.CertBundle client = leaf(root, null);
        assertDoesNotThrow(
                () ->
                        GostSsl.verify(
                                server.cert.toPem(),
                                keyPem(server.priv),
                                client.cert.toPem(),
                                keyPem(client.priv),
                                root.cert.toPem()));
    }

    @Test
    @DisplayName("Сертификат клиента вне доверия: проверка mTLS отказывает")
    void untrustedClientCertificateFails() throws Exception {
        PkixCertTestHelper.CertBundle client = leaf(foreignRoot, null);
        assertThrows(
                GostSslException.class,
                () ->
                        GostSsl.verify(
                                server.cert.toPem(),
                                keyPem(server.priv),
                                client.cert.toPem(),
                                keyPem(client.priv),
                                root.cert.toPem()),
                "клиентская цепочка не проверена: verify() не может подтвердить mTLS");
    }
}
