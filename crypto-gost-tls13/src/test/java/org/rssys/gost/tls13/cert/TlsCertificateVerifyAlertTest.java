package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Проверка подписи CertificateVerify (RFC 8446 §4.4.3): корректная подпись принимается, а любое
 * её расхождение (испорченная подпись, чужой транскрипт, чужая роль) - {@code decrypt_error}, а не
 * {@code bad_certificate}: сам сертификат может быть в порядке, не сошлась подпись рукопожатия.
 */
@DisplayName("TlsCertificateValidator.verifyCertificateVerify: алерт при неверной подписи")
class TlsCertificateVerifyAlertTest {

    private static final int HASH_LEN = TlsConstants.STREEBOG_256_HASH_LEN;
    private static PkixCertTestHelper.CertBundle bundle;
    private static TlsMessageBuilder signer;

    @BeforeAll
    static void setUp() {
        bundle = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        signer =
                new TlsMessageBuilder(
                        suite,
                        List.of(suite.getId()),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        bundle.priv,
                        List.of(bundle.cert),
                        HASH_LEN);
    }

    private static byte[] transcript() {
        byte[] hash = new byte[HASH_LEN];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = (byte) (i + 1);
        }
        return hash;
    }

    private static String context(boolean isServer) {
        return isServer
                ? TlsConstants.SERVER_CERTIFICATE_VERIFY_CTX
                : TlsConstants.CLIENT_CERTIFICATE_VERIFY_CTX;
    }

    private static void assertDecryptError(byte[] cvBody, byte[] transcript, boolean isServer) {
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.verifyCertificateVerify(
                                        cvBody, bundle.cert, transcript, isServer),
                        "неверная подпись должна отвергаться");
        assertEquals(
                TlsConstants.ALERT_DECRYPT_ERROR,
                ex.getAlertCode(),
                "RFC 8446 §4.4.3: неверная подпись CertificateVerify - decrypt_error");
    }

    @Test
    @DisplayName("Верная подпись принимается в обеих ролях")
    void validSignatureIsAccepted() {
        for (boolean isServer : new boolean[] {true, false}) {
            byte[] cvBody = signer.buildCertificateVerify(transcript(), context(isServer));
            assertDoesNotThrow(
                    () ->
                            TlsCertificateValidator.verifyCertificateVerify(
                                    cvBody, bundle.cert, transcript(), isServer),
                    "верная подпись должна приниматься, роль сервера: " + isServer);
        }
    }

    @Test
    @DisplayName("Испорченная подпись: decrypt_error для сервера и для клиента")
    void corruptedSignatureGivesDecryptError() {
        for (boolean isServer : new boolean[] {true, false}) {
            byte[] cvBody = signer.buildCertificateVerify(transcript(), context(isServer));
            cvBody[cvBody.length - 1] ^= 0x01;
            assertDecryptError(cvBody, transcript(), isServer);
        }
    }

    @Test
    @DisplayName("Подпись над чужим транскриптом: decrypt_error")
    void signatureOverOtherTranscriptGivesDecryptError() {
        byte[] cvBody = signer.buildCertificateVerify(transcript(), context(true));
        byte[] otherTranscript = transcript();
        otherTranscript[0] ^= 0x01;

        assertDecryptError(cvBody, otherTranscript, true);
    }

    @Test
    @DisplayName("Подпись серверного контекста, проверяемая как клиентская: decrypt_error")
    void signatureOfOtherRoleGivesDecryptError() {
        byte[] serverCv = signer.buildCertificateVerify(transcript(), context(true));
        byte[] clientCv = signer.buildCertificateVerify(transcript(), context(false));

        assertDecryptError(serverCv, transcript(), false);
        assertDecryptError(clientCv, transcript(), true);
    }
}
