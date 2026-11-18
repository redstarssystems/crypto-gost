package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.cert.TlsCertUtils;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Схема подписи клиента при mTLS (RFC 8446 §4.4.3, §4.4.2.3): CertificateVerify допустим только
 * схемой из {@code signature_algorithms} запроса сервера, иначе клиент отправляет пустой
 * Certificate. Наш сервер всегда присылает все семь схем, поэтому ветка недостижима через него:
 * запрос подменяется синтетическим.
 */
@DisplayName("TlsHandshakeEngine: схема подписи клиента из CertificateRequest")
class TlsHandshakeEngineClientSchemesTest {

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int NAMED_GROUP = TlsConstants.GRP_GC256A;
    // Схема ключа клиентского сертификата (кривая tc26a256)
    private static final int LEAF_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    private static final int ECDSA_P256 = 0x0403;

    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle clientCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
        clientCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsMessageBuilder builder(boolean server) {
        PkixCertTestHelper.CertBundle bundle = server ? serverCert : clientCert;
        return new TlsMessageBuilder(
                cs(),
                List.of(cs().getId()),
                NAMED_GROUP,
                LEAF_SCHEME,
                bundle.priv,
                List.of(bundle.cert),
                HASH_LEN);
    }

    private static TlsHandshakeEngine engine(TlsHandshakeEngine.Role role, boolean requestAuth) {
        boolean server = role == TlsHandshakeEngine.Role.SERVER;
        return new TlsHandshakeEngine(
                role,
                cs(),
                builder(server),
                EC_PARAMS,
                NAMED_GROUP,
                LEAF_SCHEME,
                HASH_LEN,
                null,
                requestAuth,
                null);
    }

    /** CertificateRequest как handshake-кадр: пустой контекст и только signature_algorithms. */
    private static byte[] certificateRequestFrame(int... schemes) {
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        ext.write(TlsConstants.EXT_SIGNATURE_ALGORITHMS >>> 8);
        ext.write(TlsConstants.EXT_SIGNATURE_ALGORITHMS);
        int listLength = 2 * schemes.length;
        ext.write((listLength + 2) >>> 8);
        ext.write(listLength + 2);
        ext.write(listLength >>> 8);
        ext.write(listLength);
        for (int scheme : schemes) {
            ext.write(scheme >>> 8);
            ext.write(scheme);
        }
        byte[] extensions = ext.toByteArray();
        int bodyLength = 1 + 2 + extensions.length;
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.write(TlsConstants.HT_CERTIFICATE_REQUEST);
        frame.write(bodyLength >>> 16);
        frame.write(bodyLength >>> 8);
        frame.write(bodyLength);
        frame.write(0);
        frame.write(extensions.length >>> 8);
        frame.write(extensions.length);
        frame.writeBytes(extensions);
        return frame.toByteArray();
    }

    /** Клиент, получивший вместо настоящего CertificateRequest синтетический. */
    private static TlsHandshakeEngine clientAfterRequest(int... schemes) throws Exception {
        TlsHandshakeEngine client = engine(TlsHandshakeEngine.Role.CLIENT, false);
        TlsHandshakeEngine server = engine(TlsHandshakeEngine.Role.SERVER, true);
        server.receive(client.start());
        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.receive(certificateRequestFrame(schemes));
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE, client.getState());
        return client;
    }

    @SuppressWarnings("unchecked")
    private static List<GostCertificate> chainOf(TlsHandshakeEngine client) throws Exception {
        java.lang.reflect.Field field = TlsHandshakeEngine.class.getDeclaredField("messageBuilder");
        field.setAccessible(true);
        return ((TlsMessageBuilder) field.get(client)).getCertificateChain();
    }

    @Test
    @DisplayName("схема ключа клиента в списке сервера: сертификат отправляется")
    void offeredSchemeKeepsCertificate() throws Exception {
        TlsHandshakeEngine client = clientAfterRequest(ECDSA_P256, LEAF_SCHEME);

        List<GostCertificate> chain = chainOf(client);

        assertNotNull(chain, "Схема предложена: цепочка клиента остаётся");
        assertFalse(chain.isEmpty());
    }

    @Test
    @DisplayName("в списке только чужая кривая ГОСТ: пустой Certificate, без ошибки разбора")
    void foreignGostCurveGivesEmptyCertificate() throws Exception {
        // раньше парсер бросал handshake_failure, хотя RFC 8446 §4.4.2.3 велит пустой Certificate
        TlsHandshakeEngine client =
                clientAfterRequest(
                        TlsConstants.SIG_GOST_TC26_512_A, TlsConstants.SIG_GOST_CRYPTOPRO_A);

        assertNull(chainOf(client), "Схема ключа клиента не предложена: цепочка не отправляется");
    }

    @Test
    @DisplayName("в списке только не-ГОСТ схемы: пустой Certificate")
    void nonGostSchemesGiveEmptyCertificate() throws Exception {
        TlsHandshakeEngine client = clientAfterRequest(ECDSA_P256, 0x0804, 0x0805);

        assertNull(chainOf(client));
    }

    @Test
    @DisplayName("код схемы-псевдонима (base-код другой кривой) схемой ключа не считается")
    void aliasCodeIsNotTheLeafScheme() throws Exception {
        // ключ на tc26a256 (0x0709); в списке base-код 512-битных кривых и CryptoPro-A: совпадения
        // нет
        TlsHandshakeEngine client =
                clientAfterRequest(
                        TlsConstants.SIG_GOST_TC26_512_A, TlsConstants.SIG_GOST_CRYPTOPRO_B);

        assertNull(chainOf(client));
    }

    // ------------------------------------------------------------ подписи цепочки

    private static List<GostCertificate> chainSigned512By(PkixCertTestHelper.CertBundle root)
            throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        return List.of(leaf.cert, root.cert);
    }

    @Test
    @DisplayName(
            "подпись листа ключом 512-битного CA не в списке: схема попадает в список замечаний")
    void chainSignatureSchemeNotOffered() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a512());
        List<GostCertificate> chain = chainSigned512By(root);

        List<Integer> unoffered =
                TlsCertUtils.unofferedChainSchemes(chain, new int[] {LEAF_SCHEME});

        assertEquals(List.of(TlsConstants.SIG_GOST_TC26_512_A), unoffered);
    }

    @Test
    @DisplayName("подпись цепочки в списке: замечаний нет")
    void chainSignatureSchemeOffered() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a512());
        List<GostCertificate> chain = chainSigned512By(root);

        assertTrue(
                TlsCertUtils.unofferedChainSchemes(
                                chain, new int[] {LEAF_SCHEME, TlsConstants.SIG_GOST_TC26_512_A})
                        .isEmpty());
    }

    @Test
    @DisplayName(
            "одиночный сертификат и самоподписанный якорь не проверяются: издателя в цепочке нет")
    void trustAnchorAndSingleCertificateAreNotChecked() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a512());

        assertTrue(
                TlsCertUtils.unofferedChainSchemes(List.of(root.cert), new int[] {LEAF_SCHEME})
                        .isEmpty(),
                "Самоподписанный корень единственный в цепочке: подпись не сверяется");
        assertTrue(
                TlsCertUtils.unofferedChainSchemes(
                                List.of(clientCert.cert), new int[] {LEAF_SCHEME})
                        .isEmpty());
    }
}
