package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Признак dummy change_cipher_spec сервера (RFC 8446 §D.4): взводится на первом ClientHello с
 * непустым {@code legacy_session_id}, отдаётся один раз и не взводится повторно после HRR.
 */
@DisplayName("TlsHandshakeEngine: признак dummy CCS сервера (RFC 8446 §D.4)")
class TlsHandshakeEngineServerCcsTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    private static final byte[] SESSION_ID = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32
    };

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsHandshakeEngine server(int preferredGroup) {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        preferredGroup,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN),
                TlsCiphersuite.namedGroupToParams(preferredGroup),
                preferredGroup,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    private static Map<Integer, byte[]> shares(int... groups) throws Exception {
        Map<Integer, byte[]> m = new LinkedHashMap<>();
        for (int g : groups) {
            m.put(
                    g,
                    TlsEncoding.encodePoint(
                            KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(g))
                                    .getPublic()));
        }
        return m;
    }

    /** Кадр ClientHello с заданным legacy_session_id (пустой массив - штатный клиент). */
    private static byte[] clientHello(
            int[] supportedGroups, Map<Integer, byte[]> keyShares, byte[] sessionId)
            throws Exception {
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);
        TlsMessageBuilderTestAccess.setSupportedGroups(b, supportedGroups);
        byte[] body =
                TlsMessageBuilderTestAccess.withLegacySessionId(
                        b.buildClientHello(keyShares, "localhost"), sessionId);
        return new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body).encode();
    }

    private static boolean isHrr(TlsHandshakeEngine server) throws Exception {
        byte[] frame = HandshakeOutputs.nextMessage(server);
        assertNotNull(frame, "сервер обязан ответить ServerHello или HRR");
        return TlsMessageParser.isHelloRetryRequest(
                TlsMessageParser.parseServerHello(
                        TlsHandshakeMessage.decode(frame).getBody(), SERVER_RESPONSE_TYPES_SENT));
    }

    @Test
    @DisplayName("Непустой session id, ServerHello без HRR: признак взведён и отдаётся один раз")
    void pendingWithSessionIdAndServerHello() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B},
                        shares(TlsConstants.GRP_GC256B),
                        SESSION_ID));

        assertTrue(s.isServerCompatCcsPending(), "CCS нужен: session id непустой");
        assertTrue(s.takeServerCompatCcs(), "первый take отдаёт признак");
        assertFalse(s.isServerCompatCcsPending(), "после take признак сброшен");
        assertFalse(s.takeServerCompatCcs(), "повторный take - false");
    }

    @Test
    @DisplayName("Пустой session id: dummy CCS не нужен")
    void notPendingWithEmptySessionId() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B},
                        shares(TlsConstants.GRP_GC256B),
                        new byte[0]));

        assertFalse(s.isServerCompatCcsPending(), "RFC 8446 §D.4: CCS только при непустом sid");
        assertFalse(s.takeServerCompatCcs());
    }

    @Test
    @DisplayName("HRR: признак взведён на CH1, после take не взводится повторно на CH2")
    void notRearmedOnSecondClientHelloAfterHrr() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);
        int[] groups = {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C};

        s.receive(clientHello(groups, shares(TlsConstants.GRP_GC256B), SESSION_ID));
        assertTrue(isHrr(s), "сервер должен запросить GC512C");
        assertTrue(s.isServerCompatCcsPending(), "CCS идёт после HRR");
        assertTrue(s.takeServerCompatCcs());

        s.receive(clientHello(groups, shares(TlsConstants.GRP_GC512C), SESSION_ID));
        assertFalse(isHrr(s), "второй ответ - ServerHello");
        assertFalse(s.isServerCompatCcsPending(), "после ServerHello второй CCS не отправляется");
    }
}
