package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Dummy change_cipher_spec серверного {@link GostSSLEngine} (RFC 8446 §D.4): порядок записей в
 * {@code wrap} при непустом и пустом {@code legacy_session_id}, поведение при нехватке места.
 */
@DisplayName("GostSSLEngine: dummy CCS сервера (RFC 8446 §D.4)")
class GostSSLEngineMiddleboxCcsTest {

    private static final byte[] CCS_RECORD = {
        TlsConstants.CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01
    };
    private static final byte[] SESSION_ID = new byte[32];
    private static final int[] ALL_GROUPS = {
        TlsConstants.GRP_GC256A,
        TlsConstants.GRP_GC256B,
        TlsConstants.GRP_GC256C,
        TlsConstants.GRP_GC256D,
        TlsConstants.GRP_GC512A,
        TlsConstants.GRP_GC512B,
        TlsConstants.GRP_GC512C
    };
    private static final int BIG_BUFFER =
            TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM;

    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        for (int i = 0; i < SESSION_ID.length; i++) {
            SESSION_ID[i] = (byte) (i + 1);
        }
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
    }

    private static Map<Integer, byte[]> allShares() throws Exception {
        Map<Integer, byte[]> m = new LinkedHashMap<>();
        for (int g : ALL_GROUPS) {
            m.put(
                    g,
                    TlsEncoding.encodePoint(
                            KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(g))
                                    .getPublic()));
        }
        return m;
    }

    private static byte[] clientHelloRecord(Map<Integer, byte[]> keyShares, byte[] sessionId)
            throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs,
                        List.of(cs.getId()),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        null,
                        null,
                        32);
        TlsMessageBuilderTestAccess.setSupportedGroups(b, ALL_GROUPS);
        byte[] body =
                TlsMessageBuilderTestAccess.withLegacySessionId(
                        b.buildClientHello(keyShares, "localhost"), sessionId);
        return TlsMessageBuilder.buildPlaintextRecord(
                TlsConstants.CT_HANDSHAKE,
                new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body).encode());
    }

    /** Серверный engine, принявший ClientHello и готовый отдать ответ в {@code wrap}. */
    private static GostSSLEngine serverAfterClientHello(byte[] clientHelloRecord) throws Exception {
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        SSLEngineResult r =
                server.unwrap(
                        ByteBuffer.wrap(clientHelloRecord),
                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "ClientHello принят");
        Runnable task;
        while ((task = server.getDelegatedTask()) != null) {
            task.run();
        }
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_WRAP, server.getHandshakeStatus());
        return server;
    }

    /** Разбирает буфер на TLS-записи (заголовок + тело). */
    private static List<byte[]> records(ByteBuffer flipped) {
        List<byte[]> out = new ArrayList<>();
        while (flipped.remaining() >= TlsConstants.RECORD_HEADER_SIZE) {
            int len =
                    ((flipped.get(flipped.position() + 3) & 0xFF) << 8)
                            | (flipped.get(flipped.position() + 4) & 0xFF);
            byte[] rec = new byte[TlsConstants.RECORD_HEADER_SIZE + len];
            flipped.get(rec);
            out.add(rec);
        }
        return out;
    }

    private static List<byte[]> wrapOnce(GostSSLEngine server, int capacity) throws Exception {
        ByteBuffer dst = ByteBuffer.allocate(capacity);
        SSLEngineResult r = server.wrap(ByteBuffer.allocate(0), dst);
        assertEquals(SSLEngineResult.Status.OK, r.getStatus());
        assertEquals(dst.position(), r.bytesProduced(), "bytesProduced учитывает и CCS");
        dst.flip();
        return records(dst);
    }

    @Test
    @DisplayName("Непустой session id, HRR: в wrap сначала HRR, затем CCS")
    void ccsFollowsHelloRetryRequest() throws Exception {
        GostSSLEngine server =
                serverAfterClientHello(clientHelloRecord(new LinkedHashMap<>(), SESSION_ID));

        List<byte[]> wire = wrapOnce(server, BIG_BUFFER);

        assertEquals(2, wire.size(), "ожидались HRR и CCS");
        assertEquals(TlsConstants.CT_HANDSHAKE, wire.get(0)[0], "первым идёт HRR");
        assertArrayEquals(CCS_RECORD, wire.get(1), "сразу за ним dummy CCS");
    }

    @Test
    @DisplayName("Непустой session id, ServerHello: SH, затем CCS; следующий wrap без CCS")
    void ccsFollowsServerHello() throws Exception {
        GostSSLEngine server = serverAfterClientHello(clientHelloRecord(allShares(), SESSION_ID));

        List<byte[]> first = wrapOnce(server, BIG_BUFFER);
        assertEquals(2, first.size(), "ожидались ServerHello и CCS");
        assertEquals(TlsConstants.CT_HANDSHAKE, first.get(0)[0], "первым идёт ServerHello");
        assertArrayEquals(CCS_RECORD, first.get(1), "сразу за ним dummy CCS");

        // Остальной флайт зашифрован, CCS в нём нет
        List<byte[]> rest = wrapOnce(server, BIG_BUFFER);
        assertTrue(
                rest.stream().noneMatch(r -> r[0] == TlsConstants.CT_CHANGE_CIPHER_SPEC),
                "второй CCS не отправляется");
    }

    @Test
    @DisplayName("Пустой session id: CCS не отправляется")
    void noCcsWithEmptySessionId() throws Exception {
        GostSSLEngine server = serverAfterClientHello(clientHelloRecord(allShares(), new byte[0]));

        List<byte[]> wire = wrapOnce(server, BIG_BUFFER);

        assertEquals(1, wire.size(), "только ServerHello");
        assertEquals(TlsConstants.CT_HANDSHAKE, wire.get(0)[0]);
    }

    @Test
    @DisplayName(
            "Места хватает на ServerHello, но не на CCS: BUFFER_OVERFLOW, повтор даёт один CCS")
    void overflowThenRetryYieldsSingleCcs() throws Exception {
        byte[] ch = clientHelloRecord(new LinkedHashMap<>(), SESSION_ID);
        // Размер HRR без CCS узнаём на эталонном движке
        int hrrLength = wrapOnce(serverAfterClientHello(ch), BIG_BUFFER).get(0).length;

        GostSSLEngine server = serverAfterClientHello(ch);
        ByteBuffer tooSmall = ByteBuffer.allocate(hrrLength);
        SSLEngineResult overflow = server.wrap(ByteBuffer.allocate(0), tooSmall);
        assertEquals(
                SSLEngineResult.Status.BUFFER_OVERFLOW,
                overflow.getStatus(),
                "записи вместе с CCS нет места");
        assertEquals(0, tooSmall.position(), "при BUFFER_OVERFLOW ничего не записано");

        List<byte[]> wire = wrapOnce(server, BIG_BUFFER);
        assertEquals(2, wire.size(), "после повтора HRR и ровно один CCS");
        assertArrayEquals(CCS_RECORD, wire.get(1));
    }

    @Test
    @DisplayName("HRR -> CH2 -> ServerHello: на проводе ровно один CCS, сразу после HRR")
    void singleCcsAcrossHrrAndServerHello() throws Exception {
        GostSSLEngine server =
                serverAfterClientHello(clientHelloRecord(new LinkedHashMap<>(), SESSION_ID));
        List<byte[]> first = wrapOnce(server, BIG_BUFFER);
        assertEquals(2, first.size(), "ожидались HRR и CCS");
        assertArrayEquals(CCS_RECORD, first.get(1), "CCS сразу после HRR");

        // CH2: одна запись группы, которую сервер запросил в HRR
        byte[] hrrFrame =
                Arrays.copyOfRange(
                        first.get(0), TlsConstants.RECORD_HEADER_SIZE, first.get(0).length);
        int group =
                TlsMessageParser.parseServerHello(
                                TlsHandshakeMessage.decode(hrrFrame).getBody(),
                                // первый ClientHello отправил именно эти типы расширений
                                Set.of(
                                        TlsConstants.EXT_SUPPORTED_VERSIONS,
                                        TlsConstants.EXT_KEY_SHARE))
                        .requestedGroup;
        Map<Integer, byte[]> one = new LinkedHashMap<>();
        one.put(group, allShares().get(group));
        SSLEngineResult r =
                server.unwrap(
                        ByteBuffer.wrap(clientHelloRecord(one, SESSION_ID)),
                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "CH2 принят");
        Runnable task;
        while ((task = server.getDelegatedTask()) != null) {
            task.run();
        }

        List<byte[]> second = wrapOnce(server, BIG_BUFFER);
        assertEquals(
                TlsConstants.CT_HANDSHAKE, second.get(0)[0], "после CH2 идёт открытый ServerHello");
        assertTrue(
                second.stream().noneMatch(rec -> rec[0] == TlsConstants.CT_CHANGE_CIPHER_SPEC),
                "после ServerHello второй CCS не отправляется");
    }
}
