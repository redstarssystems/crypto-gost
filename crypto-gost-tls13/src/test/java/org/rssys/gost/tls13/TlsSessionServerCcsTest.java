package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Серверный dummy change_cipher_spec (RFC 8446 §D.4) на уровне {@link TlsSession}: порядок
 * записей на проводе при непустом и пустом {@code legacy_session_id}.
 */
@DisplayName("TlsSession: dummy CCS сервера (RFC 8446 §D.4)")
class TlsSessionServerCcsTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    private static final byte[] SESSION_ID = new byte[32];
    private static final byte[] CCS_RECORD = {
        TlsConstants.CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01
    };
    private static final int[] ALL_GROUPS = {
        TlsConstants.GRP_GC256A,
        TlsConstants.GRP_GC256B,
        TlsConstants.GRP_GC256C,
        TlsConstants.GRP_GC256D,
        TlsConstants.GRP_GC512A,
        TlsConstants.GRP_GC512B,
        TlsConstants.GRP_GC512C
    };

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        for (int i = 0; i < SESSION_ID.length; i++) {
            SESSION_ID[i] = (byte) (i + 1);
        }
    }

    /** Шаг приёма: запись может зависеть от уже отправленного сервером (CH2 строится по HRR). */
    private interface IncomingStep {
        byte[] next(List<byte[]> sent) throws Exception;
    }

    /** Транспорт-заглушка: отдаёт записи по шагам, затем обрывает приём; отправленное копит. */
    private static final class ScriptedTransport implements TlsTransport {
        private final ArrayDeque<IncomingStep> incoming = new ArrayDeque<>();
        final List<byte[]> sent = new ArrayList<>();

        ScriptedTransport(IncomingStep... steps) {
            incoming.addAll(List.of(steps));
        }

        static ScriptedTransport single(byte[] firstRecord) {
            return new ScriptedTransport(sent -> firstRecord);
        }

        @Override
        public void sendRecord(byte[] record) {
            sent.add(record.clone());
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            IncomingStep step = incoming.poll();
            if (step == null) {
                throw new IOException("scripted transport: no more records");
            }
            try {
                return step.next(sent);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("scripted transport: step failed", e);
            }
        }

        @Override
        public void close() {}
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

    /** Прогоняет серверный handshake до обрыва приёма и возвращает всё отправленное. */
    private static List<byte[]> serverWire(byte[] clientHelloRecord) {
        return serverWire(ScriptedTransport.single(clientHelloRecord));
    }

    private static List<byte[]> serverWire(ScriptedTransport transport) {
        TlsSession server =
                TlsSession.createServer(
                        transport,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        serverCert.cert,
                        serverCert.priv);
        try {
            server.handshakeAsServer();
        } catch (Exception expected) {
            // handshake обрывается нарочно: после ответа на ClientHello приём пуст
        }
        return transport.sent;
    }

    private static long countCcs(List<byte[]> wire) {
        return wire.stream().filter(r -> r[0] == TlsConstants.CT_CHANGE_CIPHER_SPEC).count();
    }

    @Test
    @DisplayName("Непустой session id, ServerHello: SH, затем CCS, затем зашифрованные записи")
    void ccsFollowsServerHello() throws Exception {
        List<byte[]> wire = serverWire(clientHelloRecord(allShares(), SESSION_ID));

        assertTrue(wire.size() >= 3, "ожидались ServerHello, CCS и зашифрованный флайт");
        assertEquals(TlsConstants.CT_HANDSHAKE, wire.get(0)[0], "первым идёт ServerHello");
        assertArrayEquals(CCS_RECORD, wire.get(1), "сразу за ним dummy CCS");
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA, wire.get(2)[0], "далее зашифрованные записи");
        assertEquals(1, countCcs(wire), "CCS ровно один");
    }

    @Test
    @DisplayName("Непустой session id, HRR: HRR, затем CCS")
    void ccsFollowsHelloRetryRequest() throws Exception {
        // Пустой client_shares - запрос HRR (RFC 8446 §4.2.8)
        List<byte[]> wire = serverWire(clientHelloRecord(new LinkedHashMap<>(), SESSION_ID));

        assertTrue(wire.size() >= 2, "ожидались HRR и CCS");
        assertEquals(TlsConstants.CT_HANDSHAKE, wire.get(0)[0], "первым идёт HRR");
        assertArrayEquals(CCS_RECORD, wire.get(1), "сразу за ним dummy CCS");
        assertEquals(1, countCcs(wire), "CCS ровно один");
    }

    @Test
    @DisplayName("Пустой session id: CCS не отправляется")
    void noCcsWithEmptySessionId() throws Exception {
        List<byte[]> wire = serverWire(clientHelloRecord(allShares(), new byte[0]));

        assertTrue(wire.size() >= 2, "ожидался ответ сервера");
        assertEquals(0, countCcs(wire), "RFC 8446 §D.4: CCS только при непустом sid");
    }

    @Test
    @DisplayName("HRR -> CH2 -> ServerHello: на проводе ровно один CCS, сразу после HRR")
    void singleCcsAcrossHrrAndServerHello() throws Exception {
        ScriptedTransport transport =
                new ScriptedTransport(
                        sent -> clientHelloRecord(new LinkedHashMap<>(), SESSION_ID),
                        sent -> {
                            // CH2: одна запись группы, которую сервер запросил в HRR
                            byte[] hrrFrame =
                                    Arrays.copyOfRange(
                                            sent.get(0),
                                            TlsConstants.RECORD_HEADER_SIZE,
                                            sent.get(0).length);
                            int group =
                                    TlsMessageParser.parseServerHello(
                                                    TlsHandshakeMessage.decode(hrrFrame).getBody(),
                                                    SERVER_RESPONSE_TYPES_SENT)
                                            .requestedGroup;
                            Map<Integer, byte[]> one = new LinkedHashMap<>();
                            one.put(
                                    group,
                                    TlsEncoding.encodePoint(
                                            KeyGenerator.generateKeyPair(
                                                            TlsCiphersuite.namedGroupToParams(
                                                                    group))
                                                    .getPublic()));
                            return clientHelloRecord(one, SESSION_ID);
                        });

        List<byte[]> wire = serverWire(transport);

        assertTrue(wire.size() >= 4, "ожидались HRR, CCS, ServerHello и зашифрованный флайт");
        assertEquals(TlsConstants.CT_HANDSHAKE, wire.get(0)[0], "первым идёт HRR");
        assertArrayEquals(CCS_RECORD, wire.get(1), "CCS сразу после HRR");
        assertEquals(TlsConstants.CT_HANDSHAKE, wire.get(2)[0], "затем открытый ServerHello");
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA, wire.get(3)[0], "далее зашифрованные записи");
        assertEquals(1, countCcs(wire), "после ServerHello второй CCS не отправляется");
    }
}
