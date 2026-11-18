package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * Порядок выходного потока {@link TlsHandshakeEngine#poll()}: смена ключа записи стоит сразу за
 * сообщением, после которого она действует на проводе (RFC 8446 §4.1.3, §4.4.4, §4.6.3, §5.1).
 *
 * <p>Обозначения раскладки: {@code M<тип>} — сообщение рукопожатия, {@code K} — смена ключа
 * записи. Типы: 2 ServerHello (и HelloRetryRequest), 8 EncryptedExtensions, 11 Certificate,
 * 13 CertificateRequest, 15 CertificateVerify, 20 Finished, 24 KeyUpdate.
 */
@DisplayName("TlsHandshakeEngine: смены ключа записи в выходном потоке")
class TlsHandshakeEngineOutputStreamTest {

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int NAMED_GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;

    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle clientCert;

    @BeforeAll
    static void setUp() {
        serverCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
        clientCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsHandshakeEngine client(boolean withCert) {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        NAMED_GROUP,
                        SIG_SCHEME,
                        withCert ? clientCert.priv : null,
                        withCert ? List.of(clientCert.cert) : null,
                        HASH_LEN),
                EC_PARAMS,
                NAMED_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    private static TlsHandshakeEngine server(boolean requestClientAuth) {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        NAMED_GROUP,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN),
                EC_PARAMS,
                NAMED_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                requestClientAuth,
                null);
    }

    /** Сообщения потока без смен ключа (ключи в сменах затираются). */
    private static List<byte[]> messages(List<HandshakeOutput> stream) {
        List<byte[]> out = new ArrayList<>();
        for (HandshakeOutput item : stream) {
            if (item instanceof HandshakeOutput.Message message) {
                out.add(message.frame());
            } else {
                ((HandshakeOutput.WriteKeyChange) item).destroy();
            }
        }
        return out;
    }

    /** Подаёт сообщения пиру, применяя смены ключа чтения и подтверждая проверку сертификата. */
    private static void deliver(List<byte[]> frames, TlsHandshakeEngine to) throws Exception {
        for (byte[] frame : frames) {
            to.receive(frame);
            to.acknowledgeReadKeyChange();
            if (to.needsCertificateValidation()) {
                to.acknowledgeCertificateValidation(true);
            }
        }
    }

    /** Полное рукопожатие с заданной проверкой потоков на каждом шаге. */
    private static TlsHandshakeEngine[] handshake(
            boolean mtls, String serverFlight, String clientAfterServerHello, String clientFlight)
            throws Exception {
        TlsHandshakeEngine client = client(mtls);
        TlsHandshakeEngine server = server(mtls);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();

        List<HandshakeOutput> flight = HandshakeOutputs.drain(server);
        assertEquals(serverFlight, HandshakeOutputs.layout(flight), "поток сервера");
        List<byte[]> serverMessages = messages(flight);

        client.receive(serverMessages.get(0));
        assertTrue(client.hasReadKeysChanged(), "после ServerHello клиент читает новым ключом");
        client.acknowledgeReadKeyChange();
        List<HandshakeOutput> afterHello = HandshakeOutputs.drain(client);
        assertEquals(clientAfterServerHello, HandshakeOutputs.layout(afterHello));
        messages(afterHello);

        deliver(serverMessages.subList(1, serverMessages.size()), client);
        List<HandshakeOutput> answer = HandshakeOutputs.drain(client);
        assertEquals(clientFlight, HandshakeOutputs.layout(answer), "ответ клиента");
        assertTrue(client.isDone(), "клиент завершил рукопожатие после отдачи потока");

        deliver(messages(answer), server);
        assertTrue(server.isDone());
        return new TlsHandshakeEngine[] {client, server};
    }

    @Test
    @DisplayName("Полное рукопожатие: ServerHello, смена, полёт, смена; у клиента смена после SH")
    void fullHandshakeLayout() throws Exception {
        handshake(false, "M2 K M8 M11 M15 M20 K", "K", "M20 K");
    }

    @Test
    @DisplayName("mTLS: CertificateRequest в полёте сервера, смена ключа за Finished клиента")
    void mutualTlsLayout() throws Exception {
        handshake(true, "M2 K M8 M13 M11 M15 M20 K", "K", "M11 M15 M20 K");
    }

    @Test
    @DisplayName("PSK: ServerHello, смена, EncryptedExtensions и Finished, смена")
    void pskLayout() throws Exception {
        TlsHandshakeEngine client = client(false);
        byte[] pskKey = new byte[HASH_LEN];
        client.setPsk(pskKey, new byte[8], 42L);
        TlsHandshakeEngine server = server(false);
        server.setServerPsk(pskKey);

        server.receive(client.start());
        assertTrue(server.isPskAccepted(), "предусловие: PSK принят");
        assertEquals("M2 K M8 M20 K", HandshakeOutputs.layout(HandshakeOutputs.drain(server)));
    }

    @Test
    @DisplayName("HelloRetryRequest: смены ключа записи нет")
    void helloRetryRequestHasNoKeyChange() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                TlsConstants.GRP_GC256A,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        ECParameters.tc26a256(),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                TlsConstants.GRP_GC256B,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        ECParameters.cryptoProA(),
                        TlsConstants.GRP_GC256B,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        server.receive(client.start());
        assertFalse(server.hasReadKeysChanged(), "после HRR ключ чтения не меняется");
        assertEquals("M2", HandshakeOutputs.layout(HandshakeOutputs.drain(server)));
    }

    @Test
    @DisplayName("Ключ чтения клиента меняется при приёме Finished сервера, а не при отдаче своего")
    void clientReadKeyChangesOnServerFinished() throws Exception {
        TlsHandshakeEngine client = client(false);
        TlsHandshakeEngine server = server(false);
        server.receive(client.start());
        List<byte[]> flight = messages(HandshakeOutputs.drain(server));
        deliver(flight.subList(0, flight.size() - 1), client);
        messages(HandshakeOutputs.drain(client));

        client.receive(flight.get(flight.size() - 1));
        assertTrue(
                client.hasReadKeysChanged(),
                "за Finished сервера идут его данные: читать ключом приложения сразу");
    }

    @Test
    @DisplayName("Ключ чтения сервера меняется на Finished клиента, ключ записи — раньше")
    void serverReadKeyChangesOnClientFinished() throws Exception {
        TlsHandshakeEngine client = client(false);
        TlsHandshakeEngine server = server(false);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        List<byte[]> flight = messages(HandshakeOutputs.drain(server));
        deliver(flight, client);
        List<byte[]> answer = messages(HandshakeOutputs.drain(client));

        server.receive(answer.get(0));
        assertTrue(server.hasReadKeysChanged(), "после Finished клиента читать ключом приложения");
        assertNull(server.poll(), "ключ записи сменился раньше, в конце полёта сервера");
    }

    @Test
    @DisplayName("KeyUpdate: сообщение, затем смена; второй вызов до отдачи объединяется с первым")
    void keyUpdateLayout() throws Exception {
        TlsHandshakeEngine client = handshake(false, "M2 K M8 M11 M15 M20 K", "K", "M20 K")[0];

        client.initiateKeyUpdate(false);
        // Второе обновление вывелось бы из того же секрета: вызов объединяется со стоящим, а запрос
        // ответа повышает его, а не теряется
        client.initiateKeyUpdate(true);
        List<HandshakeOutput> stream = HandshakeOutputs.drain(client);
        assertEquals("M24 K", HandshakeOutputs.layout(stream), "одно обновление");
        byte[] keyUpdate = ((HandshakeOutput.Message) stream.get(0)).frame();
        assertEquals(
                TlsConstants.KEY_UPDATE_REQUESTED,
                keyUpdate[TlsConstants.HANDSHAKE_HEADER_SIZE],
                "запрос ответа не потерян");
        ((HandshakeOutput.WriteKeyChange) stream.get(1)).destroy();

        client.initiateKeyUpdate(false);
        assertEquals(
                "M24 K",
                HandshakeOutputs.layout(HandshakeOutputs.drain(client)),
                "после отдачи потока следующее обновление ставится заново");
    }

    @Test
    @DisplayName("Смены ключа в потоке несут разные ключи: эпохи не совпадают")
    void keyChangesCarryDistinctKeys() throws Exception {
        TlsHandshakeEngine client = client(false);
        TlsHandshakeEngine server = server(false);
        server.receive(client.start());
        List<byte[]> keys = new ArrayList<>();
        for (HandshakeOutput item : HandshakeOutputs.drain(server)) {
            if (item instanceof HandshakeOutput.WriteKeyChange change) {
                keys.add(change.keys().getKey());
                change.destroy();
            }
        }
        assertEquals(2, keys.size(), "ключи рукопожатия и ключи приложения");
        assertFalse(java.util.Arrays.equals(keys.get(0), keys.get(1)), "эпохи различны");
    }

    @Test
    @DisplayName("destroy затирает ключи в неотданных сменах потока и ключи чтения приложения")
    void destroyWipesQueuedKeyChangesAndPendingReadKeys() throws Exception {
        TlsHandshakeEngine client = client(false);
        TlsHandshakeEngine server = server(false);
        server.receive(client.start());
        // Отданы только ServerHello и EncryptedExtensions: дальше в потоке ещё две смены ключа
        server.poll();
        List<TlsTrafficKeys> queued = queuedKeys(server);
        assertFalse(queued.isEmpty(), "предусловие: в потоке стоят смены ключа");
        TlsTrafficKeys pendingRead = (TlsTrafficKeys) field(server, "readKeysAfterPeerFinished");

        server.destroy();

        for (TlsTrafficKeys keys : queued) {
            assertArrayEquals(
                    new byte[keys.getKey().length], keys.getKey(), "ключ в потоке затёрт");
        }
        assertArrayEquals(
                new byte[pendingRead.getKey().length],
                pendingRead.getKey(),
                "ключ чтения приложения, не дождавшийся Finished клиента, затёрт");
        assertNull(field(server, "serverAppTrafficSecret"), "секрет трафика приложения затёрт");
    }

    @Test
    @DisplayName("toString смены ключа не раскрывает ключи")
    void keyChangeToStringHidesKeys() throws Exception {
        TlsHandshakeEngine client = client(false);
        TlsHandshakeEngine server = server(false);
        server.receive(client.start());
        for (HandshakeOutput item : HandshakeOutputs.drain(server)) {
            if (item instanceof HandshakeOutput.WriteKeyChange change) {
                assertEquals("WriteKeyChange", change.toString());
                change.destroy();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static List<TlsTrafficKeys> queuedKeys(TlsHandshakeEngine engine) throws Exception {
        List<TlsTrafficKeys> keys = new ArrayList<>();
        for (HandshakeOutput item : (Deque<HandshakeOutput>) field(engine, "outgoingQueue")) {
            if (item instanceof HandshakeOutput.WriteKeyChange change) {
                keys.add(change.keys());
            }
        }
        return keys;
    }

    private static Object field(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }
}
