package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Лимит max_fragment_length (RFC 6066 §4) в сессии. Приём: запись с открытым текстом больше
 * согласованного лимита отвергается с record_overflow сразу после рукопожатия и после
 * KeyUpdate. Нарушителя изображает пир, у которого нарезка по лимиту отключена: AEAD не даёт
 * изменить запись на уровне транспорта. Отправка: после KeyUpdate обе стороны по-прежнему режут
 * данные по лимиту, а запись отправки сама отвергает фрагмент больше лимита.
 */
@DisplayName("TlsSession: лимит max_fragment_length")
class TlsSessionReceiveFragmentLimitTest {

    private static final int OVERSIZED_PAYLOAD = 2000;

    /** Клиент и сервер после рукопожатия с согласованным max_fragment_length = 512. */
    private static TlsSession[] connectedPairWithFragment512() throws Exception {
        return connectedPairWithFragment512(null, null);
    }

    /** То же, но отправленные клиентом и сервером записи копируются в переданные списки. */
    private static TlsSession[] connectedPairWithFragment512(
            List<byte[]> clientSent, List<byte[]> serverSent) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        var c2s = new LinkedBlockingQueue<byte[]>();
        var s2c = new LinkedBlockingQueue<byte[]>();
        InMemoryTlsTransport clientTransport =
                new InMemoryTlsTransport(s2c) {
                    @Override
                    public void sendRecord(byte[] record) {
                        if (clientSent != null) clientSent.add(record.clone());
                        c2s.add(record.clone());
                    }
                };
        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s) {
                    @Override
                    public void sendRecord(byte[] record) {
                        if (serverSent != null) serverSent.add(record.clone());
                        s2c.add(record.clone());
                    }
                };
        TlsSession server =
                TlsSession.createServer(serverTransport, suite, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(clientTransport, suite, null, null);
        client.setMaxFragmentLengthRequest(TlsConstants.MAX_FRAG_LEN_512);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> clientHandshake =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<?> serverHandshake =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientHandshake.get(15, TimeUnit.SECONDS);
            serverHandshake.get(15, TimeUnit.SECONDS);
        } finally {
            executor.shutdown();
        }
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, client.getMaxFragmentLength());
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, server.getMaxFragmentLength());
        return new TlsSession[] {client, server};
    }

    /** Клиент отправляет одной записью больше лимита: нарезку по лимиту он «забыл». */
    private static void sendOversizedRecord(TlsSession sender) throws Exception {
        sender.disableSendFragmentLimitForTest();
        sender.write(new byte[OVERSIZED_PAYLOAD]);
    }

    private static int alertOf(TlsSession receiver) {
        return assertThrows(
                        TlsException.class,
                        receiver::read,
                        "запись больше согласованного лимита должна быть отвергнута")
                .getAlertCode();
    }

    @Test
    @DisplayName("после рукопожатия: открытый текст больше лимита -> record_overflow")
    void oversizedRecordAfterHandshake() throws Exception {
        TlsSession[] pair = connectedPairWithFragment512();

        sendOversizedRecord(pair[0]);

        assertEquals(TlsConstants.ALERT_RECORD_OVERFLOW, alertOf(pair[1]));
    }

    @Test
    @DisplayName(
            "после KeyUpdate лимит на приём сохраняется: запись больше лимита -> record_overflow")
    void oversizedRecordAfterKeyUpdate() throws Exception {
        TlsSession[] pair = connectedPairWithFragment512();
        byte[] withinLimit =
                new byte[TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512) - 1];
        java.util.Arrays.fill(withinLimit, (byte) 0x41);

        pair[0].initiateKeyUpdate(false);
        pair[0].write(withinLimit);
        assertArrayEquals(
                withinLimit,
                pair[1].read(),
                "запись в пределах лимита после KeyUpdate читается как прежде");

        sendOversizedRecord(pair[0]);

        assertEquals(TlsConstants.ALERT_RECORD_OVERFLOW, alertOf(pair[1]));
    }

    /** Читает у получателя ровно {@code total} байт данных приложения. */
    private static byte[] readExactly(TlsSession receiver, int total) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (out.size() < total) {
            out.write(receiver.read());
        }
        return out.toByteArray();
    }

    /** Размеры шифртекста записей данных приложения, начиная с позиции {@code from} списка. */
    private static List<Integer> appRecordSizes(List<byte[]> sent, int from) {
        List<Integer> sizes = new ArrayList<>();
        for (byte[] record : sent.subList(from, sent.size())) {
            if ((record[0] & 0xFF) == TlsConstants.CT_APPLICATION_DATA) {
                sizes.add(record.length - TlsConstants.RECORD_HEADER_SIZE);
            }
        }
        return sizes;
    }

    private static void assertSentWithinLimit(String side, List<byte[]> sent, int from) {
        int tagLen = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getTagLen();
        int limit = TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512) + tagLen;
        List<Integer> sizes = appRecordSizes(sent, from);
        assertTrue(sizes.size() > 1, side + ": данные должны уйти несколькими записями: " + sizes);
        for (int size : sizes) {
            assertTrue(
                    size <= limit,
                    side + ": запись после KeyUpdate длиннее лимита: " + size + " > " + limit);
        }
    }

    @Test
    @DisplayName("после KeyUpdate обе стороны по-прежнему режут исходящие данные по лимиту")
    void sendIsFragmentedAfterKeyUpdateOnBothSides() throws Exception {
        List<byte[]> clientSent = new CopyOnWriteArrayList<>();
        List<byte[]> serverSent = new CopyOnWriteArrayList<>();
        TlsSession[] pair = connectedPairWithFragment512(clientSent, serverSent);
        byte[] payload = new byte[OVERSIZED_PAYLOAD];
        java.util.Arrays.fill(payload, (byte) 0x42);

        pair[0].initiateKeyUpdate(false);
        int clientFrom = clientSent.size();
        pair[0].write(payload);
        assertArrayEquals(payload, readExactly(pair[1], payload.length));
        assertSentWithinLimit("клиент", clientSent, clientFrom);

        pair[1].initiateKeyUpdate(false);
        int serverFrom = serverSent.size();
        pair[1].write(payload);
        assertArrayEquals(payload, readExactly(pair[0], payload.length));
        assertSentWithinLimit("сервер", serverSent, serverFrom);
    }

    @Test
    @DisplayName("после KeyUpdate запись отправки сама отвергает фрагмент больше лимита")
    void writerRecordRejectsOversizedFragmentAfterKeyUpdate() throws Exception {
        TlsSession[] pair = connectedPairWithFragment512();
        int limit = TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512);

        pair[0].initiateKeyUpdate(false);

        var writer = pair[0].writerRecordForTest();
        // Предел включительный: содержимое и байт типа вместе не больше лимита
        assertThrows(
                IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[limit]),
                "запись отправки после KeyUpdate должна отвергать фрагмент больше лимита");
        writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[limit - 1]);
    }
}
