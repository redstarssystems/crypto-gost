package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Контракт {@code SSLEngine.unwrap} при нехватке места в буферах приёмника: запись TLS принимается
 * целиком или не принимается совсем, движок не хранит открытый текст между вызовами.
 */
@DisplayName("GostSSLEngine: unwrap при нехватке места в буферах приёмника")
class GostSSLEngineUnwrapCapacityTest {

    /** Размер, который Undertow/XNIO даёт под открытый текст: меньше полной записи. */
    private static final int SMALL_DST_SIZE = 16364;

    private static final int FULL_RECORD_PLAINTEXT = TlsConstants.MAX_PLAINTEXT_LENGTH - 1;

    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        serverKm = EngineServerPki.create().serverKm();
    }

    @Test
    @DisplayName(
            "Мало места: BUFFER_OVERFLOW, ничего не потреблено; с большим буфером запись целая")
    void insufficientSpaceReturnsOverflowAndRecordIsRetriedWhole() throws Exception {
        Connected c = connect();
        byte[] first = pattern(FULL_RECORD_PLAINTEXT, 1);
        byte[] second = pattern(500, 2);
        ByteBuffer net = encrypt(c.client, first, second);
        int firstRecordEnd = recordLength(net, 0);
        int netBefore = net.position();

        ByteBuffer small = ByteBuffer.allocate(SMALL_DST_SIZE);
        SSLEngineResult overflow = c.server.unwrap(net, small);

        assertEquals(Status.BUFFER_OVERFLOW, overflow.getStatus(), "Нужен BUFFER_OVERFLOW");
        assertEquals(0, overflow.bytesConsumed(), "Запись не должна быть потреблена");
        assertEquals(0, overflow.bytesProduced(), "Данные не должны выдаваться частями");
        assertEquals(netBefore, net.position(), "Позиция src не должна сдвигаться");
        assertEquals(0, small.position(), "Позиция dst не должна сдвигаться");

        // Пустой src: если бы движок хранил остаток, он выдал бы его здесь
        SSLEngineResult empty = c.server.unwrap(ByteBuffer.allocate(0), small);
        assertEquals(0, empty.bytesProduced(), "Движок не хранит открытый текст между вызовами");

        // Повтор с буфером в размер записи: данные целые, номер записи не потерян
        ByteBuffer big = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult ok = c.server.unwrap(net, big);
        assertEquals(Status.OK, ok.getStatus(), "Повтор с большим буфером должен пройти");
        assertEquals(firstRecordEnd, ok.bytesConsumed(), "Запись потребляется целиком");
        assertEquals(first.length, ok.bytesProduced(), "Выдана вся запись");
        assertArrayEquals(first, contents(big), "Содержимое записи должно совпасть");

        // Следующая запись расшифровывается: порядковый номер на отказе не сдвигался
        big.clear();
        SSLEngineResult next = c.server.unwrap(net, big);
        assertEquals(second.length, next.bytesProduced(), "Вторая запись должна быть выдана");
        assertArrayEquals(second, contents(big), "Содержимое второй записи должно совпасть");
        assertEquals(0, net.remaining(), "Весь вход должен быть потреблён");
    }

    @Test
    @DisplayName(
            "Несколько буферов приёмника: запись раскладывается по порядку, потребляется один раз")
    void recordIsScatteredAcrossAllDestinations() throws Exception {
        Connected c = connect();
        byte[] data = pattern(FULL_RECORD_PLAINTEXT, 3);
        ByteBuffer net = encrypt(c.client, data);
        int recordLength = net.remaining();

        // Сумма буферов равна записи ровно; первый заведомо меньше записи
        ByteBuffer head = ByteBuffer.allocate(100);
        ByteBuffer middle = ByteBuffer.allocate(0);
        ByteBuffer tail = ByteBuffer.allocate(data.length - 100);
        SSLEngineResult result = c.server.unwrap(net, new ByteBuffer[] {head, middle, tail});

        assertEquals(Status.OK, result.getStatus(), "Запись помещается в сумму буферов");
        assertEquals(recordLength, result.bytesConsumed(), "Запись потребляется один раз");
        assertEquals(data.length, result.bytesProduced(), "produced равен длине данных");
        byte[] joined = new byte[data.length];
        head.flip().get(joined, 0, head.remaining());
        tail.flip().get(joined, 100, tail.remaining());
        assertArrayEquals(data, joined, "Порядок байт по буферам должен сохраниться");
    }

    @Test
    @DisplayName("Несколько буферов, сумма меньше записи: BUFFER_OVERFLOW без изменений")
    void totalOfDestinationsBelowRecordReturnsOverflow() throws Exception {
        Connected c = connect();
        ByteBuffer net = encrypt(c.client, pattern(FULL_RECORD_PLAINTEXT, 4));
        int netBefore = net.position();

        ByteBuffer a = ByteBuffer.allocate(8000);
        ByteBuffer b = ByteBuffer.allocate(8000);
        SSLEngineResult result = c.server.unwrap(net, new ByteBuffer[] {a, b});

        assertEquals(Status.BUFFER_OVERFLOW, result.getStatus(), "Суммы 16000 не хватает");
        assertEquals(0, result.bytesConsumed(), "Ничего не потреблено");
        assertEquals(0, result.bytesProduced(), "Ничего не выдано");
        assertEquals(netBefore, net.position(), "src не сдвинут");
        assertEquals(0, a.position() + b.position(), "Буферы приёмника не тронуты");
    }

    @Test
    @DisplayName("Запись приложения после Finished в одном src: Finished принят, запись ждёт места")
    void applicationRecordAfterFinishedWaitsForSpace() throws Exception {
        // Клиент: Finished и первая запись приложения идут одним буфером, как у браузера
        GostSSLEngine client = engine(true);
        GostSSLEngine server = engine(false);
        byte[] data = pattern(FULL_RECORD_PLAINTEXT, 5);
        ByteBuffer clientToServer = ByteBuffer.allocate(1 << 17);
        ByteBuffer serverToClient = ByteBuffer.allocate(1 << 17);
        ByteBuffer none = ByteBuffer.allocate(0);
        client.beginHandshake();
        server.beginHandshake();

        boolean dataQueued = false;
        for (int step = 0; step < 400; step++) {
            drive(client, none, serverToClient, clientToServer);
            if (!dataQueued && client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING) {
                // Handshake клиента завершён, его последние записи (Finished) ещё не доставлены
                // серверу: добавляем запись приложения в тот же буфер
                ByteBuffer app = ByteBuffer.wrap(data);
                client.wrap(app, clientToServer);
                dataQueued = true;
            }
            if (dataQueued) {
                break;
            }
            drive(server, none, clientToServer, serverToClient);
        }
        assertTrue(dataQueued, "Клиент должен завершить рукопожатие");
        clientToServer.flip();

        // Сервер видит Finished + запись приложения; в приёмнике места на неё нет
        ByteBuffer small = ByteBuffer.allocate(SMALL_DST_SIZE);
        int serverUnwraps = 0;
        boolean finishedReported = false;
        SSLEngineResult last = null;
        while (clientToServer.hasRemaining() && serverUnwraps++ < 50) {
            last = server.unwrap(clientToServer, small);
            finishedReported |= last.getHandshakeStatus() == HandshakeStatus.FINISHED;
            if (last.getStatus() == Status.BUFFER_OVERFLOW) {
                break;
            }
            if (last.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
                server.wrap(none, serverToClient);
            }
            if (last.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
                runTasks(server);
            }
            assertEquals(0, small.position(), "Данные приложения нельзя выдавать частями");
        }
        assertNotNull(last, "Сервер должен был вызвать unwrap");
        assertTrue(finishedReported, "Finished клиента принят и сообщён статусом FINISHED");
        assertEquals(Status.BUFFER_OVERFLOW, last.getStatus(), "Запись приложения не поместилась");
        assertEquals(0, last.bytesProduced(), "Ничего не выдано");
        assertEquals(0, last.bytesConsumed(), "Запись не потреблена");
        assertTrue(clientToServer.hasRemaining(), "Запись осталась в src целиком");

        ByteBuffer big = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult retry = server.unwrap(clientToServer, big);
        assertEquals(Status.OK, retry.getStatus(), "Повтор с большим буфером проходит");
        assertArrayEquals(data, contents(big), "Данные первой записи должны быть целыми");
    }

    @Test
    @DisplayName(
            "Повреждённая запись при малом приёмнике: ошибка аутентификации, а не BUFFER_OVERFLOW")
    void tamperedRecordFailsAuthenticationBeforeCapacityCheck() throws Exception {
        Connected c = connect();
        ByteBuffer net = encrypt(c.client, pattern(FULL_RECORD_PLAINTEXT, 6));
        // Порядок «аутентификация, затем проверка места»: подделка не должна выглядеть как запись,
        // которой просто не хватило буфера, иначе потребитель бесконечно увеличивал бы приёмник
        int tamperedIndex = net.position() + TlsConstants.RECORD_HEADER_SIZE + 10;
        net.put(tamperedIndex, (byte) (net.get(tamperedIndex) ^ 0x5A));

        assertThrows(
                SSLException.class,
                () -> c.server.unwrap(net, ByteBuffer.allocate(SMALL_DST_SIZE)),
                "Повреждённая запись должна давать ошибку, а не BUFFER_OVERFLOW");
    }

    @Test
    @DisplayName("Сумма буферов на байт меньше записи: BUFFER_OVERFLOW; ровно по записи: принята")
    void destinationsOneByteShortOverflowAndExactFitAccepted() throws Exception {
        Connected c = connect();
        byte[] data = pattern(FULL_RECORD_PLAINTEXT, 7);
        ByteBuffer net = encrypt(c.client, data);
        int netBefore = net.position();

        ByteBuffer shortBy1 = ByteBuffer.allocate(data.length - 1);
        SSLEngineResult overflow = c.server.unwrap(net, shortBy1);
        assertEquals(Status.BUFFER_OVERFLOW, overflow.getStatus(), "Не хватает одного байта");
        assertEquals(netBefore, net.position(), "src не сдвинут");

        ByteBuffer exact = ByteBuffer.allocate(data.length);
        SSLEngineResult ok = c.server.unwrap(net, exact);
        assertEquals(Status.OK, ok.getStatus(), "Ровно по размеру записи достаточно");
        assertEquals(data.length, ok.bytesProduced(), "Запись выдана целиком");
    }

    @Test
    @DisplayName("Приёмник только для чтения: ReadOnlyBufferException до потребления записи")
    void readOnlyDestinationIsRejectedBeforeConsumingRecord() throws Exception {
        Connected c = connect();
        byte[] data = pattern(200, 8);
        ByteBuffer net = encrypt(c.client, data);
        int netBefore = net.position();

        assertThrows(
                java.nio.ReadOnlyBufferException.class,
                () -> c.server.unwrap(net, ByteBuffer.allocate(1024).asReadOnlyBuffer()),
                "Контракт SSLEngine: исключение до потребления входа");
        assertEquals(netBefore, net.position(), "Запись не потреблена");

        ByteBuffer dst = ByteBuffer.allocate(1024);
        SSLEngineResult ok = c.server.unwrap(net, dst);
        assertEquals(data.length, ok.bytesProduced(), "Повтор с обычным буфером проходит");
        assertArrayEquals(data, contents(dst), "Запись не потеряна");
    }

    @Test
    @DisplayName("Один буфер в двух слотах учитывается один раз: BUFFER_OVERFLOW без потребления")
    void sameBufferInTwoSlotsIsCountedOnce() throws Exception {
        Connected c = connect();
        ByteBuffer net = encrypt(c.client, pattern(300, 9));
        int netBefore = net.position();
        // Если учесть буфер дважды, места «хватило бы» (2 x 200 >= 300), но писать некуда
        ByteBuffer shared = ByteBuffer.allocate(200);

        SSLEngineResult result = c.server.unwrap(net, new ByteBuffer[] {shared, shared});

        assertEquals(Status.BUFFER_OVERFLOW, result.getStatus(), "Места всего 200 байт");
        assertEquals(0, result.bytesConsumed(), "Запись не потреблена");
        assertEquals(0, result.bytesProduced(), "Ничего не выдано");
        assertEquals(netBefore, net.position(), "src не сдвинут");
        assertEquals(0, shared.position(), "Буфер приёмника не тронут");
    }

    @Test
    @DisplayName("Finished и две записи приложения: первая выдана, вторая ждёт места")
    void firstRecordAfterFinishedFitsSecondWaits() throws Exception {
        byte[] first = pattern(100, 10);
        byte[] second = pattern(FULL_RECORD_PLAINTEXT, 11);
        FinishedWithRecords f = finishedWithRecords(first, second);

        // Места хватает на первую запись и не хватает на вторую
        ByteBuffer dst = ByteBuffer.allocate(SMALL_DST_SIZE);
        SSLEngineResult head = f.server().unwrap(f.net(), dst);
        assertEquals(Status.OK, head.getStatus(), "Finished и первая запись приняты");
        assertEquals(first.length, head.bytesProduced(), "Выдана только первая запись");
        assertEquals(HandshakeStatus.FINISHED, head.getHandshakeStatus(), "Finished сообщён");
        assertArrayEquals(first, contents(dst), "Первая запись целиком");

        SSLEngineResult waiting = f.server().unwrap(f.net(), dst);
        assertEquals(Status.BUFFER_OVERFLOW, waiting.getStatus(), "Вторая не помещается");
        assertEquals(0, waiting.bytesConsumed(), "Вторая запись не потреблена");

        ByteBuffer big = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult done = f.server().unwrap(f.net(), big);
        assertEquals(second.length, done.bytesProduced(), "Вторая запись выдана целиком");
        assertArrayEquals(second, contents(big), "Содержимое второй записи");
    }

    @Test
    @DisplayName("close_notify и рукопожатие принимаются при пустом приёмнике")
    void handshakeAndAlertAreAcceptedWithEmptyDestination() throws Exception {
        // Рукопожатие целиком идёт с пустым dst: нехватка места касается только данных
        Connected c = connect();
        c.client.closeOutbound();
        ByteBuffer net = ByteBuffer.allocate(1 << 12);
        c.client.wrap(ByteBuffer.allocate(0), net);
        net.flip();

        SSLEngineResult result = c.server.unwrap(net, ByteBuffer.allocate(0));

        assertEquals(Status.CLOSED, result.getStatus(), "close_notify принимается без места");
        assertTrue(c.server.isInboundDone(), "Приём должен быть завершён");
    }

    // ---- вспомогательное ----

    private record FinishedWithRecords(GostSSLEngine server, ByteBuffer net) {}

    /**
     * Сервер, которому в одном буфере лежат Finished клиента и записи приложения, как у клиента,
     * пославшего первый запрос сразу за Finished.
     */
    private static FinishedWithRecords finishedWithRecords(byte[]... blocks) throws Exception {
        GostSSLEngine client = engine(true);
        GostSSLEngine server = engine(false);
        ByteBuffer clientToServer = ByteBuffer.allocate(1 << 17);
        ByteBuffer serverToClient = ByteBuffer.allocate(1 << 17);
        ByteBuffer none = ByteBuffer.allocate(0);
        client.beginHandshake();
        server.beginHandshake();
        for (int step = 0; step < 400; step++) {
            drive(client, none, serverToClient, clientToServer);
            if (client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING) {
                for (byte[] block : blocks) {
                    client.wrap(ByteBuffer.wrap(block), clientToServer);
                }
                clientToServer.flip();
                return new FinishedWithRecords(server, clientToServer);
            }
            drive(server, none, clientToServer, serverToClient);
        }
        throw new AssertionError("Клиент не завершил рукопожатие за 400 шагов");
    }

    private record Connected(GostSSLEngine client, GostSSLEngine server) {}

    private static GostSSLEngine engine(boolean clientMode) {
        return clientMode
                ? new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true)
                : new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    /** Рукопожатие в одном потоке с пустым dst: заодно проверяет, что оно не требует места. */
    private static Connected connect() throws Exception {
        GostSSLEngine client = engine(true);
        GostSSLEngine server = engine(false);
        ByteBuffer clientToServer = ByteBuffer.allocate(1 << 17);
        ByteBuffer serverToClient = ByteBuffer.allocate(1 << 17);
        ByteBuffer none = ByteBuffer.allocate(0);
        client.beginHandshake();
        server.beginHandshake();
        for (int step = 0; step < 400; step++) {
            drive(client, none, serverToClient, clientToServer);
            drive(server, none, clientToServer, serverToClient);
            if (client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                    && server.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                    && clientToServer.position() == 0
                    && serverToClient.position() == 0) {
                return new Connected(client, server);
            }
        }
        throw new AssertionError("Рукопожатие не завершилось за 400 шагов");
    }

    /**
     * Один шаг движка: отдать исходящие записи в {@code out}, принять входящие из {@code in},
     * выполнить задачи. {@code in} и {@code out} хранятся в режиме записи.
     */
    private static void drive(GostSSLEngine e, ByteBuffer dst, ByteBuffer in, ByteBuffer out)
            throws Exception {
        for (int i = 0; i < 20; i++) {
            HandshakeStatus hs = e.getHandshakeStatus();
            if (hs == HandshakeStatus.NEED_TASK) {
                runTasks(e);
            } else if (hs == HandshakeStatus.NEED_WRAP) {
                e.wrap(ByteBuffer.allocate(0), out);
            } else if (hs == HandshakeStatus.NEED_UNWRAP && in.position() > 0) {
                in.flip();
                SSLEngineResult r = e.unwrap(in, dst);
                in.compact();
                if (r.bytesConsumed() == 0 && r.bytesProduced() == 0) {
                    return;
                }
            } else {
                // NOT_HANDSHAKING: после рукопожатия принимаем служебные записи (тикеты)
                if (in.position() > 0) {
                    in.flip();
                    SSLEngineResult r = e.unwrap(in, dst);
                    in.compact();
                    if (r.bytesConsumed() == 0) {
                        return;
                    }
                } else {
                    return;
                }
            }
        }
    }

    private static void runTasks(GostSSLEngine e) {
        Runnable task;
        while ((task = e.getDelegatedTask()) != null) {
            task.run();
        }
    }

    /** Шифрует каждый блок отдельной записью; результат готов к чтению. */
    private static ByteBuffer encrypt(GostSSLEngine sender, byte[]... blocks) throws Exception {
        ByteBuffer net = ByteBuffer.allocate(blocks.length * (1 << 15));
        for (byte[] block : blocks) {
            SSLEngineResult r = sender.wrap(ByteBuffer.wrap(block), net);
            assertEquals(block.length, r.bytesConsumed(), "Блок должен уйти одной записью");
        }
        net.flip();
        return net;
    }

    private static int recordLength(ByteBuffer net, int index) {
        int pos = net.position();
        for (int i = 0; i < index; i++) {
            pos += TlsConstants.RECORD_HEADER_SIZE + payloadLength(net, pos);
        }
        return TlsConstants.RECORD_HEADER_SIZE + payloadLength(net, pos);
    }

    private static int payloadLength(ByteBuffer net, int pos) {
        return ((net.get(pos + 3) & 0xFF) << 8) | (net.get(pos + 4) & 0xFF);
    }

    private static byte[] contents(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        view.flip();
        byte[] bytes = new byte[view.remaining()];
        view.get(bytes);
        return bytes;
    }

    private static byte[] pattern(int length, int seed) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (seed * 31 + i);
        }
        return bytes;
    }
}
