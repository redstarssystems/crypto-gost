package org.rssys.gost.tls13;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Установленное соединение для тестов уровня {@link TlsSession}: две сессии с завершённым
 * рукопожатием и общий транспорт, через который тест может подменять и вставлять записи.
 */
record TlsSessionConnection(
        TlsSession server, TlsSession client, InMemoryTlsTransport.Pair transports) {

    private static final long HANDSHAKE_TIMEOUT_SECONDS = 15;

    /**
     * Останавливает потоки рукопожатия и ждёт их завершения.
     * <p>
     * {@code TlsSession} не потокобезопасна: закрывать сессию можно только после того, как
     * завершился поток, который выполнял её рукопожатие. {@code Future.cancel(true)} лишь
     * прерывает поток и сразу помечает задачу отменённой, а завершения не ждёт (после него
     * {@code Future.get()} возвращается мгновенно), поэтому дождаться потока можно только через
     * исполнитель. Исход, который проверяет тест (ошибка пира), нужно проверять до вызова этого
     * метода: после отмены результат задачи недоступен.
     *
     * @param executor исполнитель, в котором шли рукопожатия
     * @param tasks    задачи рукопожатия, которые могли остаться незавершёнными (ждут данных пира)
     */
    static void stopHandshakeThreads(ExecutorService executor, Future<?>... tasks)
            throws InterruptedException {
        for (Future<?> task : tasks) {
            task.cancel(true);
        }
        executor.shutdown();
        if (!executor.awaitTermination(HANDSHAKE_THREAD_STOP_SECONDS, TimeUnit.SECONDS)) {
            executor.shutdownNow();
            throw new AssertionError(
                    "Потоки рукопожатия не завершились за "
                            + HANDSHAKE_THREAD_STOP_SECONDS
                            + " с: сессию нельзя закрывать из другого потока");
        }
    }

    private static final long HANDSHAKE_THREAD_STOP_SECONDS = 15;

    /** Выполняет рукопожатие сервера и клиента (без аутентификации сервера) на наборе suite. */
    static TlsSessionConnection establish(TlsCiphersuite suite) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        transports.getServerTransport(), suite, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        transports.getClientTransport(), suite, null, null);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientHandshake =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverHandshake =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientHandshake.get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            serverHandshake.get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
        return new TlsSessionConnection(server, client, transports);
    }
}
