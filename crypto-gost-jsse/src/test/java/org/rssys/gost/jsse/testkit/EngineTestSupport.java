package org.rssys.gost.jsse.testkit;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Общие приёмы ручного управления {@link GostSSLEngine} в тестах: выполнение делегированных
 * задач, отправка накопленных записей и подача входящих байт.
 */
public final class EngineTestSupport {

    private EngineTestSupport() {}

    /** Выполняет все делегированные задачи движка. */
    public static void runTasks(GostSSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    /** Вызывает {@code wrap}, пока движок хочет отправить данные рукопожатия. */
    public static void wrapPending(GostSSLEngine engine, ByteBuffer out) throws SSLException {
        while (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            engine.wrap(ByteBuffer.allocate(0), out);
        }
    }

    /**
     * Подаёт байты движку и сразу выполняет его задачи. Останавливается, когда входные данные
     * не потребляются.
     */
    public static void feedRunningTasks(GostSSLEngine engine, ByteBuffer in) throws SSLException {
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (in.hasRemaining()) {
            SSLEngineResult r = engine.unwrap(in, app);
            runTasks(engine);
            if (r.bytesConsumed() == 0) {
                break;
            }
        }
    }

    /**
     * Подаёт байты движку, но останавливается на первой делегированной задаче: вызывающий
     * сам решает, когда её выполнить.
     */
    public static void feedUntilTask(GostSSLEngine engine, ByteBuffer in) throws SSLException {
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (in.hasRemaining()) {
            SSLEngineResult r = engine.unwrap(in, app);
            if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                return;
            }
            runTasks(engine);
            if (r.bytesConsumed() == 0) {
                break;
            }
        }
    }
}
