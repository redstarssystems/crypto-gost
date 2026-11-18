package org.rssys.gost.crossval.kuznyechik;

import org.rssys.gost.api.Cipher;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Долгоживущий worker с JAR предыдущей версии crypto-gost.
 *
 * <p>Поднимает один subprocess на тестовый класс и общается с ним бинарным протоколом
 * через stdin/stdout. Это убирает стоимость старта JVM и загрузки классов с горячего пути:
 * раньше на каждый тестовый кейс поднимались две JVM.
 *
 * <p>stderr процесса читается отдельным daemon-потоком в кольцевой буфер. Так диагностика
 * остаётся доступной, а заполненный pipe не блокирует worker.
 *
 * <p>Экземпляр потокобезопасен: запросы сериализуются {@link ReentrantLock}. JUnit по
 * умолчанию исполняет тесты последовательно, блокировка — дешёвая страховка.
 */
final class OldVersionWorker implements AutoCloseable {

    /** Таймаут на один запрос: операция на 1 МиБ занимает доли секунды. */
    private static final int REQUEST_TIMEOUT_MS = 10_000;

    /** Сколько последних строк stderr хранить для диагностики. */
    private static final int STDERR_TAIL_LINES = 50;

    /** Сколько ждать штатного завершения процесса при закрытии. */
    private static final long CLOSE_WAIT_MS = 2_000;

    private final Process process;
    private final DataOutputStream out;
    private final DataInputStream in;
    private final ReentrantLock lock = new ReentrantLock();
    private final ConcurrentLinkedDeque<String> stderrTail = new ConcurrentLinkedDeque<>();
    private final Thread stderrPump;
    private final ScheduledExecutorService watchdog;
    private volatile boolean timedOut;

    OldVersionWorker(String oldJar, String compatClasses) throws IOException {
        String javaExecutable = System.getProperty("java.home")
                + File.separator + "bin" + File.separator + "java";
        String classpath = oldJar + File.pathSeparator + compatClasses;

        ProcessBuilder processBuilder = new ProcessBuilder(
                javaExecutable,
                "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                "--add-opens", "java.base/java.util=ALL-UNNAMED",
                "--add-opens", "java.base/java.io=ALL-UNNAMED",
                "--add-opens", "java.base/java.text=ALL-UNNAMED",
                "--add-opens", "java.base/jdk.internal.misc=ALL-UNNAMED",
                "-cp", classpath,
                CrossVersionTool.class.getName(),
                "serve"
        );
        processBuilder.redirectErrorStream(false);
        this.process = processBuilder.start();
        this.out = new DataOutputStream(new BufferedOutputStream(process.getOutputStream()));
        this.in = new DataInputStream(new BufferedInputStream(process.getInputStream()));

        this.stderrPump = new Thread(this::pumpStderr, "old-version-worker-stderr");
        this.stderrPump.setDaemon(true);
        this.stderrPump.start();

        this.watchdog = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "old-version-worker-watchdog");
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Шифрует/расшифровывает данные предыдущей версией.
     *
     * @param op {@code encrypt} или {@code decrypt}
     */
    byte[] call(Cipher.Mode mode, String op, byte[] key, byte[] iv, byte[] input) throws IOException {
        return call(modeCode(mode), opCode(op), key, iv, input);
    }

    /**
     * Выполняет MGM-операцию предыдущей версией.
     *
     * @param op {@code seal} или {@code open}
     */
    byte[] callMgm(String op, byte[] key, byte[] icn, byte[] input) throws IOException {
        return call(CrossVersionTool.MODE_MGM, opCode(op), key, icn, input);
    }

    private byte[] call(byte modeCode, byte opCode, byte[] key, byte[] iv, byte[] input) throws IOException {
        lock.lock();
        try {
            ensureAlive();
            timedOut = false;
            ScheduledFuture<?> timeout = watchdog.schedule(() -> {
                timedOut = true;
                process.destroyForcibly();
            }, REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            try {
                out.writeByte(CrossVersionTool.PROTOCOL_VERSION);
                out.writeByte(modeCode);
                out.writeByte(opCode);
                writeFrame(out, key);
                writeFrame(out, iv);
                writeFrame(out, input);
                out.flush();

                int status = in.readUnsignedByte();
                int length = in.readInt();
                if (length < 0 || length > CrossVersionTool.MAX_FRAME_BYTES) {
                    throw new IOException("old-version worker: invalid response frame length " + length);
                }
                byte[] body = new byte[length];
                in.readFully(body);

                if (status == CrossVersionTool.STATUS_OP_ERROR) {
                    throw new IOException("old-version worker reported operation error: "
                            + new String(body, StandardCharsets.UTF_8));
                }
                if (status != CrossVersionTool.STATUS_OK) {
                    throw new IOException("old-version worker: unexpected status " + status);
                }
                return body;
            } catch (IOException e) {
                if (!timedOut && !process.isAlive()) {
                    throw new IOException("old-version worker died during request (exit="
                            + process.exitValue() + "); stderr tail:"
                            + System.lineSeparator() + stderrSnapshot(), e);
                }
                throw e;
            } finally {
                timeout.cancel(false);
                if (timedOut) {
                    throw new IOException("old-version worker timed out after "
                            + REQUEST_TIMEOUT_MS + " ms; stderr tail:" + System.lineSeparator() + stderrSnapshot());
                }
            }
        } finally {
            lock.unlock();
        }
    }

    private void ensureAlive() throws IOException {
        if (!process.isAlive()) {
            throw new IOException("old-version worker is not alive (exit=" + process.exitValue()
                    + "); stderr tail:" + System.lineSeparator() + stderrSnapshot());
        }
    }

    private static void writeFrame(DataOutputStream out, byte[] data) throws IOException {
        if (data.length > CrossVersionTool.MAX_FRAME_BYTES) {
            throw new IOException("Request frame too large: " + data.length);
        }
        out.writeInt(data.length);
        out.write(data);
    }

    private void pumpStderr() {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stderrTail.addLast(line);
                while (stderrTail.size() > STDERR_TAIL_LINES) {
                    stderrTail.pollFirst();
                }
            }
        } catch (IOException ignored) {
        }
    }

    private String stderrSnapshot() {
        if (stderrTail.isEmpty()) {
            return " <empty>";
        }
        StringBuilder builder = new StringBuilder();
        for (String line : stderrTail) {
            builder.append(System.lineSeparator()).append(line);
        }
        return builder.toString();
    }

    private static byte modeCode(Cipher.Mode mode) {
        switch (mode) {
            case CTR:
                return CrossVersionTool.MODE_CTR;
            case CBC:
                return CrossVersionTool.MODE_CBC;
            case CFB:
                return CrossVersionTool.MODE_CFB;
            case OFB:
                return CrossVersionTool.MODE_OFB;
            default:
                throw new IllegalArgumentException("Неподдерживаемый режим: " + mode);
        }
    }

    private static byte opCode(String op) {
        if (op.equalsIgnoreCase("encrypt") || op.equalsIgnoreCase("seal")) {
            return CrossVersionTool.OP_ENCRYPT;
        }
        return CrossVersionTool.OP_DECRYPT;
    }

    @Override
    public void close() {
        try {
            out.close();
        } catch (IOException ignored) {
        }
        try {
            if (!process.waitFor(CLOSE_WAIT_MS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                process.waitFor(CLOSE_WAIT_MS, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        } finally {
            watchdog.shutdownNow();
            try {
                stderrPump.join(CLOSE_WAIT_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
