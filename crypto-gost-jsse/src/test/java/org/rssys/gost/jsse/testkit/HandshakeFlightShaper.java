package org.rssys.gost.jsse.testkit;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.tls13.engine.HandshakeOutput;

/**
 * Переделывает полёт рукопожатия, который движок уже поставил в очередь на отправку, но ещё не
 * отдал в {@code wrap()}.
 *
 * <p>Наш движок и OpenSSL кладут каждое сообщение рукопожатия в отдельную запись, поэтому записи,
 * несущие несколько сообщений или обрывок сообщения, сами в тестах не появляются. {@code wrap()}
 * отправляет каждое сообщение очереди своей записью (длинное — несколькими), поэтому достаточно
 * переложить байты сообщений: склеенные в одно сообщение уйдут одной записью, сообщения по одному
 * байту — записями по одному байту.
 *
 * <p>Метки смены ключа записи сохраняют смысл: метки за оставленными сообщениями остаются на
 * месте, остальные встают после переложенных байтов. Так склейка внутри эпохи даёт законную
 * запись, а склейка через границу эпохи (ServerHello и следующее сообщение, хвост за Finished)
 * даёт намеренно неправильную, на которой проверяется отказ получателя.
 */
public final class HandshakeFlightShaper {

    /** Склеить все сообщения в одну запись. */
    public static final int ONE_RECORD = Integer.MAX_VALUE;

    private HandshakeFlightShaper() {}

    /**
     * Перекладывает сообщения очереди, начиная с {@code keepLeading}-го, в элементы по
     * {@code chunkSize} байт.
     *
     * @param engine движок с полётом в очереди
     * @param keepLeading сколько первых сообщений оставить как есть (вместе с метками за ними)
     * @param chunkSize размер элемента; {@link #ONE_RECORD} — все сообщения одним элементом
     * @param extraTail байты, дописываемые после последнего сообщения (например, лишнее
     *     сообщение за Finished); пустой массив — ничего не дописывать
     */
    public static void reshape(
            GostSSLEngine engine, int keepLeading, int chunkSize, byte[] extraTail) {
        Deque<HandshakeOutput> queue = outgoingQueue(engine);
        List<HandshakeOutput> kept = new ArrayList<>();
        List<HandshakeOutput> trailingKeyChanges = new ArrayList<>();
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        int messages = 0;
        for (HandshakeOutput item : queue) {
            if (item instanceof HandshakeOutput.Message message) {
                if (messages < keepLeading) {
                    kept.add(item);
                } else {
                    joined.writeBytes(message.frame());
                }
                messages++;
            } else if (messages <= keepLeading && joined.size() == 0) {
                kept.add(item);
            } else {
                trailingKeyChanges.add(item);
            }
        }
        if (messages < keepLeading) {
            throw new IllegalStateException("В очереди меньше сообщений, чем нужно оставить");
        }
        joined.writeBytes(extraTail);
        byte[] bytes = joined.toByteArray();

        queue.clear();
        queue.addAll(kept);
        if (chunkSize == ONE_RECORD) {
            queue.addLast(new HandshakeOutput.Message(bytes));
        } else {
            for (int offset = 0; offset < bytes.length; offset += chunkSize) {
                int length = Math.min(chunkSize, bytes.length - offset);
                byte[] chunk = new byte[length];
                System.arraycopy(bytes, offset, chunk, 0, length);
                queue.addLast(new HandshakeOutput.Message(chunk));
            }
        }
        queue.addAll(trailingKeyChanges);
    }

    /**
     * Переносит поток движка рукопожатия в очередь отправки, не отправляя его. После рукопожатия
     * KeyUpdate ждёт в движке до {@code wrap()}; перенос нужен, чтобы переложить его байты.
     */
    public static void pullFromHandshakeEngine(GostSSLEngine engine) {
        try {
            java.lang.reflect.Method drain =
                    GostSSLEngine.class.getDeclaredMethod("drainHandshakeOutput");
            drain.setAccessible(true);
            drain.invoke(engine);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Поток движка рукопожатия недоступен", e);
        }
    }

    /** Добавляет в конец очереди сообщение как есть (в том числе пустое: запись нулевой длины). */
    public static void appendRaw(GostSSLEngine engine, byte[] element) {
        outgoingQueue(engine).addLast(new HandshakeOutput.Message(element));
    }

    /** Ставит сообщение первым в очередь (в том числе пустое: запись нулевой длины). */
    public static void prependRaw(GostSSLEngine engine, byte[] element) {
        outgoingQueue(engine).addFirst(new HandshakeOutput.Message(element));
    }

    /** @return число сообщений, ждущих отправки (метки смены ключа не считаются) */
    public static int queuedFrames(GostSSLEngine engine) {
        int count = 0;
        for (HandshakeOutput item : outgoingQueue(engine)) {
            if (item instanceof HandshakeOutput.Message) {
                count++;
            }
        }
        return count;
    }

    @SuppressWarnings("unchecked")
    private static Deque<HandshakeOutput> outgoingQueue(GostSSLEngine engine) {
        try {
            Field field = GostSSLEngine.class.getDeclaredField("outgoingQueue");
            field.setAccessible(true);
            return (Deque<HandshakeOutput>) field.get(engine);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Очередь исходящих сообщений движка недоступна", e);
        }
    }
}
