package org.rssys.gost.tls13.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * Чтение выходного потока {@link TlsHandshakeEngine#poll()} в тестах, которые проверяют сообщения,
 * а не эпохи ключей: смены ключа записи пропускаются и сразу затираются. Порядок сообщений и смен
 * ключа проверяют отдельные тесты через {@link #drain(TlsHandshakeEngine)}.
 */
public final class HandshakeOutputs {

    private HandshakeOutputs() {}

    /**
     * Следующее сообщение потока; смены ключа записи до него пропускаются.
     *
     * @return сообщение либо {@code null}, если поток пуст
     */
    public static byte[] nextMessage(TlsHandshakeEngine engine) {
        HandshakeOutput item;
        while ((item = engine.poll()) != null) {
            if (item instanceof HandshakeOutput.Message message) {
                return message.frame();
            }
            ((HandshakeOutput.WriteKeyChange) item).destroy();
        }
        return null;
    }

    /** Весь поток до опустошения, по порядку. */
    public static List<HandshakeOutput> drain(TlsHandshakeEngine engine) {
        List<HandshakeOutput> items = new ArrayList<>();
        HandshakeOutput item;
        while ((item = engine.poll()) != null) {
            items.add(item);
        }
        return items;
    }

    /** Порядок потока строкой: {@code M} — сообщение (с типом), {@code K} — смена ключа записи. */
    public static String layout(List<HandshakeOutput> items) {
        StringBuilder sb = new StringBuilder();
        for (HandshakeOutput item : items) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            if (item instanceof HandshakeOutput.Message message) {
                sb.append('M').append(message.frame()[0] & 0xFF);
            } else {
                sb.append('K');
            }
        }
        return sb.toString();
    }
}
