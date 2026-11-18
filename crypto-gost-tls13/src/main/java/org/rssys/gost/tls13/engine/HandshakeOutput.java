package org.rssys.gost.tls13.engine;

import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * Элемент упорядоченного выходного потока {@link TlsHandshakeEngine#poll()}: сообщение
 * рукопожатия для отправки или смена ключа записи.
 * <p>
 * Ключ записи меняется на проводе после конкретного сообщения (RFC 8446 §4.4.4, §5.1, §4.6.3),
 * поэтому смена стоит в потоке сразу за ним: всё, что выдано до неё, отправляется прежним ключом,
 * всё после — новым. Эпоха привязана к месту в очереди, а не к моменту отправки, и обогнать
 * сообщение смена не может. Так же устроены JDK ({@code RecordMemo.encodeCipher}) и BoringSSL
 * (запись запечатывается при постановке в полёт).
 */
public sealed interface HandshakeOutput
        permits HandshakeOutput.Message, HandshakeOutput.WriteKeyChange {

    /**
     * Сообщение рукопожатия (заголовок и тело) для отправки текущим ключом записи; пока ключа
     * записи нет, сообщение уходит открытым (ClientHello, HelloRetryRequest, ServerHello).
     *
     * @param frame сообщение целиком; массив передаётся без копии
     */
    record Message(byte[] frame) implements HandshakeOutput {
        @Override
        public String toString() {
            return "Message[type=" + (frame[0] & 0xFF) + ", length=" + frame.length + "]";
        }
    }

    /**
     * Смена ключа записи: следующие сообщения и данные приложения защищаются новыми ключами, номер
     * записи начинается с нуля. Эпоха полная: вместе с ключами задан набор шифров, по которому
     * собирается запись (маски TLSTREE и тег зависят от набора). Без него получатель взял бы набор,
     * известный ему на момент применения, а у клиента до разбора ServerHello это первый
     * предложенный, а не согласованный.
     * <p>
     * Владение: элемент держит собственную копию ключей. Получатель создаёт из неё запись и сразу
     * вызывает {@link #destroy()}; неотданные элементы затирает движок в
     * {@link TlsHandshakeEngine#destroy()}, отданные, но не применённые, — их получатель.
     */
    final class WriteKeyChange implements HandshakeOutput {
        private final TlsTrafficKeys keys;
        private final TlsCiphersuite ciphersuite;

        WriteKeyChange(TlsTrafficKeys source, TlsCiphersuite ciphersuite) {
            this.keys = new TlsTrafficKeys(source.getKey(), source.getIv());
            this.ciphersuite = ciphersuite;
        }

        /** @return новые ключи записи */
        public TlsTrafficKeys keys() {
            return keys;
        }

        /** @return набор шифров эпохи: по нему собирается запись */
        public TlsCiphersuite ciphersuite() {
            return ciphersuite;
        }

        /** Затирает ключевой материал. */
        public void destroy() {
            keys.destroy();
        }

        /** Ключей не раскрывает. */
        @Override
        public String toString() {
            return "WriteKeyChange";
        }
    }
}
