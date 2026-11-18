package org.rssys.gost.tls13;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Транспорт-обёртка для тестов: считает открытые записи типа handshake в каждую сторону.
 *
 * <p>Открытые handshake-записи несут только ClientHello, ServerHello и HelloRetryRequest
 * (остальное рукопожатия зашифровано), поэтому две записи ClientHello у клиента означают, что
 * рукопожатие прошло через HelloRetryRequest. Нужна для кросс-валидации, где внешний узел не даёт
 * заглянуть в свои сообщения.
 */
public final class HandshakeRecordCountingTransport implements TlsTransport {

    private final TlsTransport delegate;
    private final AtomicInteger sentPlainHandshakeRecords = new AtomicInteger();
    private final AtomicInteger receivedPlainHandshakeRecords = new AtomicInteger();

    public HandshakeRecordCountingTransport(TlsTransport delegate) {
        this.delegate = delegate;
    }

    @Override
    public void sendRecord(byte[] record) throws IOException {
        if (isPlainHandshake(record)) {
            sentPlainHandshakeRecords.incrementAndGet();
        }
        delegate.sendRecord(record);
    }

    @Override
    public byte[] receiveRecord() throws IOException {
        byte[] record = delegate.receiveRecord();
        if (isPlainHandshake(record)) {
            receivedPlainHandshakeRecords.incrementAndGet();
        }
        return record;
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    /** @return сколько открытых handshake-записей отправлено (у клиента: число ClientHello) */
    public int sentPlainHandshakeRecords() {
        return sentPlainHandshakeRecords.get();
    }

    /** @return сколько открытых handshake-записей получено (у сервера: число ClientHello) */
    public int receivedPlainHandshakeRecords() {
        return receivedPlainHandshakeRecords.get();
    }

    private static boolean isPlainHandshake(byte[] record) {
        return record.length > 0 && record[0] == TlsConstants.CT_HANDSHAKE;
    }
}
