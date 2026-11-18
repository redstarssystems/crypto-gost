package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Разбор совместимого change_cipher_spec (RFC 8446 §5, §D.4):
 * {@link TlsUtils#consumeCompatibilityCcs(ByteBuffer)}.
 */
@DisplayName("TlsUtils.consumeCompatibilityCcs: совместимый change_cipher_spec")
class TlsUtilsCcsTest {

    private static byte[] record(byte contentType, byte... payload) {
        byte[] r = new byte[TlsConstants.RECORD_HEADER_SIZE + payload.length];
        r[0] = contentType;
        r[1] = 0x03;
        r[2] = 0x03;
        r[3] = (byte) (payload.length >> 8);
        r[4] = (byte) payload.length;
        System.arraycopy(payload, 0, r, TlsConstants.RECORD_HEADER_SIZE, payload.length);
        return r;
    }

    @Test
    @DisplayName("Корректный CCS (длина 1, значение 0x01) потребляется целиком")
    void validCcsConsumed() throws Exception {
        ByteBuffer src = ByteBuffer.wrap(record(TlsConstants.CT_CHANGE_CIPHER_SPEC, (byte) 0x01));

        TlsUtils.CcsResult r = TlsUtils.consumeCompatibilityCcs(src);

        assertEquals(TlsUtils.CcsStatus.CONSUMED, r.status());
        assertEquals(6, r.consumed());
        assertEquals(6, src.position(), "позиция сдвинута на запись");
    }

    @Test
    @DisplayName("Не CCS: буфер не меняется")
    void otherRecordIsNotCcs() throws Exception {
        ByteBuffer src = ByteBuffer.wrap(record(TlsConstants.CT_HANDSHAKE, (byte) 0x01));

        TlsUtils.CcsResult r = TlsUtils.consumeCompatibilityCcs(src);

        assertEquals(TlsUtils.CcsStatus.NOT_CCS, r.status());
        assertEquals(0, src.position());
    }

    @Test
    @DisplayName("Неполный CCS (только заголовок или меньше) -> INCOMPLETE, буфер не меняется")
    void incompleteCcs() throws Exception {
        byte[] full = record(TlsConstants.CT_CHANGE_CIPHER_SPEC, (byte) 0x01);

        for (int len : new int[] {1, 3, TlsConstants.RECORD_HEADER_SIZE}) {
            ByteBuffer src = ByteBuffer.wrap(full, 0, len);
            TlsUtils.CcsResult r = TlsUtils.consumeCompatibilityCcs(src);
            assertEquals(TlsUtils.CcsStatus.INCOMPLETE, r.status(), "длина " + len);
            assertEquals(0, src.position());
        }
    }

    @Test
    @DisplayName("Длина не 1 отвергается сразу, не дожидаясь остатка записи")
    void wrongLengthRejectedImmediately() {
        // заголовок объявляет 2 байта, тела ещё нет
        ByteBuffer headerOnly =
                ByteBuffer.wrap(
                        record(TlsConstants.CT_CHANGE_CIPHER_SPEC, (byte) 0x01, (byte) 0x01),
                        0,
                        TlsConstants.RECORD_HEADER_SIZE);

        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsUtils.consumeCompatibilityCcs(headerOnly));
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.getAlertCode());

        assertThrows(
                TlsException.class,
                () ->
                        TlsUtils.consumeCompatibilityCcs(
                                ByteBuffer.wrap(record(TlsConstants.CT_CHANGE_CIPHER_SPEC))));
    }

    @Test
    @DisplayName("Значение не 0x01 -> unexpected_message")
    void wrongValueRejected() {
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsUtils.consumeCompatibilityCcs(
                                        ByteBuffer.wrap(
                                                record(
                                                        TlsConstants.CT_CHANGE_CIPHER_SPEC,
                                                        (byte) 0x02))));
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.getAlertCode());
    }

    @Test
    @DisplayName("buildCompatibilityCcsRecord: 14 03 03 00 01 01 и круговая проверка приёмом")
    void builtCcsIsExactAndConsumable() throws Exception {
        byte[] built = TlsUtils.buildCompatibilityCcsRecord();

        assertArrayEquals(
                new byte[] {TlsConstants.CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01},
                built,
                "запись CCS должна совпадать побайтно");
        assertEquals(TlsConstants.CCS_RECORD_SIZE, built.length);

        TlsUtils.CcsResult r = TlsUtils.consumeCompatibilityCcs(ByteBuffer.wrap(built));
        assertEquals(TlsUtils.CcsStatus.CONSUMED, r.status(), "собранный CCS принимается");
        assertEquals(built.length, r.consumed());
    }
}
