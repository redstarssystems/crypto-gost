package org.rssys.gost.tls13.record;
import org.rssys.gost.tls13.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.util.AuthenticationException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты TlsRecord — уровень записей TLS 1.3 с MGM AEAD (RFC 8446 §5).
 * Проверяет protect/unprotect, sequence numbers, аутентификацию, ошибки.
 */
@DisplayName("TlsRecord — уровень записей TLS 1.3")
class TlsRecordTest {

    private static final SecureRandom RNG = new SecureRandom();

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        RNG.nextBytes(key);
        return key;
    }

    private static byte[] randomIv() {
        byte[] iv = new byte[16];
        RNG.nextBytes(iv);
        iv[0] &= 0x7F;
        return iv;
    }

    private static byte[] fixedKey() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0xAB);
        return key;
    }

    private static byte[] fixedIv() {
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0xCD);
        iv[0] &= 0x7F;
        return iv;
    }

    /**
     * Создаёт пару writer/reader с одинаковыми ключами и IV.
     * Writer используется для protect, reader — для unprotect.
     * Каждый ведёт собственный счётчик seqNum, начиная с 0.
     */
    private static RecordPair newPair() {
        byte[] key = randomKey();
        byte[] iv = randomIv();
        return new RecordPair(
                new TlsRecord(key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                new TlsRecord(key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    private static RecordPair fixedPair() {
        return new RecordPair(
                new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    private static final class RecordPair {
        final TlsRecord writer;
        final TlsRecord reader;

        RecordPair(TlsRecord w, TlsRecord r) {
            this.writer = w;
            this.reader = r;
        }

        byte[] protect(byte ct, byte[] data) {
            return writer.protect(ct, data);
        }

        TlsParsedRecord unprotect(byte[] record) throws Exception {
            return reader.unprotect(record);
        }
    }

    // -----------------------------------------------------------------------
    // Основные тесты protect/unprotect
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("protect/unprotect handshake данных")
    void testProtectUnprotectHandshake() throws Exception {
        RecordPair pair = newPair();
        byte[] handshakeData = "hello from client".getBytes();

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_HANDSHAKE, handshakeData);
        assertNotNull(protectedRecord);

        assertEquals(TlsConstants.RECORD_HEADER_SIZE + handshakeData.length + 1 + 16,
                protectedRecord.length);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_HANDSHAKE, parsed.getContentType());
        assertArrayEquals(handshakeData, parsed.getData());
    }

    @Test
    @DisplayName("protect/unprotect application данных")
    void testProtectUnprotectApplicationData() throws Exception {
        RecordPair pair = newPair();
        byte[] appData = new byte[100];
        RNG.nextBytes(appData);

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_APPLICATION_DATA, appData);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(appData, parsed.getData());
    }

    @Test
    @DisplayName("protect/unprotect alert")
    void testProtectUnprotectAlert() throws Exception {
        RecordPair pair = newPair();
        byte[] alertData = new byte[]{1, 40};

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_ALERT, alertData);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_ALERT, parsed.getContentType());
        assertArrayEquals(alertData, parsed.getData());
    }

    @Test
    @DisplayName("protect/unprotect пустых данных")
    void testProtectUnprotectEmptyData() throws Exception {
        RecordPair pair = newPair();
        byte[] emptyData = new byte[0];

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_HANDSHAKE, emptyData);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_HANDSHAKE, parsed.getContentType());
        assertEquals(0, parsed.getData().length);
    }

    @Test
    @DisplayName("protect/unprotect с максимальным размером данных")
    void testProtectUnprotectMaxSize() throws Exception {
        RecordPair pair = newPair();
        // max fragment that fits in TLSInnerPlaintext (2^14 - 1 for content_type)
        byte[] maxData = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH - 1];
        RNG.nextBytes(maxData);

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_APPLICATION_DATA, maxData);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(maxData, parsed.getData());
    }

    // -----------------------------------------------------------------------
    // Sequence number
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("порядковый номер увеличивается после каждого protect")
    void testSequenceNumberIncrementsOnProtect() {
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertEquals(0, writer.getSequenceNumber());

        writer.protect(TlsConstants.CT_HANDSHAKE, new byte[]{1, 2, 3});
        assertEquals(1, writer.getSequenceNumber());

        writer.protect(TlsConstants.CT_HANDSHAKE, new byte[]{4, 5, 6});
        assertEquals(2, writer.getSequenceNumber());
    }

    @Test
    @DisplayName("порядковый номер reader увеличивается после unprotect")
    void testSequenceNumberIncrementsOnUnprotect() throws Exception {
        RecordPair pair = fixedPair();

        byte[] rec = pair.protect(TlsConstants.CT_HANDSHAKE, new byte[]{1});

        assertEquals(0, pair.reader.getSequenceNumber());
        TlsParsedRecord parsed = pair.unprotect(rec);
        assertEquals(1, pair.reader.getSequenceNumber());
        assertNotNull(parsed);
    }

    @Test
    @DisplayName("разные seqNum дают разные шифротексты для одинаковых данных")
    void testDifferentSeqNumProducesDifferentCiphertext() {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        byte[] data = "same data".getBytes();

        TlsRecord r0 = new TlsRecord(key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord r1 = new TlsRecord(key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        r1.setSequenceNumber(1);

        byte[] ct0 = r0.protect(TlsConstants.CT_HANDSHAKE, data);
        byte[] ct1 = r1.protect(TlsConstants.CT_HANDSHAKE, data);

        assertFalse(Arrays.equals(
                Arrays.copyOfRange(ct0, 5, ct0.length),
                Arrays.copyOfRange(ct1, 5, ct1.length)));
    }

    @Test
    @DisplayName("reader с тем же ключом и seqNum=0 расшифровывает первую запись")
    void testReaderDecryptsFirstRecord() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "test data".getBytes();
        byte[] record = pair.protect(TlsConstants.CT_HANDSHAKE, data);

        TlsParsedRecord parsed = pair.unprotect(record);
        assertArrayEquals(data, parsed.getData());
    }

    // -----------------------------------------------------------------------
    // Детерминированность
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("детерминированное шифрование при одинаковых параметрах")
    void testDeterministicEncryption() {
        byte[] data = "deterministic".getBytes();

        TlsRecord w1 = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord w2 = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

        byte[] ct1 = w1.protect(TlsConstants.CT_HANDSHAKE, data);
        byte[] ct2 = w2.protect(TlsConstants.CT_HANDSHAKE, data);

        assertArrayEquals(ct1, ct2);
    }

    // -----------------------------------------------------------------------
    // Ошибки аутентификации
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("подмена ciphertext вызывает AuthenticationException")
    void testTamperedCiphertextThrows() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "sensitive data".getBytes();

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_APPLICATION_DATA, data);

        protectedRecord[TlsConstants.RECORD_HEADER_SIZE + 4] ^= 0x42;

        assertThrows(AuthenticationException.class,
                () -> pair.unprotect(protectedRecord));
    }

    @Test
    @DisplayName("подмена tag вызывает AuthenticationException")
    void testTamperedTagThrows() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "important data".getBytes();

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_APPLICATION_DATA, data);

        protectedRecord[protectedRecord.length - 1] ^= 0xFF;

        assertThrows(AuthenticationException.class,
                () -> pair.unprotect(protectedRecord));
    }

    @Test
    @DisplayName("подмена заголовка вызывает AuthenticationException")
    void testTamperedHeaderThrows() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "data".getBytes();

        byte[] protectedRecord = pair.protect(
                TlsConstants.CT_HANDSHAKE, data);

        protectedRecord[0] = TlsConstants.CT_ALERT;

        assertThrows(AuthenticationException.class,
                () -> pair.unprotect(protectedRecord));
    }

    // -----------------------------------------------------------------------
    // Некорректные записи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("слишком короткая запись вызывает исключение")
    void testRecordTooShortThrows() {
        TlsRecord reader = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] tooShort = new byte[TlsConstants.RECORD_HEADER_SIZE + 1];

        assertThrows(IllegalArgumentException.class,
                () -> reader.unprotect(tooShort));
    }

    @Test
    @DisplayName("null данные в protect вызывают исключение")
    void testNullDataInProtectThrows() {
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, null));
    }

    @Test
    @DisplayName("слишком большой фрагмент вызывает исключение")
    void testOversizedDataThrows() {
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] tooBig = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH];

        assertThrows(IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, tooBig));
    }

    @Test
    @DisplayName("null запись в unprotect вызывает исключение")
    void testNullRecordInUnprotectThrows() {
        TlsRecord reader = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalArgumentException.class,
                () -> reader.unprotect(null));
    }

    // -----------------------------------------------------------------------
    // Некорректные параметры конструктора
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("конструктор: ключ null")
    void testConstructorNullKeyThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new TlsRecord(null, fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    @Test
    @DisplayName("конструктор: ключ неверной длины")
    void testConstructorWrongKeyLengthThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new TlsRecord(new byte[16], fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    @Test
    @DisplayName("конструктор: IV неверной длины")
    void testConstructorWrongIvLengthThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new TlsRecord(fixedKey(), new byte[8], 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    @Test
    @DisplayName("конструктор: неверная длина тега")
    void testConstructorInvalidTagLenThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new TlsRecord(fixedKey(), fixedIv(), 0, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    // -----------------------------------------------------------------------
    // Множественные записи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("множественные protect/unprotect с нарастающим seqNum")
    void testMultipleRecordsRoundtrip() throws Exception {
        RecordPair pair = fixedPair();

        for (int i = 0; i < 10; i++) {
            byte[] data = ("message " + i).getBytes();
            byte[] protectedRecord = pair.protect(
                    TlsConstants.CT_APPLICATION_DATA, data);

            TlsParsedRecord parsed = pair.unprotect(protectedRecord);
            assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
            assertArrayEquals(data, parsed.getData());
        }

        assertEquals(10, pair.writer.getSequenceNumber());
        assertEquals(10, pair.reader.getSequenceNumber());
    }

    @Test
    @DisplayName("чередование protect и unprotect с разными типами")
    void testInterleavedProtectUnprotect() throws Exception {
        RecordPair pair = fixedPair();

        byte[] hs = pair.protect(TlsConstants.CT_HANDSHAKE, "handshake".getBytes());
        TlsParsedRecord p1 = pair.unprotect(hs);
        assertEquals(TlsConstants.CT_HANDSHAKE, p1.getContentType());

        byte[] app = pair.protect(TlsConstants.CT_APPLICATION_DATA, "app".getBytes());
        TlsParsedRecord p2 = pair.unprotect(app);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, p2.getContentType());

        byte[] alert = pair.protect(TlsConstants.CT_ALERT, new byte[]{1, 0});
        TlsParsedRecord p3 = pair.unprotect(alert);
        assertEquals(TlsConstants.CT_ALERT, p3.getContentType());
    }

    // -----------------------------------------------------------------------
    // MGM nonce: MSB clearing (RFC 9058 §3, RFC 9367 §3.3)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("MGM nonce: MSB первого байта очищается (nonce[0] & 0x7F)")
    void testNonceMsbCleared() {
        // IV с установленным MSB (0xFF) — buildNonce должен очистить его
        TlsRecord record = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] ivWithMsb = new byte[16];
        Arrays.fill(ivWithMsb, (byte) 0xCD);
        ivWithMsb[0] = (byte) 0xFF;

        record.buildNonce(ivWithMsb);
        assertEquals(0x7F, record.buildNoncePeek() & 0xFF,
                "MSB не очищен: nonce[0] должен быть 0x7F");

        // SeqNum с битом 63: после XOR MSB мог бы восстановиться, но buildNonce очищает после
        record.setSequenceNumber(Long.MAX_VALUE);
        record.buildNonce(ivWithMsb);
        assertEquals(0x7F, record.buildNoncePeek() & 0xFF,
                "MSB должен быть очищен даже после XOR с seqNum, у которого бит 63=1");
    }

    @Test
    @DisplayName("MGM nonce: разные seqNum дают разные nonce при одинаковом IV")
    void testNonceDifferentSeqNums() {
        TlsRecord record = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] iv = fixedIv();

        record.setSequenceNumber(0);
        record.buildNonce(iv);
        byte[] nonce0 = record.buildNoncePeekAll();

        record.setSequenceNumber(1);
        record.buildNonce(iv);
        byte[] nonce1 = record.buildNoncePeekAll();

        assertFalse(Arrays.equals(nonce0, nonce1));
    }

    // -----------------------------------------------------------------------
    // S-вариант cipher suite: SNMAX = 0x3FFFFFFFFFF
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("S-вариант: protect/unprotect roundtrip")
    void testSnmaxSProtectUnprotect() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord writer = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        TlsRecord reader = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        byte[] data = "S-variant data".getBytes();
        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);
        TlsParsedRecord parsed = reader.unprotect(record);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(data, parsed.getData());
    }

    @Test
    @DisplayName("S-вариант: SNMAX = 0x3FFFFFFFFFF → переполнение")
    void testSnmaxSOverflow() {
        TlsRecord record = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        // SNMAX = 0x3FFFFFFFFFF; protect при seqNum = SNMAX - 1 должен пройти
        record.setSequenceNumber(0x3FFFFFFFFFEL);
        assertDoesNotThrow(() -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{1}));
        // seqNum стал = 0x3FFFFFFFFFF, protect при seqNum >= SNMAX должен бросить
        assertThrows(IllegalStateException.class,
                () -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{1}));
    }

    @Test
    @DisplayName("S-вариант: SNMAX exhaustion через unprotect")
    void testSnmaxSUnprotectOverflow() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord writer = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        writer.setSequenceNumber(0x3FFFFFFFFFEL);
        byte[] data = new byte[]{42};
        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);

        TlsRecord reader = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        reader.setSequenceNumber(0x3FFFFFFFFFEL);
        TlsParsedRecord parsed = reader.unprotect(record);
        assertArrayEquals(data, parsed.getData());

        assertThrows(IllegalStateException.class,
                () -> reader.unprotect(record));
    }

    @Test
    @DisplayName("S-вариант: seqNum=0 roundtrip")
    void testSnmaxSSeqNumZero() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord writer = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        TlsRecord reader = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        byte[] data = new byte[]{0};
        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);
        TlsParsedRecord parsed = reader.unprotect(record);
        assertArrayEquals(data, parsed.getData());
    }

    @Test
    @DisplayName("S-вариант: seqNum=7 и seqNum=8 дают разные ключи (граница C3)")
    void testSVariantC3Boundary() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord rec = new TlsRecord(key, iv, 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        rec.setSequenceNumber(7);
        byte[] data7 = rec.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{1});
        rec.setSequenceNumber(8);
        byte[] data8 = rec.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{1});
        assertFalse(Arrays.equals(data7, data8),
                "seqNum 7 и 8 должны давать разные ciphertext (C3 boundary для S)");
    }

    // -----------------------------------------------------------------------
    // Формат записи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("структура защищённой записи соответствует TLS 1.3")
    void testRecordStructure() {
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] data = new byte[10];
        RNG.nextBytes(data);

        byte[] protectedRecord = writer.protect(
                TlsConstants.CT_APPLICATION_DATA, data);

        assertEquals(TlsConstants.CT_APPLICATION_DATA, protectedRecord[0]);
        assertEquals(TlsConstants.LEGACY_VERSION_MAJOR, protectedRecord[1]);
        assertEquals(TlsConstants.LEGACY_VERSION_MINOR, protectedRecord[2]);

        int payloadLen = ((protectedRecord[3] & 0xFF) << 8) | (protectedRecord[4] & 0xFF);
        int innerLen = data.length + 1;
        assertEquals(innerLen + 16, payloadLen);
    }

    @Test
    @DisplayName("сериализация seqNum как big-endian в nonce")
    void testSeqNumEncodingInNonce() {
        byte[] zeroIv = new byte[16];
        byte[] key = fixedKey();

        TlsRecord record = new TlsRecord(key, zeroIv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

        byte[] data = "test".getBytes();
        byte[] ct0 = record.protect(TlsConstants.CT_HANDSHAKE, data);
        byte[] ct1 = record.protect(TlsConstants.CT_HANDSHAKE, data);
        byte[] ct2 = record.protect(TlsConstants.CT_HANDSHAKE, data);

        assertFalse(Arrays.equals(ct0, ct1));
        assertFalse(Arrays.equals(ct1, ct2));
    }

    // -----------------------------------------------------------------------
    // Inner plaintext: нулевые байты данных
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("unprotect: внутренний plaintext с нулевыми байтами данных")
    void testZeroBytesInData() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = new byte[]{0x00, 0x00, 0x00};
        byte[] record = pair.protect(TlsConstants.CT_APPLICATION_DATA, data);
        TlsParsedRecord parsed = pair.unprotect(record);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(data, parsed.getData());
    }

    // -----------------------------------------------------------------------
    // Последовательный номер (seqNum) на границе Long.MAX_VALUE
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("seqNum = Long.MAX_VALUE: protect/unprotect roundtrip")
    void testSeqNumMaxValueRoundtrip() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord writer = new TlsRecord(key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord reader = new TlsRecord(key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

        writer.setSequenceNumber(Long.MAX_VALUE);
        reader.setSequenceNumber(Long.MAX_VALUE);

        byte[] data = "hello".getBytes();
        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);

        TlsParsedRecord parsed = reader.unprotect(record);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(data, parsed.getData());
    }

    @Test
    @DisplayName("seqNum overflow: после Long.MAX_VALUE бросает IllegalStateException")
    void testSeqNumOverflowThrows() {
        TlsRecord record = new TlsRecord(fixedKey(), fixedIv(), 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        record.setSequenceNumber(Long.MAX_VALUE);

        assertDoesNotThrow(() -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{1}));

        assertThrows(IllegalStateException.class,
                () -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{1}));
    }

    // -----------------------------------------------------------------------
    // offset/len overload (regression: protect without Arrays.copyOfRange)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("protect(ct, data) и protect(ct, data, 0, data.length) идентичны")
    void testProtectOverloadMatch() {
        byte[] data = new byte[100];
        RNG.nextBytes(data);

        TlsRecord r1 = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord r2 = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

        byte[] record1 = r1.protect(TlsConstants.CT_APPLICATION_DATA, data);
        byte[] record2 = r2.protect(TlsConstants.CT_APPLICATION_DATA, data, 0, data.length);

        assertArrayEquals(record1, record2);
    }

    @Test
    @DisplayName("protect(ct, data, offset, len) с подмассивом")
    void testProtectSubarray() throws Exception {
        RecordPair pair = fixedPair();
        byte[] full = new byte[200];
        RNG.nextBytes(full);

        byte[] subExpected = Arrays.copyOfRange(full, 50, 150);
        byte[] record = pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, full, 50, 100);
        TlsParsedRecord parsed = pair.reader.unprotect(record);

        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(subExpected, parsed.getData());
    }

    @Test
    @DisplayName("protect с некорректными offset/len бросает IllegalArgumentException")
    void testProtectInvalidOffsetLen() {
        TlsRecord rec = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] data = new byte[50];

        assertThrows(IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, -1, 10));
        assertThrows(IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, 0, -1));
        assertThrows(IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, 40, 20));
        assertThrows(IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, 0, 51));
    }

    // -----------------------------------------------------------------------
    // ByteBuffer-перегрузки (для JSSE)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("ByteBuffer protect/unprotect: handshake roundtrip")
    void testByteBufferProtectUnprotectHandshake() throws Exception {
        RecordPair pair = newPair();
        byte[] data = "привет от клиента".getBytes("UTF-8");

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.RECORD_HEADER_SIZE + data.length + 1 + 16 + 64);

        int written = pair.writer.protect(TlsConstants.CT_HANDSHAKE, src, dst);
        assertTrue(written > 0, "Должны быть записаны байты в dst");
        assertEquals(0, src.remaining(), "src должен быть полностью прочитан");

        dst.flip();
        ByteBuffer plain = ByteBuffer.allocate(data.length + 64);
        byte ct = pair.reader.unprotect(dst, plain);

        assertEquals(TlsConstants.CT_HANDSHAKE, ct);
        plain.flip();
        byte[] result = new byte[plain.remaining()];
        plain.get(result);
        assertArrayEquals(data, result);
    }

    @Test
    @DisplayName("ByteBuffer protect/unprotect: пустые данные")
    void testByteBufferEmptyData() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[0];

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(256);

        pair.writer.protect(TlsConstants.CT_ALERT, src, dst);
        dst.flip();

        ByteBuffer plain = ByteBuffer.allocate(64);
        byte ct = pair.reader.unprotect(dst, plain);
        assertEquals(TlsConstants.CT_ALERT, ct);
        plain.flip();
        assertEquals(0, plain.remaining(), "Пустые данные — 0 байт после unprotect");
    }

    @Test
    @DisplayName("ByteBuffer protect/unprotect: максимальный размер")
    void testByteBufferMaxSize() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH - 1];
        RNG.nextBytes(data);

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(
                TlsConstants.RECORD_HEADER_SIZE + data.length + 1 + 16 + 64);

        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();

        ByteBuffer plain = ByteBuffer.allocate(data.length + 64);
        byte ct = pair.reader.unprotect(dst, plain);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, ct);
        plain.flip();
        byte[] result = new byte[plain.remaining()];
        plain.get(result);
        assertArrayEquals(data, result);
    }

    @Test
    @DisplayName("ByteBuffer protect: недостаточный dst кидает IllegalArgumentException")
    void testByteBufferDstTooSmall() {
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ByteBuffer src = ByteBuffer.wrap(new byte[]{1, 2, 3});
        ByteBuffer dst = ByteBuffer.allocate(2);

        assertThrows(IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, src, dst));
    }

    @Test
    @DisplayName("ByteBuffer protect: null буферы кидают исключение")
    void testByteBufferNullBuffers() {
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ByteBuffer buf = ByteBuffer.allocate(64);

        assertThrows(IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, null, buf));
        assertThrows(IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, buf, null));
    }

    @Test
    @DisplayName("ByteBuffer unprotect: подмена ciphertext кидает AuthenticationException")
    void testByteBufferTamperedCiphertext() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "test".getBytes();

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(256);
        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();

        // Подменяем байт в ciphertext (после 5-байтового заголовка)
        byte[] tampered = new byte[dst.remaining()];
        dst.get(tampered);
        tampered[5 + 3] ^= 0xFF;

        ByteBuffer tamperedBuf = ByteBuffer.wrap(tampered);
        ByteBuffer plain = ByteBuffer.allocate(64);

        assertThrows(AuthenticationException.class,
                () -> pair.reader.unprotect(tamperedBuf, plain));
    }

    @Test
    @DisplayName("ByteBuffer unprotect: недостаточный plaintext кидает исключение")
    void testByteBufferPlaintextTooSmall() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[100];
        RNG.nextBytes(data);

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(256);
        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();

        ByteBuffer smallPlain = ByteBuffer.allocate(1);
        assertThrows(IllegalArgumentException.class,
                () -> pair.reader.unprotect(dst, smallPlain));
    }

    @Test
    @DisplayName("ByteBuffer unprotect: null буферы кидают исключение")
    void testByteBufferUnprotectNull() {
        TlsRecord reader = new TlsRecord(fixedKey(), fixedIv(), 16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ByteBuffer buf = ByteBuffer.allocate(64);

        assertThrows(IllegalArgumentException.class,
                () -> reader.unprotect(null, buf));
        assertThrows(IllegalArgumentException.class,
                () -> reader.unprotect(buf, null));
    }
}
