package org.rssys.gost.tls13.record;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.pkix.cert.PkixCertTestHelper.hex;
import static org.rssys.gost.pkix.cert.PkixCertTestHelper.hexStr;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.crypto.TlsTree;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты TlsRecord — уровень записей TLS 1.3 с MGM AEAD (RFC 8446 §5).
 * Проверяет protect/unprotect, sequence numbers, аутентификацию, ошибки.
 */
@DisplayName("TlsRecord — уровень записей TLS 1.3")
class TlsRecordTest {

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        return key;
    }

    private static byte[] randomIv() {
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
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
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    private static RecordPair fixedPair() {
        return new RecordPair(
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
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

        byte[] protectedRecord = pair.protect(TlsConstants.CT_HANDSHAKE, handshakeData);
        assertNotNull(protectedRecord);

        assertEquals(
                TlsConstants.RECORD_HEADER_SIZE + handshakeData.length + 1 + 16,
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
        CryptoRandom.INSTANCE.nextBytes(appData);

        byte[] protectedRecord = pair.protect(TlsConstants.CT_APPLICATION_DATA, appData);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(appData, parsed.getData());
    }

    @Test
    @DisplayName("защита/расшифровка алерта")
    void testProtectUnprotectAlert() throws Exception {
        RecordPair pair = newPair();
        byte[] alertData = new byte[] {1, 40};

        byte[] protectedRecord = pair.protect(TlsConstants.CT_ALERT, alertData);

        TlsParsedRecord parsed = pair.unprotect(protectedRecord);
        assertEquals(TlsConstants.CT_ALERT, parsed.getContentType());
        assertArrayEquals(alertData, parsed.getData());
    }

    @Test
    @DisplayName("protect/unprotect пустых данных")
    void testProtectUnprotectEmptyData() throws Exception {
        RecordPair pair = newPair();
        byte[] emptyData = new byte[0];

        byte[] protectedRecord = pair.protect(TlsConstants.CT_HANDSHAKE, emptyData);

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
        CryptoRandom.INSTANCE.nextBytes(maxData);

        byte[] protectedRecord = pair.protect(TlsConstants.CT_APPLICATION_DATA, maxData);

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
        TlsRecord writer =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertEquals(0, writer.getSequenceNumber());

        writer.protect(TlsConstants.CT_HANDSHAKE, new byte[] {1, 2, 3});
        assertEquals(1, writer.getSequenceNumber());

        writer.protect(TlsConstants.CT_HANDSHAKE, new byte[] {4, 5, 6});
        assertEquals(2, writer.getSequenceNumber());
    }

    @Test
    @DisplayName("порядковый номер reader увеличивается после unprotect")
    void testSequenceNumberIncrementsOnUnprotect() throws Exception {
        RecordPair pair = fixedPair();

        byte[] rec = pair.protect(TlsConstants.CT_HANDSHAKE, new byte[] {1});

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

        TlsRecord r0 =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord r1 =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        r1.setSequenceNumber(1);

        byte[] ct0 = r0.protect(TlsConstants.CT_HANDSHAKE, data);
        byte[] ct1 = r1.protect(TlsConstants.CT_HANDSHAKE, data);

        assertFalse(
                Arrays.equals(
                        Arrays.copyOfRange(ct0, 5, ct0.length),
                        Arrays.copyOfRange(ct1, 5, ct1.length)));
    }

    // -----------------------------------------------------------------------
    // Детерминированность
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("детерминированное шифрование при одинаковых параметрах")
    void testDeterministicEncryption() {
        byte[] data = "deterministic".getBytes();

        TlsRecord w1 =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord w2 =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

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

        byte[] protectedRecord = pair.protect(TlsConstants.CT_APPLICATION_DATA, data);

        protectedRecord[TlsConstants.RECORD_HEADER_SIZE + 4] ^= 0x42;

        assertThrows(AuthenticationException.class, () -> pair.unprotect(protectedRecord));
    }

    @Test
    @DisplayName("подмена tag вызывает AuthenticationException")
    void testTamperedTagThrows() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "important data".getBytes();

        byte[] protectedRecord = pair.protect(TlsConstants.CT_APPLICATION_DATA, data);

        protectedRecord[protectedRecord.length - 1] ^= 0xFF;

        assertThrows(AuthenticationException.class, () -> pair.unprotect(protectedRecord));
    }

    @Test
    @DisplayName("подмена внешнего типа в заголовке: unexpected_message (RFC 8446 §5.2, §5)")
    void testTamperedHeaderThrows() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = "data".getBytes();

        byte[] protectedRecord = pair.protect(TlsConstants.CT_HANDSHAKE, data);

        protectedRecord[0] = TlsConstants.CT_ALERT;

        TlsException error =
                assertThrows(TlsException.class, () -> pair.unprotect(protectedRecord));
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                error.getAlertCode(),
                "Внешний тип не application_data: неожиданная запись, а не ошибка проверки");
    }

    @Test
    @DisplayName(
            "внешний тип не application_data отвергается по заголовку во всех вариантах unprotect")
    void testUnexpectedOuterTypeRejectedByHeaderInAllVariants() throws Exception {
        for (byte outerType :
                new byte[] {
                    TlsConstants.CT_ALERT,
                    TlsConstants.CT_HANDSHAKE,
                    TlsConstants.CT_CHANGE_CIPHER_SPEC
                }) {
            for (int payloadLength : new int[] {0, 2, 40}) {
                byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + payloadLength];
                record[0] = outerType;
                record[1] = 3;
                record[2] = 3;
                record[3] = (byte) (payloadLength >>> 8);
                record[4] = (byte) payloadLength;
                String reason = "тип " + outerType + ", длина " + payloadLength;

                TlsException viaArray =
                        assertThrows(
                                TlsException.class, () -> fixedPair().unprotect(record), reason);
                TlsException viaInto =
                        assertThrows(
                                TlsException.class,
                                () -> fixedPair().reader.unprotectInto(record, new byte[64], 0),
                                reason);
                // для заголовка из одних 5 байт и неполной записи ответ тот же, без ожидания тела
                ByteBuffer partial = ByteBuffer.wrap(record, 0, TlsConstants.RECORD_HEADER_SIZE);
                TlsException viaBuffer =
                        assertThrows(
                                TlsException.class,
                                () ->
                                        fixedPair()
                                                .reader
                                                .unprotect(partial, ByteBuffer.allocate(64)),
                                reason);
                for (TlsException error : new TlsException[] {viaArray, viaInto, viaBuffer}) {
                    assertEquals(
                            TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode(), reason);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Некорректные записи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("подлинная запись без типа содержимого: unexpected_message, а не ошибка проверки")
    void testAuthenticRecordWithoutContentTypeIsUnexpectedMessage() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsRecord writer = new TlsRecord(fixedKey(), fixedIv(), 16, suite);
        TlsRecord reader = new TlsRecord(fixedKey(), fixedIv(), 16, suite);
        // Тип 0 и нулевые данные: весь внутренний открытый текст из нулей, тег при этом верен
        byte[] record = writer.protect((byte) 0, new byte[] {0});

        TlsException error = assertThrows(TlsException.class, () -> reader.unprotect(record));

        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                error.getAlertCode(),
                "Запись без типа содержимого подлинна, ответ должен быть unexpected_message");
    }

    @Test
    @DisplayName("слишком короткая запись вызывает исключение")
    void testRecordTooShortThrows() {
        TlsRecord reader =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] tooShort = new byte[TlsConstants.RECORD_HEADER_SIZE + 1];
        // внешний тип должен быть верным, иначе запись отвергается раньше по типу
        tooShort[0] = TlsConstants.CT_APPLICATION_DATA;

        TlsException error = assertThrows(TlsException.class, () -> reader.unprotect(tooShort));
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                error.getAlertCode(),
                "Слишком короткая запись должна давать decode_error, а не ошибку вызова");
    }

    @Test
    @DisplayName("null данные в protect вызывают исключение")
    void testNullDataInProtectThrows() {
        TlsRecord writer =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(
                IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, null));
    }

    @Test
    @DisplayName("слишком большой фрагмент вызывает исключение")
    void testOversizedDataThrows() {
        TlsRecord writer =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] tooBig = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH];

        assertThrows(
                IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, tooBig));
    }

    @Test
    @DisplayName("null запись в unprotect вызывает исключение")
    void testNullRecordInUnprotectThrows() {
        TlsRecord reader =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalArgumentException.class, () -> reader.unprotect(null));
    }

    // -----------------------------------------------------------------------
    // Некорректные параметры конструктора
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("конструктор: ключ null")
    void testConstructorNullKeyThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsRecord(
                                null,
                                fixedIv(),
                                16,
                                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    @Test
    @DisplayName("конструктор: ключ неверной длины")
    void testConstructorWrongKeyLengthThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsRecord(
                                new byte[16],
                                fixedIv(),
                                16,
                                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    @Test
    @DisplayName("конструктор: IV неверной длины")
    void testConstructorWrongIvLengthThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsRecord(
                                fixedKey(),
                                new byte[8],
                                16,
                                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    @Test
    @DisplayName("конструктор: неверная длина тега")
    void testConstructorInvalidTagLenThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsRecord(
                                fixedKey(),
                                fixedIv(),
                                0,
                                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
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
            byte[] protectedRecord = pair.protect(TlsConstants.CT_APPLICATION_DATA, data);

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

        byte[] alert = pair.protect(TlsConstants.CT_ALERT, new byte[] {1, 0});
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
        TlsRecord record =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] ivWithMsb = new byte[16];
        Arrays.fill(ivWithMsb, (byte) 0xCD);
        ivWithMsb[0] = (byte) 0xFF;

        record.buildNonce(ivWithMsb);
        assertEquals(
                0x7F, record.buildNoncePeek() & 0xFF, "MSB не очищен: nonce[0] должен быть 0x7F");

        // Номер записи со всеми установленными битами (включая бит 63) затрагивает только байты
        // 8..15 nonce и старший бит nonce[0] не восстанавливает
        record.setSequenceNumber(-1L);
        record.buildNonce(ivWithMsb);
        assertEquals(
                0x7F,
                record.buildNoncePeek() & 0xFF,
                "MSB должен оставаться очищенным и при seqNum со всеми битами 1");
    }

    @Test
    @DisplayName("MGM nonce: разные seqNum дают разные nonce при одинаковом IV")
    void testNonceDifferentSeqNums() {
        TlsRecord record =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
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
        TlsRecord writer =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        TlsRecord reader =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        byte[] data = "S-variant data".getBytes();
        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);
        TlsParsedRecord parsed = reader.unprotect(record);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(data, parsed.getData());
    }

    @Test
    @DisplayName("S-вариант: SNMAX = 0x3FFFFFFFFFF -> переполнение")
    void testSnmaxSOverflow() {
        TlsRecord record =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        // SNMAX = 0x3FFFFFFFFFF; protect при seqNum = SNMAX - 1 должен пройти
        record.setSequenceNumber(0x3FFFFFFFFFEL);
        assertDoesNotThrow(() -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}));
        // seqNum стал = 0x3FFFFFFFFFF, protect при seqNum >= SNMAX должен бросить
        assertThrows(
                IllegalStateException.class,
                () -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}));
    }

    @Test
    @DisplayName("S-вариант: SNMAX exhaustion через unprotect")
    void testSnmaxSUnprotectOverflow() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord writer =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        writer.setSequenceNumber(0x3FFFFFFFFFEL);
        byte[] data = new byte[] {42};
        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);

        TlsRecord reader =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        reader.setSequenceNumber(0x3FFFFFFFFFEL);
        TlsParsedRecord parsed = reader.unprotect(record);
        assertArrayEquals(data, parsed.getData());

        assertThrows(IllegalStateException.class, () -> reader.unprotect(record));
    }

    // -----------------------------------------------------------------------
    // Формат записи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("структура защищённой записи соответствует TLS 1.3")
    void testRecordStructure() {
        TlsRecord writer =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] data = new byte[10];
        CryptoRandom.INSTANCE.nextBytes(data);

        byte[] protectedRecord = writer.protect(TlsConstants.CT_APPLICATION_DATA, data);

        assertEquals(TlsConstants.CT_APPLICATION_DATA, protectedRecord[0]);
        assertEquals(TlsConstants.LEGACY_VERSION_MAJOR, protectedRecord[1]);
        assertEquals(TlsConstants.LEGACY_VERSION_MINOR, protectedRecord[2]);

        int payloadLen = ((protectedRecord[3] & 0xFF) << 8) | (protectedRecord[4] & 0xFF);
        int innerLen = data.length + 1;
        assertEquals(innerLen + 16, payloadLen);
    }

    @Test
    @DisplayName("nonce: номер записи big-endian в байтах 8..15 IV, старший бит nonce очищен")
    void testSeqNumEncodingInNonce() {
        // Эталон выписан вручную (RFC 8446 §5.3: nonce = IV XOR (0^8 || seq), big-endian; очистка
        // старшего бита для MGM по RFC 9058 §3 и RFC 9367 §3.3), а не получен повтором цикла из
        // buildNonce. IV с установленным старшим битом: проверяется и очистка бита
        byte[] iv = {
            (byte) 0xFF,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            (byte) 0x88,
            (byte) 0x99,
            (byte) 0xAA,
            (byte) 0xBB,
            (byte) 0xCC,
            (byte) 0xDD,
            (byte) 0xEE,
            (byte) 0xFF
        };
        // seq = 01 02 03 04 05 06 07 08: затронуты все байты 8..15
        byte[] expectedWide = {
            0x7F,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            (byte) 0x89,
            (byte) 0x9B,
            (byte) 0xA9,
            (byte) 0xBF,
            (byte) 0xC9,
            (byte) 0xDB,
            (byte) 0xE9,
            (byte) 0xF7
        };
        // seq = 0xFF: затронут только последний байт (0xFF ^ 0xFF = 0x00)
        byte[] expectedNarrow = {
            0x7F,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            (byte) 0x88,
            (byte) 0x99,
            (byte) 0xAA,
            (byte) 0xBB,
            (byte) 0xCC,
            (byte) 0xDD,
            (byte) 0xEE,
            0x00
        };

        assertArrayEquals(expectedWide, nonceFor(iv, 0x0102030405060708L), "широкий номер записи");
        assertArrayEquals(expectedNarrow, nonceFor(iv, 0xFFL), "номер записи в младшем байте");
    }

    private byte[] nonceFor(byte[] iv, long seqNum) {
        TlsRecord record =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        record.setSequenceNumber(seqNum);
        record.buildNonce(iv);
        return record.buildNoncePeekAll();
    }

    // -----------------------------------------------------------------------
    // Inner plaintext: нулевые байты данных
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("unprotect: внутренний plaintext с нулевыми байтами данных")
    void testZeroBytesInData() throws Exception {
        RecordPair pair = fixedPair();
        byte[] data = new byte[] {0x00, 0x00, 0x00};
        byte[] record = pair.protect(TlsConstants.CT_APPLICATION_DATA, data);
        TlsParsedRecord parsed = pair.unprotect(record);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(data, parsed.getData());
    }

    // -----------------------------------------------------------------------
    // Последовательный номер (seqNum) на границе Long.MAX_VALUE
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("seqNum = Long.MAX_VALUE: обратимость защита/расшифровка")
    void testSeqNumMaxValueRoundtrip() throws Exception {
        byte[] key = fixedKey();
        byte[] iv = fixedIv();
        TlsRecord writer =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord reader =
                new TlsRecord(
                        key, iv, 16, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

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
        TlsRecord record =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        record.setSequenceNumber(Long.MAX_VALUE);

        assertDoesNotThrow(() -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}));

        assertThrows(
                IllegalStateException.class,
                () -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}));
    }

    // -----------------------------------------------------------------------
    // offset/len overload (regression: protect without Arrays.copyOfRange)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("protect(ct, data) и protect(ct, data, 0, data.length) идентичны")
    void testProtectOverloadMatch() {
        byte[] data = new byte[100];
        CryptoRandom.INSTANCE.nextBytes(data);

        TlsRecord r1 =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsRecord r2 =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
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
        CryptoRandom.INSTANCE.nextBytes(full);

        byte[] subExpected = Arrays.copyOfRange(full, 50, 150);
        byte[] record = pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, full, 50, 100);
        TlsParsedRecord parsed = pair.reader.unprotect(record);

        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(subExpected, parsed.getData());
    }

    @Test
    @DisplayName("protect с некорректными offset/len бросает IllegalArgumentException")
    void testProtectInvalidOffsetLen() {
        TlsRecord rec =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] data = new byte[50];

        assertThrows(
                IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, -1, 10));
        assertThrows(
                IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, 0, -1));
        assertThrows(
                IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, 40, 20));
        assertThrows(
                IllegalArgumentException.class,
                () -> rec.protect(TlsConstants.CT_APPLICATION_DATA, data, 0, 51));
    }

    // -----------------------------------------------------------------------
    // ByteBuffer-перегрузки (для JSSE)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("ByteBuffer защита/расшифровка: обратимость handshake (UnprotectResult)")
    void testByteBufferProtectUnprotectHandshake() throws Exception {
        RecordPair pair = newPair();
        byte[] data = "привет от клиента".getBytes("UTF-8");

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst =
                ByteBuffer.allocate(TlsConstants.RECORD_HEADER_SIZE + data.length + 1 + 16 + 64);

        int written = pair.writer.protect(TlsConstants.CT_HANDSHAKE, src, dst);
        assertTrue(written > 0, "Должны быть записаны байты в dst");
        assertEquals(0, src.remaining(), "src должен быть полностью прочитан");

        dst.flip();
        ByteBuffer plain = ByteBuffer.allocate(data.length + 64);
        UnprotectResult r = pair.reader.unprotect(dst, plain);

        assertSame(UnprotectResult.Status.OK, r.status);
        assertEquals(TlsConstants.CT_HANDSHAKE, r.contentType);
        assertEquals(0, r.hint);
        plain.flip();
        byte[] result = new byte[plain.remaining()];
        plain.get(result);
        assertArrayEquals(data, result);
    }

    @Test
    @DisplayName("ByteBuffer protect/unprotect: пустые данные (UnprotectResult)")
    void testByteBufferEmptyData() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[0];

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(256);

        pair.writer.protect(TlsConstants.CT_ALERT, src, dst);
        dst.flip();

        ByteBuffer plain = ByteBuffer.allocate(64);
        UnprotectResult r = pair.reader.unprotect(dst, plain);
        assertSame(UnprotectResult.Status.OK, r.status);
        assertEquals(TlsConstants.CT_ALERT, r.contentType);
        assertEquals(0, r.hint);
        plain.flip();
        assertEquals(0, plain.remaining(), "Пустые данные — 0 байт после unprotect");
    }

    @Test
    @DisplayName("ByteBuffer protect/unprotect: максимальный размер (UnprotectResult)")
    void testByteBufferMaxSize() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH - 1];
        CryptoRandom.INSTANCE.nextBytes(data);

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst =
                ByteBuffer.allocate(TlsConstants.RECORD_HEADER_SIZE + data.length + 1 + 16 + 64);

        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();

        ByteBuffer plain = ByteBuffer.allocate(data.length + 64);
        UnprotectResult r = pair.reader.unprotect(dst, plain);
        assertSame(UnprotectResult.Status.OK, r.status);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, r.contentType);
        assertEquals(0, r.hint);
        plain.flip();
        byte[] result = new byte[plain.remaining()];
        plain.get(result);
        assertArrayEquals(data, result);
    }

    @Test
    @DisplayName("ByteBuffer protect: недостаточный dst кидает IllegalArgumentException")
    void testByteBufferDstTooSmall() {
        TlsRecord writer =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ByteBuffer src = ByteBuffer.wrap(new byte[] {1, 2, 3});
        ByteBuffer dst = ByteBuffer.allocate(2);

        assertThrows(
                IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, src, dst));
    }

    // -----------------------------------------------------------------------
    // Regression: защита записи с известными key/IV (первичный прогон -> эталон)
    // -----------------------------------------------------------------------

    // Regression fixture: protect(CT_HANDSHAKE, {0x08,0x00,0x00,0x02,0x00,0x00})
    // key = SWK_HS (RFC 9367 A.1.2), iv = SIV_HS, seqNum=0, tagLen=16, cipher suite S
    // Внутренний plaintext: 6 байт данных + 0x16 (CT_HANDSHAKE) = 7 байт innerLen
    // Full record = header(5) || ciphertext(7) || tag(16) = 28 байт
    private static final byte[] RECORD_FIXTURE_KEY =
            hex("E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01");
    private static final byte[] RECORD_FIXTURE_IV = hex("6969FFAAA4525281EEBBEB4CBD0B640E");
    private static final byte[] RECORD_FIXTURE_PLAINTEXT =
            new byte[] {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};

    // Первичный прогон -> эталон. Заменить при изменении формата записи/криптоалгоритмов.
    // Regression only — не KAT (RFC 9367 не содержит полные record vectors для protect).
    // Вектор: protect(CT_HANDSHAKE, {0x08,0x00,0x00,0x02,0x00,0x00})
    // Key=SWK_HS, IV=SIV_HS (RFC 9367 A.1.2), seqNum=0, tagLen=16, cipher suite S
    // header(5) || ciphertext(7) || tag(16) = 28 байт
    private static final byte[] RECORD_FIXTURE_EXPECTED =
            hex("1703030017940E5D2C753AE5FEBD20012CC9E3EB24A379841E02ABBE");

    @Test
    @DisplayName("protect: regression — ByteBuffer protect с известными key/IV")
    void testByteBufferProtectRegression() {
        TlsRecord rec =
                new TlsRecord(
                        RECORD_FIXTURE_KEY,
                        RECORD_FIXTURE_IV,
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        ByteBuffer src = ByteBuffer.wrap(RECORD_FIXTURE_PLAINTEXT);
        ByteBuffer dst = ByteBuffer.allocate(128);
        int written = rec.protect(TlsConstants.CT_HANDSHAKE, src, dst);
        dst.flip();
        byte[] actual = new byte[written];
        dst.get(actual);
        assertArrayEquals(RECORD_FIXTURE_EXPECTED, actual, () -> "Получено: " + hexStr(actual));
    }

    @Test
    @DisplayName("protect: byte[] и ByteBuffer overloads дают одинаковый результат")
    void testProtectOverloadsMatch() {
        TlsRecord rec =
                new TlsRecord(
                        RECORD_FIXTURE_KEY,
                        RECORD_FIXTURE_IV,
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        byte[] data = new byte[50];
        CryptoRandom.INSTANCE.nextBytes(data);

        byte[] fromByteArray = rec.protect(TlsConstants.CT_APPLICATION_DATA, data);

        TlsRecord rec2 =
                new TlsRecord(
                        RECORD_FIXTURE_KEY,
                        RECORD_FIXTURE_IV,
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(128);
        rec2.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();
        byte[] fromByteBuffer = new byte[dst.remaining()];
        dst.get(fromByteBuffer);

        assertArrayEquals(fromByteArray, fromByteBuffer);
    }

    @Test
    @DisplayName("ByteBuffer protect: src.position сдвинут, dst.position сдвинут")
    void testByteBufferProtectPositions() {
        TlsRecord rec =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] data = new byte[] {1, 2, 3, 4, 5};
        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(128);
        assertEquals(0, src.position());
        assertEquals(0, dst.position());

        int written = rec.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);

        assertEquals(data.length, src.position(), "src должен быть полностью прочитан");
        assertEquals(
                written, dst.position(), "position должен равняться количеству записанных байт");
        assertEquals(0, src.remaining(), "src должен быть пуст");
    }

    @Test
    @DisplayName("ByteBuffer protect: null буферы кидают исключение")
    void testByteBufferNullBuffers() {
        TlsRecord writer =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ByteBuffer buf = ByteBuffer.allocate(64);

        assertThrows(
                IllegalArgumentException.class,
                () -> writer.protect(TlsConstants.CT_HANDSHAKE, null, buf));
        assertThrows(
                IllegalArgumentException.class,
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

        assertThrows(
                AuthenticationException.class, () -> pair.reader.unprotect(tamperedBuf, plain));
    }

    @Test
    @DisplayName("ByteBuffer расшифровка: OUTPUT_TOO_SMALL — подсказка + откат")
    void testByteBufferUnprotectOutputTooSmall() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[100];
        CryptoRandom.INSTANCE.nextBytes(data);

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(256);
        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();

        int posBefore = dst.position();
        ByteBuffer smallPlain = ByteBuffer.allocate(1);
        UnprotectResult r = pair.reader.unprotect(dst, smallPlain);

        assertSame(UnprotectResult.Status.OUTPUT_TOO_SMALL, r.status);
        assertTrue(r.hint > 0, "hint должен указывать минимальный размер plaintext");
        assertEquals(posBefore, dst.position(), "position record должен быть восстановлен");
    }

    @Test
    @DisplayName(
            "Предел на открытый текст: запись приложения сверх предела не потребляется, номер цел")
    void testApplicationDataLimitKeepsRecordAndSequence() throws Exception {
        RecordPair pair = newPair();
        byte[] first = new byte[100];
        byte[] second = new byte[10];
        CryptoRandom.INSTANCE.nextBytes(first);
        CryptoRandom.INSTANCE.nextBytes(second);
        ByteBuffer wire = ByteBuffer.allocate(512);
        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, ByteBuffer.wrap(first), wire);
        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, ByteBuffer.wrap(second), wire);
        wire.flip();
        int posBefore = wire.position();
        long sequenceBefore = pair.reader.getSequenceNumber();

        ByteBuffer plain = ByteBuffer.allocate(256);
        UnprotectResult tooSmall = pair.reader.unprotect(wire, plain, first.length - 1);

        assertSame(UnprotectResult.Status.OUTPUT_TOO_SMALL, tooSmall.status);
        assertEquals(first.length, tooSmall.hint, "hint = нужный размер открытого текста");
        assertEquals(posBefore, wire.position(), "запись не потреблена");
        assertEquals(0, plain.position(), "в приёмник ничего не записано");
        assertEquals(sequenceBefore, pair.reader.getSequenceNumber(), "номер записи не сдвинут");

        // Повтор с достаточным пределом расшифровывает ту же запись, следом идёт вторая
        UnprotectResult ok = pair.reader.unprotect(wire, plain, first.length);
        assertSame(UnprotectResult.Status.OK, ok.status);
        plain.flip();
        byte[] got = new byte[plain.remaining()];
        plain.get(got);
        assertArrayEquals(first, got, "первая запись целиком");
        plain.clear();
        assertSame(
                UnprotectResult.Status.OK,
                pair.reader.unprotect(wire, plain, second.length).status,
                "вторая запись читается: номер записи не терялся");
    }

    @Test
    @DisplayName("Отрицательный предел на открытый текст отвергается")
    void testNegativeApplicationDataLimitRejected() {
        RecordPair pair = newPair();

        assertThrows(
                IllegalArgumentException.class,
                () -> pair.reader.unprotect(ByteBuffer.allocate(0), ByteBuffer.allocate(16), -1));
    }

    @Test
    @DisplayName("Предел на открытый текст не действует на записи рукопожатия")
    void testApplicationDataLimitDoesNotApplyToHandshake() throws Exception {
        RecordPair pair = newPair();
        byte[] body = new byte[100];
        CryptoRandom.INSTANCE.nextBytes(body);
        ByteBuffer wire = ByteBuffer.allocate(256);
        pair.writer.protect(TlsConstants.CT_HANDSHAKE, ByteBuffer.wrap(body), wire);
        wire.flip();

        UnprotectResult r = pair.reader.unprotect(wire, ByteBuffer.allocate(256), 0);

        assertSame(UnprotectResult.Status.OK, r.status, "рукопожатие принимается при пределе 0");
        assertEquals(TlsConstants.CT_HANDSHAKE, r.contentType);
    }

    @Test
    @DisplayName("ByteBuffer unprotect: NEED_MORE_INPUT — недостаточно байт для заголовка")
    void testByteBufferUnprotectUnderflowHeader() throws Exception {
        RecordPair pair = newPair();

        // Менее 5 байт — не хватает даже на заголовок
        ByteBuffer tooShort = ByteBuffer.wrap(new byte[] {0x17, 0x03, 0x03});
        int posBefore = tooShort.position();
        ByteBuffer plain = ByteBuffer.allocate(64);

        UnprotectResult r = pair.reader.unprotect(tooShort, plain);

        assertSame(UnprotectResult.Status.NEED_MORE_INPUT, r.status);
        assertEquals(
                TlsConstants.RECORD_HEADER_SIZE, r.hint, "hint = минимальный размер заголовка");
        assertEquals(posBefore, tooShort.position(), "position НЕ должен измениться");
    }

    @Test
    @DisplayName("ByteBuffer unprotect: NEED_MORE_INPUT — заголовок есть, body неполный")
    void testByteBufferUnprotectUnderflowBody() throws Exception {
        RecordPair pair = newPair();

        // Полный заголовок (declaredLen=20, т.е. ciphertext+tag=20) + всего 4 байта body
        // totalRecordLen = 5 + 20 = 25, но в буфере только 9 -> NEED_MORE_INPUT с hint=25
        ByteBuffer partial = ByteBuffer.allocate(9);
        partial.put(new byte[] {0x17, 0x03, 0x03, 0x00, 0x14}); // length=20
        partial.put(new byte[] {1, 2, 3, 4});
        partial.flip();

        int posBefore = partial.position();
        ByteBuffer plain = ByteBuffer.allocate(64);

        UnprotectResult r = pair.reader.unprotect(partial, plain);

        assertSame(UnprotectResult.Status.NEED_MORE_INPUT, r.status);
        // totalRecordLen = 5 + 20 = 25
        assertEquals(25, r.hint, "hint = точная полная длина записи");
        assertEquals(posBefore, partial.position(), "position НЕ должен измениться");
    }

    @Test
    @DisplayName("ByteBuffer расшифровка: OK — успех после повтора после OUTPUT_TOO_SMALL")
    void testByteBufferUnprotectRetryAfterOutputTooSmall() throws Exception {
        RecordPair pair = newPair();
        byte[] data = new byte[50];
        CryptoRandom.INSTANCE.nextBytes(data);

        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer dst = ByteBuffer.allocate(256);
        pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
        dst.flip();

        int posBefore = dst.position();

        // First call: OUTPUT_TOO_SMALL
        ByteBuffer smallPlain = ByteBuffer.allocate(1);
        UnprotectResult r1 = pair.reader.unprotect(dst, smallPlain);
        assertSame(UnprotectResult.Status.OUTPUT_TOO_SMALL, r1.status);

        // Retry with large enough buffer
        assertEquals(posBefore, dst.position(), "position восстановлен после rollback");
        ByteBuffer bigPlain = ByteBuffer.allocate(256);
        UnprotectResult r2 = pair.reader.unprotect(dst, bigPlain);
        assertSame(UnprotectResult.Status.OK, r2.status);

        bigPlain.flip();
        byte[] result = new byte[bigPlain.remaining()];
        bigPlain.get(result);
        assertArrayEquals(data, result);
    }

    @Test
    @DisplayName("ByteBuffer unprotect: reuse — 3 последовательных, нет stale-data")
    void testByteBufferUnprotectReuse() throws Exception {
        // Три записи разного размера через один TlsRecord — проверка что recordBuf reuse
        // не оставляет stale tail от предыдущей записи в данных следующей.
        byte[] small = new byte[] {1, 2, 3};
        byte[] large = new byte[200];
        CryptoRandom.INSTANCE.nextBytes(large);
        byte[] medium = new byte[50];
        CryptoRandom.INSTANCE.nextBytes(medium);

        RecordPair pair = newPair();
        for (byte[] data : new byte[][] {large, medium, small}) {
            ByteBuffer src = ByteBuffer.wrap(data);
            ByteBuffer dst = ByteBuffer.allocate(256);
            pair.writer.protect(TlsConstants.CT_APPLICATION_DATA, src, dst);
            dst.flip();

            ByteBuffer plain = ByteBuffer.allocate(256);
            UnprotectResult r = pair.reader.unprotect(dst, plain);
            assertSame(UnprotectResult.Status.OK, r.status);
            plain.flip();
            byte[] result = new byte[plain.remaining()];
            plain.get(result);
            assertArrayEquals(data, result);
        }
    }

    @Test
    @DisplayName("ByteBuffer unprotect: null буферы кидают исключение")
    void testByteBufferUnprotectNull() {
        TlsRecord reader =
                new TlsRecord(
                        fixedKey(),
                        fixedIv(),
                        16,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ByteBuffer buf = ByteBuffer.allocate(64);

        assertThrows(IllegalArgumentException.class, () -> reader.unprotect(null, buf));
        assertThrows(IllegalArgumentException.class, () -> reader.unprotect(buf, null));
    }

    @Test
    @DisplayName("padding: TLSInnerPlaintext на границе maxInnerPlaintext(16624) проходит")
    void testPaddingAtBoundaryAccepted() throws Exception {
        int tagLen = 16;
        int dataLen = 16383;
        int paddingLen = 240;
        int innerLen = dataLen + paddingLen + 1; // data + zeros + content_type
        int payloadLen = innerLen + tagLen;

        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        byte[] key = fixedKey();
        byte[] iv = fixedIv();

        // Создаём reader для проверки расшифровки
        TlsRecord reader = new TlsRecord(key, iv, tagLen, suite);

        // Nonce при seqNum=0 = IV с очищенным MSB (у fixedIv уже MSB=0)
        byte[] nonce = iv.clone();
        nonce[0] &= 0x7F;

        // Per-record ключ через TLSTREE для seqNum=0
        byte[] perRecordKey = TlsTree.tlstree(key, 0, suite.getC1(), suite.getC2(), suite.getC3());

        // Собираем TLSInnerPlaintext по RFC 8446 §5.2: данные || content_type || padding_zeros
        byte[] innerPlaintext = new byte[innerLen];
        byte[] data = new byte[dataLen];
        CryptoRandom.INSTANCE.nextBytes(data);
        System.arraycopy(data, 0, innerPlaintext, 0, dataLen);
        innerPlaintext[dataLen] = TlsConstants.CT_APPLICATION_DATA;

        // AAD: outer_content_type || legacy_version || payload_length
        byte[] aad = new byte[5];
        aad[0] = TlsConstants.CT_APPLICATION_DATA;
        aad[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        aad[2] = TlsConstants.LEGACY_VERSION_MINOR;
        aad[3] = (byte) (payloadLen >>> 8);
        aad[4] = (byte) payloadLen;

        // Шифруем через MGM
        Kuznyechik kuz = new Kuznyechik();
        Mgm mgm = new Mgm(kuz, tagLen);
        SymmetricKey symKey = new SymmetricKey(perRecordKey);
        mgm.init(true, new ParametersWithIV(symKey, nonce));
        symKey.destroy();

        mgm.updateAAD(aad, 0, aad.length);
        byte[] ciphertext = new byte[innerLen];
        mgm.processBytes(innerPlaintext, 0, innerLen, ciphertext, 0);
        byte[] tag = new byte[tagLen];
        mgm.finishEncryption(tag, 0);

        // Собираем TLS-запись: header || ciphertext || tag
        int recordLen = TlsConstants.RECORD_HEADER_SIZE + payloadLen;
        byte[] record = new byte[recordLen];
        record[0] = TlsConstants.CT_APPLICATION_DATA;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (payloadLen >>> 8);
        record[4] = (byte) payloadLen;
        System.arraycopy(ciphertext, 0, record, TlsConstants.RECORD_HEADER_SIZE, innerLen);
        System.arraycopy(tag, 0, record, TlsConstants.RECORD_HEADER_SIZE + innerLen, tagLen);

        // Расшифровка — должна пройти без ALERT_RECORD_OVERFLOW
        TlsParsedRecord parsed = reader.unprotect(record);
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                parsed.getContentType(),
                "Тип содержимого должен совпадать");
        assertArrayEquals(
                data, parsed.getData(), "Расшифрованные данные должны совпадать с исходными");
    }

    private record PaddedRecord(byte[] wire, byte[] data) {}

    /** Подлинная запись с заданной длиной содержимого и нулевым padding, собранная вручную. */
    private static PaddedRecord paddedRecord(int dataLen, int paddingLen) throws Exception {
        int tagLen = 16;
        int innerLen = dataLen + paddingLen + 1;
        int payloadLen = innerLen + tagLen;

        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        byte[] key = fixedKey();
        byte[] iv = fixedIv();

        byte[] nonce = iv.clone();
        nonce[0] &= 0x7F;

        byte[] perRecordKey = TlsTree.tlstree(key, 0, suite.getC1(), suite.getC2(), suite.getC3());

        byte[] innerPlaintext = new byte[innerLen];
        byte[] data = new byte[dataLen];
        CryptoRandom.INSTANCE.nextBytes(data);
        System.arraycopy(data, 0, innerPlaintext, 0, dataLen);
        innerPlaintext[dataLen] = TlsConstants.CT_APPLICATION_DATA;

        byte[] aad = new byte[5];
        aad[0] = TlsConstants.CT_APPLICATION_DATA;
        aad[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        aad[2] = TlsConstants.LEGACY_VERSION_MINOR;
        aad[3] = (byte) (payloadLen >>> 8);
        aad[4] = (byte) payloadLen;

        Kuznyechik kuz = new Kuznyechik();
        Mgm mgm = new Mgm(kuz, tagLen);
        SymmetricKey symKey = new SymmetricKey(perRecordKey);
        mgm.init(true, new ParametersWithIV(symKey, nonce));
        symKey.destroy();

        mgm.updateAAD(aad, 0, aad.length);
        byte[] ciphertext = new byte[innerLen];
        mgm.processBytes(innerPlaintext, 0, innerLen, ciphertext, 0);
        byte[] tag = new byte[tagLen];
        mgm.finishEncryption(tag, 0);

        int recordLen = TlsConstants.RECORD_HEADER_SIZE + payloadLen;
        byte[] record = new byte[recordLen];
        record[0] = TlsConstants.CT_APPLICATION_DATA;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (payloadLen >>> 8);
        record[4] = (byte) payloadLen;
        System.arraycopy(ciphertext, 0, record, TlsConstants.RECORD_HEADER_SIZE, innerLen);
        System.arraycopy(tag, 0, record, TlsConstants.RECORD_HEADER_SIZE + innerLen, tagLen);

        return new PaddedRecord(record, data);
    }

    @ParameterizedTest
    @ValueSource(ints = {240, 250, 255})
    @DisplayName(
            "ByteBuffer unprotect: padding до границы maxInnerPlaintext, содержимое в пределах")
    void testPaddingBoundaryByteBuffer(int paddingLen) throws Exception {
        // Меняется только padding: содержимое остаётся не больше 2^14, шифротекст доходит до
        // предела MAX_CIPHERTEXT_LENGTH
        int dataLen = TlsConstants.MAX_CIPHERTEXT_LENGTH - 16 - paddingLen - 1;
        PaddedRecord record = paddedRecord(dataLen, paddingLen);
        TlsRecord reader = freshFixedReader();

        ByteBuffer plainBuf = ByteBuffer.allocate(dataLen + 64);
        UnprotectResult r = reader.unprotect(ByteBuffer.wrap(record.wire()), plainBuf);

        assertSame(UnprotectResult.Status.OK, r.status);
        assertEquals(TlsConstants.CT_APPLICATION_DATA, r.contentType);
        plainBuf.flip();
        byte[] result = new byte[plainBuf.remaining()];
        plainBuf.get(result);
        assertArrayEquals(record.data(), result);
    }

    @Test
    @DisplayName("Содержимое ровно 2^14 принимается, на байт больше - record_overflow")
    void testContentLengthLimitIsExactlyFourteenBits() throws Exception {
        PaddedRecord atLimit = paddedRecord(TlsConstants.MAX_PLAINTEXT_LENGTH, 0);
        ByteBuffer plain = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH + 64);
        assertSame(
                UnprotectResult.Status.OK,
                freshFixedReader().unprotect(ByteBuffer.wrap(atLimit.wire()), plain).status,
                "RFC 8446 §5.1: содержимое в 2^14 байт допустимо");

        PaddedRecord overLimit = paddedRecord(TlsConstants.MAX_PLAINTEXT_LENGTH + 1, 0);
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () ->
                                freshFixedReader()
                                        .unprotect(
                                                ByteBuffer.wrap(overLimit.wire()),
                                                ByteBuffer.allocate(
                                                        TlsConstants.MAX_PLAINTEXT_LENGTH + 64)));
        assertEquals(
                TlsConstants.ALERT_RECORD_OVERFLOW,
                e.getAlertCode(),
                "Содержимое больше 2^14 - record_overflow, даже если шифротекст в пределах");
    }

    private static TlsRecord freshFixedReader() {
        return new TlsRecord(
                fixedKey(),
                fixedIv(),
                16,
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    @Test
    @DisplayName("превышение MAX_CIPHERTEXT_LENGTH -> ALERT_RECORD_OVERFLOW")
    void testOuterPayloadTooLongRejected() {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsRecord reader = new TlsRecord(fixedKey(), fixedIv(), 16, suite);

        int payloadLen = TlsConstants.MAX_CIPHERTEXT_LENGTH + 1; // 16641
        // doDecrypt проверяет payloadLen > MAX_CIPHERTEXT_LENGTH первой из двух
        // overflow-проверок. Вторая (ciphertextLen > maxInnerPlaintext) физически
        // недостижима: ciphertextLen > maxInnerPlaintext ⇒ payloadLen > MAX_CIPHERTEXT_LENGTH
        // из-за ciphertextLen = payloadLen − tagLen, поэтому всегда срабатывает первая.
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + payloadLen];
        record[0] = TlsConstants.CT_APPLICATION_DATA;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (payloadLen >>> 8);
        record[4] = (byte) payloadLen;

        TlsException ex = assertThrows(TlsException.class, () -> reader.unprotect(record));
        assertTrue(
                ex.getMessage().contains("Record too long"),
                "Сообщение должно указывать на превышение длины");
    }
}
