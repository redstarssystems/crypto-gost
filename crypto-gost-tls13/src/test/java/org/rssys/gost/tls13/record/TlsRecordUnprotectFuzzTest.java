package org.rssys.gost.tls13.record;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.util.AuthenticationException;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Fuzz-тесты для {@link TlsRecord#unprotect}.
 * <p>
 * Атакуем уровень записей TLS 1.3: противник шлёт произвольные байты,
 * сервер пытается расшифровать через MGM AEAD. Fuzzer находит баги,
 * которые не ловятся unit-тестами — NPE/AIOOBE в doDecrypt, stale data,
 * состояние последовательности после ошибок.
 * <p>
 * Каждый {@code @FuzzTest} — один entry point. Покрываем ByteBuffer и byte[]
 * перегрузки, а также stateful последовательность (сессия из N записей).
 * <p>
 * ПОЧЕМУ ловим только TlsException|IllegalArgumentException|
 * IllegalStateException|AuthenticationException, а не RuntimeException:
 * TlsRecord НЕ ДОЛЖЕН кидать NPE/AIOOBE на битом входе — это баги.
 * IllegalArgumentException ловим — checkBounds кидает IAE, а не TlsException.
 * AuthenticationException — корректная реакция на подмену ciphertext.
 * IllegalStateException — переполнение seqNum (SNMAX), тоже ожидаемое.
 */
class TlsRecordUnprotectFuzzTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static final int TAG_LEN = 16;
    private static final int MAX_RECORD_SIZE =
            TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH;
    private static final int PLAINTEXT_BUF_SIZE =
            TlsConstants.MAX_PLAINTEXT_LENGTH + 64;

    // ========================================================================
    // P0: Stateless entry points
    // ========================================================================

    /**
     * Основной entry point: {@link TlsRecord#unprotect(ByteBuffer, ByteBuffer)}.
     * Покрывает все 5 стадий автомата + doDecrypt().
     */
    @FuzzTest
    void fuzzByteBufferUnprotect(FuzzedDataProvider data) {
        TlsRecord reader = newReader();
        byte[] input = data.consumeRemainingAsBytes();
        ByteBuffer src = ByteBuffer.wrap(input);
        ByteBuffer plaintext = ByteBuffer.allocate(PLAINTEXT_BUF_SIZE);
        try {
            reader.unprotect(src, plaintext);
        } catch (TlsException | IllegalArgumentException
                | IllegalStateException | AuthenticationException e) {
            // ожидаемо для битого ввода
        }
    }

    /**
     * byte[]-перегрузка {@link TlsRecord#unprotect(byte[])}.
     * Тот же doDecrypt, другой аллокационный путь (TlsParsedRecord).
     */
    @FuzzTest
    void fuzzByteArrayUnprotect(FuzzedDataProvider data) {
        TlsRecord reader = newReader();
        byte[] input = data.consumeRemainingAsBytes();
        try {
            reader.unprotect(input);
        } catch (TlsException | IllegalArgumentException
                | IllegalStateException | AuthenticationException e) {
        }
    }

    /**
     * Zero-alloc перегрузка {@link TlsRecord#unprotectInto(byte[], byte[], int)}.
     * Прямая запись в caller-буфер, без аллокации TlsParsedRecord.
     */
    @FuzzTest
    void fuzzUnprotectInto(FuzzedDataProvider data) {
        TlsRecord reader = newReader();
        byte[] input = data.consumeRemainingAsBytes();
        byte[] dest = new byte[PLAINTEXT_BUF_SIZE];
        try {
            reader.unprotectInto(input, dest, 0);
        } catch (TlsException | IllegalArgumentException
                | IllegalStateException | AuthenticationException e) {
        }
    }

    // ========================================================================
    // P1: Stateful — seqNum растёт между вызовами внутри одной сессии
    // ========================================================================

    /**
     * Сессия из N последовательных unprotect на одном TlsRecord.
     * <p>
     * Состояние между вызовами: seqNum (растёт на каждый OK), TLSTREE
     * per-record key derivation (меняет текущий ключ). Fuzzer находит
     * баги в multi-record взаимодействиях — переполнение seqNum,
     * некорректный re-key, stale данные после ошибки.
     * <p>
     * ЗАЩИТА от consumeInt-исчерпания: проверяем remainingBytes > 5
     * (4 байта на consumeInt + 1 байт минимум тела).
     */
    @FuzzTest
    void fuzzSequentialUnprotect(FuzzedDataProvider data) {
        TlsRecord reader = newReader();
        int calls;
        try {
            calls = Math.max(1, data.consumeInt(1, 32));
        } catch (IllegalArgumentException e) {
            return;
        }
        while (calls-- > 0 && data.remainingBytes() > 5) {
            int size;
            try {
                size = data.consumeInt(5,
                        Math.min(MAX_RECORD_SIZE, data.remainingBytes()));
            } catch (IllegalArgumentException e) {
                break;
            }
            byte[] record = data.consumeBytes(size);
            if (record.length < TlsConstants.RECORD_HEADER_SIZE) continue;
            ByteBuffer src = ByteBuffer.wrap(record);
            ByteBuffer plaintext = ByteBuffer.allocate(PLAINTEXT_BUF_SIZE);
            try {
                reader.unprotect(src, plaintext);
            } catch (TlsException | IllegalArgumentException
                    | IllegalStateException | AuthenticationException e) {
                // seqNum НЕ растёт при ошибке — проверяется следующими вызовами
            }
        }
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    /**
     * Создаёт TlsRecord со свежими копиями ключа/IV.
     * <p>
     * ПОЧЕМУ не static final byte[]: TlsRecord не клонирует массив — он может
     * затереть его через destroy(). Static mutable state нестабилен при
     * параллельном фаззинге. fixedKey()/fixedIv() создают новый массив
     * каждый вызов, сохраняя детерминизм (константное наполнение).
     */
    private static TlsRecord newReader() {
        return new TlsRecord(fixedKey(), fixedIv(), TAG_LEN, SUITE);
    }

    /** Фиксированный ключ: все байты 0xAB. */
    private static byte[] fixedKey() {
        byte[] key = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
        Arrays.fill(key, (byte) 0xAB);
        return key;
    }

    /** Фиксированный IV: все байты 0xCD, кроме iv[0] сброшен MSB. */
    private static byte[] fixedIv() {
        byte[] iv = new byte[TlsConstants.MGM_IV_SIZE];
        Arrays.fill(iv, (byte) 0xCD);
        iv[0] &= 0x7F;
        return iv;
    }
}
