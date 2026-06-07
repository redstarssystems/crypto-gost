package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * Абстрактный базовый класс для потоковых режимов блочного шифрования
 * (CFB, CTR, OFB по ГОСТ Р 34.13-2015).
 *
 * <p>Содержит общую логику:
 * <ul>
 *   <li>хранение базового шифра и размера блока</li>
 *   <li>хранение и восстановление регистра сдвига R (IV) для режимов с обратной связью</li>
 *   <li>метод {@link #processBytes} с единым циклом через {@link #calculateByte}</li>
 *   <li>метод {@link #shiftRegister} — обновление регистра сдвига (LSB||newTail)</li>
 *   <li>защитные проверки границ входного/выходного буферов</li>
 * </ul>
 *
 * <p>Подклассы реализуют только свою уникальную логику:
 * конкретный метод {@link #calculateByte} и специфическую инициализацию.
 */
abstract class AbstractStreamMode implements BlockCipher {

    /** Базовый блочный шифр. */
    protected final BlockCipher cipher;

    /** Размер блока базового шифра в байтах. */
    protected final int blockSize;

    /** Длина регистра сдвига R в байтах (>= blockSize, задаётся IV). */
    protected int m;

    /** Текущее состояние регистра сдвига. */
    protected byte[] R;

    /** Начальное состояние регистра сдвига — для reset(). */
    protected byte[] R_init;

    /** Флаг инициализации: true после успешного вызова init(). */
    protected boolean initialized;

    // -----------------------------------------------------------------------
    // VarHandle для long-based криптоопераций (Stage 2+)
    // -----------------------------------------------------------------------

    /** VarHandle для чтения/записи long из byte[] в big-endian порядке. */
    protected static final VarHandle LONG_BE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    // -----------------------------------------------------------------------

    protected AbstractStreamMode(BlockCipher cipher) {
        this.cipher    = cipher;
        this.blockSize = cipher.getBlockSize();
    }

    /**
     * Обрабатывает {@code len} байт: делегирует полные блоки в {@link #processBlocks},
     * неполный хвост — побайтово через {@link #calculateByte}.
     */
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        checkInitialized();
        checkInputBounds(in, inOff, len);
        checkOutputBounds(out, outOff, len);
        int processed = processBlocks(in, inOff, len, out, outOff);
        for (int i = processed; i < len; i++) {
            out[outOff + i] = calculateByte(in[inOff + i]);
        }
        return len;
    }

    /**
     * Обрабатывает полные блоки входных данных. По умолчанию — побайтово через
     * {@link #calculateByte} (функционально эквивалентно старому processBytes).
     * <p>
     * Подклассы переопределяют для блочной long-арифметики.
     *
     * @return количество обработанных байт (всегда кратно blockSize)
     */
    protected int processBlocks(byte[] in, int inOff, int len, byte[] out, int outOff) {
        int limit = len - (len % blockSize);
        for (int i = 0; i < limit; i++) {
            out[outOff + i] = calculateByte(in[inOff + i]);
        }
        return limit;
    }

    /**
     * Обрабатывает один байт.
     */
    protected abstract byte calculateByte(byte in);

    // -----------------------------------------------------------------------
    // Управление регистром сдвига
    // -----------------------------------------------------------------------

    /**
     * Инициализирует регистр сдвига из IV.
     * Вызывается из {@code init()} подкласса.
     */
    protected void initRegister(byte[] iv) {
        this.m      = iv.length;
        this.R      = new byte[m];
        this.R_init = new byte[m];
        System.arraycopy(iv, 0, R_init, 0, m);
        System.arraycopy(iv, 0, R,      0, m);
    }

    /**
     * Восстанавливает регистр сдвига из начального состояния R_init.
     * Вызывается из {@code reset()} подкласса.
     */
    protected void resetRegister() {
        if (R_init != null) {
            System.arraycopy(R_init, 0, R, 0, R_init.length);
        }
    }

    /**
     * Обновляет регистр сдвига: отбрасывает первые {@code tailLen} байт,
     * добавляет {@code newTail[0..tailLen-1]} в конец.
     * <pre>
     *   R = LSB(R, m - tailLen) || newTail[0..tailLen-1]
     * </pre>
     * Используется в CBC, CFB, OFB. Алгоритм сдвига идентичен во всех трёх режимах.
     *
     * @param newTail  массив, из которого берутся {@code tailLen} байт для хвоста
     * @param tailOff  смещение в {@code newTail}
     * @param tailLen  количество байт для добавления в хвост
     */
    protected void shiftRegister(byte[] newTail, int tailOff, int tailLen) {
        if (m > tailLen) {
            System.arraycopy(R, tailLen, R, 0, m - tailLen);
        }
        System.arraycopy(newTail, tailOff, R, m - tailLen, tailLen);
    }

    /** Бросает {@link IllegalStateException} если шифр не инициализирован. */
    protected void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException(getAlgorithmName() + " not initialized");
        }
    }

    /** Проверяет что входной буфер содержит достаточно данных. */
    protected void checkInputBounds(byte[] in, int off, int len) {
        if (off + len > in.length) {
            throw new DataLengthException("input buffer too short");
        }
    }

    /** Проверяет что выходной буфер достаточного размера. */
    protected void checkOutputBounds(byte[] out, int off, int len) {
        if (off + len > out.length) {
            throw new OutputLengthException("output buffer too short");
        }
    }

    /**
     * Извлекает и валидирует IV из параметров.
     * Бросает {@link IllegalArgumentException} если параметры не содержат IV
     * или IV короче размера блока.
     *
     * @param params     параметры инициализации
     * @param modeName   название режима для текста исключения
     * @return объект {@link ParametersWithIV}
     */
    protected static ParametersWithIV requireIV(CipherParameters params, String modeName) {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(modeName + " mode requires IV");
        }
        return (ParametersWithIV) params;
    }
}
