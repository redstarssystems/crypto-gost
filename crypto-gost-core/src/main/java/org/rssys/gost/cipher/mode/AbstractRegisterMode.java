package org.rssys.gost.cipher.mode;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

/**
 * Общая часть режимов с регистром сдвига (CBC, CFB, CTR, OFB по ГОСТ Р 34.13-2015): базовый шифр,
 * регистр R по IV, проверки границ буферов. Побайтовую и пакетную обработку добавляет
 * {@link AbstractStreamCipherMode}: CBC работает только блоками, и потоковых методов у него нет.
 */
abstract class AbstractRegisterMode implements BlockCipher {

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
    // VarHandle для long-based криптоопераций
    // -----------------------------------------------------------------------

    /** VarHandle для чтения/записи long из byte[] в big-endian порядке. */
    protected static final VarHandle LONG_BE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    // -----------------------------------------------------------------------

    protected AbstractRegisterMode(BlockCipher cipher) {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
    }

    // -----------------------------------------------------------------------
    // Управление регистром сдвига
    // -----------------------------------------------------------------------

    /**
     * Инициализирует регистр сдвига из IV.
     * Вызывается из {@code init()} подкласса.
     *
     * <p>Длина регистра m = n·z задаётся длиной IV, где n - размер блока, z >= 1
     * (ГОСТ Р 34.13-2015, режимы CBC, OFB, CFB). IV другой длины не является ни одним из
     * режимов стандарта: регистр сдвигался бы на лишние байты и результат молча расходился бы с
     * эталоном.
     *
     * @throws IllegalArgumentException если длина IV не кратна размеру блока или равна нулю
     */
    protected void initRegister(byte[] iv) {
        if (iv.length == 0 || iv.length % blockSize != 0) {
            throw new IllegalArgumentException(
                    "IV length must be a positive multiple of the block size ("
                            + blockSize
                            + " bytes), got "
                            + iv.length);
        }
        this.m = iv.length;
        this.R = new byte[m];
        this.R_init = new byte[m];
        System.arraycopy(iv, 0, R_init, 0, m);
        System.arraycopy(iv, 0, R, 0, m);
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
     * Обнуляет базовый шифр и затирает регистры сдвига.
     * После вызова экземпляр непригоден для использования.
     */
    @Override
    public void destroy() {
        cipher.destroy();
        if (R != null) {
            Arrays.fill(R, (byte) 0);
            R = null;
        }
        if (R_init != null) {
            Arrays.fill(R_init, (byte) 0);
            R_init = null;
        }
        initialized = false;
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
