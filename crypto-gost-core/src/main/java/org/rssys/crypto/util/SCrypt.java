package org.rssys.crypto.util;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Реализация функции выработки ключа на основе пароля scrypt (RFC 7914).
 *
 * <p>scrypt — memory-hard KDF, спроектированная для противодействия
 * атакам с использованием специализированного оборудования (ASIC, GPU).
 * Использует PBKDF2-HmacSHA256 в качестве внутреннего PRF.
 *
 * <p>ЭТО ЕДИНСТВЕННЫЙ КЛАСС ВО ВСЁМ ПРОЕКТЕ, ГДЕ ИСПОЛЬЗУЕТСЯ СТОРОННЯЯ
 * КРИПТОГРАФИЯ (JCA {@code HmacSHA256} и рукописная Salsa20/8 из RFC 7914).
 * Продиктовано спецификацией scrypt (RFC 7914), которая по определению
 * требует SHA-256. Во всех остальных модулях библиотеки криптография —
 * строго через {@code org.rssys.gost.*}.
 *
 * <h3>Параметры по умолчанию в {@code KeyGenerator.deriveKey}:</h3>
 * <pre>
 *   N      = 131072 (2¹⁷)  — параметр стоимости CPU/памяти
 *   r      = 8             — размер блока
 *   p      = 1             — параллелизм
 *   dkLen  = 32            — длина ключа для ГОСТ-алгоритмов (256 бит)
 * </pre>
 * Памяти нужно 128·N·r байт (при этих значениях 128 МиБ одним массивом); N выбирают по бюджету памяти
 * и времени: не ниже минимума OWASP (2¹⁷ при r = 8, p = 1) и не больше, чем выдерживает устройство.
 *
 * <h3>Замечания по безопасности:</h3>
 * <ul>
 *   <li><b>Очистка пароля:</b> {@code passwd} — это массив, переданный вызывающим кодом.
 *       {@code SCrypt.generate()} не обнуляет его — это ответственность вызывающего.
 *       После вызова рекомендуется: {@code Arrays.fill(passwd, (byte) 0)}.</li>
 *   <li><b>Сравнение производных ключей:</b> для сравнения результата с эталоном
 *       используйте {@code MessageDigest.isEqual(derived, expected)} вместо
 *       {@code Arrays.equals} — первый выполняется за constant-time и защищает
 *       от timing-атак на уровне приложения.</li>
 *   <li><b>Промежуточные буферы:</b> рабочие буферы B, XY, V, X обнуляются в блоке
 *       {@code finally} после завершения вычисления.</li>
 * </ul>
 *
 * <p>Ссылки:
 * <ul>
 *   <li>RFC 7914: https://www.rfc-editor.org/rfc/rfc7914</li>
 * </ul>
 */
public class SCrypt {

    /** Чтение и запись 32-битных слов little-endian прямо в массиве байт (RFC 7914 §3). */
    private static final VarHandle INT_LE =
            MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

    /** Чтение и запись 64-битных слов для побайтового XOR блоками по 8 байт. */
    private static final VarHandle LONG_LE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

    /** Размер блока Salsa20/8 в байтах. */
    private static final int SALSA_BLOCK = 64;

    /**
     * Вырабатывает ключ на основе пароля по алгоритму scrypt.
     *
     * @param passwd  пароль в виде байтового массива; не обнуляется методом —
     *                очистка после вызова возлагается на вызывающий код
     * @param salt    соль (рекомендуется случайная, не менее 16 байт)
     * @param N       параметр стоимости CPU/памяти; должен быть степенью 2, больше 1
     * @param r       размер блока (рекомендуется 8)
     * @param p       параметр параллелизма (рекомендуется 1–4)
     * @param dkLen   длина выходного ключа в байтах (рекомендуется 32 для ГОСТ)
     * @return производный ключ длиной {@code dkLen} байт
     * @throws IllegalArgumentException если параметры не удовлетворяют ограничениям
     * @throws GeneralSecurityException если HMAC-SHA256 недоступен в JCA
     */
    public static byte[] generate(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen)
            throws GeneralSecurityException {

        // --- валидация параметров (по образцу RFC 7914 §2 и BouncyCastle) ---
        if (passwd == null) throw new IllegalArgumentException("passwd must not be null");
        if (salt == null) throw new IllegalArgumentException("salt must not be null");
        if (N < 2 || (N & (N - 1)) != 0)
            throw new IllegalArgumentException("N must be a power of 2 greater than 1");
        if (r < 1) throw new IllegalArgumentException("r must be >= 1");
        if (p < 1) throw new IllegalArgumentException("p must be >= 1");
        if (dkLen < 1) throw new IllegalArgumentException("dkLen must be >= 1");
        if (N > Integer.MAX_VALUE / 128 / r) throw new IllegalArgumentException("N is too large");
        if (r > Integer.MAX_VALUE / 128 / p) throw new IllegalArgumentException("r is too large");

        // ЕДИНСТВЕННОЕ место в проекте, где используется сторонняя криптография (JCA HmacSHA256).
        // Спецификация scrypt (RFC 7914) требует SHA-256 как PRF — иного пути нет.
        // см. crypto-gost-core/doc/adr/adr-05.md
        Mac mac = Mac.getInstance("HmacSHA256");
        // JCA не принимает ключ нулевой длины. Пустой пароль заменяем массивом {0x00} —
        // это соответствует поведению RFC 2104 §2 (ключ дополняется нулями до длины блока)
        // и совместимо с OpenSSL/Python scrypt для вектора RFC 7914 §12.1.
        // Примечание: SecretKeySpec копирует passwd внутри — оригинальный массив
        // не сохраняется в mac после init(). Очистка passwd — ответственность вызывающего.
        byte[] macKey = (passwd.length == 0) ? new byte[] {0} : passwd;
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));

        byte[] DK = new byte[dkLen];

        // Рабочие буферы — обнуляются в finally для минимизации времени жизни
        // промежуточного ключевого материала в heap
        byte[] B = new byte[128 * r * p];
        byte[] XY = new byte[256 * r];
        byte[] V = new byte[128 * r * N];
        // Рабочий блок BlockMix: один на весь вызов, а не по массиву на каждый из 2·N вызовов
        byte[] X = new byte[SALSA_BLOCK];

        try {
            // Шаг 1: PBKDF2 для инициализации буфера B из пароля и соли
            pbkdf2(mac, salt, 1, B, p * 128 * r);

            // Шаг 2: smix для каждого из p блоков — основная memory-hard функция
            for (int i = 0; i < p; i++) {
                smix(B, i * 128 * r, r, N, V, XY, X);
            }

            // Шаг 3: финальный PBKDF2 для получения производного ключа из B
            pbkdf2(mac, B, 1, DK, dkLen);

        } finally {
            // Обнуляем промежуточные буферы независимо от результата (в т.ч. при исключении).
            // V — самый большой буфер (128·r·N байт), содержит memory-hard таблицу.
            Arrays.fill(B, (byte) 0);
            Arrays.fill(XY, (byte) 0);
            Arrays.fill(V, (byte) 0);
            Arrays.fill(X, (byte) 0);
        }

        return DK;
    }

    // -----------------------------------------------------------------------
    // smix — основная функция scrypt (RFC 7914 §5)
    // -----------------------------------------------------------------------

    private static void smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY, byte[] X) {
        int Xi = 0;
        int Yi = 128 * r;

        System.arraycopy(B, Bi, XY, Xi, 128 * r);

        // Фаза 1: заполняем V последовательными применениями BlockMix-Salsa8
        for (int i = 0; i < N; i++) {
            System.arraycopy(XY, Xi, V, i * 128 * r, 128 * r);
            blockmixSalsa8(XY, Xi, Yi, r, X);
        }

        // Фаза 2: псевдослучайные обращения к V (memory-hard часть)
        for (int i = 0; i < N; i++) {
            int j = integerify(XY, Xi, r) & (N - 1);
            blockxor(V, j * 128 * r, XY, Xi, 128 * r);
            blockmixSalsa8(XY, Xi, Yi, r, X);
        }

        System.arraycopy(XY, Xi, B, Bi, 128 * r);
    }

    // -----------------------------------------------------------------------
    // BlockMix-Salsa20/8 (RFC 7914 §4)
    // -----------------------------------------------------------------------

    private static void blockmixSalsa8(byte[] BY, int Bi, int Yi, int r, byte[] X) {
        System.arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

        for (int i = 0; i < 2 * r; i++) {
            blockxor(BY, i * 64 + Bi, X, 0, 64);
            salsa20_8(X);
            System.arraycopy(X, 0, BY, Yi + i * 64, 64);
        }

        for (int i = 0; i < r; i++) {
            System.arraycopy(BY, Yi + i * 2 * 64, BY, Bi + i * 64, 64);
            System.arraycopy(BY, Yi + i * 2 * 64 + 64, BY, Bi + (i + r) * 64, 64);
        }
    }

    // -----------------------------------------------------------------------
    // Salsa20/8 (8 раундов, RFC 7914 §3)
    // -----------------------------------------------------------------------

    private static void salsa20_8(byte[] B) {
        // 32 локальные переменные вместо двух массивов int[16]: функция вызывается 2·N·2r раз
        // за вычисление, и массивы на каждый вызов давали гигабайты мусора. Значения живут в
        // регистрах и стеке, затирать нечего.
        int j0 = (int) INT_LE.get(B, 0);
        int j1 = (int) INT_LE.get(B, 4);
        int j2 = (int) INT_LE.get(B, 8);
        int j3 = (int) INT_LE.get(B, 12);
        int j4 = (int) INT_LE.get(B, 16);
        int j5 = (int) INT_LE.get(B, 20);
        int j6 = (int) INT_LE.get(B, 24);
        int j7 = (int) INT_LE.get(B, 28);
        int j8 = (int) INT_LE.get(B, 32);
        int j9 = (int) INT_LE.get(B, 36);
        int j10 = (int) INT_LE.get(B, 40);
        int j11 = (int) INT_LE.get(B, 44);
        int j12 = (int) INT_LE.get(B, 48);
        int j13 = (int) INT_LE.get(B, 52);
        int j14 = (int) INT_LE.get(B, 56);
        int j15 = (int) INT_LE.get(B, 60);

        int x0 = j0;
        int x1 = j1;
        int x2 = j2;
        int x3 = j3;
        int x4 = j4;
        int x5 = j5;
        int x6 = j6;
        int x7 = j7;
        int x8 = j8;
        int x9 = j9;
        int x10 = j10;
        int x11 = j11;
        int x12 = j12;
        int x13 = j13;
        int x14 = j14;
        int x15 = j15;

        // 8 раундов (4 пары: column + row)
        for (int i = 0; i < 4; i++) {
            x4 ^= R(x0 + x12, 7);
            x8 ^= R(x4 + x0, 9);
            x12 ^= R(x8 + x4, 13);
            x0 ^= R(x12 + x8, 18);
            x9 ^= R(x5 + x1, 7);
            x13 ^= R(x9 + x5, 9);
            x1 ^= R(x13 + x9, 13);
            x5 ^= R(x1 + x13, 18);
            x14 ^= R(x10 + x6, 7);
            x2 ^= R(x14 + x10, 9);
            x6 ^= R(x2 + x14, 13);
            x10 ^= R(x6 + x2, 18);
            x3 ^= R(x15 + x11, 7);
            x7 ^= R(x3 + x15, 9);
            x11 ^= R(x7 + x3, 13);
            x15 ^= R(x11 + x7, 18);
            x1 ^= R(x0 + x3, 7);
            x2 ^= R(x1 + x0, 9);
            x3 ^= R(x2 + x1, 13);
            x0 ^= R(x3 + x2, 18);
            x6 ^= R(x5 + x4, 7);
            x7 ^= R(x6 + x5, 9);
            x4 ^= R(x7 + x6, 13);
            x5 ^= R(x4 + x7, 18);
            x11 ^= R(x10 + x9, 7);
            x8 ^= R(x11 + x10, 9);
            x9 ^= R(x8 + x11, 13);
            x10 ^= R(x9 + x8, 18);
            x12 ^= R(x15 + x14, 7);
            x13 ^= R(x12 + x15, 9);
            x14 ^= R(x13 + x12, 13);
            x15 ^= R(x14 + x13, 18);
        }

        INT_LE.set(B, 0, j0 + x0);
        INT_LE.set(B, 4, j1 + x1);
        INT_LE.set(B, 8, j2 + x2);
        INT_LE.set(B, 12, j3 + x3);
        INT_LE.set(B, 16, j4 + x4);
        INT_LE.set(B, 20, j5 + x5);
        INT_LE.set(B, 24, j6 + x6);
        INT_LE.set(B, 28, j7 + x7);
        INT_LE.set(B, 32, j8 + x8);
        INT_LE.set(B, 36, j9 + x9);
        INT_LE.set(B, 40, j10 + x10);
        INT_LE.set(B, 44, j11 + x11);
        INT_LE.set(B, 48, j12 + x12);
        INT_LE.set(B, 52, j13 + x13);
        INT_LE.set(B, 56, j14 + x14);
        INT_LE.set(B, 60, j15 + x15);
    }

    /** Циклический сдвиг влево на b бит. */
    private static int R(int a, int b) {
        return (a << b) | (a >>> (32 - b));
    }

    /** XOR len байт из S[Si..] в D[Di..]; len кратно 8. */
    private static void blockxor(byte[] S, int Si, byte[] D, int Di, int len) {
        // len всегда кратно 64 (блок Salsa20/8 или 128·r), поэтому идём словами по 8 байт
        for (int i = 0; i < len; i += Long.BYTES) {
            LONG_LE.set(D, Di + i, (long) LONG_LE.get(D, Di + i) ^ (long) LONG_LE.get(S, Si + i));
        }
    }

    /**
     * Integerify: читает последний 64-байтный блок X как little-endian int
     * для псевдослучайного выбора индекса в V (RFC 7914 §5, шаг 8).
     */
    private static int integerify(byte[] B, int Bi, int r) {
        int n = (2 * r - 1) * 64 + Bi;
        return (int) INT_LE.get(B, n);
    }

    // -----------------------------------------------------------------------
    // PBKDF2-HmacSHA256 (RFC 7914 §2, RFC 2898 §5.2)
    //
    // Вычисляет dkLen байт производного ключа за c итераций.
    // В scrypt c=1 (одна итерация), что допустимо поскольку память-hard
    // компонент (smix) обеспечивает стойкость против перебора.
    //
    // Примечание: mac.doFinal() по спецификации JCA автоматически вызывает
    // reset() после завершения — mac готов к следующему использованию
    // с тем же ключом без явного сброса состояния.
    // -----------------------------------------------------------------------

    private static void pbkdf2(Mac mac, byte[] S, int c, byte[] DK, int dkLen)
            throws GeneralSecurityException {

        int hLen = mac.getMacLength();
        int l = (int) Math.ceil((double) dkLen / hLen);
        int r = dkLen - (l - 1) * hLen;

        byte[] U = new byte[hLen];
        byte[] T = new byte[hLen];
        byte[] tmp = new byte[S.length + 4];

        System.arraycopy(S, 0, tmp, 0, S.length);

        try {
            for (int i = 1; i <= l; i++) {
                // Кодируем номер блока i как big-endian int (RFC 2898 §5.2, шаг 3)
                tmp[S.length] = (byte) (i >> 24 & 0xff);
                tmp[S.length + 1] = (byte) (i >> 16 & 0xff);
                tmp[S.length + 2] = (byte) (i >> 8 & 0xff);
                tmp[S.length + 3] = (byte) (i & 0xff);

                mac.update(tmp);
                mac.doFinal(U, 0); // doFinal автоматически сбрасывает mac
                System.arraycopy(U, 0, T, 0, hLen);

                for (int j = 1; j < c; j++) {
                    mac.update(U);
                    mac.doFinal(U, 0);
                    for (int k = 0; k < hLen; k++) T[k] ^= U[k];
                }

                int destLen = (i == l) ? r : hLen;
                System.arraycopy(T, 0, DK, (i - 1) * hLen, destLen);
            }
        } finally {
            // Обнуляем промежуточные буферы, содержащие производный ключевой материал
            Arrays.fill(U, (byte) 0);
            Arrays.fill(T, (byte) 0);
            Arrays.fill(tmp, (byte) 0);
        }
    }
}
