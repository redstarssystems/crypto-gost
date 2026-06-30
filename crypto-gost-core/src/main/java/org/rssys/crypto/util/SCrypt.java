package org.rssys.crypto.util;

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
 * <h3>Рекомендуемые параметры на 2026 год:</h3>
 * <pre>
 *   N      = 1048576 (2²⁰) — параметр стоимости CPU/памяти
 *   r      = 8             — размер блока
 *   p      = 1             — параллелизм
 *   dkLen  = 32            — длина ключа для ГОСТ-алгоритмов (256 бит)
 * </pre>
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
 *   <li><b>Промежуточные буферы:</b> рабочие буферы B, XY, V обнуляются в блоке
 *       {@code finally} после завершения вычисления.</li>
 * </ul>
 *
 * <p>Ссылки:
 * <ul>
 *   <li>RFC 7914: https://www.rfc-editor.org/rfc/rfc7914</li>
 * </ul>
 */
public class SCrypt {

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

        try {
            // Шаг 1: PBKDF2 для инициализации буфера B из пароля и соли
            pbkdf2(mac, salt, 1, B, p * 128 * r);

            // Шаг 2: smix для каждого из p блоков — основная memory-hard функция
            for (int i = 0; i < p; i++) {
                smix(B, i * 128 * r, r, N, V, XY);
            }

            // Шаг 3: финальный PBKDF2 для получения производного ключа из B
            pbkdf2(mac, B, 1, DK, dkLen);

        } finally {
            // Обнуляем промежуточные буферы независимо от результата (в т.ч. при исключении).
            // V — самый большой буфер (128·r·N байт), содержит memory-hard таблицу.
            Arrays.fill(B, (byte) 0);
            Arrays.fill(XY, (byte) 0);
            Arrays.fill(V, (byte) 0);
        }

        return DK;
    }

    // -----------------------------------------------------------------------
    // smix — основная функция scrypt (RFC 7914 §5)
    // -----------------------------------------------------------------------

    private static void smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY) {
        int Xi = 0;
        int Yi = 128 * r;

        System.arraycopy(B, Bi, XY, Xi, 128 * r);

        // Фаза 1: заполняем V последовательными применениями BlockMix-Salsa8
        for (int i = 0; i < N; i++) {
            System.arraycopy(XY, Xi, V, i * 128 * r, 128 * r);
            blockmixSalsa8(XY, Xi, Yi, r);
        }

        // Фаза 2: псевдослучайные обращения к V (memory-hard часть)
        for (int i = 0; i < N; i++) {
            int j = integerify(XY, Xi, r) & (N - 1);
            blockxor(V, j * 128 * r, XY, Xi, 128 * r);
            blockmixSalsa8(XY, Xi, Yi, r);
        }

        System.arraycopy(XY, Xi, B, Bi, 128 * r);
    }

    // -----------------------------------------------------------------------
    // BlockMix-Salsa20/8 (RFC 7914 §4)
    // -----------------------------------------------------------------------

    private static void blockmixSalsa8(byte[] BY, int Bi, int Yi, int r) {
        byte[] X = new byte[64];
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
        // Читаем входной блок как 16 little-endian int
        int[] B32 = new int[16];
        for (int i = 0; i < 16; i++) {
            int j = i * 4;
            B32[i] =
                    (B[j] & 0xff)
                            | ((B[j + 1] & 0xff) << 8)
                            | ((B[j + 2] & 0xff) << 16)
                            | ((B[j + 3] & 0xff) << 24);
        }

        int[] x = B32.clone();

        // 8 раундов (4 пары: column + row)
        for (int i = 0; i < 4; i++) {
            x[4] ^= R(x[0] + x[12], 7);
            x[8] ^= R(x[4] + x[0], 9);
            x[12] ^= R(x[8] + x[4], 13);
            x[0] ^= R(x[12] + x[8], 18);
            x[9] ^= R(x[5] + x[1], 7);
            x[13] ^= R(x[9] + x[5], 9);
            x[1] ^= R(x[13] + x[9], 13);
            x[5] ^= R(x[1] + x[13], 18);
            x[14] ^= R(x[10] + x[6], 7);
            x[2] ^= R(x[14] + x[10], 9);
            x[6] ^= R(x[2] + x[14], 13);
            x[10] ^= R(x[6] + x[2], 18);
            x[3] ^= R(x[15] + x[11], 7);
            x[7] ^= R(x[3] + x[15], 9);
            x[11] ^= R(x[7] + x[3], 13);
            x[15] ^= R(x[11] + x[7], 18);
            x[1] ^= R(x[0] + x[3], 7);
            x[2] ^= R(x[1] + x[0], 9);
            x[3] ^= R(x[2] + x[1], 13);
            x[0] ^= R(x[3] + x[2], 18);
            x[6] ^= R(x[5] + x[4], 7);
            x[7] ^= R(x[6] + x[5], 9);
            x[4] ^= R(x[7] + x[6], 13);
            x[5] ^= R(x[4] + x[7], 18);
            x[11] ^= R(x[10] + x[9], 7);
            x[8] ^= R(x[11] + x[10], 9);
            x[9] ^= R(x[8] + x[11], 13);
            x[10] ^= R(x[9] + x[8], 18);
            x[12] ^= R(x[15] + x[14], 7);
            x[13] ^= R(x[12] + x[15], 9);
            x[14] ^= R(x[13] + x[12], 13);
            x[15] ^= R(x[14] + x[13], 18);
        }

        for (int i = 0; i < 16; i++) {
            B32[i] += x[i];
        }

        // Записываем результат обратно в little-endian
        for (int i = 0; i < 16; i++) {
            int j = i * 4;
            B[j] = (byte) (B32[i] & 0xff);
            B[j + 1] = (byte) (B32[i] >> 8 & 0xff);
            B[j + 2] = (byte) (B32[i] >> 16 & 0xff);
            B[j + 3] = (byte) (B32[i] >> 24 & 0xff);
        }
    }

    /** Циклический сдвиг влево на b бит. */
    private static int R(int a, int b) {
        return (a << b) | (a >>> (32 - b));
    }

    /** XOR len байт из S[Si..] в D[Di..]. */
    private static void blockxor(byte[] S, int Si, byte[] D, int Di, int len) {
        for (int i = 0; i < len; i++) {
            D[Di + i] ^= S[Si + i];
        }
    }

    /**
     * Integerify: читает последний 64-байтный блок X как little-endian int
     * для псевдослучайного выбора индекса в V (RFC 7914 §5, шаг 8).
     */
    private static int integerify(byte[] B, int Bi, int r) {
        int n = (2 * r - 1) * 64 + Bi;
        return (B[n] & 0xff)
                | ((B[n + 1] & 0xff) << 8)
                | ((B[n + 2] & 0xff) << 16)
                | ((B[n + 3] & 0xff) << 24);
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
