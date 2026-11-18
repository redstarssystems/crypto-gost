package org.rssys.gost.api;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cbc;
import org.rssys.gost.cipher.mode.Cfb;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.cipher.mode.Ofb;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.ISO7816d4Padding;
import org.rssys.gost.util.Pkcs7Padding;

/**
 * API для симметричного шифрования по ГОСТ Р 34.12/34.13-2015.
 *
 * <p>Поддерживаемый шифр: Кузнечик (ГОСТ Р 34.12-2015), ключ 256 бит.
 *
 * <p>Поддерживаемые режимы (ГОСТ Р 34.13-2015):
 * <ul>
 *   <li>{@link Mode#CTR} — режим гаммирования. IV = 8 байт (строго по §4.4).
 *       Не требует padding. Симметричен: encrypt = decrypt.</li>
 *   <li>{@link Mode#CFB} — режим гаммирования с обратной связью по шифртексту. IV по умолчанию
 *       16 байт, явный IV кратен 16 байт.</li>
 *   <li>{@link Mode#OFB} — режим гаммирования с обратной связью по выходу. IV по умолчанию
 *       16 байт, явный IV кратен 16 байт.</li>
 *   <li>{@link Mode#CBC} — режим простой замены с зацеплением. IV по умолчанию 16 байт,
 *       явный IV кратен 16 байт.
 *       Требует данные кратные 16 байт — используйте {@link Padding}.</li>
 * </ul>
 *
 * <h3>Формат выходных данных при вызове encrypt() без явного IV:</h3>
 * <pre>
 *   [IV (8 или 16 байт)] [шифртекст]
 * </pre>
 * Метод {@code decrypt()} автоматически читает IV из начала массива, но только IV по умолчанию
 * (8 байт для CTR, 16 байт для остальных режимов). Для IV длиной m = 2n и более используйте
 * перегрузки с явным IV.
 * При работе с внешними системами, ожидающими чистый шифртекст, используйте
 * другой метод с явным IV.
 *
 * <h3>Padding для CBC:</h3>
 * <ul>
 *   <li>{@link Padding#PKCS7} (по умолчанию) — PKCS#7 (RFC 5652), совместим с Java JCE.</li>
 *   <li>{@link Padding#ISO7816_4} — ISO 7816-4 (0x80 || 0x00...).</li>
 *   <li>{@link Padding#NONE} — без padding; бросает {@link IllegalArgumentException}
 *       если данные не кратны 16 байт.</li>
 * </ul>
 *
 * <p>Для CTR, CFB, OFB параметр {@code Padding} игнорируется — эти режимы
 * работают с данными произвольной длины.
 *
 * <h3>Thread-safety:</h3>
 * Статические методы потокобезопасны.
 * Потоковые обёртки ({@link #encryptingStream}, {@link #decryptingStream})
 * создают новые экземпляры шифра и <b>не являются</b> потокобезопасными.
 *
 */
public final class Cipher {

    /** Блочный размер шифра в байтах (ГОСТ Р 34.12-2015). */
    public static final int BLOCK_SIZE = Kuznyechik.BLOCK_SIZE;

    /** Размер ключа в байтах. */
    public static final int KEY_SIZE = Kuznyechik.KEY_SIZE;

    private Cipher() {}

    public enum Mode {
        /** Режим гаммирования (CTR/GCTR). IV = 8 байт. Не требует padding. */
        CTR,
        /** Режим простой замены с зацеплением (CBC). IV = 16 байт. Требует padding. */
        CBC,
        /** Режим гаммирования с обратной связью по шифртексту (CFB). IV = 16 байт. */
        CFB,
        /** Режим гаммирования с обратной связью по выходу (OFB). IV = 16 байт. */
        OFB
    }

    /**
     * Схема дополнения данных для режима CBC.
     * Для CTR, CFB, OFB этот параметр игнорируется.
     */
    public enum Padding {
        /** PKCS#7 (RFC 5652) — рекомендуется для совместимости с Java JCE. */
        PKCS7,
        /** ISO 7816-4 (0x80 || 0x00...). */
        ISO7816_4,
        /** Без padding. Для CBC бросает исключение если данные не кратны 16. */
        NONE
    }

    // -----------------------------------------------------------------------
    // Блочные методы шифрования
    // -----------------------------------------------------------------------

    /**
     * Шифрует данные. IV = 8 байт для CTR, 16 байт для остальных режимов.
     * Для CBC применяется PKCS7 padding.
     * Возвращает: {@code [IV | шифртекст]}.
     */
    public static byte[] encrypt(byte[] data, SymmetricKey key, Mode mode) {
        return encrypt(data, key, mode, Padding.PKCS7);
    }

    /**
     * Шифрует данные с указанной схемой padding.
     * Возвращает: {@code [IV | шифртекст]}.
     */
    public static byte[] encrypt(byte[] data, SymmetricKey key, Mode mode, Padding padding) {
        byte[] iv = generateIV(mode);
        byte[] ciphertext = encryptWithIV(data, key, iv, mode, padding);
        // Prepend IV: [IV | ciphertext]
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    /**
     * Шифрует данные с явно заданным IV.
     * Возвращает только шифртекст без IV (для совместимости с внешними системами).
     *
     * <p>Требования к IV по ГОСТ Р 34.13-2015:
     * <ul>
     *   <li>CTR: ровно 8 байт</li>
     *   <li>CBC, CFB, OFB: кратно 16 байт (m = n·z, z ≥ 1); IV другой длины отвергается</li>
     * </ul>
     */
    public static byte[] encrypt(byte[] data, SymmetricKey key, byte[] iv, Mode mode) {
        return encrypt(data, key, iv, mode, Padding.PKCS7);
    }

    /**
     * Шифрует данные с явным IV и указанной схемой padding.
     */
    public static byte[] encrypt(
            byte[] data, SymmetricKey key, byte[] iv, Mode mode, Padding padding) {
        return encryptWithIV(data, key, iv, mode, padding);
    }

    /**
     * Расшифровывает данные. Ожидает формат {@code [IV | шифртекст]},
     * где IV извлекается автоматически из начала массива.
     * Для CBC удаляет PKCS7 padding.
     */
    public static byte[] decrypt(byte[] data, SymmetricKey key, Mode mode) {
        return decrypt(data, key, mode, Padding.PKCS7);
    }

    /**
     * Расшифровывает данные с указанной схемой padding.
     * Ожидает формат {@code [IV | шифртекст]}.
     */
    public static byte[] decrypt(byte[] data, SymmetricKey key, Mode mode, Padding padding) {
        int ivLen = ivLength(mode);
        if (data.length < ivLen) {
            throw new IllegalArgumentException(
                    "data too short: expected at least " + ivLen + " bytes for IV");
        }
        byte[] iv = Arrays.copyOfRange(data, 0, ivLen);
        byte[] ciphertext = Arrays.copyOfRange(data, ivLen, data.length);
        return decryptWithIV(ciphertext, key, iv, mode, padding);
    }

    /**
     * Расшифровывает данные с явно заданным IV.
     * Принимает чистый шифртекст без IV.
     */
    public static byte[] decrypt(byte[] ciphertext, SymmetricKey key, byte[] iv, Mode mode) {
        return decrypt(ciphertext, key, iv, mode, Padding.PKCS7);
    }

    /**
     * Расшифровывает данные с явным IV и указанной схемой padding.
     */
    public static byte[] decrypt(
            byte[] ciphertext, SymmetricKey key, byte[] iv, Mode mode, Padding padding) {
        return decryptWithIV(ciphertext, key, iv, mode, padding);
    }

    // -----------------------------------------------------------------------
    // Потоковые методы шифрования
    // -----------------------------------------------------------------------

    /**
     * Создаёт шифрующий выходной поток. IV генерируется автоматически и записывается
     * в {@code out} первым перед шифртекстом.
     *
     * <p><b>Не потокобезопасен.</b> Один поток на одно соединение/файл.
     *
     * @param out  поток выходных данных для записи {@code [IV | шифртекст]}
     * @param key  ключ шифрования
     * @param mode режим шифрования
     * @return шифрующий {@link OutputStream}
     * @throws IOException если не удалось записать IV в {@code out}
     * @throws UnsupportedOperationException если режим не поддерживает потоковую обработку (CBC);
     *     в {@code out} при этом ничего не записывается
     * @throws IllegalArgumentException если ключ не подходит шифру; в {@code out} при этом
     *     ничего не записывается
     */
    public static OutputStream encryptingStream(OutputStream out, SymmetricKey key, Mode mode)
            throws IOException {
        byte[] iv = generateIV(mode);
        // Шифр строится до записи IV: иначе при отказе (CBC, неверный ключ) в поток вызывающего
        // уже ушли бы байты IV, а исключение оставило бы его с «обрезанным» сообщением.
        StreamCipher cipher = initStreamCipher(key, iv, mode, true);
        try {
            out.write(iv); // записываем IV первым
        } catch (IOException | RuntimeException e) {
            cipher.destroy();
            throw e;
        }
        return wrapEncrypting(out, cipher);
    }

    /**
     * Создаёт шифрующий выходной поток вывода с явным указанием IV.
     * IV в поток не записывается — управление на стороне вызывающего.
     *
     * @throws UnsupportedOperationException если режим не поддерживает потоковую обработку (CBC)
     * @throws IllegalArgumentException если ключ или IV не подходят шифру
     */
    public static OutputStream encryptingStream(
            OutputStream out, SymmetricKey key, byte[] iv, Mode mode) throws IOException {
        return wrapEncrypting(out, initStreamCipher(key, iv, mode, true));
    }

    /**
     * Создаёт расшифровывающий входной поток. Читает IV из первых байт {@code in} автоматически.
     *
     * <p><b>Не потокобезопасен.</b>
     *
     * @param in   входной поток данных в формате {@code [IV | шифртекст]}
     * @param key  ключ расшифрования
     * @param mode режим работы шифра
     * @return расшифровывающий {@link InputStream}
     * @throws IOException если не удалось прочитать IV из {@code in}
     * @throws UnsupportedOperationException если режим не поддерживает потоковую обработку (CBC);
     *     из {@code in} при этом ничего не читается
     * @throws IllegalArgumentException если ключ не подходит шифру; из {@code in} при этом
     *     ничего не читается
     */
    public static InputStream decryptingStream(InputStream in, SymmetricKey key, Mode mode)
            throws IOException {
        // Режим и ключ проверяем до чтения IV: иначе при отказе байты IV уже изъяты из потока
        // вызывающего, и повторить попытку с другим режимом или ключом нельзя.
        initStreamCipher(key, new byte[ivLength(mode)], mode, false).destroy();
        // Читаем IV из потока
        int ivLen = ivLength(mode);
        byte[] iv = new byte[ivLen];
        int read = 0;
        while (read < ivLen) {
            int n = in.read(iv, read, ivLen - read);
            if (n < 0) throw new IOException("Stream ended before IV was fully read");
            read += n;
        }
        return wrapDecrypting(in, initStreamCipher(key, iv, mode, false));
    }

    /**
     * Создаёт расшифровывающий поток ввода с явным указанием IV.
     * IV из потока не читается.
     *
     * @throws UnsupportedOperationException если режим не поддерживает потоковую обработку (CBC)
     * @throws IllegalArgumentException если ключ или IV не подходят шифру
     */
    public static InputStream decryptingStream(
            InputStream in, SymmetricKey key, byte[] iv, Mode mode) throws IOException {
        return wrapDecrypting(in, initStreamCipher(key, iv, mode, false));
    }

    // -----------------------------------------------------------------------
    // Внутренние вспомогательные методы
    // -----------------------------------------------------------------------

    /** Генерирует случайный IV нужной длины для заданного режима. */
    private static byte[] generateIV(Mode mode) {
        byte[] iv = new byte[ivLength(mode)];
        CryptoRandom.INSTANCE.nextBytes(iv);
        return iv;
    }

    /**
     * Длина IV по ГОСТ Р 34.13-2015:
     * CTR  — n/2 = 8 байт; CBC, CFB, OFB — n = 16 байт.
     */
    private static int ivLength(Mode mode) {
        return (mode == Mode.CTR) ? BLOCK_SIZE / 2 : BLOCK_SIZE;
    }

    /** Применяет padding для CBC или проверяет кратность для NONE. */
    private static byte[] applyPadding(byte[] data, Mode mode, Padding padding) {
        if (mode != Mode.CBC) return data;
        return switch (padding) {
            case PKCS7 -> Pkcs7Padding.pad(data, BLOCK_SIZE);
            case ISO7816_4 -> ISO7816d4Padding.pad(data, BLOCK_SIZE);
            case NONE -> {
                if (data.length % BLOCK_SIZE != 0) {
                    throw new IllegalArgumentException(
                            "CBC/NONE requires data length to be a multiple of "
                                    + BLOCK_SIZE
                                    + ", got "
                                    + data.length);
                }
                yield data;
            }
        };
    }

    /** Удаляет padding после расшифрования CBC. */
    private static byte[] removePadding(byte[] data, Mode mode, Padding padding) {
        if (mode != Mode.CBC) return data;
        return switch (padding) {
            case PKCS7 -> Pkcs7Padding.unpad(data, BLOCK_SIZE);
            case ISO7816_4 -> ISO7816d4Padding.unpad(data, BLOCK_SIZE);
            case NONE -> data;
        };
    }

    /** Шифрует данные с явным IV. */
    private static byte[] encryptWithIV(
            byte[] data, SymmetricKey key, byte[] iv, Mode mode, Padding padding) {
        return transform(applyPadding(data, mode, padding), key, iv, mode, true);
    }

    /** Расшифровывает данные с явным IV. */
    private static byte[] decryptWithIV(
            byte[] ciphertext, SymmetricKey key, byte[] iv, Mode mode, Padding padding) {
        if (mode == Mode.CBC && ciphertext.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException(
                    "CBC ciphertext length must be a multiple of " + BLOCK_SIZE);
        }
        return removePadding(transform(ciphertext, key, iv, mode, false), mode, padding);
    }

    /**
     * Прогоняет данные целиком через режим: потоковые режимы одним вызовом, CBC поблочно. Состояние
     * режима затирается при любом исходе.
     */
    private static byte[] transform(
            byte[] input, SymmetricKey key, byte[] iv, Mode mode, boolean encrypt) {
        BlockCipher engine = newMode(mode);
        try {
            engine.init(encrypt, new ParametersWithIV(key, iv));
            byte[] out = new byte[input.length];
            if (engine instanceof StreamCipher stream) {
                stream.processBytes(input, 0, input.length, out, 0);
            } else {
                for (int offset = 0; offset < input.length; offset += BLOCK_SIZE) {
                    engine.processBlock(input, offset, out, offset);
                }
            }
            return out;
        } finally {
            engine.destroy();
        }
    }

    /** Создаёт неинициализированный режим на новом экземпляре Кузнечика. */
    private static BlockCipher newMode(Mode mode) {
        return mode == Mode.CBC ? new Cbc(new Kuznyechik()) : newStreamMode(mode);
    }

    /** Создаёт неинициализированный потоковый режим (CBC в потоковом API не поддерживается). */
    private static StreamCipher newStreamMode(Mode mode) {
        return switch (mode) {
            case CTR -> new Ctr(new Kuznyechik());
            case CFB -> new Cfb(new Kuznyechik());
            case OFB -> new Ofb(new Kuznyechik());
            case CBC ->
                    throw new UnsupportedOperationException(
                            "CBC mode is not supported in streaming API. Use static"
                                    + " encrypt()/decrypt().");
        };
    }

    /** Размер буфера шифртекста потока: длинная запись шифруется и пишется порциями. */
    private static final int STREAM_CHUNK_SIZE = 8192;

    /** Оборачивает уже инициализированный шифр в шифрующий выходной поток. */
    private static OutputStream wrapEncrypting(OutputStream out, StreamCipher cipher) {
        return new FilterOutputStream(out) {
            private final byte[] oneByte = new byte[1];

            /**
             * Буфер шифртекста: один на поток, а не по массиву на каждый {@code write}. Входной
             * массив принадлежит вызывающему и шифровать на месте его нельзя. Шифртекст не секрет,
             * затирать буфер не нужно.
             */
            private byte[] encBuf;

            @Override
            public void write(int b) throws IOException {
                oneByte[0] = cipher.returnByte((byte) b);
                out.write(oneByte[0] & 0xFF);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                Objects.checkFromIndexSize(off, len, b.length);
                int chunk = Math.min(len, STREAM_CHUNK_SIZE);
                if (encBuf == null || encBuf.length < chunk) {
                    encBuf = new byte[chunk];
                }
                while (len > 0) {
                    int n = Math.min(len, encBuf.length);
                    cipher.processBytes(b, off, n, encBuf, 0);
                    out.write(encBuf, 0, n);
                    off += n;
                    len -= n;
                }
            }

            @Override
            public void close() throws IOException {
                try {
                    out.close();
                } finally {
                    cipher.destroy();
                }
            }
        };
    }

    /** Оборачивает уже инициализированный шифр в расшифровывающий входной поток. */
    private static InputStream wrapDecrypting(InputStream in, StreamCipher cipher) {
        return new FilterInputStream(in) {

            @Override
            public int read() throws IOException {
                int b = in.read();
                if (b < 0) return -1;
                return cipher.returnByte((byte) b) & 0xFF;
            }

            @Override
            public int read(byte[] buf, int off, int len) throws IOException {
                int n = in.read(buf, off, len);
                if (n <= 0) return n;
                // На месте: буфер вызывающего принимает только что прочитанный шифртекст, и ни один
                // режим не читает вход позже записи выхода на то же место.
                cipher.processBytes(buf, off, n, buf, off);
                return n;
            }

            @Override
            public void close() throws IOException {
                try {
                    in.close();
                } finally {
                    cipher.destroy();
                }
            }
        };
    }

    /** Создаёт и инициализирует потоковый шифр. */
    private static StreamCipher initStreamCipher(
            SymmetricKey key, byte[] iv, Mode mode, boolean encrypt) {
        StreamCipher cipher = newStreamMode(mode);
        cipher.init(encrypt, new ParametersWithIV(key, iv));
        return cipher;
    }
}
