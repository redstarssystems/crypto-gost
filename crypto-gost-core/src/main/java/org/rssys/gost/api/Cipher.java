package org.rssys.gost.api;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
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
 *   <li>{@link Mode#CFB} — режим гаммирования с обратной связью по шифртексту. IV = 16 байт.</li>
 *   <li>{@link Mode#OFB} — режим гаммирования с обратной связью по выходу. IV = 16 байт.</li>
 *   <li>{@link Mode#CBC} — режим простой замены с зацеплением. IV = 16 байт.
 *       Требует данные кратные 16 байт — используйте {@link Padding}.</li>
 * </ul>
 *
 * <h3>Формат выходных данных при вызове encrypt() без явного IV:</h3>
 * <pre>
 *   [IV (8 или 16 байт)] [шифртекст]
 * </pre>
 * Метод {@code decrypt()} автоматически читает IV из начала массива.
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
    public static final int BLOCK_SIZE = 16;

    /** Размер ключа в байтах. */
    public static final int KEY_SIZE = 32;

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
     *   <li>CBC, CFB, OFB: не менее 16 байт</li>
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
     */
    public static OutputStream encryptingStream(OutputStream out, SymmetricKey key, Mode mode)
            throws IOException {
        byte[] iv = generateIV(mode);
        out.write(iv); // записываем IV первым
        return buildEncryptingStream(out, key, iv, mode);
    }

    /**
     * Создаёт шифрующий выходной поток вывода с явным указанием IV.
     * IV в поток не записывается — управление на стороне вызывающего.
     */
    public static OutputStream encryptingStream(
            OutputStream out, SymmetricKey key, byte[] iv, Mode mode) throws IOException {
        return buildEncryptingStream(out, key, iv, mode);
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
     */
    public static InputStream decryptingStream(InputStream in, SymmetricKey key, Mode mode)
            throws IOException {
        // Читаем IV из потока
        int ivLen = ivLength(mode);
        byte[] iv = new byte[ivLen];
        int read = 0;
        while (read < ivLen) {
            int n = in.read(iv, read, ivLen - read);
            if (n < 0) throw new IOException("Stream ended before IV was fully read");
            read += n;
        }
        return buildDecryptingStream(in, key, iv, mode);
    }

    /**
     * Создаёт расшифровывающий поток ввода с явным указанием IV.
     * IV из потока не читается.
     */
    public static InputStream decryptingStream(
            InputStream in, SymmetricKey key, byte[] iv, Mode mode) throws IOException {
        return buildDecryptingStream(in, key, iv, mode);
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
        switch (padding) {
            case PKCS7:
                return Pkcs7Padding.addPadding(data, BLOCK_SIZE);
            case ISO7816_4:
                {
                    // Вычисляем необходимый padding до следующего кратного blockSize
                    int padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
                    byte[] padded = new byte[data.length + padLen];
                    System.arraycopy(data, 0, padded, 0, data.length);
                    // addPadding записывает 0x80 на позицию data.length и заполняет нулями до конца
                    ISO7816d4Padding.addPadding(padded, data.length);
                    return padded;
                }
            case NONE:
                if (data.length % BLOCK_SIZE != 0) {
                    throw new IllegalArgumentException(
                            "CBC/NONE requires data length to be a multiple of "
                                    + BLOCK_SIZE
                                    + ", got "
                                    + data.length);
                }
                return data;
            default:
                throw new IllegalArgumentException("Unknown padding: " + padding);
        }
    }

    /** Удаляет padding после расшифрования CBC. */
    private static byte[] removePadding(byte[] data, Mode mode, Padding padding) {
        if (mode != Mode.CBC) return data;
        switch (padding) {
            case PKCS7:
                return Pkcs7Padding.removePadding(data, BLOCK_SIZE);
            case ISO7816_4:
                {
                    try {
                        int padCount = ISO7816d4Padding.padCount(data);
                        return Arrays.copyOf(data, data.length - padCount);
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Invalid ISO 7816-4 padding", e);
                    }
                }
            case NONE:
                return data;
            default:
                throw new IllegalArgumentException("Unknown padding: " + padding);
        }
    }

    /** Шифрует данные с явным IV. */
    private static byte[] encryptWithIV(
            byte[] data, SymmetricKey key, byte[] iv, Mode mode, Padding padding) {
        byte[] input = applyPadding(data, mode, padding);

        switch (mode) {
            case CTR:
                {
                    Ctr ctr = new Ctr(new Kuznyechik());
                    ctr.init(true, new ParametersWithIV(key, iv));
                    byte[] out = new byte[input.length];
                    ctr.processBytes(input, 0, input.length, out, 0);
                    return out;
                }
            case CFB:
                {
                    Cfb cfb = new Cfb(new Kuznyechik());
                    cfb.init(true, new ParametersWithIV(key, iv));
                    byte[] out = new byte[input.length];
                    cfb.processBytes(input, 0, input.length, out, 0);
                    return out;
                }
            case OFB:
                {
                    Ofb ofb = new Ofb(new Kuznyechik());
                    ofb.init(true, new ParametersWithIV(key, iv));
                    byte[] out = new byte[input.length];
                    ofb.processBytes(input, 0, input.length, out, 0);
                    return out;
                }
            case CBC:
                {
                    // CBC — блочный режим, обрабатываем поблочно
                    Cbc cbc = new Cbc(new Kuznyechik());
                    cbc.init(true, new ParametersWithIV(key, iv));
                    byte[] out = new byte[input.length];
                    for (int offset = 0; offset < input.length; offset += BLOCK_SIZE) {
                        cbc.processBlock(input, offset, out, offset);
                    }
                    return out;
                }
            default:
                throw new IllegalArgumentException("Unknown mode: " + mode);
        }
    }

    /** Расшифровывает данные с явным IV. */
    private static byte[] decryptWithIV(
            byte[] ciphertext, SymmetricKey key, byte[] iv, Mode mode, Padding padding) {
        byte[] raw;
        switch (mode) {
            case CTR:
                {
                    Ctr ctr = new Ctr(new Kuznyechik());
                    ctr.init(false, new ParametersWithIV(key, iv));
                    raw = new byte[ciphertext.length];
                    ctr.processBytes(ciphertext, 0, ciphertext.length, raw, 0);
                    break;
                }
            case CFB:
                {
                    Cfb cfb = new Cfb(new Kuznyechik());
                    cfb.init(false, new ParametersWithIV(key, iv));
                    raw = new byte[ciphertext.length];
                    cfb.processBytes(ciphertext, 0, ciphertext.length, raw, 0);
                    break;
                }
            case OFB:
                {
                    Ofb ofb = new Ofb(new Kuznyechik());
                    ofb.init(false, new ParametersWithIV(key, iv));
                    raw = new byte[ciphertext.length];
                    ofb.processBytes(ciphertext, 0, ciphertext.length, raw, 0);
                    break;
                }
            case CBC:
                {
                    if (ciphertext.length % BLOCK_SIZE != 0) {
                        throw new IllegalArgumentException(
                                "CBC ciphertext length must be a multiple of " + BLOCK_SIZE);
                    }
                    Cbc cbc = new Cbc(new Kuznyechik());
                    cbc.init(false, new ParametersWithIV(key, iv));
                    raw = new byte[ciphertext.length];
                    for (int offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE) {
                        cbc.processBlock(ciphertext, offset, raw, offset);
                    }
                    break;
                }
            default:
                throw new IllegalArgumentException("Unknown mode: " + mode);
        }
        return removePadding(raw, mode, padding);
    }

    /** Строит шифрующий выходной поток. */
    private static OutputStream buildEncryptingStream(
            OutputStream out, SymmetricKey key, byte[] iv, Mode mode) {
        return new FilterOutputStream(out) {
            private final byte[] oneByte = new byte[1];
            private final StreamCipher cipher = initStreamCipher(key, iv, mode, true);

            @Override
            public void write(int b) throws IOException {
                oneByte[0] = cipher.returnByte((byte) b);
                out.write(oneByte[0] & 0xFF);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                byte[] encBuf = new byte[len];
                cipher.processBytes(b, off, len, encBuf, 0);
                out.write(encBuf, 0, len);
            }
        };
    }

    /** Строит расшифровывающий входной поток. */
    private static InputStream buildDecryptingStream(
            InputStream in, SymmetricKey key, byte[] iv, Mode mode) {
        return new FilterInputStream(in) {
            private final StreamCipher cipher = initStreamCipher(key, iv, mode, false);

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
                byte[] dec = new byte[n];
                cipher.processBytes(buf, off, n, dec, 0);
                System.arraycopy(dec, 0, buf, off, n);
                return n;
            }
        };
    }

    /**
     * Инициализирует потоковый шифр.
     */
    private static StreamCipher initStreamCipher(
            SymmetricKey key, byte[] iv, Mode mode, boolean encrypt) {
        switch (mode) {
            case CTR:
                {
                    Ctr ctr = new Ctr(new Kuznyechik());
                    ctr.init(encrypt, new ParametersWithIV(key, iv));
                    return ctr;
                }
            case CFB:
                {
                    Cfb cfb = new Cfb(new Kuznyechik());
                    cfb.init(encrypt, new ParametersWithIV(key, iv));
                    return cfb;
                }
            case OFB:
                {
                    Ofb ofb = new Ofb(new Kuznyechik());
                    ofb.init(encrypt, new ParametersWithIV(key, iv));
                    return ofb;
                }
            case CBC:
                throw new UnsupportedOperationException(
                        "CBC mode is not supported in streaming API. Use static encrypt()/decrypt().");
            default:
                throw new IllegalArgumentException("Unknown mode: " + mode);
        }
    }
}
