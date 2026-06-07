package org.rssys.gost.api;

import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.rssys.gost.util.CryptoRandom;

/**
 * API для потокового аутентифицированного шифрования
 * с chunking по ГОСТ Р 34.13-2015 §4.6.
 *
 * <h3>Зачем chunking?</h3>
 * CMAC вычисляется от открытого текста и требует знания всех данных перед
 * шифрованием. Для потока произвольного размера данные разбиваются на
 * независимые чанки фиксированного размера. Каждый чанк имеет собственный IV
 * и CMAC — обрабатывается и верифицируется независимо. Память потребляется
 * O(chunkSize), а не O(totalData).
 *
 * <h3>Формат потока:</h3>
 * <pre>
 * Заголовок (13 байт):
 *   magic[4]     = 0x47 0x4F 0x53 0x54  ("GOST")
 *   version[1]   = 0x01
 *   chunkSize[4] = размер чанка в байтах (big-endian int)
 *   reserved[4]  = 0x00000000
 *
 * Каждый чанк (21 + N байт):
 *   chunkLen[4]  = длина ciphertext (≤ chunkSize), big-endian int
 *   flags[1]     = 0x00 обычный / 0x01 последний чанк
 *   IV[8]        = случайный IV для CTR
 *   CMAC[8]      = CMAC(plaintext чанка), первые 8 байт
 *   ciphertext[N]
 * </pre>
 *
 * <p>Флаг последнего чанка защищает от усечения потока (truncation attack):
 * если поток обрезан до финального чанка — расшифрование выбросит
 * {@link AuthenticationException}.
 *
 * <h3>Пример использования:</h3>
 * <pre>{@code
 * SymmetricKey key = KeyGenerator.generateSymmetricKey();
 *
 * // Шифрование
 * try (OutputStream sealed = AuthenticatedStream.sealing(fileOut, key)) {
 *     sealed.write(data);
 * }
 *
 * // Расшифрование
 * try (InputStream opened = AuthenticatedStream.opening(fileIn, key)) {
 *     byte[] buf = new byte[4096];
 *     int n;
 *     while ((n = opened.read(buf)) > 0) {
 *         process(buf, 0, n);
 *     }
 * } catch (AuthenticationException e) {
 *     // Поток повреждён или подменён
 * }
 * }</pre>
 *
 * <p><b>Не потокобезопасен.</b> Создавайте отдельный экземпляр на каждое соединение.
 */
public final class AuthenticatedStream {

    /** Размер чанка по умолчанию: 64 КБ. */
    public static final int DEFAULT_CHUNK_SIZE = 65536;

    /** Магическое число заголовка: "GOST". */
    static final byte[] MAGIC = {0x47, 0x4F, 0x53, 0x54};

    /** Версия формата. */
    static final byte VERSION = 0x01;

    /** Флаг: обычный чанк. */
    static final byte FLAG_NORMAL = 0x00;

    /** Флаг: последний чанк (защита от truncation attack). */
    static final byte FLAG_LAST = 0x01;

    /** Максимальный размер чанка, допускаемый при открытии. */
    static final int MAX_CHUNK_SIZE = 1_048_576; // 1 МБ

    /** Размер заголовка потока в байтах. */
    static final int HEADER_SIZE = 13; // magic(4) + version(1) + chunkSize(4) + reserved(4)

    /** Размер заголовка чанка: chunkLen(4) + flags(1) + IV(8) + CMAC(8). */
    static final int CHUNK_HEADER_SIZE = 21;

    private AuthenticatedStream() {}

    // -----------------------------------------------------------------------
    // Одноключевой API
    // -----------------------------------------------------------------------

    /**
     * Создаёт шифрующий поток с аутентификацией.
     *
     * <p>Записывает заголовок потока сразу при создании. Данные разбиваются
     * на чанки по {@link #DEFAULT_CHUNK_SIZE} байт при {@code close()}.
     *
     * @param out выходной поток с зашифрованными данными
     * @param key ключ шифрования
     * @return шифрующий {@link OutputStream}
     * @throws IOException если не удалось записать заголовок
     */
    public static OutputStream sealing(OutputStream out, SymmetricKey key) throws IOException {
        return sealing(out, key, DEFAULT_CHUNK_SIZE);
    }

    /**
     * Создаёт шифрующий поток с аутентификацией и заданным размером блока (chunk).
     *
     * @param out       выходной поток с зашифрованными данными
     * @param key       ключ шифрования
     * @param chunkSize размер чанка в байтах (рекомендуется кратно 16, минимум 16)
     * @return шифрующий {@link OutputStream}
     * @throws IOException              если не удалось записать заголовок
     * @throws IllegalArgumentException если chunkSize < 16
     */
    public static OutputStream sealing(OutputStream out, SymmetricKey key, int chunkSize)
            throws IOException {
        return new SealingStream(out, key, chunkSize);
    }

    /**
     * Создаёт расшифровывающий поток с проверкой аутентичности данных.
     *
     * <p>Читает и проверяет заголовок потока сразу при создании.
     * Данные каждого чанка верифицируются через CMAC перед отдачей вызывающему.
     *
     * @param in  поток зашифрованных данных в формате AuthenticatedStream
     * @param key ключ расшифрования — тот же что при sealing
     * @return расшифровывающий {@link InputStream}
     * @throws IOException                 если не удалось прочитать заголовок
     * @throws AuthenticationException если заголовок повреждён
     */
    public static InputStream opening(InputStream in, SymmetricKey key)
            throws IOException, AuthenticationException {
        return new OpeningStream(in, key);
    }

    // -----------------------------------------------------------------------
    // SealingStream — шифрующий поток
    // -----------------------------------------------------------------------

    private static final class SealingStream extends OutputStream {

        private final OutputStream out;
        private final SymmetricKey key;
        private final int chunkSize;

        /** Внутренний буфер для накопления одного чанка plaintext (ручное управление). */
        private final byte[] chunkBuf;
        private int chunkCount;

        /** Порядковый номер чанка (неявная защита от reorder/duplicate). */
        private long seqNo = 0;

        private boolean closed = false;

        SealingStream(OutputStream out, SymmetricKey key, int chunkSize) throws IOException {
            if (chunkSize < 16)
                throw new IllegalArgumentException("chunkSize must be >= 16 bytes");
            this.out       = out;
            this.key       = key;
            this.chunkSize = chunkSize;
            this.chunkBuf  = new byte[chunkSize];
            this.chunkCount = 0;
            writeStreamHeader();
        }

        /** Записывает заголовок потока. */
        private void writeStreamHeader() throws IOException {
            out.write(MAGIC);
            out.write(VERSION);
            writeInt(out, chunkSize);
            writeInt(out, 0); // reserved
        }

        @Override
        public void write(int b) throws IOException {
            checkNotClosed();
            chunkBuf[chunkCount++] = (byte) b;
            if (chunkCount >= chunkSize) {
                flushChunk(false);
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            checkNotClosed();
            int remaining = len;
            int srcOff = off;
            while (remaining > 0) {
                int space = chunkSize - chunkCount;
                int toWrite = Math.min(remaining, space);
                System.arraycopy(b, srcOff, chunkBuf, chunkCount, toWrite);
                chunkCount += toWrite;
                srcOff     += toWrite;
                remaining  -= toWrite;
                if (chunkCount >= chunkSize) {
                    flushChunk(false);
                }
            }
        }

        /**
         * Шифрует и записывает один чанк.
         * @param isLast true для последнего чанка
         */
        private void flushChunk(boolean isLast) throws IOException {
            byte[] plaintext = Arrays.copyOf(chunkBuf, chunkCount);
            chunkCount = 0;

            // Генерируем случайный IV для CTR
            byte[] iv = new byte[AuthenticatedCipher.IV_LEN];
            CryptoRandom.INSTANCE.nextBytes(iv);

            // CMAC от AAD(seqNo || flags) || открытого текста
            byte[] aad = buildAad(seqNo, isLast ? FLAG_LAST : FLAG_NORMAL);
            byte[] fullCmac = AuthenticatedCipher.computeCmac(aad, plaintext, key);
            byte[] tag = Arrays.copyOf(fullCmac, AuthenticatedCipher.TAG_LEN);
            Arrays.fill(fullCmac, (byte) 0);
            seqNo++;

            // CTR шифрование
            byte[] ciphertext = AuthenticatedCipher.ctrEncrypt(plaintext, key, iv);

            // Заголовок чанка: chunkLen(4) + flags(1) + IV(8) + CMAC(8)
            writeInt(out, ciphertext.length);
            out.write(isLast ? FLAG_LAST : FLAG_NORMAL);
            out.write(iv);
            out.write(tag);
            out.write(ciphertext);

            Arrays.fill(tag, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
        }

        @Override
        public void close() throws IOException {
            if (closed) return;
            closed = true;
            try {
                flushChunk(true);
                out.flush();
            } finally {
                Arrays.fill(chunkBuf, (byte) 0);
            }
        }

        private void checkNotClosed() throws IOException {
            if (closed) throw new IOException("Stream is closed");
        }
    }

    // -----------------------------------------------------------------------
    // OpeningStream — расшифровывающий поток
    // -----------------------------------------------------------------------

    private static final class OpeningStream extends InputStream {

        private final InputStream in;
        private final SymmetricKey key;
        private final int chunkSize;

        /** Буфер расшифрованных данных текущего чанка. */
        private byte[] plainBuf = new byte[0];
        /** Позиция чтения в plainBuf. */
        private int plainPos = 0;

        /** Порядковый номер чанка (неявная защита от reorder/duplicate). */
        private long seqNo = 0;

        private boolean lastChunkSeen = false;
        private boolean streamEnded   = false;

        OpeningStream(InputStream in, SymmetricKey key)
                throws IOException, AuthenticationException {
            this.in  = in;
            this.key = key;
            this.chunkSize = readAndVerifyStreamHeader();
        }

        /** Читает и проверяет 13-байтный заголовок потока. Возвращает chunkSize. */
        private int readAndVerifyStreamHeader()
                throws IOException, AuthenticationException {
            byte[] header = readExactly(HEADER_SIZE);
            // Проверяем magic
            if (header[0] != MAGIC[0] || header[1] != MAGIC[1] ||
                header[2] != MAGIC[2] || header[3] != MAGIC[3]) {
                throw new AuthenticationException(
                    "Invalid stream header: GOST signature not found");
            }
            if (header[4] != VERSION) {
                throw new AuthenticationException(
                    "Unsupported format version: " + (header[4] & 0xFF));
            }
            int declaredChunkSize = readIntFromBytes(header, 5);
            if (declaredChunkSize < 16 || declaredChunkSize > MAX_CHUNK_SIZE) {
                throw new AuthenticationException(
                    "Invalid chunk size in header: " + declaredChunkSize);
            }
            return declaredChunkSize;
        }

        /**
         * Читает и расшифровывает следующий чанк из потока.
         * После CMAC-проверки данные помещаются в plainBuf.
         *
         * @return false если поток исчерпан
         */
        private boolean readNextChunk() throws IOException, AuthenticationException {
            if (lastChunkSeen) return false;

            // Читаем заголовок чанка: chunkLen(4) + flags(1) + IV(8) + CMAC(8)
            byte[] chunkHeader;
            try {
                chunkHeader = readExactly(CHUNK_HEADER_SIZE);
            } catch (IOException e) {
                // Поток завершился без флага последнего чанка — усечение!
                throw new AuthenticationException(
                    "Unexpected end of stream: last chunk not found (truncation attack?)");
            }

            int chunkLen = readIntFromBytes(chunkHeader, 0);
            byte flags   = chunkHeader[4];
            byte[] iv    = Arrays.copyOfRange(chunkHeader, 5,  13);
            byte[] tag   = Arrays.copyOfRange(chunkHeader, 13, 21);

            if (chunkLen < 0 || chunkLen > chunkSize) {
                throw new AuthenticationException(
                    "Invalid chunk length: " + chunkLen);
            }

            // Читаем шифртекст чанка
            byte[] ciphertext = (chunkLen > 0) ? readExactly(chunkLen) : new byte[0];

            // CTR расшифрование
            byte[] plaintext = AuthenticatedCipher.ctrEncrypt(ciphertext, key, iv);

            // Проверяем CMAC от AAD(seqNo || flags) || открытого текста
            byte[] aad      = buildAad(seqNo, flags);
            byte[] fullCmac = AuthenticatedCipher.computeCmac(aad, plaintext, key);
            byte[] expected = Arrays.copyOf(fullCmac, AuthenticatedCipher.TAG_LEN);
            Arrays.fill(fullCmac, (byte) 0);
            seqNo++;

            boolean valid = java.security.MessageDigest.isEqual(expected, tag);
            Arrays.fill(expected, (byte) 0);

            if (!valid) {
                Arrays.fill(plaintext, (byte) 0);
                throw new AuthenticationException(
                    "Chunk integrity violation: CMAC mismatch. " +
                    "Stream is corrupted or tampered.");
            }

            plainBuf = plaintext;
            plainPos = 0;

            if (flags == FLAG_LAST) {
                lastChunkSeen = true;
            }

            return true;
        }

        @Override
        public int read() throws IOException {
            byte[] buf = new byte[1];
            int n = read(buf, 0, 1);
            return (n < 0) ? -1 : (buf[0] & 0xFF);
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            if (streamEnded) return -1;

            // Заполняем буфер из расшифрованных чанков
            int totalRead = 0;
            while (totalRead < len) {
                // Если текущий чанк исчерпан — читаем следующий
                if (plainPos >= plainBuf.length) {
                    boolean hasMore;
                    try {
                        hasMore = readNextChunk();
                    } catch (AuthenticationException e) {
                        streamEnded = true;
                        Arrays.fill(plainBuf, (byte) 0);
                        plainBuf = new byte[0];
                        throw new IOException("Authentication error: " + e.getMessage(), e);
                    }
                    if (!hasMore || plainBuf.length == 0) {
                        streamEnded = true;
                        break;
                    }
                }

                int available = plainBuf.length - plainPos;
                int toCopy    = Math.min(available, len - totalRead);
                System.arraycopy(plainBuf, plainPos, buf, off + totalRead, toCopy);
                plainPos   += toCopy;
                totalRead  += toCopy;
            }

            return (totalRead == 0 && streamEnded) ? -1 : totalRead;
        }

        @Override
        public void close() throws IOException {
            // Ключи принадлежат вызывающему — не уничтожаем их здесь
            Arrays.fill(plainBuf, (byte) 0);
        }

        // -----------------------------------------------------------------------
        // Вспомогательные методы чтения
        // -----------------------------------------------------------------------

        /** Читает ровно n байт или бросает IOException. */
        private byte[] readExactly(int n) throws IOException {
            byte[] buf = new byte[n];
            int read = 0;
            while (read < n) {
                int r = in.read(buf, read, n - read);
                if (r < 0) throw new IOException(
                    "Unexpected end of stream: expected " + n + " bytes, read " + read);
                read += r;
            }
            return buf;
        }

        /** Читает big-endian int из массива байт с заданным смещением. */
        private static int readIntFromBytes(byte[] b, int off) {
            return ((b[off]   & 0xFF) << 24) |
                   ((b[off+1] & 0xFF) << 16) |
                   ((b[off+2] & 0xFF) <<  8) |
                    (b[off+3] & 0xFF);
        }
    }

    // -----------------------------------------------------------------------
    // Утилиты
    // -----------------------------------------------------------------------

    /** Строит AAD = seqNo(8) || flags(1) для аутентификации порядка чанков. */
    private static byte[] buildAad(long seqNo, byte flags) {
        byte[] aad = new byte[9];
        aad[0] = (byte)(seqNo >> 56);
        aad[1] = (byte)(seqNo >> 48);
        aad[2] = (byte)(seqNo >> 40);
        aad[3] = (byte)(seqNo >> 32);
        aad[4] = (byte)(seqNo >> 24);
        aad[5] = (byte)(seqNo >> 16);
        aad[6] = (byte)(seqNo >>  8);
        aad[7] = (byte)(seqNo);
        aad[8] = flags;
        return aad;
    }

    /** Записывает big-endian int в поток. */
    private static void writeInt(OutputStream out, int v) throws IOException {
        out.write((v >> 24) & 0xFF);
        out.write((v >> 16) & 0xFF);
        out.write((v >>  8) & 0xFF);
        out.write( v        & 0xFF);
    }
}
