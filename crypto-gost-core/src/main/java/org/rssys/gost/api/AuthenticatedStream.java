package org.rssys.gost.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * API для потокового аутентифицированного шифрования
 * с chunking по ГОСТ Р 34.13-2015 §4.6.
 *
 * <h3>Зачем chunking?</h3>
 * CMAC вычисляется от шифртекста и требует знания всех данных перед
 * шифрованием. Для потока произвольного размера данные разбиваются на
 * независимые чанки фиксированного размера. Каждый чанк имеет собственный IV
 * и CMAC — обрабатывается и верифицируется независимо. Память потребляется
 * O(chunkSize), а не O(totalData).
 *
 * <h3>Формат потока (Encrypt-then-MAC):</h3>
 * <pre>
 * Заголовок (13 байт):
 *   streamNonce[8] = случайные байты (CryptoRandom, per-stream)
 *   version[1]     = 0x02
 *   chunkSize[4]   = размер чанка в байтах (big-endian int)
 *
 * Каждый чанк (29 + N байт):
 *   chunkLen[4]  = длина ciphertext (≤ chunkSize), big-endian int
 *   flags[1]     = 0x00 обычный / 0x01 последний чанк
 *   IV[8]        = случайный IV для CTR
 *   CMAC[16]     = CMAC(ciphertext чанка), полный тег 128 бит
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

    /** Версия формата. */
    static final byte VERSION = 0x02;

    /** Флаг: обычный чанк. */
    static final byte FLAG_NORMAL = 0x00;

    /** Флаг: последний чанк (защита от truncation attack). */
    static final byte FLAG_LAST = 0x01;

    /** Максимальный размер чанка, допускаемый при открытии. */
    static final int MAX_CHUNK_SIZE = 1_048_576; // 1 МБ

    /** Размер заголовка потока в байтах: nonce(8) + version(1) + chunkSize(4). */
    static final int HEADER_SIZE = 13;

    /** Размер заголовка чанка: chunkLen(4) + flags(1) + IV(8) + CMAC(16). */
    static final int CHUNK_HEADER_SIZE = 29;

    /** Длина ключа Кузнечика (256 бит) в байтах. */
    private static final int KEY_LEN = 32;

    /** Метка для KDF: генерация per-stream ключей. */
    private static final byte[] KDF_LABEL = "auth-stream".getBytes(StandardCharsets.US_ASCII);

    /**
     * Выводит per-stream ключи cmacKey и ctrKey из мастер-ключа и streamNonce.
     * Промежуточные byte[] затираются через try/finally.
     */
    private static void deriveStreamKeys(
            SymmetricKey masterKey, byte[] streamNonce, SymmetricKey[] outKeys) {
        byte[] masterBytes = masterKey.getKey();
        try {
            byte[] keyMaterial =
                    KdfTreeGostR3411_2012_256.generate(
                            masterBytes, KDF_LABEL, streamNonce, 2, KEY_LEN);
            try {
                byte[] cmacKeyBytes = Arrays.copyOf(keyMaterial, KEY_LEN);
                byte[] ctrKeyBytes = Arrays.copyOfRange(keyMaterial, KEY_LEN, 2 * KEY_LEN);
                try {
                    outKeys[0] = new SymmetricKey(cmacKeyBytes);
                    outKeys[1] = new SymmetricKey(ctrKeyBytes);
                } finally {
                    Arrays.fill(cmacKeyBytes, (byte) 0);
                    Arrays.fill(ctrKeyBytes, (byte) 0);
                }
            } finally {
                Arrays.fill(keyMaterial, (byte) 0);
            }
        } finally {
            Arrays.fill(masterBytes, (byte) 0);
        }
    }

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

        /** Заголовок потока (nonce[8] + version[1] + chunkSize[4]), нужен для AAD при seqNo=0. */
        private byte[] firstHeader;

        /** Per-stream ключ для CMAC, выведенный через KDF из мастер-ключа. */
        private SymmetricKey cmacKey;

        /** Per-stream ключ для CTR, выведенный через KDF из мастер-ключа. */
        private SymmetricKey ctrKey;

        /** Порядковый номер чанка (неявная защита от reorder/duplicate). */
        private long seqNo = 0;

        private boolean closed = false;

        SealingStream(OutputStream out, SymmetricKey key, int chunkSize) throws IOException {
            if (chunkSize < 16) throw new IllegalArgumentException("chunkSize must be >= 16 bytes");
            this.out = out;
            this.key = key;
            this.chunkSize = chunkSize;
            this.chunkBuf = new byte[chunkSize];
            this.chunkCount = 0;
            writeStreamHeader();
        }

        /** Записывает заголовок потока: streamNonce[8] + version[1] + chunkSize[4]. */
        private void writeStreamHeader() throws IOException {
            byte[] streamNonce = new byte[8];
            CryptoRandom.INSTANCE.nextBytes(streamNonce);

            // KDF: из мастер-ключа и streamNonce выводим per-stream ключи для CMAC и CTR
            SymmetricKey[] keys = new SymmetricKey[2];
            AuthenticatedStream.deriveStreamKeys(key, streamNonce, keys);
            this.cmacKey = keys[0];
            this.ctrKey = keys[1];

            out.write(streamNonce);
            out.write(VERSION);
            writeInt(out, chunkSize);
            // Сохраняем полный заголовок для аутентификации через AAD seqNo=0
            firstHeader = new byte[HEADER_SIZE];
            System.arraycopy(streamNonce, 0, firstHeader, 0, 8);
            firstHeader[8] = VERSION;
            firstHeader[9] = (byte) (chunkSize >> 24);
            firstHeader[10] = (byte) (chunkSize >> 16);
            firstHeader[11] = (byte) (chunkSize >> 8);
            firstHeader[12] = (byte) chunkSize;
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
                srcOff += toWrite;
                remaining -= toWrite;
                if (chunkCount >= chunkSize) {
                    flushChunk(false);
                }
            }
        }

        /**
         * Шифрует и записывает один чанк (Encrypt-then-MAC).
         * @param isLast true для последнего чанка
         */
        private void flushChunk(boolean isLast) throws IOException {
            byte[] plaintext = Arrays.copyOf(chunkBuf, chunkCount);
            chunkCount = 0;

            byte[] iv = new byte[AuthenticatedCipher.IV_LEN];
            CryptoRandom.INSTANCE.nextBytes(iv);

            // AAD: seqNo(8) || flags(1) || IV(8), для первого чанка (seqNo=0) с заголовком потока
            byte[] aad =
                    buildAad(
                            seqNo == 0 ? firstHeader : null,
                            seqNo,
                            isLast ? FLAG_LAST : FLAG_NORMAL,
                            iv);
            if (firstHeader != null) {
                Arrays.fill(firstHeader, (byte) 0);
                firstHeader = null;
            }

            // CTR шифрование
            byte[] ciphertext = AuthenticatedCipher.ctrEncrypt(plaintext, ctrKey, iv);
            seqNo++;

            // CMAC от AAD || ciphertext (Encrypt-then-MAC)
            byte[] fullCmac = AuthenticatedCipher.computeCmac(aad, ciphertext, cmacKey);

            // Заголовок чанка: chunkLen(4) + flags(1) + IV(8) + CMAC(16)
            writeInt(out, ciphertext.length);
            out.write(isLast ? FLAG_LAST : FLAG_NORMAL);
            out.write(iv);
            out.write(fullCmac);
            Arrays.fill(fullCmac, (byte) 0);
            out.write(ciphertext);

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
                if (firstHeader != null) Arrays.fill(firstHeader, (byte) 0);
                if (cmacKey != null) cmacKey.destroy();
                if (ctrKey != null) ctrKey.destroy();
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

        /** Заголовок потока (13 байт), прочитанный из входного потока. */
        private byte[] firstHeader;

        /** Per-stream ключ для CMAC, выведенный через KDF из мастер-ключа. */
        private SymmetricKey cmacKey;

        /** Per-stream ключ для CTR, выведенный через KDF из мастер-ключа. */
        private SymmetricKey ctrKey;

        /** Буфер расшифрованных данных текущего чанка. */
        private byte[] plainBuf = new byte[0];

        /** Позиция чтения в plainBuf. */
        private int plainPos = 0;

        /** Порядковый номер чанка (неявная защита от reorder/duplicate). */
        private long seqNo = 0;

        private boolean lastChunkSeen = false;
        private boolean streamEnded = false;

        OpeningStream(InputStream in, SymmetricKey key)
                throws IOException, AuthenticationException {
            this.in = in;
            this.key = key;
            this.chunkSize = readAndVerifyStreamHeader();
        }

        /** Читает и проверяет 13-байтный заголовок потока. Возвращает chunkSize. */
        private int readAndVerifyStreamHeader() throws IOException, AuthenticationException {
            byte[] header = readExactly(HEADER_SIZE);
            // Включим заголовок в AAD первого чанка для защиты целостности.
            // Nonce (8 байт) на позициях 0..7 — аутентифицируется только через CMAC.
            if (header[8] != VERSION) {
                throw new AuthenticationException(
                        "Unsupported format version: "
                                + (header[8] & 0xFF)
                                + " (expected "
                                + VERSION
                                + ")");
            }
            int declaredChunkSize = readIntFromBytes(header, 9);
            if (declaredChunkSize < 16 || declaredChunkSize > MAX_CHUNK_SIZE) {
                throw new AuthenticationException(
                        "Invalid chunk size in header: " + declaredChunkSize);
            }
            this.firstHeader = header;

            // KDF: из мастер-ключа и streamNonce (header[0..7]) выводим per-stream ключи
            SymmetricKey[] keys = new SymmetricKey[2];
            byte[] streamNonce = Arrays.copyOf(header, 8);
            try {
                AuthenticatedStream.deriveStreamKeys(key, streamNonce, keys);
            } finally {
                Arrays.fill(streamNonce, (byte) 0);
            }
            this.cmacKey = keys[0];
            this.ctrKey = keys[1];

            return declaredChunkSize;
        }

        /**
         * Читает и расшифровывает следующий чанк из потока.
         * CMAC проверяется от шифртекста ДО расшифрования (Encrypt-then-MAC).
         *
         * @return false если поток исчерпан
         */
        private boolean readNextChunk() throws IOException, AuthenticationException {
            if (lastChunkSeen) return false;

            // Читаем заголовок чанка: chunkLen(4) + flags(1) + IV(8) + CMAC(16)
            byte[] chunkHeader;
            try {
                chunkHeader = readExactly(CHUNK_HEADER_SIZE);
            } catch (IOException e) {
                // Поток завершился без флага последнего чанка — усечение!
                throw new AuthenticationException(
                        "Unexpected end of stream: last chunk not found (truncation attack?)");
            }

            int chunkLen = readIntFromBytes(chunkHeader, 0);
            byte flags = chunkHeader[4];
            byte[] iv = Arrays.copyOfRange(chunkHeader, 5, 13);
            byte[] tag = Arrays.copyOfRange(chunkHeader, 13, 13 + AuthenticatedCipher.TAG_LEN);

            if (chunkLen < 0 || chunkLen > chunkSize) {
                throw new AuthenticationException("Invalid chunk length: " + chunkLen);
            }

            // Читаем шифртекст чанка
            byte[] ciphertext = (chunkLen > 0) ? readExactly(chunkLen) : new byte[0];

            // Проверяем CMAC от AAD(seqNo || flags || IV) || шифртекста ДО расшифрования
            byte[] aad = buildAad(seqNo == 0 ? firstHeader : null, seqNo, flags, iv);
            byte[] fullCmac = AuthenticatedCipher.computeCmac(aad, ciphertext, cmacKey);
            seqNo++;

            boolean valid = java.security.MessageDigest.isEqual(fullCmac, tag);
            Arrays.fill(fullCmac, (byte) 0);

            if (!valid) {
                Arrays.fill(ciphertext, (byte) 0);
                Arrays.fill(tag, (byte) 0);
                Arrays.fill(iv, (byte) 0);
                throw new AuthenticationException(
                        "Chunk integrity violation: CMAC mismatch. "
                                + "Stream is corrupted or tampered.");
            }

            // Только после успешной верификации — расшифрование
            byte[] plaintext = AuthenticatedCipher.ctrEncrypt(ciphertext, ctrKey, iv);

            Arrays.fill(ciphertext, (byte) 0);
            Arrays.fill(tag, (byte) 0);
            Arrays.fill(iv, (byte) 0);

            // После успешной верификации первого чанка заголовок больше не нужен
            if (firstHeader != null) {
                Arrays.fill(firstHeader, (byte) 0);
                firstHeader = null;
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
                int toCopy = Math.min(available, len - totalRead);
                System.arraycopy(plainBuf, plainPos, buf, off + totalRead, toCopy);
                plainPos += toCopy;
                totalRead += toCopy;
            }

            return (totalRead == 0 && streamEnded) ? -1 : totalRead;
        }

        @Override
        public void close() throws IOException {
            // Мастер-ключ принадлежит вызывающему — не уничтожаем его.
            // Per-stream ключи — наши, уничтожаем.
            Arrays.fill(plainBuf, (byte) 0);
            if (firstHeader != null) Arrays.fill(firstHeader, (byte) 0);
            if (cmacKey != null) cmacKey.destroy();
            if (ctrKey != null) ctrKey.destroy();
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
                if (r < 0)
                    throw new IOException(
                            "Unexpected end of stream: expected " + n + " bytes, read " + read);
                read += r;
            }
            return buf;
        }

        /** Читает big-endian int из массива байт с заданным смещением. */
        private static int readIntFromBytes(byte[] b, int off) {
            return ((b[off] & 0xFF) << 24)
                    | ((b[off + 1] & 0xFF) << 16)
                    | ((b[off + 2] & 0xFF) << 8)
                    | (b[off + 3] & 0xFF);
        }
    }

    // -----------------------------------------------------------------------
    // Утилиты
    // -----------------------------------------------------------------------

    /**
     * Строит AAD для CMAC.
     * Для первого чанка (firstHeader != null): header(13) || seqNo(8) || flags(1) || IV(8).
     * Для остальных чанков (firstHeader == null): seqNo(8) || flags(1) || IV(8).
     * IV включён в AAD — подмена IV в заголовке чанка обнаруживается.
     */
    private static byte[] buildAad(byte[] firstHeader, long seqNo, byte flags, byte[] iv) {
        int hdrLen = (firstHeader != null) ? firstHeader.length : 0;
        byte[] aad = new byte[hdrLen + 9 + iv.length];
        int off = 0;
        if (firstHeader != null) {
            System.arraycopy(firstHeader, 0, aad, 0, hdrLen);
            off = hdrLen;
        }
        aad[off] = (byte) (seqNo >> 56);
        aad[off + 1] = (byte) (seqNo >> 48);
        aad[off + 2] = (byte) (seqNo >> 40);
        aad[off + 3] = (byte) (seqNo >> 32);
        aad[off + 4] = (byte) (seqNo >> 24);
        aad[off + 5] = (byte) (seqNo >> 16);
        aad[off + 6] = (byte) (seqNo >> 8);
        aad[off + 7] = (byte) seqNo;
        aad[off + 8] = flags;
        System.arraycopy(iv, 0, aad, off + 9, iv.length);
        return aad;
    }

    /** Записывает big-endian int в поток. */
    private static void writeInt(OutputStream out, int v) throws IOException {
        out.write((v >> 24) & 0xFF);
        out.write((v >> 16) & 0xFF);
        out.write((v >> 8) & 0xFF);
        out.write(v & 0xFF);
    }
}
