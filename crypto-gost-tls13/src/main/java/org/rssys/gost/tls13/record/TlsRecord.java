package org.rssys.gost.tls13.record;

import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.crypto.TlsTreeCache;

import java.nio.ByteBuffer;
import java.util.Arrays;


/**
 * Уровень записей TLS 1.3 (RFC 8446 Section 5).
 * Шифрование/дешифрование записей с использованием MGM (RFC 9058)
 * и внешним per-record ре-кейингом TLSTREE (RFC 9367 §4.2).
 */
public final class TlsRecord {

    private final byte[] startKey;
    private final byte[] startIv;
    private final Mgm mgm;
    private final byte[] aadBuf = new byte[5];
    private final byte[] nonceBuf = new byte[TlsConstants.MGM_IV_SIZE];
    private final byte[] tagBuf;
    // scratch-буферы: переиспользуются между вызовами protect/unprotect
    // Вместо того чтобы аллоцировать byte[len+1] на каждый TLS-рекорд,
    // держим фиксированный буфер максимального размера.
    // Non thread-safe — TlsRecord используется из одного потока.
    private final byte[] innerPlaintext = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH];
    private final byte[] ciphertext = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH];
    private final byte[] plaintext = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH];
    private final byte[] currentKeyBuf = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
    private long seqNum;
    private final int tagLen;

    // Параметры TLSTREE
    private final long snmax;
    private final long c1;
    private final long c2;
    private final long c3;
    private final TlsTreeCache treeCache;

    /**
     * @param key         начальный ключевой материал K_start_key (32 байта);
     *                    ПОСЛЕ передачи caller НЕ ДОЛЖЕН модифицировать массив
     * @param iv          начальный IV K_start_iv (16 байт);
     *                    ПОСЛЕ передачи caller НЕ ДОЛЖЕН модифицировать массив
     * @param tagLen      длина тега аутентификации (16 для MGM)
     * @param ciphersuite cipher suite для TLSTREE-констант и SNMAX
     */
    public TlsRecord(byte[] key, byte[] iv, int tagLen, TlsCiphersuite ciphersuite) {
        if (key == null || key.length != TlsConstants.KUZNYECHIK_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        if (iv == null || iv.length != TlsConstants.MGM_IV_SIZE) {
            throw new IllegalArgumentException("IV must be 16 bytes");
        }
        if (tagLen <= 0 || tagLen > TlsConstants.MGM_TAG_SIZE) {
            throw new IllegalArgumentException("Tag length must be positive");
        }
        if (ciphersuite == null) {
            throw new IllegalArgumentException("ciphersuite must not be null");
        }
        this.startKey = key;
        this.startIv = iv;
        this.tagLen = tagLen;
        this.tagBuf = new byte[tagLen];
        this.seqNum = 0;
        this.mgm = new Mgm(new Kuznyechik());
        this.snmax = ciphersuite.getSnmax();
        this.c1 = ciphersuite.getC1();
        this.c2 = ciphersuite.getC2();
        this.c3 = ciphersuite.getC3();
        this.treeCache = new TlsTreeCache(startKey, c1, c2, c3);
    }

    /** Обнуляет ключи, IV, scratch-буферы и сбрасывает seqNum. */
    public void destroy() {
        treeCache.destroy();
        TlsUtils.wipeArray(startKey);
        TlsUtils.wipeArray(startIv);
        TlsUtils.wipeArray(innerPlaintext);
        TlsUtils.wipeArray(ciphertext);
        TlsUtils.wipeArray(plaintext);
        TlsUtils.wipeArray(currentKeyBuf);
        TlsUtils.wipeArray(tagBuf);
        TlsUtils.wipeArray(aadBuf);
        TlsUtils.wipeArray(nonceBuf);
        seqNum = 0;
    }

    /**
     * @return текущий порядковый номер записи
     */
    public long getSequenceNumber() {
        return seqNum;
    }

    /** @return длина тега аутентификации */
    public int getTagLen() {
        return tagLen;
    }

    /**
     * Устанавливает порядковый номер (для синхронизации после смены ключей).
     *
     * @param seqNum порядковый номер
     */
    public void setSequenceNumber(long seqNum) {
        this.seqNum = seqNum;
    }

    /**
     * Защищает (шифрует + аутентифицирует) открытые данные.
     *
     * @param contentType тип содержимого (CT_HANDSHAKE, CT_APPLICATION_DATA, CT_ALERT)
     * @param data        открытые данные
     * @return TLS-запись: заголовок(5) || ciphertext(N) || tag(tagLen)
     * @throws IllegalArgumentException если data == null
     * @throws IllegalStateException    при переполнении порядкового номера
     */
    public byte[] protect(byte contentType, byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        return protect(contentType, data, 0, data.length);
    }

    /**
     * Защищает (шифрует + аутентифицирует) открытые данные с указанием смещения и длины.
     * Позволяет избежать промежуточной копии при фрагментации больших данных.
     *
     * @param contentType тип содержимого
     * @param data        открытые данные
     * @param offset      смещение в data
     * @param len         длина фрагмента
     * @return TLS-запись: заголовок(5) || ciphertext(N) || tag(tagLen)
     * @throws IllegalArgumentException при некорректных offset/len
     * @throws IllegalStateException при переполнении порядкового номера
     */
    public byte[] protect(byte contentType, byte[] data, int offset, int len) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        if (offset < 0 || len < 0 || offset + len > data.length) {
            throw new IllegalArgumentException("Invalid offset/length");
        }
        // inner plaintext = fragment || content_type (1 byte), ≤ 2^14
        if (len + 1 > TlsConstants.MAX_PLAINTEXT_LENGTH) {
            throw new IllegalArgumentException("Data exceeds maximum fragment size");
        }
        if (seqNum < 0) {
            throw new IllegalStateException("Sequence number overflow");
        }
        checkSnmax();

        // Per-record TLSTREE в переиспользуемый буфер (RFC 9367 §4.1)
        boolean keyChanged = treeCache.deriveKeyInto(seqNum, currentKeyBuf, 0);

        // Внутренний открытый текст в переиспользуемом буфере: fragment(N) || inner_type(1)
        int innerLen = len + 1;
        System.arraycopy(data, offset, innerPlaintext, 0, len);
        innerPlaintext[len] = contentType;

        // Nonce = sender_write_iv XOR seqNum (RFC 8446 §5.3, RFC 9367 §4.1)
        buildNonce(startIv);

        // AAD = outer_content_type || legacy_version || payload_length
        int payloadLen = innerLen + tagLen;
        aadBuf[0] = TlsConstants.CT_APPLICATION_DATA;
        aadBuf[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        aadBuf[2] = TlsConstants.LEGACY_VERSION_MINOR;
        aadBuf[3] = (byte) (payloadLen >>> 8);
        aadBuf[4] = (byte) payloadLen;

        // Шифрование MGM
        if (keyChanged) {
            SymmetricKey symKey = new SymmetricKey(currentKeyBuf);
            mgm.init(true, new ParametersWithIV(symKey, nonceBuf));
            symKey.destroy();
        } else {
            mgm.reinitICN(nonceBuf);
        }
        mgm.updateAAD(aadBuf, 0, aadBuf.length);

        mgm.processBytes(innerPlaintext, 0, innerLen, ciphertext, 0);

        mgm.finishEncryption(tagBuf, 0);
        // currentKeyBuf не зануляем между вызовами — будет перезаписан при следующем deriveKeyInto

        // Сборка записи: заголовок || ciphertext || tag
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + innerLen + tagLen];
        record[0] = TlsConstants.CT_APPLICATION_DATA;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (payloadLen >>> 8);
        record[4] = (byte) payloadLen;
        System.arraycopy(ciphertext, 0, record, TlsConstants.RECORD_HEADER_SIZE, innerLen);
        System.arraycopy(tagBuf, 0, record, TlsConstants.RECORD_HEADER_SIZE + innerLen, tagLen);

        seqNum++;
        return record;
    }

    /**
     * Снимает защиту (дешифрует + проверяет аутентификацию) TLS-записи.
     *
     * @param record TLS-запись: заголовок(5) || ciphertext(N) || tag(tagLen)
     * @return распарсенный тип содержимого и открытые данные
     * @throws AuthenticationException при ошибке аутентификации/подмене данных
     * @throws IllegalArgumentException при некорректном формате записи
     * @throws IllegalStateException при переполнении порядкового номера
     * @throws TlsException при превышении максимального размера записи
     */
    public TlsParsedRecord unprotect(byte[] record) throws AuthenticationException, TlsException {
        DecryptResult r = doDecrypt(record);
        TlsParsedRecord parsed = new TlsParsedRecord(r.contentType, plaintext, r.dataLen);
        // plaintext не затираем между вызовами — будет перезаписан при следующем unprotect.
        // Затирается в destroy() при завершении сессии.
        seqNum++;
        return parsed;
    }

    /**
     * Дешифрует TLS-запись напрямую в предоставленный буфер, избегая
     * промежуточной копии в {@link TlsParsedRecord}.
     * <p>
     * Отличается от {@link #unprotect(byte[])} тем, что не создаёт
     * {@code TlsParsedRecord} и не аллоцирует новый {@code byte[]}
     * через {@code Arrays.copyOf}. Данные записываются в {@code dest}
     * начиная с {@code destOff}.
     *
     * @param record  TLS-запись: заголовок(5) || ciphertext || tag
     * @param dest    буфер для открытых данных (без inner content type)
     * @param destOff смещение в dest
     * @return RecordInfo с типом содержимого и длиной данных
     */
    public RecordInfo unprotectInto(byte[] record, byte[] dest, int destOff)
            throws AuthenticationException, TlsException {
        if (dest == null) {
            throw new IllegalArgumentException("Destination buffer must not be null");
        }
        DecryptResult r = doDecrypt(record);
        if (destOff < 0 || destOff + r.dataLen > dest.length) {
            throw new IllegalArgumentException(
                    "Destination buffer too small: need " + (destOff + r.dataLen) +
                    ", have " + dest.length);
        }
        System.arraycopy(plaintext, 0, dest, destOff, r.dataLen);
        seqNum++;
        return new RecordInfo(r.contentType, r.dataLen);
    }

    // ========================================================================
    // ByteBuffer-перегрузки для JSSE-модуля
    // ========================================================================

    /**
     * Шифрует и аутентифицирует данные из {@code src} и записывает
     * TLS-запись в {@code dst}.
     * <p>
     * Читает до {@link TlsConstants#MAX_PLAINTEXT_LENGTH} - 1 байт из src,
     * шифрует MGM и записывает:
     * {@code [header(5) || ciphertext(N) || tag(tagLen)]}.
     * <p>
     * После вызова position обоих буферов сдвинут на число прочитанных/записанных
     * байт. limit не изменяется — caller выполняет flip/compact на dst.
     * <p>
     * Поведение идентично {@link #protect(byte, byte[], int, int)} —
     * общая реализация через {@link #protect(byte, byte[], int, int)} после
     * копирования из src во временный массив.
     *
     * @param contentType тип содержимого (CT_HANDSHAKE, CT_APPLICATION_DATA, CT_ALERT)
     * @param src         буфер с открытыми данными (position будет сдвинут)
     * @param dst         буфер для TLS-записи (position будет сдвинут)
     * @return количество байт, записанных в dst
     * @throws IllegalArgumentException если src == null || dst == null, или dst недостаточен, или данные превышают MAX_PLAINTEXT_LENGTH
     * @throws IllegalStateException    при переполнении порядкового номера
     */
    public int protect(byte contentType, ByteBuffer src, ByteBuffer dst) {
        if (src == null || dst == null) {
            throw new IllegalArgumentException("Buffers must not be null");
        }
        int len = src.remaining();
        if (len + 1 > TlsConstants.MAX_PLAINTEXT_LENGTH) {
            throw new IllegalArgumentException(
                    "Data exceeds maximum fragment size: " + len);
        }
        int payloadLen = len + 1 + tagLen;
        if (dst.remaining() < TlsConstants.RECORD_HEADER_SIZE + payloadLen) {
            throw new IllegalArgumentException(
                    "Destination buffer too small: need " +
                    (TlsConstants.RECORD_HEADER_SIZE + payloadLen) +
                    ", have " + dst.remaining());
        }
        // Копируем из src во временный массив, затем делегируем byte[]-реализацию.
        // Альтернатива — прямой MGM поверх ByteBuffer — потребовала бы дублирования
        // всей crypto-логики. Для JSSE-модуля одна доп.копия на record приемлема.
        byte[] data = new byte[len];
        src.get(data);
        byte[] record = protect(contentType, data, 0, len);
        dst.put(record);
        return record.length;
    }

    /**
     * Снимает защиту (дешифрует + проверяет аутентификацию) TLS-записи из
     * {@code record} и записывает открытые данные в {@code plaintext}.
     * <p>
     * Использует двухступенчатую логику: сначала читает заголовок (5 байт) без
     * потребления, узнаёт точную длину записи, и только при достаточном количестве
     * байт — consume и расшифровка. Это позволяет вернуть точный {@code hint}
     * для {@link UnprotectResult.Status#NEED_MORE_INPUT}.
     * <p>
     * Состояние буферов после вызова:
     * <ul>
     *   <li>{@code OK} — position обоих буферов сдвинут на число записанных байт.
     *       Caller выполняет flip на plaintext для чтения.</li>
     *   <li>{@code NEED_MORE_INPUT} — position record НЕ изменился.
     *       Caller добавляет данные и повторяет вызов.</li>
     *   <li>{@code OUTPUT_TOO_SMALL} — position record восстановлен.
     *       Caller увеличивает plaintext буфер и повторяет вызов.
     *       Расшифровка будет выполнена заново.</li>
     * </ul>
     *
     * @param record    буфер с TLS-записью
     * @param plaintext буфер для открытых данных
     * @return результат дешифрования с указанием статуса
     * @throws AuthenticationException при ошибке аутентификации/подмене
     * @throws IllegalArgumentException при некорректном формате записи
     * @throws TlsException            при превышении максимального размера
     * @throws IllegalStateException   при переполнении порядкового номера
     */
    public UnprotectResult unprotect(ByteBuffer record, ByteBuffer plaintext)
            throws AuthenticationException, TlsException {
        if (record == null || plaintext == null) {
            throw new IllegalArgumentException("Buffers must not be null");
        }

        int recLen = record.remaining();
        int initialPos = record.position();

        // Stage 1: достаточно ли байт для заголовка?
        if (recLen < TlsConstants.RECORD_HEADER_SIZE) {
            return UnprotectResult.needMoreInput(TlsConstants.RECORD_HEADER_SIZE);
        }

        // Stage 2: peek заголовок — узнаём declared payload length (без consume)
        int declaredLen = ((record.get(initialPos + 3) & 0xFF) << 8)
                        | (record.get(initialPos + 4) & 0xFF);
        int totalRecordLen = TlsConstants.RECORD_HEADER_SIZE + declaredLen;

        // Грубая проверка: payload не может быть меньше tag
        if (declaredLen < tagLen) {
            throw new IllegalArgumentException(
                    "Record payload too small for tag: " + declaredLen);
        }

        // Stage 3: хватает ли байт на всю запись?
        if (recLen < totalRecordLen) {
            return UnprotectResult.needMoreInput(totalRecordLen);
        }

        // Stage 4: consume + расшифровка (без seqNum++ — будет на успехе)
        byte[] recBytes = new byte[totalRecordLen];
        record.get(recBytes);
        DecryptResult dr = doDecrypt(recBytes);
        int plaintextLen = dr.dataLen;

        // Stage 5: проверить dst до записи
        if (plaintext.remaining() < plaintextLen) {
            record.position(initialPos);
            // Затираем расшифрованные данные: caller повторит unprotect
            // с большим буфером, между retry данные не должны оставаться в памяти
            Arrays.fill(this.plaintext, 0, plaintextLen, (byte) 0);
            return UnprotectResult.outputTooSmall(plaintextLen);
        }

        plaintext.put(this.plaintext, 0, plaintextLen);
        seqNum++;
        return UnprotectResult.ok(dr.contentType);
    }

    /**
     * Результат {@link #unprotectInto}: тип содержимого и длина данных.
     */
    public static final class RecordInfo {
        public final byte contentType;
        public final int length;

        public RecordInfo(byte contentType, int length) {
            this.contentType = contentType;
            this.length = length;
        }
    }

    /** Внутренний результат дешифрования до копирования в выходной буфер. */
    private static final class DecryptResult {
        final byte contentType;
        final int dataLen;

        DecryptResult(byte contentType, int dataLen) {
            this.contentType = contentType;
            this.dataLen = dataLen;
        }
    }

    /**
     * Разбирает заголовок TLS-записи, дешифрует MGM и выполняет
     * constant-time поиск inner content type.
     * <p>
     * Оставляет открытые данные (включая content type) в {@link #plaintext}.
     * Не инкрементирует {@link #seqNum} — caller делает это после
     * копирования данных в целевой буфер или TlsParsedRecord.
     * <p>
     * TLSTREE per-record ре-кейинг через {@link TlsTreeCache#deriveKeyInto}.
     * Если ключ не изменился (только ICN) — вызывает mgm.reinitICN() вместо
     * полного mgm.init() для производительности.
     *
     * @throws TlsException при превышении максимального размера записи
     */
    private DecryptResult doDecrypt(byte[] record) throws AuthenticationException, TlsException {
        if (record == null || record.length < TlsConstants.RECORD_HEADER_SIZE + tagLen) {
            throw new IllegalArgumentException("Record too short");
        }
        if (seqNum < 0) {
            throw new IllegalStateException("Sequence number overflow");
        }
        checkSnmax();

        // Парсинг заголовка
        byte outerContentType = record[0];
        int legacyVersion = ((record[1] & 0xFF) << 8) | (record[2] & 0xFF);
        if (legacyVersion != TlsConstants.PROTOCOL_TLS_1_2) {
            throw new IllegalArgumentException("Invalid legacy version");
        }
        int payloadLen = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);

        if (payloadLen > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Record too long: " + payloadLen + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        if (record.length != TlsConstants.RECORD_HEADER_SIZE + payloadLen) {
            throw new IllegalArgumentException("Record length mismatch");
        }

        int ciphertextLen = payloadLen - tagLen;
        if (ciphertextLen < 0) {
            throw new IllegalArgumentException("Record payload too small for tag");
        }
        if (ciphertextLen > TlsConstants.MAX_PLAINTEXT_LENGTH) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Decrypted payload too long: " + ciphertextLen + " > " + TlsConstants.MAX_PLAINTEXT_LENGTH);
        }

        // Per-record TLSTREE в переиспользуемый буфер (RFC 9367 §4.1)
        boolean keyChanged = treeCache.deriveKeyInto(seqNum, currentKeyBuf, 0);

        // Nonce = sender_write_iv XOR seqNum (RFC 8446 §5.3)
        buildNonce(startIv);

        // AAD
        aadBuf[0] = outerContentType;
        aadBuf[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        aadBuf[2] = TlsConstants.LEGACY_VERSION_MINOR;
        aadBuf[3] = (byte) (payloadLen >>> 8);
        aadBuf[4] = (byte) payloadLen;

        // Дешифрование MGM
        if (keyChanged) {
            SymmetricKey symKey = new SymmetricKey(currentKeyBuf);
            mgm.init(false, new ParametersWithIV(symKey, nonceBuf));
            symKey.destroy();
        } else {
            mgm.reinitICN(nonceBuf);
        }
        mgm.updateAAD(aadBuf, 0, aadBuf.length);

        mgm.processBytes(record, TlsConstants.RECORD_HEADER_SIZE, ciphertextLen, plaintext, 0);
        mgm.finishDecryption(record, TlsConstants.RECORD_HEADER_SIZE + ciphertextLen);

        // Constant-time поиск последнего ненулевого байта (inner content type).
        // TLS 1.3 padding: 0x00 байты после inner_content_type.
        // Чтобы избежать timing side-channel, сканируем ВСЕ байты безусловно.
        // Сканируем только ciphertextLen — за пределами этой границы в буфере
        // могут быть stale данные от предыдущего unprotect (буфер переиспользуется).
        int lastNonZero = -1;
        int found = 0;
        for (int i = ciphertextLen - 1; i >= 0; i--) {
            int x = plaintext[i] & 0xFF;
            int isNonZero = ((x - 1) >>> 31) ^ 1;
            int notYetFound = found ^ 1;
            int update = isNonZero & notYetFound;
            int mask = -update;
            lastNonZero = (lastNonZero & ~mask) | (i & mask);
            found |= isNonZero;
        }
        if (lastNonZero < 0) {
            throw new AuthenticationException("Decrypted record has no content type");
        }

        byte innerContentType = plaintext[lastNonZero];
        return new DecryptResult(innerContentType, lastNonZero);
    }

    // ========================================================================
    // Внутренние методы
    // ========================================================================

    /**
     * Строит nonce по RFC 8446 Section 5.3:
     * nonce = IV XOR (0^8 || seq_num), где seq_num — 8-байтный big-endian.
     * MSB первого байта очищается для MGM ICN (RFC 9058 §3, RFC 9367 §3.3).
     *
     * @param iv инициализационный вектор
     */
    void buildNonce(byte[] iv) {
        System.arraycopy(iv, 0, nonceBuf, 0, TlsConstants.MGM_IV_SIZE);
        long s = seqNum;
        for (int i = 0; i < 8; i++) {
            nonceBuf[15 - i] ^= (byte) (s & 0xFF);
            s >>>= 8;
        }
        nonceBuf[0] &= 0x7F;
    }

    /** Для тестов: возвращает первый байт nonce после buildNonce(). */
    byte buildNoncePeek() {
        return nonceBuf[0];
    }

    /** Для тестов: возвращает nonceBuf после buildNonce(). */
    byte[] buildNoncePeekAll() {
        return nonceBuf.clone();
    }

    /**
     * Проверяет, не превышен ли SNMAX для данного cipher suite.
     * Использует unsigned-сравнение для корректной работы с L-вариантом
     * (SNMAX = 2^64 - 1). Беззнаковое сравнение критично: snmax для L
     * равен 0xFFFFFFFFFFFFFFFF, который в signed long равен -1, но
     * Long.compareUnsigned корректно трактует его как 2^64-1.
     */
    private void checkSnmax() {
        // Long.compareUnsigned корректен: snmax==Long.MIN_VALUE...-1 трактуется как беззнаковое 2^63...2^64-1
        if (Long.compareUnsigned(seqNum, snmax) >= 0) {
            throw new IllegalStateException(
                    "SNMAX exceeded: " + Long.toUnsignedString(seqNum));
        }
    }

}
