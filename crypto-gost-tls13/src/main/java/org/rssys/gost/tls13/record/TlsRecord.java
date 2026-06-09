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
    private final int maxInnerPlaintext;
    private final byte[] plaintext;
    private final byte[] currentKeyBuf = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
    // Буфер для входящей зашифрованной TLS-записи + заголовок.
    // Переиспользуется между вызовами unprotect — не аллоцируем byte[] на каждый decrypt.
    // Размер: HEADER(5) + MAX_CIPHERTEXT(16640) = 16645. Достаточно для любой записи RFC 8446.
    // НЕ удаляется при возможном shared-buffer рефакторинге transport↔record,
    // потому что MGM API (mgm.processBytes/mgm.finishDecryption) принимает
    // только byte[], не ByteBuffer. ByteBuffer от transport копируется сюда
    // один раз — цена ~5мкс/16KB на современном CPU.
    private final byte[] recordBuf = new byte[TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH];
    private long seqNum;
    private final int tagLen;

    // Параметры TLSTREE
    private final long snmax;
    private long rekeyThreshold = -1L;   // -1 = default (80% SNMAX)
    private final long c1;
    private final long c2;
    private final long c3;
    private final TlsTreeCache treeCache;

    // max_fragment_length (RFC 6066 §4): лимит на отправку и приём (plaintext, без inner_type)
    private int maxFragmentLength = TlsConstants.MAX_PLAINTEXT_LENGTH;

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
        this.maxInnerPlaintext = TlsConstants.MAX_CIPHERTEXT_LENGTH - tagLen;
        this.plaintext = new byte[maxInnerPlaintext];
        this.seqNum = 0;
        this.mgm = new Mgm(new Kuznyechik());
        this.snmax = ciphersuite.getSnmax();
        this.c1 = ciphersuite.getC1();
        this.c2 = ciphersuite.getC2();
        this.c3 = ciphersuite.getC3();
        this.treeCache = new TlsTreeCache(startKey, c1, c2, c3);
    }

    /**
     * Устанавливает max_fragment_length для отправки и приёма (RFC 6066 §4).
     *
     * @param maxFragLenCode код расширения (1=512, 2=1024, 3=2048, 4=4096),
     *                        0 = сброс на дефолт (16384)
     */
    public void setMaxFragmentLength(int maxFragLenCode) {
        this.maxFragmentLength = (maxFragLenCode >= 1 && maxFragLenCode <= 4)
                ? TlsConstants.MAX_FRAG_LEN_VALUES[maxFragLenCode]
                : TlsConstants.MAX_PLAINTEXT_LENGTH;
    }

    /** Обнуляет ключи, IV, scratch-буферы и сбрасывает seqNum. */
    public void destroy() {
        treeCache.destroy();
        mgm.destroy();
        TlsUtils.wipeArray(startKey);
        TlsUtils.wipeArray(startIv);
        TlsUtils.wipeArray(innerPlaintext);
        TlsUtils.wipeArray(ciphertext);
        TlsUtils.wipeArray(plaintext);
        TlsUtils.wipeArray(currentKeyBuf);
        TlsUtils.wipeArray(tagBuf);
        TlsUtils.wipeArray(aadBuf);
        TlsUtils.wipeArray(nonceBuf);
        TlsUtils.wipeArray(recordBuf);
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
     * Устанавливает порядковый номер записи.
     * <p>
     * <b>Назначение:</b> только для тестов и бенчмарков. В production-коде не используется —
     * смена ключей (KeyUpdate, RFC 8446 §7.2) создаёт новый экземпляр {@code TlsRecord}
     * с новым ключом и {@code seqNum = 0}.
     * <p>
     * <b>Внимание:</b> НЕ вызывать на активном {@code TlsRecord}. При фиксированном
     * {@code startKey} / {@code startIv} установка {@code seqNum} в уже использованное
     * значение приводит к повтору nonce ({@code nonce = startIv XOR seqNum}) при очередном
     * вызове {@link #protect}. Повтор nonce при одном ключе — нарушение безопасности MGM.
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
     * <p>
     * Реализация — тонкий wrapper над {@link #protect(byte, ByteBuffer, ByteBuffer)}.
     *
     * @param contentType тип содержимого
     * @param data        открытые данные
     * @param offset      смещение в data
     * @param len         длина фрагмента
     * @return TLS-запись: заголовок(5) || ciphertext(N) || tag(tagLen)
     * @throws IllegalArgumentException при некорректных offset/len
     */
    public byte[] protect(byte contentType, byte[] data, int offset, int len) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        if (offset < 0 || len < 0 || offset + len > data.length) {
            throw new IllegalArgumentException("Invalid offset/length");
        }
        if (len + 1 > maxFragmentLength) {
            throw new IllegalArgumentException("Data exceeds maximum fragment size");
        }
        ByteBuffer src = ByteBuffer.wrap(data, offset, len);
        int totalSize = TlsConstants.RECORD_HEADER_SIZE + len + 1 + tagLen;
        byte[] result = new byte[totalSize];
        ByteBuffer dst = ByteBuffer.wrap(result);
        protect(contentType, src, dst);
        return result;
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
        if (record == null) {
            throw new IllegalArgumentException("Record must not be null");
        }
        DecryptResult r = doDecrypt(record, record.length);
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
        if (record == null) {
            throw new IllegalArgumentException("Record must not be null");
        }
        if (dest == null) {
            throw new IllegalArgumentException("Destination buffer must not be null");
        }
        DecryptResult r = doDecrypt(record, record.length);
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
     * Основной (primary) метод protect — zero-alloc на горячем пути:
     * читает данные напрямую из src в переиспользуемый scratch-буфер
     * {@link #innerPlaintext}, и пишет готовую запись напрямую в dst,
     * избегая промежуточных {@code byte[]} аллокаций.
     * <p>
     * После вызова position обоих буферов сдвинут на число прочитанных/записанных
     * байт. limit не изменяется — caller выполняет flip/compact на dst.
     * <p>
     * Поведение идентично {@link #protect(byte, byte[], int, int)} —
     * byte[]-overload реализован как wrapper над этим методом.
     *
     * @param contentType тип содержимого (CT_HANDSHAKE, CT_APPLICATION_DATA, CT_ALERT)
     * @param src         буфер с открытыми данными (position будет сдвинут на len)
     * @param dst         буфер для TLS-записи (position будет сдвинут на totalSize)
     * @return количество байт, записанных в dst
     * @throws IllegalArgumentException если src == null || dst == null, или dst недостаточен, или данные превышают maxFragmentLength
     * @throws IllegalStateException    при переполнении порядкового номера
     */
    public int protect(byte contentType, ByteBuffer src, ByteBuffer dst) {
        if (src == null || dst == null) {
            throw new IllegalArgumentException("Buffers must not be null");
        }
        int len = src.remaining();
        if (len + 1 > maxFragmentLength) {
            throw new IllegalArgumentException(
                    "Data exceeds maximum fragment size: " + len);
        }
        int innerLen = len + 1;
        int totalSize = TlsConstants.RECORD_HEADER_SIZE + innerLen + tagLen;
        if (dst.remaining() < totalSize) {
            throw new IllegalArgumentException(
                    "Destination buffer too small: need " + totalSize +
                    ", have " + dst.remaining());
        }
        if (seqNum < 0) {
            throw new IllegalStateException("Sequence number overflow");
        }
        checkSnmax();

        // Per-record TLSTREE в переиспользуемый буфер (RFC 9367 §4.1)
        boolean keyChanged = treeCache.deriveKeyInto(seqNum, currentKeyBuf, 0);

        // Внутренний открытый текст напрямую из src в scratch-буфер
        src.get(innerPlaintext, 0, len);
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

        // Сборка записи напрямую в dst: заголовок || ciphertext || tag
        dst.put(TlsConstants.CT_APPLICATION_DATA);
        dst.put(TlsConstants.LEGACY_VERSION_MAJOR);
        dst.put(TlsConstants.LEGACY_VERSION_MINOR);
        dst.put((byte) (payloadLen >>> 8));
        dst.put((byte) payloadLen);
        dst.put(ciphertext, 0, innerLen);
        dst.put(tagBuf, 0, tagLen);

        seqNum++;
        return totalSize;
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

        // Stage 3a: проверка на превышение MAX_CIPHERTEXT_LENGTH ДО consume в recordBuf
        // (doDecrypt тоже проверяет, но record.get в Stage 4 упадёт с BufferOverflowException
        // если declaredLen > recordBuf.length — а recordBuf фиксированного размера)
        if (declaredLen > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Record too long: " + declaredLen + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        // Stage 4: consume + расшифровка (без seqNum++ — будет на успехе)
        record.get(recordBuf, 0, totalRecordLen);
        DecryptResult dr = doDecrypt(recordBuf, totalRecordLen);
        int plaintextLen = dr.dataLen;

        // Stage 5: проверить dst до записи
        if (plaintext.remaining() < plaintextLen) {
            record.position(initialPos);
            // Затираем расшифрованные данные: caller повторит unprotect
            // с большим буфером, между retry данные не должны оставаться в памяти
            Arrays.fill(this.plaintext, 0, plaintextLen, (byte) 0);
            // recordBuf содержит ciphertext+tag (публичные wire-байты, не ключевой материал).
            // Затираем только для защиты следующего вызова от partial state.
            Arrays.fill(recordBuf, 0, totalRecordLen, (byte) 0);
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
     * @param buf буфер с TLS-записью (заголовок || ciphertext || tag)
     * @param len точная длина записи (buf.length >= len)
     * @return результат дешифрования
     * @throws TlsException при превышении максимального размера записи
     */
    private DecryptResult doDecrypt(byte[] buf, int len) throws AuthenticationException, TlsException {
        if (buf == null || len < TlsConstants.RECORD_HEADER_SIZE + tagLen) {
            throw new IllegalArgumentException("Record too short");
        }
        if (seqNum < 0) {
            throw new IllegalStateException("Sequence number overflow");
        }
        checkSnmax();

        // Парсинг заголовка
        byte outerContentType = buf[0];
        int legacyVersion = ((buf[1] & 0xFF) << 8) | (buf[2] & 0xFF);
        if (legacyVersion != TlsConstants.PROTOCOL_TLS_1_2) {
            throw new IllegalArgumentException("Invalid legacy version");
        }
        int payloadLen = ((buf[3] & 0xFF) << 8) | (buf[4] & 0xFF);

        if (payloadLen > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Record too long: " + payloadLen + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        if (len != TlsConstants.RECORD_HEADER_SIZE + payloadLen) {
            throw new IllegalArgumentException("Record length mismatch");
        }

        int ciphertextLen = payloadLen - tagLen;
        if (ciphertextLen < 0) {
            throw new IllegalArgumentException("Record payload too small for tag");
        }
        if (ciphertextLen > maxInnerPlaintext) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Decrypted payload too long: " + ciphertextLen + " > " + maxInnerPlaintext);
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

        mgm.processBytes(buf, TlsConstants.RECORD_HEADER_SIZE, ciphertextLen, plaintext, 0);
        mgm.finishDecryption(buf, TlsConstants.RECORD_HEADER_SIZE + ciphertextLen);

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
        // Проверка против явно согласованного max_fragment_length (RFC 6066 §4).
        // При дефолтном значении (MAX_PLAINTEXT_LENGTH) проверка не применяется —
        // защита от запредельно больших записей обеспечивается maxInnerPlaintext выше.
        if (maxFragmentLength < TlsConstants.MAX_PLAINTEXT_LENGTH && lastNonZero > maxFragmentLength) {
            throw new TlsException(TlsConstants.ALERT_RECORD_OVERFLOW,
                    "Decrypted record exceeds negotiated max fragment length: "
                    + lastNonZero + " > " + maxFragmentLength);
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

    /**
     * @return true если seqNum достиг 80% порога SNMAX — сигнал к KeyUpdate.
     *         L-вариант (2^64-1) использует константу 0xCCCCCCCCCCCCCCCC,
     *         S-вариант — snmax * 4 / 5 через unsigned арифметику.
     */
    public boolean isApproachingRekeyLimit() {
        if (rekeyThreshold >= 0) {
            return Long.compareUnsigned(seqNum, rekeyThreshold) >= 0;
        }
        if (snmax == -1L) {
            // L-вариант (2^64-1): порог 80% unsigned
            return Long.compareUnsigned(seqNum, 0xCCCCCCCCCCCCCCCCL) >= 0;
        }
        // S-вариант: snmax < 2^42, snmax * 4 безопасно в signed long
        long threshold = Long.divideUnsigned(snmax * 4, 5);
        return Long.compareUnsigned(seqNum, threshold) >= 0;
    }

    /**
     * Устанавливает порог rekey.
     * <p>
     * Если порог >= 0, isApproachingRekeyLimit() срабатывает при достижении
     * seqNum >= threshold. -1 = использовать дефолтный порог (80% SNMAX).
     * <p>
     * Метод публичный для использования в тестах. В продакшен-коде порог
     * не меняется.
     *
     * @param threshold порог seqNum или -1 для дефолта
     */
    public void setRekeyThreshold(long threshold) {
        this.rekeyThreshold = threshold;
    }


}
