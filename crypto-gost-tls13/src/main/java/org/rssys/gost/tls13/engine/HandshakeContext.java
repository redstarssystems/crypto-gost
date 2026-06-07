package org.rssys.gost.tls13.engine;

import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Эфемерное состояние handshake: ECDHE-ключи, transcript, key schedule.
 * <p>
 * Вынесен из {@link TlsSession} для изоляции состояния, которое:
 * <ul>
 *   <li>существует только во время handshake (создаётся в начале, уничтожается в конце)</li>
 *   <li>должно быть гарантированно зачищено после завершения рукопожатия</li>
 *   <li>независимо от долговременных ключей сессии (TrafficKeys, TlsRecord)</li>
 * </ul>
 * <p>
 * {@link #destroy()} затирает ECDHE-приватный ключ (через {@link PrivateKeyParameters#destroy()}),
 * уничтожает key schedule и обнуляет ссылки на transcript и публичный ключ пира.
 * Вызывается в {@code finally} после успешного или аварийного завершения handshake.
 */
public final class HandshakeContext {

    private PrivateKeyParameters ecdhePrivateKey;
    private final Map<Integer, PrivateKeyParameters> ecdheKeyMap = new LinkedHashMap<>();
    private PublicKeyParameters peerEcdhePublicKey;
    private byte[] transcriptBuf = new byte[8192];
    private int transcriptSize;
    private Digest hsDigest;
    private TlsKeySchedule keySchedule;
    private List<byte[]> acceptedCaDns = Collections.emptyList();

    public HandshakeContext(int hashLen) {
        this.hsDigest = hashLen == TlsConstants.STREEBOG_512_HASH_LEN
                ? new Streebog512()
                : new Streebog256();
    }

    public void setEcdhePrivateKey(PrivateKeyParameters key) {
        this.ecdhePrivateKey = key;
    }

    public PrivateKeyParameters getEcdhePrivateKey() {
        return ecdhePrivateKey;
    }

    /** Добавляет ECDHE-ключ для указанной группы (multi key_share, RFC 8446 §4.2.8). */
    public void addEcdheKey(int namedGroup, PrivateKeyParameters key) {
        ecdheKeyMap.put(namedGroup, key);
    }

    /** Возвращает ECDHE-ключ для указанной группы, null если не найден. */
    public PrivateKeyParameters getEcdheKey(int namedGroup) {
        return ecdheKeyMap.get(namedGroup);
    }

    /** Проверяет, есть ли ECDHE-ключ для указанной группы. */
    public boolean hasEcdheKey(int namedGroup) {
        return ecdheKeyMap.containsKey(namedGroup);
    }

    /** Затирает и удаляет все ECDHE-ключи из multi key_share. */
    public void destroyEcdheKeys() {
        for (PrivateKeyParameters key : ecdheKeyMap.values()) {
            if (key != null) key.destroy();
        }
        ecdheKeyMap.clear();
    }

    public void setPeerEcdhePublicKey(PublicKeyParameters key) {
        this.peerEcdhePublicKey = key;
    }

    public PublicKeyParameters getPeerEcdhePublicKey() {
        return peerEcdhePublicKey;
    }

    public void setKeySchedule(TlsKeySchedule ks) {
        this.keySchedule = ks;
    }

    public TlsKeySchedule getKeySchedule() {
        return keySchedule;
    }

    public void setAcceptedCaDns(List<byte[]> acceptedCaDns) {
        this.acceptedCaDns = acceptedCaDns;
    }

    /** Возвращает список DistinguishedName из certificate_authorities extension
     *  CertificateRequest (RFC 8446 §4.2.4).
     *  Пустой список если extension отсутствует — семантика "сервер не указал предпочтений". */
    public List<byte[]> getAcceptedCaDns() {
        return acceptedCaDns;
    }

    /**
     * Добавляет handshake-фрейм в транскрипт (RFC 8446 §4.4.1).
     * Транскрипт — это все handshake-сообщения в порядке их отправки/получения,
     * включая handshake-заголовок (type + length). Хэш транскрипта используется
     * для вывода traffic secrets и verify_data.
     */
    public void addToTranscript(byte[] handshakeFrame) {
        ensureTranscriptCapacity(handshakeFrame.length);
        System.arraycopy(handshakeFrame, 0, transcriptBuf, transcriptSize, handshakeFrame.length);
        transcriptSize += handshakeFrame.length;
    }

    /** Добавляет слайс массива в транскрипт (без выделения промежуточной копии). */
    public void addToTranscript(byte[] src, int off, int len) {
        ensureTranscriptCapacity(len);
        System.arraycopy(src, off, transcriptBuf, transcriptSize, len);
        transcriptSize += len;
    }

    /**
     * Обеспечивает вместимость буфера транскрипта.
     * При необходимости удваивает размер буфера (growth factor 2x).
     */
    private void ensureTranscriptCapacity(int additional) {
        int needed = transcriptSize + additional;
        if (needed > transcriptBuf.length) {
            transcriptBuf = Arrays.copyOf(transcriptBuf,
                Math.max(transcriptBuf.length * 2, needed));
        }
    }

    /**
     * Вычисляет Transcript-Hash(RFC 8446 §4.4.1): Streebog-256/512 от всего
     * накопленного транскрипта. Вызывается в нескольких точках handshake:
     * <ul>
     *   <li>после получения/отправки ServerHello (вывод handshake traffic secrets)</li>
     *   <li>после Certificate + CertificateVerify (вывод finished_key)</li>
     *   <li>после Finished (вывод application traffic secrets)</li>
     * </ul>
     *
     * @return дайджест транскрипта
     */
    public byte[] transcriptHash() {
        hsDigest.reset();
        hsDigest.update(transcriptBuf, 0, transcriptSize);
        byte[] hash = new byte[hsDigest.getDigestSize()];
        hsDigest.doFinal(hash, 0);
        return hash;
    }

    /**
     * Заменяет текущий транскрипт на сообщение message_hash (RFC 8446 §4.4.1).
     * <p>
     * При HRR (HelloRetryRequest) первый ClientHello заменяется на
     * handshake-сообщение с типом 254 (message_hash), содержащее
     * Hash(CH1). Это гарантирует, что Transcript-Hash для handshake
     * traffic secrets включает CH1 через дайджест фиксированной длины.
     * <p>
     * Предусловие: транскрипт содержит CH1 (и только CH1, без HRR).
     */
    public void replaceTranscriptWithMessageHash() {
        byte[] ch1Hash = transcriptHash();
        transcriptSize = 0;
        // message_hash handshake-сообщение: type(254) || length(3) || hash(hashLen)
        int hashLen = hsDigest.getDigestSize();
        byte[] frame = new byte[4 + hashLen];
        frame[0] = (byte) 254;
        int len = hashLen;
        frame[1] = (byte) (len >>> 16);
        frame[2] = (byte) (len >>> 8);
        frame[3] = (byte) len;
        System.arraycopy(ch1Hash, 0, frame, 4, hashLen);
        TlsUtils.wipeArray(ch1Hash);
        addToTranscript(frame);
    }

    /**
     * Зачищает эфемерные материалы handshake.
     * <p>
     * Вызывается после успешного завершения handshake (в конце
     * {@link TlsSession#handshakeAsClient()} / {@link TlsSession#handshakeAsServer()})
     * для минимизации времени жизни ключевого материала в heap.
     * <p>
     * Затирает:
     * <ul>
     *   <li>ECDHE-приватный ключ через {@link PrivateKeyParameters#destroy()}</li>
     *   <li>key schedule (обнуляет все секреты)</li>
     *   <li>транскрипт (обнуляет ссылку)</li>
     *   <li>публичный ECDHE-ключ пира (обнуляет ссылку)</li>
     *   <li>дайджесты транскрипта (сброс + обнуление ссылок)</li>
     * </ul>
     */
    public void destroy() {
        if (keySchedule != null) {
            keySchedule.destroy();
            keySchedule = null;
        }
        if (transcriptBuf != null) {
            Arrays.fill(transcriptBuf, (byte) 0);
            transcriptBuf = null;
        }
        peerEcdhePublicKey = null;
        if (ecdhePrivateKey != null) {
            ecdhePrivateKey.destroy();
            ecdhePrivateKey = null;
        }
        destroyEcdheKeys();
        if (hsDigest != null) {
            hsDigest.reset();
            hsDigest = null;
        }
    }
}
