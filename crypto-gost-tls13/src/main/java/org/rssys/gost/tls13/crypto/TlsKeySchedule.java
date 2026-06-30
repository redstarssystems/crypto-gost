package org.rssys.gost.tls13.crypto;

import org.rssys.gost.digest.Digest;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * Key schedule TLS 1.3 (RFC 8446 §7.1) с ГОСТ-примитивами по RFC 9367.
 * <p>
 * В отличие от KDF_GOST_R_3411_2012_256 (RFC 7836), TLS 1.3 ГОСТ
 * использует стандартный HKDF-Extract/Expand (RFC 5869) с
 * HMAC-Streebog-256 (RFC 9367 §3.3).
 * </p>
 * <pre>
 * early = HKDF-Extract(0, 0)
 * handshake = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)
 * master = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)
 * </pre>
 */
public final class TlsKeySchedule {

    private final TlsCiphersuite ciphersuite;
    private final int hashLen;

    private byte[] earlySecret;
    private byte[] handshakeSecret;
    private byte[] masterSecret;
    // Кеш Streebog(""): lazy, потому что во всех 4+ точках
    // хеш пустой строки всегда одинаков для данного hashLen.
    // Публичное значение — не затирается в destroy().
    private byte[] emptyHash;
    private boolean destroyed;

    /**
     * @param ciphersuite cipher suite (определяет hashLen: 32 для 256-bit, 64 для 512-bit)
     */
    public TlsKeySchedule(TlsCiphersuite ciphersuite) {
        if (ciphersuite == null) {
            throw new IllegalArgumentException("ciphersuite must not be null");
        }
        this.ciphersuite = ciphersuite;
        this.hashLen = ciphersuite.getHashLen();
    }

    /**
     * Early Secret = HKDF-Extract(0, 0) — режим без PSK.
     *
     * @return early secret (копия)
     */
    public byte[] getEarlySecret() {
        checkNotDestroyed();
        if (earlySecret == null) {
            byte[] zero = new byte[hashLen];
            earlySecret = HkdfStreebog.extract(zero, zero, hashLen);
        }
        return earlySecret.clone();
    }

    /**
     * Handshake Secret = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)
     *
     * @param ecdheSharedSecret общий секрет ECDHE
     */
    public void deriveHandshakeSecret(byte[] ecdheSharedSecret) {
        checkNotDestroyed();
        if (ecdheSharedSecret == null || ecdheSharedSecret.length == 0) {
            throw new IllegalArgumentException("ECDHE shared secret must not be null or empty");
        }
        byte[] early = getEarlySecret();
        byte[] emptyHash = computeEmptyHash();
        byte[] derived =
                HkdfStreebog.deriveSecret(early, HkdfStreebog.PREFIXED_DERIVED, emptyHash, hashLen);
        try {
            TlsUtils.wipeArray(handshakeSecret);
            handshakeSecret = HkdfStreebog.extract(derived, ecdheSharedSecret, hashLen);
        } finally {
            TlsUtils.wipeArray(derived);
            TlsUtils.wipeArray(early);
            // emptyHash не затираем — это кеш-ссылка на поле emptyHash (computeEmptyHash)
        }
    }

    /**
     * Master Secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)
     */
    public void deriveMasterSecret() {
        checkNotDestroyed();
        if (handshakeSecret == null) {
            throw new IllegalStateException(
                    "Handshake secret must be derived before master secret");
        }
        byte[] emptyHash = computeEmptyHash();
        byte[] derived =
                HkdfStreebog.deriveSecret(
                        handshakeSecret, HkdfStreebog.PREFIXED_DERIVED, emptyHash, hashLen);
        try {
            byte[] zero = new byte[hashLen];
            masterSecret = HkdfStreebog.extract(derived, zero, hashLen);
        } finally {
            TlsUtils.wipeArray(derived);
            TlsUtils.wipeArray(handshakeSecret);
            handshakeSecret = null;
        }
    }

    /**
     * @param transcriptHash хеш транскрипта
     * @return сырой handshake traffic secret (серверный) без обнуления.
     *         Нужен для выработки finished_key.
     *         Caller обязан затереть возвращённый массив через
     *         {@link TlsUtils#wipeArray} после использования.
     */
    public byte[] getServerHandshakeTrafficSecret(byte[] transcriptHash) {
        return HkdfStreebog.deriveSecret(
                handshakeSecret, HkdfStreebog.PREFIXED_S_HS_TRAFFIC, transcriptHash, hashLen);
    }

    /**
     * @param transcriptHash хеш транскрипта
     * @return сырой handshake traffic secret (клиентский) без обнуления.
     *         Нужен для выработки finished_key.
     *         Caller обязан затереть возвращённый массив через
     *         {@link TlsUtils#wipeArray} после использования.
     */
    public byte[] getClientHandshakeTrafficSecret(byte[] transcriptHash) {
        return HkdfStreebog.deriveSecret(
                handshakeSecret, HkdfStreebog.PREFIXED_C_HS_TRAFFIC, transcriptHash, hashLen);
    }

    /**
     * @param transcriptHash хеш транскрипта
     * @return сырой application traffic secret (серверный) без обнуления.
     *         Нужен для KeyUpdate (RFC 8446 §7.2).
     *         Caller обязан затереть возвращённый массив через
     *         {@link TlsUtils#wipeArray} после использования.
     */
    public byte[] getServerApplicationTrafficSecret(byte[] transcriptHash) {
        return HkdfStreebog.deriveSecret(
                masterSecret, HkdfStreebog.PREFIXED_S_AP_TRAFFIC, transcriptHash, hashLen);
    }

    /**
     * @param transcriptHash хеш транскрипта
     * @return сырой application traffic secret (клиентский) без обнуления.
     *         Нужен для KeyUpdate (RFC 8446 §7.2).
     *         Caller обязан затереть возвращённый массив через
     *         {@link TlsUtils#wipeArray} после использования.
     */
    public byte[] getClientApplicationTrafficSecret(byte[] transcriptHash) {
        return HkdfStreebog.deriveSecret(
                masterSecret, HkdfStreebog.PREFIXED_C_AP_TRAFFIC, transcriptHash, hashLen);
    }

    // ========================================================================
    // Finished verify_data — чтобы не зависеть от порядка сообщений
    // в транскрипте, пересылаем ключ напрямую (RFC 8446 §4.4.4)
    // ========================================================================

    /**
     * Вычисляет verify_data для Finished:
     * finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hashLen)
     * verify_data = HMAC-Streebog(finished_key, raw_transcript)
     *
     * @param trafficSecret traffic secret
     * @param transcript хеш транскрипта
     * @return verify_data
     */
    public byte[] computeVerifyData(byte[] trafficSecret, byte[] transcript) {
        checkNotDestroyed();
        byte[] finishedKey =
                HkdfStreebog.expandLabel(
                        trafficSecret,
                        HkdfStreebog.PREFIXED_FINISHED,
                        HkdfStreebog.EMPTY_CONTEXT,
                        hashLen,
                        hashLen);
        Hmac hmac = HkdfStreebog.newHmac(hashLen);
        hmac.init(finishedKey);
        hmac.update(transcript, 0, transcript.length);
        byte[] verifyData = new byte[hashLen];
        hmac.doFinal(verifyData, 0);
        hmac.clear();
        TlsUtils.wipeArray(finishedKey);
        return verifyData;
    }

    // ========================================================================
    // PSK (Pre-Shared Key) — RFC 8446 §7.1
    // ========================================================================

    /**
     * Early Secret = HKDF-Extract(0, PSK) — режим с PSK.
     * Переопределяет early_secret, если он уже был вычислен.
     * Вызывается перед deriveHandshakeSecret().
     *
     * @param psk предварительный общий ключ (PSK)
     */
    public void deriveEarlySecret(byte[] psk) {
        checkNotDestroyed();
        if (psk == null || psk.length == 0) {
            throw new IllegalArgumentException("PSK must not be null or empty");
        }
        byte[] zero = new byte[hashLen];
        TlsUtils.wipeArray(earlySecret);
        earlySecret = HkdfStreebog.extract(zero, psk, hashLen);
    }

    /**
     * Resumption Master Secret = Derive-Secret(master_secret, "res master", "").
     * Вызывается после deriveMasterSecret().
     *
     * @return resumption master secret
     * @throws IllegalStateException если master_secret не выведен
     */
    public byte[] getResumptionMasterSecret() {
        checkNotDestroyed();
        if (masterSecret == null) {
            throw new IllegalStateException("Master secret not yet derived");
        }
        byte[] emptyHash = computeEmptyHash();
        return HkdfStreebog.deriveSecret(
                masterSecret, HkdfStreebog.PREFIXED_RES_MASTER, emptyHash, hashLen);
    }

    // ========================================================================
    // Жизненный цикл
    // ========================================================================

    /** Обнуляет все секреты (early, handshake, master). */
    public void destroy() {
        if (!destroyed) {
            destroyed = true;
            TlsUtils.wipeArray(earlySecret);
            TlsUtils.wipeArray(handshakeSecret);
            TlsUtils.wipeArray(masterSecret);
        }
    }

    /** @return true если ключевой материал уничтожен */
    public boolean isDestroyed() {
        return destroyed;
    }

    // ========================================================================
    // Внутренние методы
    // ========================================================================

    /**
     * Вырабатывает traffic key и IV из traffic secret.
     *
     * key = HKDF-Expand-Label(traffic_secret, "key", "", keyLen)
     * iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", ivLen)
     *
     * Почему caller, а не get*TrafficKeys: в TlsSession handshake traffic
     * secret уже выработан (через get*TrafficSecret для Finished). Передача
     * готового secret сюда позволяет избежать повторного deriveSecret,
     * экономя один expandLabel на секрет.
     *
     * Caller обязан затереть {@code trafficSecret} после вызова
     * (через {@link TlsUtils#wipeArray} или try/finally).
     *
     * @param trafficSecret traffic secret (не затирается внутри)
     * @return traffic keys (key + IV)
     */
    public TlsTrafficKeys deriveTrafficKeys(byte[] trafficSecret) {
        byte[] key =
                HkdfStreebog.expandLabel(
                        trafficSecret,
                        HkdfStreebog.PREFIXED_KEY,
                        HkdfStreebog.EMPTY_CONTEXT,
                        ciphersuite.getKeyLen(),
                        hashLen);
        byte[] iv =
                HkdfStreebog.expandLabel(
                        trafficSecret,
                        HkdfStreebog.PREFIXED_IV,
                        HkdfStreebog.EMPTY_CONTEXT,
                        ciphersuite.getIvLen(),
                        hashLen);
        return new TlsTrafficKeys(key, iv);
    }

    /**
     * Вычисляет хеш Streebog от пустой строки — используется как context
     * для Derive-Secret (RFC 8446 §7.1: Transcript-Hash("")). Кешируется
     * на всё время жизни KeySchedule.
     *
     * @return хеш пустой строки
     */
    private byte[] computeEmptyHash() {
        if (emptyHash != null) return emptyHash;
        Digest d = HkdfStreebog.newDigest(hashLen);
        emptyHash = new byte[hashLen];
        d.doFinal(emptyHash, 0);
        return emptyHash;
    }

    /**
     * Проверяет, что KeySchedule не уничтожен (destroy() не вызывался).
     * @throws IllegalStateException если schedule уже зачищен
     */
    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("KeySchedule has been destroyed");
        }
    }
}
