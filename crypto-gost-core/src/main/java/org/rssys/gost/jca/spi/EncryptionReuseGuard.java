package org.rssys.gost.jca.spi;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.rssys.gost.api.Digest;
import org.rssys.gost.cipher.SymmetricKey;

/**
 * Защита от повтора пары (ключ, nonce) при шифровании внутри одного экземпляра {@code Cipher}.
 *
 * <p>Повтор nonce под тем же ключом ломает режимы шифрования: в CTR и OFB совпадает гамма (раскрывается
 * XOR открытых текстов), в CFB - первые блоки, в CBC предсказуемый IV позволяет проверять догадки о
 * первом блоке, в MGM страдает ещё и аутентичность. Блокировка шифра после {@code doFinal} закрывает
 * только неявный повтор; явный {@code init(ENCRYPT, key, sameNonce)} ловит этот помощник.
 *
 * <p><b>Модель.</b> Пара «ожидает», пока наружу не вышел шифртекст ({@link #setPending}): повторный
 * {@code init} с ней безопасен, гамма не использовалась. После {@link #commit} пара считается
 * использованной, и {@link #prepare} отвергает её. Использованная пара переживает {@code init} на
 * расшифрование, иначе защиту обходит цепочка encrypt -> init(DECRYPT) -> init(ENCRYPT). Помнится
 * только <b>последняя</b> использованная пара (как у SunJCE GCM и CTR-ACPKM): A -> B -> A проходит.
 * Уникальность nonce между экземплярами {@code Cipher} обеспечивает вызывающий.
 *
 * <p><b>Ключ не хранится.</b> Вместо ключа помнится отпечаток: Стрибог-256 от метки и ключа. Совпадение
 * отпечатков двух разных ключей (вероятность 2^-256 для конкретной пары) даёт лишь ложный отказ,
 * ложного разрешения повтора не бывает.
 * Это эвристика внутри экземпляра, а не криптографическое свойство.
 *
 * <p>Не потокобезопасен, как и {@code Cipher}.
 */
final class EncryptionReuseGuard {

    /**
     * Метка доменного разделения: отпечаток для защиты от повтора нельзя спутать с хешем того же
     * ключа, посчитанным в другом месте (и наоборот); тот, кто увидит отпечаток в куче, не получит
     * готовый хеш ключа для других целей.
     */
    private static final byte[] FINGERPRINT_LABEL =
            "crypto-gost.encryption-reuse-guard.v1".getBytes(StandardCharsets.US_ASCII);

    private final String nonceName;
    private final String operation;

    /** Токен {@code отпечаток ‖ nonce} пары, на которой уже выдан шифртекст. */
    private byte[] used;

    /** Токен пары последней инициализации на шифрование, шифртекст ещё не выдан. */
    private byte[] pending;

    /**
     * @param nonceName название nonce в сообщении об отказе: {@code IV}, {@code ICN} или {@code UKM}
     * @param operation название операции в сообщении об отказе, например {@code encryption}
     */
    EncryptionReuseGuard(String nonceName, String operation) {
        this.nonceName = nonceName;
        this.operation = operation;
    }

    /**
     * Проверяет пару и возвращает её токен. Состояние помощника не меняется: токен передаётся в
     * {@link #setPending} только после успешной инициализации шифра, а при отказе вызывающий затирает
     * его через {@link #wipe}. Ключ хешируется один раз.
     *
     * @param key   ключ шифрования
     * @param nonce эффективный nonce: та часть IV/ICN/UKM, от которой зависит гамма
     * @return токен пары; владение переходит вызывающему
     * @throws InvalidAlgorithmParameterException если на этой паре уже выдан шифртекст
     */
    byte[] prepare(SymmetricKey key, byte[] nonce) throws InvalidAlgorithmParameterException {
        byte[] token = token(key, nonce);
        if (used != null && MessageDigest.isEqual(used, token)) {
            wipe(token);
            throw new InvalidAlgorithmParameterException(
                    "Cannot reuse key and " + nonceName + " for " + operation);
        }
        return token;
    }

    /** Запоминает пару как ожидающую; прежняя ожидающая пара затирается, токен переходит в собственность. */
    void setPending(byte[] token) {
        wipe(pending);
        pending = token;
    }

    /** Переводит ожидающую пару в использованную: вызывается, когда непустой шифртекст выдан. */
    void commit() {
        if (pending == null) {
            return;
        }
        wipe(used);
        used = pending;
        pending = null;
    }

    /** Забывает ожидающую пару (расшифрование, потеря состояния); использованная сохраняется. */
    void discardPending() {
        wipe(pending);
        pending = null;
    }

    /** Затирает токен; {@code null} допустим. */
    static void wipe(byte[] token) {
        if (token != null) {
            Arrays.fill(token, (byte) 0);
        }
    }

    private static byte[] token(SymmetricKey key, byte[] nonce) {
        byte[] keyBytes = key.getKey();
        byte[] hashInput = new byte[FINGERPRINT_LABEL.length + keyBytes.length];
        byte[] fingerprint = null;
        try {
            System.arraycopy(FINGERPRINT_LABEL, 0, hashInput, 0, FINGERPRINT_LABEL.length);
            System.arraycopy(keyBytes, 0, hashInput, FINGERPRINT_LABEL.length, keyBytes.length);
            fingerprint = Digest.digest256(hashInput);
            byte[] token = new byte[fingerprint.length + nonce.length];
            System.arraycopy(fingerprint, 0, token, 0, fingerprint.length);
            System.arraycopy(nonce, 0, token, fingerprint.length, nonce.length);
            return token;
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(hashInput, (byte) 0);
            wipe(fingerprint);
        }
    }
}
