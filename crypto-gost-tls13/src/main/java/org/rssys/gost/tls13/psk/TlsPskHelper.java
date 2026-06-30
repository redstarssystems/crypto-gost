package org.rssys.gost.tls13.psk;

import java.util.Arrays;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.crypto.HkdfStreebog;

/**
 * Пакетный helper для PSK-операций (binder, PSK derivation).
 *
 * <p>Все методы статические, не зависят от session state.</p>
 */
public final class TlsPskHelper {

    private TlsPskHelper() {}

    /**
     * Создаёт дайджест Streebog нужной длины.
     * @param hashLen 32 -> Streebog-256, 64 -> Streebog-512
     */
    private static Digest newDigest(int hashLen) {
        return HkdfStreebog.newDigest(hashLen);
    }

    /**
     * Вычисляет PSK binder по RFC 8446 §4.2.11.2.
     * <p>HMAC(binder_key, Hash(Truncate(CH))), где Truncate(CH) убирает binders list.</p>
     *
     * @param clientHelloBody полное тело ClientHello (включая binders)
     * @param psk            Pre-Shared Key
     * @param hashLen        длина хэша (32 для Streebog256)
     * @return binder (hashLen байт)
     */
    public static byte[] computeBinder(byte[] clientHelloBody, byte[] psk, int hashLen) {
        int bindersTotalLen = 3 + hashLen;
        byte[] truncated = Arrays.copyOf(clientHelloBody, clientHelloBody.length - bindersTotalLen);

        Digest d = newDigest(hashLen);
        d.update(truncated, 0, truncated.length);
        byte[] chHash = new byte[hashLen];
        d.doFinal(chHash, 0);

        byte[] zero = new byte[hashLen];
        byte[] earlySecret = HkdfStreebog.extract(zero, psk, hashLen);

        byte[] emptyHash = new byte[hashLen];
        d = newDigest(hashLen);
        d.doFinal(emptyHash, 0);
        byte[] binderKey =
                HkdfStreebog.deriveSecret(
                        earlySecret, HkdfStreebog.PREFIXED_RES_BINDER, emptyHash, hashLen);
        TlsUtils.wipeArray(earlySecret);
        TlsUtils.wipeArray(emptyHash);

        Hmac hmac = HkdfStreebog.newHmac(hashLen);
        hmac.init(binderKey);
        hmac.update(chHash, 0, chHash.length);
        byte[] binder = new byte[hashLen];
        hmac.doFinal(binder, 0);
        hmac.clear();
        TlsUtils.wipeArray(binderKey);
        TlsUtils.wipeArray(chHash);

        return binder;
    }

    /**
     * Вычисляет PSK binder для второго ClientHello после HRR (RFC 8446 §4.2.11.2).
     * <p>
     * Отличие от {@link #computeBinder}: transcript_hash включает Hash(CH1 + HRR)
     * через hrrPrefixHash = Hash(message_hash + HRR), за которым следует
     * Truncated(CH2). binder_key без изменений (контекст Derive-Secret = "").
     *
     * @param hrrPrefixHash Hash(message_hash + HRR) — префикс транскрипта до CH2
     * @param ch2Body       полное тело второго ClientHello (включая binders)
     * @param psk           Pre-Shared Key
     * @param hashLen       длина хэша (32 для Streebog256)
     * @return binder (hashLen байт)
     */
    public static byte[] computeBinderForHrr(
            byte[] hrrPrefixHash, byte[] ch2Body, byte[] psk, int hashLen) {
        int bindersTotalLen = 3 + hashLen;
        byte[] truncated = Arrays.copyOf(ch2Body, ch2Body.length - bindersTotalLen);

        // fullTranscriptHash = Hash(hrrPrefixHash || Truncated_CH2)
        Digest d = newDigest(hashLen);
        d.update(hrrPrefixHash, 0, hrrPrefixHash.length);
        d.update(truncated, 0, truncated.length);
        byte[] fullTranscriptHash = new byte[hashLen];
        d.doFinal(fullTranscriptHash, 0);

        byte[] zero = new byte[hashLen];
        byte[] earlySecret = HkdfStreebog.extract(zero, psk, hashLen);

        byte[] emptyHash = new byte[hashLen];
        d = newDigest(hashLen);
        d.doFinal(emptyHash, 0);
        byte[] binderKey =
                HkdfStreebog.deriveSecret(
                        earlySecret, HkdfStreebog.PREFIXED_RES_BINDER, emptyHash, hashLen);
        TlsUtils.wipeArray(earlySecret);
        TlsUtils.wipeArray(emptyHash);

        Hmac hmac = HkdfStreebog.newHmac(hashLen);
        hmac.init(binderKey);
        hmac.update(fullTranscriptHash, 0, fullTranscriptHash.length);
        byte[] binder = new byte[hashLen];
        hmac.doFinal(binder, 0);
        hmac.clear();
        TlsUtils.wipeArray(binderKey);
        TlsUtils.wipeArray(fullTranscriptHash);

        return binder;
    }

    /**
     * Проверяет PSK binder для второго ClientHello после HRR (серверная сторона).
     *
     * @param hrrPrefixHash Hash(message_hash + HRR)
     * @param ch2Body       полное тело второго ClientHello
     * @param psk           Pre-Shared Key
     * @param hashLen       длина хэша
     * @return true если binder совпадает
     */
    public static boolean verifyBinderForHrr(
            byte[] hrrPrefixHash, byte[] ch2Body, byte[] psk, int hashLen) {
        byte[] expected = computeBinderForHrr(hrrPrefixHash, ch2Body, psk, hashLen);
        byte[] actual = Arrays.copyOfRange(ch2Body, ch2Body.length - hashLen, ch2Body.length);
        boolean result = java.security.MessageDigest.isEqual(expected, actual);
        TlsUtils.wipeArray(expected);
        return result;
    }

    /**
     * Проверяет PSK binder (серверная сторона). Constant-time сравнение.
     *
     * @param clientHelloBody полное тело ClientHello
     * @param psk            Pre-Shared Key
     * @param hashLen        длина хэша
     * @return true если binder совпадает
     */
    public static boolean verifyBinder(byte[] clientHelloBody, byte[] psk, int hashLen) {
        byte[] expected = computeBinder(clientHelloBody, psk, hashLen);
        byte[] actual =
                Arrays.copyOfRange(
                        clientHelloBody, clientHelloBody.length - hashLen, clientHelloBody.length);
        boolean result = java.security.MessageDigest.isEqual(expected, actual);
        TlsUtils.wipeArray(expected);
        return result;
    }

    /**
     * Вырабатывает PSK из Resumption Master Secret и ticket_nonce.
     * <p>PSK = HKDF-Expand-Label(res_master, "resumption", ticket_nonce, Hash.length)</p>
     *
     * @param resumptionMasterSecret Resumption Master Secret (32 байта)
     * @param ticketNonce            nonce из NewSessionTicket
     * @param hashLen                длина хэша
     * @return PSK или null если rms == null
     */
    public static byte[] derivePsk(byte[] resumptionMasterSecret, byte[] ticketNonce, int hashLen) {
        if (resumptionMasterSecret == null) return null;
        return HkdfStreebog.expandLabel(
                resumptionMasterSecret,
                HkdfStreebog.PREFIXED_RESUMPTION,
                ticketNonce,
                hashLen,
                hashLen);
    }
}
