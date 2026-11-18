package org.rssys.gost.tls13.psk;

import java.util.Arrays;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.crypto.TlsKeySchedule;

/**
 * Пакетный helper для PSK-операций (binder, PSK derivation).
 *
 * <p>Все методы статические, не зависят от session state.</p>
 */
public final class TlsPskHelper {

    private TlsPskHelper() {}

    /** Длина заголовка списка binders: 2 байта длины списка и 1 байт длины binder-а. */
    private static final int BINDERS_LIST_HEADER_LEN = 3;

    /** Пустой префикс транскрипта первого ClientHello: общий, чтобы не выделять массив на каждый вызов. */
    private static final byte[] NO_PREFIX = new byte[0];

    /**
     * Создаёт дайджест Streebog нужной длины.
     * @param hashLen 32 -> Streebog-256, 64 -> Streebog-512
     */
    private static Digest newDigest(int hashLen) {
        return HkdfStreebog.newDigest(hashLen);
    }

    /**
     * Наибольшая длина identity (тикета), которую клиент может предложить в ClientHello.
     * <p>Предел задаёт не {@code opaque identity<1..2^16-1>}, а размер расширения: данные
     * {@code pre_shared_key} с одной identity и одним binder (длина списка identity, длина identity,
     * identity, возраст, длина списка binders, длина binder, binder) обязаны уместиться в uint16.
     * Тикет длиннее не помещается в ClientHello: длины переполнились бы, и пир ответил бы
     * {@code decode_error}. Часть блока расширений занимают и другие расширения, поэтому реальный
     * предел для конкретного ClientHello ещё немного меньше. Поэтому значение - грубый фильтр, а не
     * гарантия: тикет такой длины может не поместиться, и тогда ClientHello собирается без PSK.</p>
     *
     * @param hashLen длина хэша, она же длина binder
     * @return наибольшая допустимая длина identity в байтах
     */
    public static int maxIdentityLength(int hashLen) {
        return TlsConstants.MAX_EXTENSIONS_BLOCK_SIZE
                - TlsConstants.PSK_EXTENSION_FIXED_LENGTH
                - hashLen;
    }

    /**
     * Вычисляет PSK binder по RFC 8446 §4.2.11.2.
     * <p>HMAC(binder_key, Hash(Truncate(CH))), где Truncate(CH) убирает binders list.
     * Транскрипт хэш считается от полного handshake-фрейма (тип + длина + тело), а не только от тела.</p>
     *
     * @param handshakeFrame полный handshake-фрейм ClientHello (включая binders)
     * @param psk            Pre-Shared Key
     * @param hashLen        длина хэша (32 для Streebog256)
     * @return binder (hashLen байт)
     */
    public static byte[] computeBinder(byte[] handshakeFrame, byte[] psk, int hashLen) {
        return computeBinderOverTranscript(
                NO_PREFIX,
                handshakeFrame,
                singleBinderVectorOffset(handshakeFrame, hashLen),
                psk,
                hashLen);
    }

    /**
     * Вычисляет PSK binder по RFC 8446 §4.2.11.2 для ClientHello с произвольным числом binder.
     * <p>Транскрипт усекается по началу вектора binders (вместе с его 2-байтовой длиной), поэтому
     * binder каждой identity считается по одному и тому же усечённому ClientHello.</p>
     *
     * @param handshakeFrame      полный handshake-фрейм ClientHello (содержимое binders не учитывается)
     * @param bindersVectorOffset смещение вектора binders во фрейме
     * @param psk                 Pre-Shared Key этой identity
     * @param hashLen             длина хэша (32 для Streebog256)
     * @return binder (hashLen байт)
     */
    public static byte[] computeBinder(
            byte[] handshakeFrame, int bindersVectorOffset, byte[] psk, int hashLen) {
        return computeBinderOverTranscript(
                NO_PREFIX, handshakeFrame, bindersVectorOffset, psk, hashLen);
    }

    /**
     * Вычисляет PSK binder второго ClientHello после HRR для произвольного числа binder.
     *
     * @param transcriptPrefix    {@code message_hash || HRR} в сыром виде
     * @param ch2Frame            полный handshake-фрейм второго ClientHello
     * @param bindersVectorOffset смещение вектора binders во фрейме
     * @param psk                 Pre-Shared Key этой identity
     * @param hashLen             длина хэша
     * @return binder (hashLen байт)
     */
    public static byte[] computeBinderAfterHrr(
            byte[] transcriptPrefix,
            byte[] ch2Frame,
            int bindersVectorOffset,
            byte[] psk,
            int hashLen) {
        return computeBinderOverTranscript(
                transcriptPrefix, ch2Frame, bindersVectorOffset, psk, hashLen);
    }

    /**
     * Вычисляет PSK binder для второго ClientHello после HRR (RFC 8446 §4.2.11.2).
     * <p>
     * Транскрипт binder-а = {@code message_hash || HRR || Truncate(CH2)}, хэшируется одним
     * проходом: {@code Hash(transcriptPrefix || Truncate(CH2))}. Вложенный вариант
     * {@code Hash(Hash(prefix) || Truncate(CH2))} не соответствует RFC и не проходит
     * проверку у OpenSSL и КриптоПро. binder_key не меняется (контекст Derive-Secret = "").
     *
     * @param transcriptPrefix {@code message_hash || HRR} в сыром виде (без хэширования)
     * @param ch2Frame         полный handshake-фрейм второго ClientHello (включая binders)
     * @param psk              Pre-Shared Key
     * @param hashLen          длина хэша (32 для Streebog256)
     * @return binder (hashLen байт)
     */
    public static byte[] computeBinderAfterHrr(
            byte[] transcriptPrefix, byte[] ch2Frame, byte[] psk, int hashLen) {
        return computeBinderOverTranscript(
                transcriptPrefix,
                ch2Frame,
                singleBinderVectorOffset(ch2Frame, hashLen),
                psk,
                hashLen);
    }

    /**
     * Проверяет PSK binder для второго ClientHello после HRR (серверная сторона).
     * Constant-time сравнение.
     *
     * @param transcriptPrefix   {@code message_hash || HRR} в сыром виде (без хэширования)
     * @param ch2Frame           полный handshake-фрейм второго ClientHello
     * @param bindersVectorOffset смещение вектора binders (его 2-байтовой длины) во фрейме: по нему
     *                           режется Truncate(CH2), RFC 8446 §4.2.11.2
     * @param binderOffset       смещение проверяемого binder (само значение, без байта длины) во фрейме
     * @param psk                Pre-Shared Key
     * @param hashLen            длина хэша
     * @return true если binder совпадает
     */
    public static boolean verifyBinderAfterHrr(
            byte[] transcriptPrefix,
            byte[] ch2Frame,
            int bindersVectorOffset,
            int binderOffset,
            byte[] psk,
            int hashLen) {
        byte[] expected =
                computeBinderOverTranscript(
                        transcriptPrefix, ch2Frame, bindersVectorOffset, psk, hashLen);
        return matchesBinderAt(expected, ch2Frame, binderOffset);
    }

    /**
     * Проверяет PSK binder (серверная сторона). Constant-time сравнение.
     * <p>В ClientHello может быть несколько identity и столько же binder; проверяется только binder
     * выбранной identity (RFC 8446 §4.2.11), а транскрипт усекается по началу всего вектора binders.</p>
     *
     * @param handshakeFrame     полный handshake-фрейм ClientHello (включая binders)
     * @param bindersVectorOffset смещение вектора binders (его 2-байтовой длины) во фрейме
     * @param binderOffset       смещение проверяемого binder (само значение, без байта длины) во фрейме
     * @param psk                Pre-Shared Key
     * @param hashLen            длина хэша
     * @return true если binder совпадает
     */
    public static boolean verifyBinder(
            byte[] handshakeFrame,
            int bindersVectorOffset,
            int binderOffset,
            byte[] psk,
            int hashLen) {
        byte[] expected =
                computeBinderOverTranscript(
                        NO_PREFIX, handshakeFrame, bindersVectorOffset, psk, hashLen);
        return matchesBinderAt(expected, handshakeFrame, binderOffset);
    }

    /**
     * Общая часть вычисления binder: {@code HMAC(finished_key, Hash(prefix || Truncate(CH)))}.
     * <p>Предусловие: {@code bindersVectorOffset} - начало вектора binders во фрейме; всё, что
     * правее, отсекается перед хэшированием (RFC 8446 §4.2.11.2).</p>
     */
    private static byte[] computeBinderOverTranscript(
            byte[] transcriptPrefix,
            byte[] chFrame,
            int bindersVectorOffset,
            byte[] psk,
            int hashLen) {
        if (bindersVectorOffset < 0 || bindersVectorOffset > chFrame.length) {
            throw new IllegalArgumentException(
                    "Binders vector offset is outside ClientHello frame");
        }

        byte[] transcriptHash = new byte[hashLen];
        Digest d = newDigest(hashLen);
        d.update(transcriptPrefix, 0, transcriptPrefix.length);
        d.update(chFrame, 0, bindersVectorOffset);
        d.doFinal(transcriptHash, 0);

        try {
            return TlsKeySchedule.computePskBinder(psk, transcriptHash, hashLen);
        } finally {
            TlsUtils.wipeArray(transcriptHash);
        }
    }

    /**
     * Смещение вектора binders в собственном кадре клиента: он собирает ClientHello с одной identity,
     * поэтому вектор занимает ровно хвост (2 байта длины списка, 1 байт длины binder и сам binder).
     * Сервер этим хвостом не пользуется: он режет по смещению из разбора.
     */
    private static int singleBinderVectorOffset(byte[] ownFrame, int hashLen) {
        int offset = ownFrame.length - (BINDERS_LIST_HEADER_LEN + hashLen);
        if (offset < 0) {
            throw new IllegalArgumentException("ClientHello frame is shorter than binders list");
        }
        return offset;
    }

    /** Сравнивает ожидаемый binder с байтами фрейма по смещению и затирает ожидаемый. */
    private static boolean matchesBinderAt(byte[] expected, byte[] frame, int binderOffset) {
        boolean inFrame = binderOffset >= 0 && binderOffset + expected.length <= frame.length;
        boolean result =
                inFrame
                        && java.security.MessageDigest.isEqual(
                                expected,
                                Arrays.copyOfRange(
                                        frame, binderOffset, binderOffset + expected.length));
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
        return TlsKeySchedule.derivePsk(resumptionMasterSecret, ticketNonce, hashLen);
    }
}
