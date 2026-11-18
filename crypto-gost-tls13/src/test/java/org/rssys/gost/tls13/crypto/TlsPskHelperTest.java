package org.rssys.gost.tls13.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.util.CryptoRandom;

/**
 * Регрессионные тесты PSK binder (RFC 8446 §4.2.11.2).
 *
 * Проверяются два исправления:
 *   1. Binder считается от полного handshake-фрейма (а не только от тела).
 *   2. Binder использует finished_key = HKDF-Expand-Label(binder_key, 'finished', '', Hash.length),
 *      а не голый binder_key (RFC 8446 §4.4.4).
 */
@DisplayName("PSK binder: граница транскрипта (фрейм) и деривация finished_key")
class TlsPskHelperTest {

    private static final int HL = TlsConstants.STREEBOG_256_HASH_LEN;

    /** Строит минимальный body ClientHello с PSK-блоком (binder == нули). */
    private static byte[] buildChBodyWithPsk(byte[] pskId, int hashLen) {
        // preamble (38 bytes: protocol(2)+random(32)+sessionId(2+1)+cipher(2+2)+comp(1+1))
        // + extensions_len(2) + minimal extensions
        byte[] preamble = new byte[2 + 32 + 3 + 4 + 2];
        // protocol_version: 0x0303
        preamble[0] = (byte) 0x03;
        preamble[1] = (byte) 0x03;
        // random: 32 bytes zero
        // session_id: len=0
        preamble[34] = 0;
        // cipher_suites: len=2, suite=0xC103
        preamble[35] = 0;
        preamble[36] = 2;
        preamble[37] = (byte) 0xC1;
        preamble[38] = 0x03;
        // compression: len=1, value=0
        preamble[39] = 1;
        preamble[40] = 0;

        // build PSK pre_shared_key extension (must be last)
        int bLen = 2 + 1 + hashLen; // binder list(2) + entry(1) + binder(hashLen)
        // ext body: identities list(2) + identity len(2) + identity + age(4) + binders;
        // без префикса длины identity фикстура была короче записываемой структуры на 2 байта,
        // как и сборщик, поэтому не ловила дефект
        int pskExtSize = 2 + 2 + pskId.length + 4 + bLen;
        byte[] pskExt = new byte[2 + 2 + pskExtSize]; // type(2) + len(2) + body
        pskExt[0] = (byte) (TlsConstants.EXT_PRE_SHARED_KEY >>> 8);
        pskExt[1] = (byte) TlsConstants.EXT_PRE_SHARED_KEY;
        pskExt[2] = (byte) (pskExtSize >>> 8);
        pskExt[3] = (byte) pskExtSize;
        // identities_len = identity_len + 6 (identity + age)
        int idListLen = pskId.length + 6;
        pskExt[4] = (byte) (idListLen >>> 8);
        pskExt[5] = (byte) idListLen;
        // identity_len
        pskExt[6] = (byte) (pskId.length >>> 8);
        pskExt[7] = (byte) pskId.length;
        System.arraycopy(pskId, 0, pskExt, 8, pskId.length);
        // obfuscated_ticket_age = 0
        int pos = 8 + pskId.length;
        pskExt[pos++] = 0;
        pskExt[pos++] = 0;
        pskExt[pos++] = 0;
        pskExt[pos++] = 0;
        // binders list: len = 1 + hashLen
        pskExt[pos++] = (byte) ((1 + hashLen) >>> 8);
        pskExt[pos++] = (byte) (1 + hashLen);
        pskExt[pos] = (byte) hashLen;
        // binder bytes are already zero (new byte[])

        byte[] body = new byte[preamble.length + 2 + pskExt.length];
        System.arraycopy(preamble, 0, body, 0, preamble.length);
        body[preamble.length] = (byte) (pskExt.length >>> 8);
        body[preamble.length + 1] = (byte) pskExt.length;
        System.arraycopy(pskExt, 0, body, preamble.length + 2, pskExt.length);
        return body;
    }

    /**
     * Регрессия 1: полный handshake-фрейм против тела без заголовка.
     */
    @Test
    @DisplayName("binder совпадает на полном фрейме, расходится на теле без заголовка")
    void binderFrameVsBody() {
        byte[] psk = new byte[HL];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] pskId = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(pskId);

        byte[] chBody = buildChBodyWithPsk(pskId, HL);
        byte[] chFrame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode();

        // Вычисляем binder от фрейма
        byte[] binder = TlsPskHelper.computeBinder(chFrame, psk, HL);
        assertNotNull(binder);
        assertEquals(HL, binder.length);

        // Вписываем binder в тело (в конец, поверх нулей)
        System.arraycopy(binder, 0, chBody, chBody.length - HL, HL);
        // Перекодируем фрейм с binder
        chFrame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode();

        // Верификация на полном фрейме — должна пройти
        assertTrue(
                TlsPskHelper.verifyBinder(
                        chFrame, vectorOffset(chFrame), binderOffset(chFrame), psk, HL),
                "binder должен верифицироваться на полном handshake-фрейме");

        // Верификация на теле без заголовка — должна РАСХОДИТЬСЯ
        assertFalse(
                TlsPskHelper.verifyBinder(
                        chBody, vectorOffset(chBody), binderOffset(chBody), psk, HL),
                "binder должен расходиться на теле без 4-байтового заголовка");
    }

    /**
     * Регрессия 2: finished_key — обязательная промежуточная деривация.
     */
    @Test
    @DisplayName("binder через finished_key отличается от прямого HMAC(binder_key, chHash)")
    void binderRequiresFinishedKey() {
        byte[] psk = new byte[HL];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] pskId = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(pskId);

        byte[] chBody = buildChBodyWithPsk(pskId, HL);
        byte[] chFrame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode();
        byte[] binder = TlsPskHelper.computeBinder(chFrame, psk, HL);

        System.arraycopy(binder, 0, chBody, chBody.length - HL, HL);
        chFrame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode();
        byte[] actualBinder = Arrays.copyOfRange(chBody, chBody.length - HL, chBody.length);

        // Вычисляем binder_key
        byte[] zero = new byte[HL];
        byte[] earlySecret = HkdfStreebog.extract(zero, psk, HL);
        byte[] emptyHash = new byte[HL];
        HkdfStreebog.newDigest(HL).doFinal(emptyHash, 0);
        byte[] binderKey = HkdfStreebog.deriveSecret(earlySecret, "res binder", emptyHash, HL);
        TlsUtils.wipeArray(earlySecret);
        TlsUtils.wipeArray(emptyHash);

        // chHash = Hash(full_frame_without_binder)
        int bindersTotalLen = 3 + HL;
        byte[] truncated = Arrays.copyOf(chFrame, chFrame.length - bindersTotalLen);
        byte[] chHash = new byte[HL];
        Digest d = HkdfStreebog.newDigest(HL);
        d.update(truncated, 0, truncated.length);
        d.doFinal(chHash, 0);

        // Старая (неправильная) формула: HMAC(binder_key, chHash)
        Hmac oldHmac = HkdfStreebog.newHmac(HL);
        oldHmac.init(binderKey);
        oldHmac.update(chHash, 0, chHash.length);
        byte[] oldBinder = new byte[HL];
        oldHmac.doFinal(oldBinder, 0);
        oldHmac.clear();

        assertFalse(
                Arrays.equals(oldBinder, actualBinder),
                "HMAC(binder_key, chHash) должен отличаться от правильного binder");

        // Правильная формула: finished_key -> HMAC(finished_key, chHash)
        byte[] finishedKey =
                HkdfStreebog.expandLabel(binderKey, "finished", HkdfStreebog.EMPTY_CONTEXT, HL, HL);
        Hmac correctHmac = HkdfStreebog.newHmac(HL);
        correctHmac.init(finishedKey);
        correctHmac.update(chHash, 0, chHash.length);
        byte[] correctBinder = new byte[HL];
        correctHmac.doFinal(correctBinder, 0);
        correctHmac.clear();
        TlsUtils.wipeArray(finishedKey);

        assertArrayEquals(
                correctBinder, actualBinder, "binder через finished_key должен совпадать с actual");
    }

    /** Независимый от продакшен-кода Streebog-256 над склейкой частей. */
    private static byte[] streebog256(byte[]... parts) {
        Digest d = HkdfStreebog.newDigest(HL);
        for (byte[] part : parts) {
            d.update(part, 0, part.length);
        }
        byte[] out = new byte[HL];
        d.doFinal(out, 0);
        return out;
    }

    /** Эталон binder: HMAC(finished_key, transcriptHash), ключи из PSK по RFC 8446 §7.1. */
    private static byte[] referenceBinder(byte[] psk, byte[] transcriptHash) {
        byte[] earlySecret = HkdfStreebog.extract(new byte[HL], psk, HL);
        byte[] binderKey = HkdfStreebog.deriveSecret(earlySecret, "res binder", streebog256(), HL);
        byte[] finishedKey =
                HkdfStreebog.expandLabel(binderKey, "finished", HkdfStreebog.EMPTY_CONTEXT, HL, HL);
        Hmac hmac = HkdfStreebog.newHmac(HL);
        hmac.init(finishedKey);
        hmac.update(transcriptHash, 0, transcriptHash.length);
        byte[] binder = new byte[HL];
        hmac.doFinal(binder, 0);
        return binder;
    }

    /** Префикс транскрипта: message_hash(CH1) || HRR, собранный вручную по RFC 8446 §4.4.1. */
    private static byte[] referencePrefix(byte[] ch1Frame, byte[] hrrFrame) {
        byte[] messageHash = new byte[4 + HL];
        messageHash[0] = TlsConstants.HT_MESSAGE_HASH;
        messageHash[3] = (byte) HL;
        System.arraycopy(streebog256(ch1Frame), 0, messageHash, 4, HL);
        byte[] prefix = new byte[messageHash.length + hrrFrame.length];
        System.arraycopy(messageHash, 0, prefix, 0, messageHash.length);
        System.arraycopy(hrrFrame, 0, prefix, messageHash.length, hrrFrame.length);
        return prefix;
    }

    /** Смещение вектора binders в кадре с единственным binder в хвосте: длина списка, длина binder, binder. */
    private static int vectorOffset(byte[] frame) {
        return frame.length - (3 + HL);
    }

    /** Смещение значения единственного binder в хвосте кадра. */
    private static int binderOffset(byte[] frame) {
        return frame.length - HL;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    @Test
    @DisplayName(
            "binder после HRR: один хэш от message_hash || HRR || усечённый CH2 (RFC 8446 §4.2.11.2)")
    void binderAfterHrrMatchesIndependentReference() {
        byte[] psk = randomBytes(HL);
        byte[] ch1Frame = randomBytes(120);
        byte[] hrrFrame = randomBytes(60);
        byte[] prefix = referencePrefix(ch1Frame, hrrFrame);

        byte[] ch2Body = buildChBodyWithPsk(randomBytes(8), HL);
        byte[] ch2Frame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, ch2Body).encode();
        byte[] truncated = Arrays.copyOf(ch2Frame, ch2Frame.length - (3 + HL));

        byte[] expected = referenceBinder(psk, streebog256(prefix, truncated));
        byte[] actual = TlsPskHelper.computeBinderAfterHrr(prefix, ch2Frame, psk, HL);

        assertArrayEquals(expected, actual, "binder должен совпасть с независимым расчётом");

        // Вложенный вариант Hash(Hash(prefix) || trunc) - прежняя ошибка - даёт другой binder
        byte[] nested = referenceBinder(psk, streebog256(streebog256(prefix), truncated));
        assertFalse(Arrays.equals(nested, actual), "вложенный хэш не должен совпадать с binder");
    }

    @Test
    @DisplayName(
            "binder после HRR: проверка принимает верный и отвергает подмену префикса, binder и усечение")
    void verifyBinderAfterHrrRejectsTampering() {
        byte[] psk = randomBytes(HL);
        byte[] prefix = referencePrefix(randomBytes(120), randomBytes(60));
        byte[] ch2Body = buildChBodyWithPsk(randomBytes(8), HL);
        byte[] ch2Frame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, ch2Body).encode();
        byte[] binder = TlsPskHelper.computeBinderAfterHrr(prefix, ch2Frame, psk, HL);
        System.arraycopy(binder, 0, ch2Frame, ch2Frame.length - HL, HL);

        assertTrue(
                TlsPskHelper.verifyBinderAfterHrr(
                        prefix, ch2Frame, vectorOffset(ch2Frame), binderOffset(ch2Frame), psk, HL),
                "верный binder должен приниматься");

        byte[] otherPrefix = prefix.clone();
        otherPrefix[otherPrefix.length - 1] ^= 1;
        assertFalse(
                TlsPskHelper.verifyBinderAfterHrr(
                        otherPrefix,
                        ch2Frame,
                        vectorOffset(ch2Frame),
                        binderOffset(ch2Frame),
                        psk,
                        HL),
                "подменённый префикс транскрипта должен отвергаться");

        byte[] tamperedBinder = ch2Frame.clone();
        tamperedBinder[tamperedBinder.length - 1] ^= 1;
        assertFalse(
                TlsPskHelper.verifyBinderAfterHrr(
                        prefix,
                        tamperedBinder,
                        vectorOffset(tamperedBinder),
                        binderOffset(tamperedBinder),
                        psk,
                        HL),
                "подменённый binder должен отвергаться");

        byte[] tamperedBody = ch2Frame.clone();
        tamperedBody[10] ^= 1;
        assertFalse(
                TlsPskHelper.verifyBinderAfterHrr(
                        prefix,
                        tamperedBody,
                        vectorOffset(tamperedBody),
                        binderOffset(tamperedBody),
                        psk,
                        HL),
                "подмена усечённой части ClientHello должна отвергаться");

        byte[] cutFrame = Arrays.copyOf(ch2Frame, ch2Frame.length - 1);
        assertFalse(
                TlsPskHelper.verifyBinderAfterHrr(
                        prefix, cutFrame, vectorOffset(cutFrame), binderOffset(cutFrame), psk, HL),
                "обрезанный на байт фрейм должен отвергаться");

        assertFalse(
                TlsPskHelper.verifyBinderAfterHrr(
                        prefix,
                        ch2Frame,
                        vectorOffset(ch2Frame),
                        binderOffset(ch2Frame),
                        randomBytes(HL),
                        HL),
                "чужой PSK должен отвергаться");

        byte[] tooShort = new byte[HL];
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        TlsPskHelper.verifyBinderAfterHrr(
                                prefix,
                                tooShort,
                                vectorOffset(tooShort),
                                binderOffset(tooShort),
                                psk,
                                HL),
                "фрейм короче списка binders должен отвергаться исключением");
    }
}
