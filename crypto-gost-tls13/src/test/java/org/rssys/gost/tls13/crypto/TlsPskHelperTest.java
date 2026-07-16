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
        int pskExtSize = 2 + pskId.length + 4 + bLen; // ext body: id_list + age + binders
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
                TlsPskHelper.verifyBinder(chFrame, psk, HL),
                "binder должен верифицироваться на полном handshake-фрейме");

        // Верификация на теле без заголовка — должна РАСХОДИТЬСЯ
        assertFalse(
                TlsPskHelper.verifyBinder(chBody, psk, HL),
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
        byte[] binderKey =
                HkdfStreebog.deriveSecret(
                        earlySecret, HkdfStreebog.PREFIXED_RES_BINDER, emptyHash, HL);
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
                HkdfStreebog.expandLabel(
                        binderKey,
                        HkdfStreebog.PREFIXED_FINISHED,
                        HkdfStreebog.EMPTY_CONTEXT,
                        HL,
                        HL);
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

    /**
     * HRR: computeBinderForHrr / verifyBinderForHrr.
     */
    @Test
    @DisplayName("HRR binder с полным фреймом: round-trip")
    void hrrBinderFrameVsBody() {
        byte[] psk = new byte[HL];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] pskId = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(pskId);
        byte[] hrrPrefix = new byte[HL];
        CryptoRandom.INSTANCE.nextBytes(hrrPrefix);

        byte[] chBody = buildChBodyWithPsk(pskId, HL);
        byte[] chFrame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode();

        byte[] binder = TlsPskHelper.computeBinderForHrr(hrrPrefix, chFrame, psk, HL);
        assertNotNull(binder);
        assertEquals(HL, binder.length);

        System.arraycopy(binder, 0, chBody, chBody.length - HL, HL);
        chFrame = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode();

        assertTrue(
                TlsPskHelper.verifyBinderForHrr(hrrPrefix, chFrame, psk, HL),
                "HRR binder должен верифицироваться на полном фрейме");
        assertFalse(
                TlsPskHelper.verifyBinderForHrr(hrrPrefix, chBody, psk, HL),
                "HRR binder должен расходиться на теле без заголовка");
    }
}
