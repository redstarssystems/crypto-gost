package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("MGM: порядок вызовов и неполный блок")
class MgmStateTest {

    private static final int TAG = 16;

    private final SymmetricKey key = new SymmetricKey(randomBytes(32));
    private final byte[] icn = icn();

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    private static byte[] icn() {
        byte[] value = randomBytes(16);
        value[0] &= 0x7F;
        return value;
    }

    private Mgm encrypting() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(key, icn));
        return mgm;
    }

    /** Шифртекст и тег за один вызов {@code processBytes}. */
    private byte[] sealAtOnce(byte[] plain) {
        Mgm mgm = encrypting();
        byte[] out = new byte[plain.length + TAG];
        mgm.processBytes(plain, 0, plain.length, out, 0);
        mgm.finishEncryption(out, plain.length);
        return out;
    }

    @Test
    @DisplayName("Два неполных вызова 5+5 отвергаются: шифртекст разошёлся бы с RFC 9058")
    void dataAfterPartialBlockIsRejected() {
        Mgm mgm = encrypting();
        byte[] out = new byte[10];
        mgm.processBytes(new byte[5], 0, 5, out, 0);
        assertThrows(
                IllegalStateException.class,
                () -> mgm.processBytes(new byte[5], 0, 5, out, 5),
                "после неполного блока продолжать сообщение нельзя");
    }

    @Test
    @DisplayName(
            "Полные блоки по частям и неполный хвост в конце дают тот же результат, что один вызов")
    void fullBlocksInPiecesWithPartialTailMatchSingleCall() {
        byte[] plain = randomBytes(37);
        byte[] expected = sealAtOnce(plain);

        Mgm mgm = encrypting();
        byte[] out = new byte[plain.length + TAG];
        mgm.processBytes(plain, 0, 16, out, 0);
        mgm.processBytes(plain, 16, 16, out, 16);
        mgm.processBytes(plain, 32, 5, out, 32);
        mgm.finishEncryption(out, plain.length);
        assertArrayEquals(expected, out, "порционная обработка должна совпасть с одним вызовом");
    }

    @Test
    @DisplayName("Пустой вызов после неполного блока допустим")
    void emptyCallAfterPartialBlockIsAllowed() {
        Mgm mgm = encrypting();
        byte[] out = new byte[5];
        mgm.processBytes(new byte[5], 0, 5, out, 0);
        assertEquals(0, mgm.processBytes(new byte[0], 0, 0, out, 5), "пустой вызов не меняет MAC");
    }

    @Test
    @DisplayName("reinitICN снимает запрет после неполного блока")
    void reinitIcnClearsPartialBlockState() {
        Mgm mgm = encrypting();
        byte[] out = new byte[16];
        mgm.processBytes(new byte[5], 0, 5, out, 0);
        mgm.reinitICN(icn());
        assertDoesNotThrow(
                () -> mgm.processBytes(new byte[16], 0, 16, out, 0),
                "после нового ICN сообщение начинается заново");
    }

    @Test
    @DisplayName("processBytes после finishEncryption отвергается")
    void processBytesAfterFinishIsRejected() {
        Mgm mgm = encrypting();
        byte[] out = new byte[16 + TAG];
        mgm.processBytes(new byte[16], 0, 16, out, 0);
        mgm.finishEncryption(out, 16);
        assertThrows(
                IllegalStateException.class,
                () -> mgm.processBytes(new byte[16], 0, 16, out, 0),
                "после выданного тега сообщение закрыто");
    }

    @Test
    @DisplayName("updateAAD после finishEncryption отвергается")
    void updateAadAfterFinishIsRejected() {
        Mgm mgm = encrypting();
        byte[] aad = new byte[8];
        byte[] tag = new byte[TAG];
        mgm.updateAAD(aad, 0, aad.length);
        mgm.finishEncryption(tag, 0);
        assertThrows(
                IllegalStateException.class,
                () -> mgm.updateAAD(aad, 0, aad.length),
                "после выданного тега сообщение закрыто");
    }

    @Test
    @DisplayName("Повторный finishDecryption отвергается как завершённое сообщение")
    void secondFinishDecryptionIsRejected() throws AuthenticationException {
        byte[] plain = randomBytes(16);
        byte[] sealed = sealAtOnce(plain);
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(false, new ParametersWithIV(key, icn));
        byte[] out = new byte[16];
        mgm.processBytes(sealed, 0, 16, out, 0);
        mgm.finishDecryption(sealed, 16);
        assertArrayEquals(plain, out, "расшифрованный текст");
        assertThrows(
                IllegalStateException.class,
                () -> mgm.finishDecryption(sealed, 16),
                "повторная проверка тега после завершения");
    }

    @Test
    @DisplayName("finish* на неинициализированном объекте: оба раза «не инициализирован»")
    void finishWithoutInitReportsNotInitializedEveryTime() {
        Mgm mgm = new Mgm(new Kuznyechik());
        byte[] tag = new byte[TAG];
        for (int attempt = 0; attempt < 2; attempt++) {
            IllegalStateException failure =
                    assertThrows(
                            IllegalStateException.class,
                            () -> mgm.finishEncryption(tag, 0),
                            "finishEncryption без init, попытка " + attempt);
            assertTrue(
                    failure.getMessage().contains("not initialized"),
                    "причина должна оставаться «не инициализирован»: " + failure.getMessage());
        }
    }

    @Test
    @DisplayName("Содержимое тега не зависит от разбиения AAD на части")
    void tagIsIndependentOfAadSplit() {
        byte[] aad = randomBytes(33);
        byte[] plain = randomBytes(16);

        Mgm whole = encrypting();
        byte[] outWhole = new byte[16 + TAG];
        whole.updateAAD(aad, 0, aad.length);
        whole.processBytes(plain, 0, 16, outWhole, 0);
        whole.finishEncryption(outWhole, 16);

        Mgm parts = encrypting();
        byte[] outParts = new byte[16 + TAG];
        parts.updateAAD(aad, 0, 5);
        parts.updateAAD(aad, 5, 17);
        parts.updateAAD(aad, 22, 11);
        parts.processBytes(plain, 0, 16, outParts, 0);
        parts.finishEncryption(outParts, 16);

        assertTrue(Arrays.equals(outWhole, outParts), "дробный AAD должен давать тот же тег");
    }
}
