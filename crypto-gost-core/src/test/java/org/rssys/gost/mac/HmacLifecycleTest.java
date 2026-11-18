package org.rssys.gost.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog256;

@DisplayName("Hmac — жизненный цикл: без init, после destroy, после неудачного init")
class HmacLifecycleTest {

    private static final byte[] KEY = filled(32, (byte) 0x11);
    private static final byte[] MSG = "данные для HMAC".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("без init update, doFinal и reset бросают IllegalStateException")
    void noInitRejectsEveryOperation() {
        Hmac hmac = new Hmac(new Streebog256());

        assertThrows(IllegalStateException.class, () -> hmac.update((byte) 1), "update(byte)");
        assertThrows(
                IllegalStateException.class,
                () -> hmac.update(MSG, 0, MSG.length),
                "update(byte[]) без init должен быть отвергнут");
        assertThrows(
                IllegalStateException.class,
                () -> hmac.doFinal(new byte[32], 0),
                "doFinal без init не должен возвращать тег, не зависящий от ключа");
        assertThrows(IllegalStateException.class, hmac::reset, "reset без init");
    }

    @Test
    @DisplayName("после destroy объект неинициализирован")
    void destroyedRejectsEveryOperation() {
        Hmac hmac = initialized(KEY);
        hmac.destroy();

        assertThrows(IllegalStateException.class, () -> hmac.update((byte) 1));
        assertThrows(IllegalStateException.class, () -> hmac.update(MSG, 0, MSG.length));
        assertThrows(IllegalStateException.class, () -> hmac.doFinal(new byte[32], 0));
        assertThrows(IllegalStateException.class, hmac::reset);
    }

    @Test
    @DisplayName("после clear объект неинициализирован")
    void clearedRejectsEveryOperation() {
        Hmac hmac = initialized(KEY);
        hmac.clear();

        assertThrows(IllegalStateException.class, () -> hmac.update((byte) 1));
        assertThrows(IllegalStateException.class, () -> hmac.update(MSG, 0, MSG.length));
        assertThrows(IllegalStateException.class, () -> hmac.doFinal(new byte[32], 0));
        assertThrows(IllegalStateException.class, hmac::reset);
    }

    @Test
    @DisplayName("повторный init после destroy даёт тот же тег, что у нового экземпляра")
    void reinitAfterDestroyMatchesFreshInstance() {
        byte[] expected = tag(initialized(KEY), MSG);

        Hmac reused = initialized(KEY);
        reused.destroy();
        reused.init(KEY);

        assertArrayEquals(expected, tag(reused, MSG), "Тег после повторного init не совпал");
    }

    @Test
    @DisplayName("после doFinal объект остаётся инициализированным и считает следующее сообщение")
    void staysInitializedAfterDoFinal() {
        Hmac hmac = initialized(KEY);
        byte[] first = tag(hmac, MSG);

        assertArrayEquals(first, tag(hmac, MSG), "Второй тег того же сообщения отличается");
    }

    @Test
    @DisplayName("reset после doFinal сбрасывает накопленные данные")
    void resetAfterDoFinalDiscardsPartialData() {
        Hmac hmac = initialized(KEY);
        byte[] expected = tag(hmac, MSG);

        hmac.update(new byte[] {1, 2, 3}, 0, 3);
        hmac.reset();

        assertArrayEquals(expected, tag(hmac, MSG), "reset не сбросил частичные данные");
    }

    @Test
    @DisplayName("пустой ключ допустим и равен ключу из нулей длины блока (RFC 2104)")
    void emptyKeyIsValid() {
        Hmac emptyKey = new Hmac(new Streebog256());
        emptyKey.init(new byte[0]);

        Hmac zeroBlockKey = new Hmac(new Streebog256());
        zeroBlockKey.init(new byte[64]);

        assertArrayEquals(
                tag(zeroBlockKey, MSG),
                tag(emptyKey, MSG),
                "Пустой ключ должен дополняться нулями до длины блока");
    }

    @Test
    @DisplayName("init((byte[]) null) бросает исключение и сбрасывает прежний ключ")
    void failedByteArrayInitResetsState() {
        Hmac hmac = initialized(KEY);

        assertThrows(IllegalArgumentException.class, () -> hmac.init((byte[]) null));

        assertThrows(
                IllegalStateException.class,
                () -> hmac.doFinal(new byte[32], 0),
                "После неудачного init прежний ключ не должен оставаться рабочим");
    }

    @Test
    @DisplayName("init((CipherParameters) null) бросает исключение и сбрасывает прежний ключ")
    void failedNullParametersInitResetsState() {
        Hmac hmac = initialized(KEY);

        assertThrows(IllegalArgumentException.class, () -> hmac.init((CipherParameters) null));

        assertThrows(IllegalStateException.class, () -> hmac.update((byte) 1));
    }

    @Test
    @DisplayName("init с параметрами не того типа бросает исключение и сбрасывает прежний ключ")
    void failedWrongTypeInitResetsState() {
        Hmac hmac = initialized(KEY);
        CipherParameters wrongType = new ParametersWithIV(new SymmetricKey(KEY), new byte[8]);

        assertThrows(IllegalArgumentException.class, () -> hmac.init(wrongType));

        assertThrows(IllegalStateException.class, () -> hmac.doFinal(new byte[32], 0));
    }

    @Test
    @DisplayName("после неудачного init успешный init возвращает объект в работу")
    void successfulInitAfterFailedInitWorks() {
        byte[] expected = tag(initialized(KEY), MSG);
        Hmac hmac = initialized(KEY);
        assertThrows(IllegalArgumentException.class, () -> hmac.init((byte[]) null));

        hmac.init(KEY);

        assertArrayEquals(expected, tag(hmac, MSG), "Тег после восстановления init не совпал");
    }

    @Test
    @DisplayName("неудачный init затирает ключевые буферы прежнего ключа")
    void failedInitWipesKeyDerivedBuffers() throws Exception {
        Hmac hmac = initialized(KEY);
        assertNotAllZero(padOf(hmac, "inputPad"), "inputPad после init должен быть ненулевым");

        assertThrows(IllegalArgumentException.class, () -> hmac.init((byte[]) null));

        assertAllZero(padOf(hmac, "inputPad"), "inputPad не затёрт после неудачного init");
        assertAllZero(padOf(hmac, "outputPad"), "outputPad не затёрт после неудачного init");
    }

    @Test
    @DisplayName("неудачный init(CipherParameters) затирает ключевые буферы прежнего ключа")
    void failedParametersInitWipesKeyDerivedBuffers() throws Exception {
        Hmac hmac = initialized(KEY);

        assertThrows(IllegalArgumentException.class, () -> hmac.init((CipherParameters) null));

        assertAllZero(padOf(hmac, "inputPad"), "inputPad не затёрт после неудачного init");
        assertAllZero(padOf(hmac, "outputPad"), "outputPad не затёрт после неудачного init");
    }

    @Test
    @DisplayName("неудачный init с параметрами не того типа затирает ключевые буферы")
    void failedWrongTypeInitWipesKeyDerivedBuffers() throws Exception {
        Hmac hmac = initialized(KEY);
        CipherParameters wrongType = new ParametersWithIV(new SymmetricKey(KEY), new byte[8]);

        assertThrows(IllegalArgumentException.class, () -> hmac.init(wrongType));

        assertAllZero(padOf(hmac, "inputPad"), "inputPad не затёрт после неудачного init");
        assertAllZero(padOf(hmac, "outputPad"), "outputPad не затёрт после неудачного init");
    }

    /** Доступ к приватным буферам только для проверки затирания: публичного API для этого нет. */
    private static byte[] padOf(Hmac hmac, String field) throws Exception {
        java.lang.reflect.Field f = Hmac.class.getDeclaredField(field);
        f.setAccessible(true);
        return (byte[]) f.get(hmac);
    }

    private static void assertAllZero(byte[] data, String message) {
        for (byte b : data) {
            if (b != 0) {
                throw new AssertionError(message);
            }
        }
    }

    private static void assertNotAllZero(byte[] data, String message) {
        for (byte b : data) {
            if (b != 0) {
                return;
            }
        }
        throw new AssertionError(message);
    }

    private static Hmac initialized(byte[] key) {
        Hmac hmac = new Hmac(new Streebog256());
        hmac.init(key);
        return hmac;
    }

    private static byte[] tag(Hmac hmac, byte[] message) {
        hmac.update(message, 0, message.length);
        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    private static byte[] filled(int length, byte value) {
        byte[] data = new byte[length];
        Arrays.fill(data, value);
        return data;
    }
}
