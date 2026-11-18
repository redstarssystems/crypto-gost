package org.rssys.gost.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.StreebogStateProbe;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("Затирание ключевого материала в Streebog, Hmac и Cmac")
class KeyMaterialWipeTest {

    private static final byte[] MSG = "данные для проверки".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("Hmac.clear затирает рабочие буферы Streebog, включая K xor ipad")
    void hmacClearWipesStreebogWorkBuffers() throws Exception {
        Streebog256 digest = new Streebog256();
        Hmac hmac = new Hmac(digest);
        hmac.init(randomBytes(32));
        hmac.update(MSG, 0, MSG.length);
        hmac.doFinal(new byte[32], 0);

        // до clear() блок K xor ipad заведомо лежит в рабочих словах (доказательство, что тест
        // ловит дефект, а не проверяет пустоту)
        assertTrue(
                StreebogStateProbe.hasLeftoverState(digest),
                "перед clear() в рабочих полях ожидается K xor ipad");

        hmac.clear();

        // все поля-массивы совпадают со свежим объектом: рабочие слова нулевые, h равен
        // начальному значению, объект пригоден и не хранит производных от ключа
        StreebogStateProbe.assertWipedLikeFresh(digest);
    }

    @Test
    @DisplayName("Streebog.destroy оставляет объект пригодным: хеш совпадает с новым экземпляром")
    void streebogUsableAfterDestroy() {
        Streebog256 used = new Streebog256();
        used.update(MSG, 0, MSG.length);
        used.destroy();

        byte[] actual = digestOf(used);
        byte[] expected = digestOf(new Streebog256());

        assertArrayEquals(expected, actual, "после destroy() хеш должен совпадать с эталонным");
    }

    @Test
    @DisplayName("Hmac после clear и повторного init даёт тот же тег, что и новый экземпляр")
    void hmacReusableAfterClear() {
        byte[] key = randomBytes(32);

        Hmac reused = new Hmac(new Streebog256());
        reused.init(randomBytes(32));
        reused.clear();
        reused.init(key);

        assertArrayEquals(tagOf(newHmac(key)), tagOf(reused), "тег после clear() + init()");
    }

    @Test
    @DisplayName("Cmac: повторный init другим ключом даёт тег, как у нового экземпляра")
    void cmacReinitMatchesFreshInstance() {
        SymmetricKey firstKey = new SymmetricKey(randomBytes(32));
        SymmetricKey secondKey = new SymmetricKey(randomBytes(32));

        Cmac reused = new Cmac(new Kuznyechik());
        reused.init(firstKey);
        reused.init(secondKey);

        Cmac fresh = new Cmac(new Kuznyechik());
        fresh.init(secondKey);

        assertArrayEquals(tagOf(fresh), tagOf(reused), "тег после повторного init");
    }

    @Test
    @DisplayName("Cmac: неудачный init не портит подключи, состояние остаётся согласованным")
    void cmacFailedInitKeepsConsistentState() {
        SymmetricKey originalKey = new SymmetricKey(randomBytes(32));
        Cmac cmac = new Cmac(new Kuznyechik());
        cmac.init(originalKey);

        // 16 байт — неверная длина ключа Кузнечика: init обязан упасть
        assertThrows(
                IllegalArgumentException.class,
                () -> cmac.init(new SymmetricKey(randomBytes(16))),
                "ключ неверной длины должен быть отвергнут");

        // Подключи не обнулены заранее: шифр и подключи остались от прежнего ключа, поэтому
        // тег совпадает с тегом под прежним ключом, а не молча искажается.
        Cmac fresh = new Cmac(new Kuznyechik());
        fresh.init(originalKey);
        assertArrayEquals(
                tagOf(fresh), tagOf(cmac), "после неудачного init тег должен быть прежним");
    }

    private static Hmac newHmac(byte[] key) {
        Hmac hmac = new Hmac(new Streebog256());
        hmac.init(key);
        return hmac;
    }

    private static byte[] tagOf(Mac mac) {
        mac.update(MSG, 0, MSG.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    private static byte[] digestOf(Streebog digest) {
        digest.update(MSG, 0, MSG.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }
}
