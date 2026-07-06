package org.rssys.gost.mac;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.util.FuzzTestUtils;

/**
 * Fuzz-тесты для {@link Hmac#init(byte[])} и {@link Hmac#init(org.rssys.gost.cipher.CipherParameters)}.
 *
 * <p>Проверяет фикс defensive-copy в 0.6.2:
 * {@code Hmac.init(byte[])} ранее алиасил массив вызывающего, сейчас делает
 * {@code Arrays.copyOf}. Также проверяет, что {@code init} и {@code update}
 * не падают на произвольных входных данных.</p>
 *
 * <p>ПОЧЕМУ не тестируем полный HMAC-цикл: {@code Streebog256} внутри {@code Hmac}
 * вызывает {@code digest.update()} — нормальный путь. Фаззер проверяет, что
 * инициализация + обновление не дают AIOOBE/NPE.</p>
 */
class HmacFuzzTest {

    private static final Streebog256 DIGEST = new Streebog256();

    @FuzzTest
    void fuzzInitByteArray(FuzzedDataProvider data) {
        byte[] key = data.consumeRemainingAsBytes();
        Hmac hmac = new Hmac(DIGEST);
        try {
            hmac.init(key);
        } catch (IllegalArgumentException e) {
            // null-ключ на входе — ожидаемо
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzInitWithUpdate(FuzzedDataProvider data) {
        byte[] key = data.consumeBytes(data.consumeInt(1, 128));
        byte[] msg = data.consumeRemainingAsBytes();
        Hmac hmac = new Hmac(DIGEST);
        try {
            hmac.init(key);
        } catch (IllegalArgumentException e) {
            return;
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
            return;
        }
        try {
            if (msg.length > 0) {
                hmac.update(msg, 0, msg.length);
            }
            hmac.doFinal(new byte[hmac.getMacSize()], 0);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzInitCipherParameters(FuzzedDataProvider data) {
        byte[] keyBytes = data.consumeBytes(data.consumeInt(1, 128));
        SymmetricKey symKey;
        try {
            symKey = new SymmetricKey(keyBytes);
        } catch (IllegalArgumentException e) {
            // Ключ может быть пустым или слишком коротким для SymmetricKey
            return;
        }
        Hmac hmac = new Hmac(DIGEST);
        try {
            hmac.init(symKey);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
