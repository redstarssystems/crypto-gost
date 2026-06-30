package org.rssys.gost.kdf;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тесты для KDF-функций.
 * <p>
 * label/seed/key приходят из TLS handshake — недоверенный источник.
 * Проверяется робастность на произвольных длинах (NPE/AIOOBE/IOOBE).
 * <p>
 * ПОЧЕМУ ловим IllegalArgumentException + RuntimeException: все методы
 * содержат явные guard-ы (null checks, range checks), кидающие IAE.
 * Всё остальное — баг.
 */
class GostKdfFuzzTest {

    private static final int MAX_BUF = 65536;

    /**
     * Fuzz-тест для {@link KdfGostR3411_2012_256#expand}.
     * Случайные key/label/seed/outputLength.
     * outputLength ограничен MAX_BUF для предотвращения OOM.
     */
    @FuzzTest
    void fuzzKdfExpand(FuzzedDataProvider data) {
        byte[] key = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        byte[] label = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        byte[] seed = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        int outputLength = data.consumeInt(0, MAX_BUF);
        try {
            KdfGostR3411_2012_256.expand(key, label, seed, outputLength);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: guard на null/negative/too-large
        }
    }

    /**
     * Fuzz-тест для {@link KdfTreeGostR3411_2012_256#generate}.
     * Случайные kin/label/seed/count/keyLen.
     * count в [0,512] покрывает guard [1,255] + невалидные; keyLen ограничен MAX_BUF.
     */
    @FuzzTest
    void fuzzKdfTreeGenerate(FuzzedDataProvider data) {
        byte[] kin = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        byte[] label = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        byte[] seed = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        int count = data.consumeInt(0, 512);
        int keyLen = data.consumeInt(0, MAX_BUF);
        try {
            KdfTreeGostR3411_2012_256.generate(kin, label, seed, count, keyLen);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: guard на null/invalid count/too-large keyLen
        }
    }

    /**
     * Fuzz-тест для {@link Pbkdf2Streebog#generate(byte[], byte[], int, int)}.
     * Случайные password/salt/c/dkLen.
     * c в [1, 1_000] — малая верхняя граница сохраняет exec/s фаззера высоким;
     * корректность на больших c проверяется юнит-тестами с фиксированными векторами.
     * dkLen ограничен MAX_BUF для предотвращения OOM от new byte[dkLen].
     */
    @FuzzTest
    void fuzzPbkdf2Generate(FuzzedDataProvider data) {
        byte[] password = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        byte[] salt = data.consumeBytes(data.consumeInt(0, MAX_BUF));
        int c = data.consumeInt(1, 1_000);
        int dkLen = data.consumeInt(0, MAX_BUF);
        try {
            Pbkdf2Streebog.generate(password, salt, c, dkLen);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: guard на null/negative iteration count/dkLen
        }
    }
}
