package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.util.FuzzTestUtils;

/**
 * Fuzz-тесты для {@link GostPemUtils#pemToDer(byte[])} и
 * {@link GostPemUtils#decodePemBlocks(byte[])}.
 *
 * <p>Парсеры PEM/Base64 принимают недоверенный файловый ввод.
 * Внутри: {@code new String(US_ASCII)}, regex-замена заголовков,
 * {@code Base64.getDecoder().decode()}.</p>
 *
 * <p>Проверяет Memory DoS-фикс 0.6.2:
 * <ul>
 *   <li>{@code MAX_PEM_SIZE} = 10 МБ — размер до парсинга, {@code IllegalArgumentException}</li>
 * </ul>
 *
 * <p>Ожидаемое поведение: {@code IllegalArgumentException} на битом Base64/PEM,
 * отсутствие AIOOBE / NPE / NegativeArraySizeException.</p>
 */
class GostPemUtilsFuzzTest {

    @FuzzTest
    void fuzzPemToDer(FuzzedDataProvider data) {
        byte[] pem = data.consumeRemainingAsBytes();
        if (pem.length == 0) return;
        try {
            GostPemUtils.pemToDer(pem);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: битый Base64, превышение MAX_PEM_SIZE, неверный PEM
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzDecodePemBlocks(FuzzedDataProvider data) {
        byte[] pem = data.consumeRemainingAsBytes();
        if (pem.length == 0) return;
        try {
            GostPemUtils.decodePemBlocks(pem);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: битый Base64, превышение MAX_PEM_SIZE, нет валидных блоков
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
