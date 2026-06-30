package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.security.Security;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.api.Digest;

@DisplayName("GostMessageDigestSpi — Стрибог через JCA MessageDigest")
class GostMessageDigestTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    // Тестовое сообщение из RFC 6986 §А.1 (пустая строка)
    private static final byte[] EMPTY = new byte[0];

    // Тестовые данные
    private static final byte[] DATA =
            "Тест ГОСТ Р 34.11-2012".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // Стрибог-256 и Стрибог-512 — параметризованные тесты
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @DisplayName("getInstance не бросает исключений, длина совпадает с ожидаемой")
    @CsvSource({"GOST3411-2012-256, 32", "GOST3411-2012-512, 64"})
    void testGetInstance(String algorithm, int expectedLen) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        assertNotNull(md);
        assertEquals(expectedLen, md.getDigestLength());
    }

    @ParameterizedTest
    @DisplayName("результат совпадает с эталонным Digest.digest*")
    @CsvSource({"GOST3411-2012-256, 32", "GOST3411-2012-512, 64"})
    void testOutputMatchesReferenceApi(String algorithm, int hlen) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        byte[] jcaResult = md.digest(DATA);
        byte[] refResult = hlen == 32 ? Digest.digest256(DATA) : Digest.digest512(DATA);
        assertArrayEquals(
                refResult,
                jcaResult,
                "JCA MessageDigest должен давать тот же результат что и Digest.digest*");
    }

    @ParameterizedTest
    @DisplayName("инкрементальное обновление (byte-by-byte) = однократное")
    @CsvSource({"GOST3411-2012-256", "GOST3411-2012-512"})
    void testIncrementalByByte(String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        byte[] full = md.digest(DATA);

        md.reset();
        for (byte b : DATA) {
            md.update(b);
        }
        byte[] incremental = md.digest();
        assertArrayEquals(
                full, incremental, "Инкрементальный хэш (by byte) должен совпадать с полным");
    }

    @ParameterizedTest
    @DisplayName("инкрементальное обновление (chunked) = однократное")
    @CsvSource({"GOST3411-2012-256, 3", "GOST3411-2012-512, 5"})
    void testIncrementalByChunk(String algorithm, int chunkSize) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        byte[] full = md.digest(DATA);

        md.reset();
        int offset = 0;
        while (offset < DATA.length) {
            int len = Math.min(chunkSize, DATA.length - offset);
            md.update(DATA, offset, len);
            offset += len;
        }
        byte[] incremental = md.digest();
        assertArrayEquals(
                full, incremental, "Инкрементальный хэш (chunked) должен совпадать с полным");
    }

    @ParameterizedTest
    @DisplayName("длина выходного массива совпадает с ожидаемой")
    @CsvSource({"GOST3411-2012-256, 32", "GOST3411-2012-512, 64"})
    void testDigestLength(String algorithm, int expectedLen) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        assertEquals(expectedLen, md.digest(DATA).length);
    }

    // -----------------------------------------------------------------------
    // Стрибог-256 (оставшиеся неповторяющиеся тесты)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GOST3411-2012-256: reset позволяет повторное использование")
    void testReset256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", PROVIDER);
        byte[] first = md.digest(DATA);
        byte[] second = md.digest(DATA);
        assertArrayEquals(first, second, "После reset должен вернуть тот же хэш");
    }

    // -----------------------------------------------------------------------
    // Алиасы
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("алиас Streebog-256 работает через JCA")
    void testAlias256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("Streebog-256", PROVIDER);
        assertArrayEquals(Digest.digest256(DATA), md.digest(DATA));
    }

    @Test
    @DisplayName("алиас OID 1.2.643.7.1.1.2.2 работает через JCA")
    void testOid256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("1.2.643.7.1.1.2.2", PROVIDER);
        assertArrayEquals(Digest.digest256(DATA), md.digest(DATA));
    }

    @Test
    @DisplayName("алиас OID 1.2.643.7.1.1.2.3 работает через JCA")
    void testOid512() throws Exception {
        MessageDigest md = MessageDigest.getInstance("1.2.643.7.1.1.2.3", PROVIDER);
        assertArrayEquals(Digest.digest512(DATA), md.digest(DATA));
    }
}
