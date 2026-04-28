package org.rssys.gost.jca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostMessageDigestSpi — Стрибог через JCA MessageDigest")
class GostMessageDigestTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    // Тестовое сообщение из RFC 6986 §А.1 (пустая строка)
    private static final byte[] EMPTY = new byte[0];

    // Тестовые данные
    private static final byte[] DATA = "Тест ГОСТ Р 34.11-2012".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // Стрибог-256
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GOST3411-2012-256: getInstance не бросает исключений")
    void testGetInstance256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", PROVIDER);
        assertNotNull(md);
        assertEquals(32, md.getDigestLength());
    }

    @Test
    @DisplayName("GOST3411-2012-256: результат совпадает с эталонным Digest.digest256")
    void testOutput256MatchesReferenceApi() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", PROVIDER);
        byte[] jcaResult = md.digest(DATA);
        byte[] refResult = Digest.digest256(DATA);
        assertArrayEquals(refResult, jcaResult,
            "JCA MessageDigest должен давать тот же результат что и Digest.digest256");
    }

    @Test
    @DisplayName("GOST3411-2012-256: инкрементальное обновление = однократное")
    void testIncremental256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", PROVIDER);

        // Однократный вызов
        byte[] full = md.digest(DATA);

        // Инкрементальный по байту
        md.reset();
        for (byte b : DATA) {
            md.update(b);
        }
        byte[] incremental = md.digest();

        assertArrayEquals(full, incremental, "Инкрементальный хэш должен совпадать с полным");
    }

    @Test
    @DisplayName("GOST3411-2012-256: reset позволяет повторное использование")
    void testReset256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", PROVIDER);
        byte[] first  = md.digest(DATA);
        byte[] second = md.digest(DATA);
        assertArrayEquals(first, second, "После reset должен вернуть тот же хэш");
    }

    @Test
    @DisplayName("GOST3411-2012-256: длина выходного массива = 32")
    void testDigestLength256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", PROVIDER);
        assertEquals(32, md.digest(DATA).length);
    }

    // -----------------------------------------------------------------------
    // Стрибог-512
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GOST3411-2012-512: getInstance не бросает исключений")
    void testGetInstance512() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-512", PROVIDER);
        assertNotNull(md);
        assertEquals(64, md.getDigestLength());
    }

    @Test
    @DisplayName("GOST3411-2012-512: результат совпадает с эталонным Digest.digest512")
    void testOutput512MatchesReferenceApi() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-512", PROVIDER);
        byte[] jcaResult = md.digest(DATA);
        byte[] refResult = Digest.digest512(DATA);
        assertArrayEquals(refResult, jcaResult,
            "JCA MessageDigest должен давать тот же результат что и Digest.digest512");
    }

    @Test
    @DisplayName("GOST3411-2012-512: длина выходного массива = 64")
    void testDigestLength512() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-512", PROVIDER);
        assertEquals(64, md.digest(DATA).length);
    }

    @Test
    @DisplayName("GOST3411-2012-512: инкрементальное обновление = однократное")
    void testIncremental512() throws Exception {
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-512", PROVIDER);
        byte[] full = md.digest(DATA);

        md.reset();
        md.update(DATA, 0, DATA.length / 2);
        md.update(DATA, DATA.length / 2, DATA.length - DATA.length / 2);
        byte[] chunked = md.digest();

        assertArrayEquals(full, chunked, "Разбитый на чанки хэш должен совпадать с полным");
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
