package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.MacData;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.PfxData;

/**
 * Проверка MAC на эталонных PFX из приложения A RFC 9548 (примеры A.2 и A.3).
 * <p>
 * Эти файлы собраны независимо от нашей библиотеки, поэтому тест проверяет, что мы читаем и
 * записываем {@code MacData} в той же форме, что и стандарт: OID хэша без параметров. Полная
 * загрузка ключа здесь не проверяется: в A.2 ключ хранится в PKCS#8 версии 1, а в A.3
 * сертификат лежит в EncryptedData, а ключ зашифрован Магмой.
 */
@DisplayName("GostPkcs12Mac: эталонные PFX из RFC 9548 (A.2, A.3)")
class GostPkcs12Rfc9548MacTest {

    /** Пароль из RFC 9548 A.2 и A.3 (в RFC он дан в hex, это UTF-8 строка «Пароль для PFX»). */
    private static final String RFC_PASSWORD = "Пароль для PFX";

    private static final int RFC_ITERATIONS = 2048;
    private static final int RFC_SALT_LENGTH = 8;

    private static byte[] resource(String name) throws IOException {
        try (InputStream in =
                GostPkcs12Rfc9548MacTest.class.getResourceAsStream("/rfc9548/" + name)) {
            assertNotNull(in, "не найден ресурс " + name);
            return in.readAllBytes();
        }
    }

    private static byte[] rfcPassword() {
        return RFC_PASSWORD.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertRfcMac(String resourceName) throws IOException {
        byte[] pfx = resource(resourceName);
        PfxData data = GostPkcs12Parser.parsePfx(pfx, RFC_ITERATIONS);
        MacData macData = data.getMacData();

        assertNotNull(macData, resourceName + ": в эталоне должен быть MacData");
        assertEquals(
                GostOids.DIGEST_512,
                macData.getDigestAlgorithm(),
                resourceName + ": RFC 9548 §7 требует OID хэша id-tc26-gost3411-12-512");
        assertEquals(RFC_ITERATIONS, macData.getIterations(), resourceName + ": итерации");
        assertEquals(RFC_SALT_LENGTH, macData.getSalt().length, resourceName + ": длина соли");

        assertDoesNotThrow(
                () -> GostPkcs12Mac.verify(macData, rfcPassword(), data.getAuthSafeRawContent()),
                resourceName + ": MAC эталона должен проходить проверку");

        // Побайтово: наша запись MacData с теми же параметрами совпадает с эталоном,
        // который в PFX идёт последним элементом
        byte[] recomputed =
                GostPkcs12Mac.compute(
                        data.getAuthSafeRawContent(),
                        rfcPassword(),
                        RFC_ITERATIONS,
                        macData.getSalt());
        byte[] fileTail = Arrays.copyOfRange(pfx, pfx.length - recomputed.length, pfx.length);
        assertArrayEquals(
                fileTail,
                recomputed,
                resourceName + ": MacData из compute должен совпадать с эталоном RFC побайтово");
    }

    @Test
    @DisplayName("A.2: MAC эталонного PFX проверяется и воспроизводится побайтово")
    void testExampleA2() throws IOException {
        assertRfcMac("a2.pfx");
    }

    @Test
    @DisplayName("A.3: MAC эталонного PFX проверяется и воспроизводится побайтово")
    void testExampleA3() throws IOException {
        assertRfcMac("a3.pfx");
    }

    @Test
    @DisplayName("A.2: неверный пароль -> MAC не проходит")
    void testExampleA2WrongPassword() throws IOException {
        PfxData data = GostPkcs12Parser.parsePfx(resource("a2.pfx"), RFC_ITERATIONS);
        byte[] wrongPassword = "Пароль для PXF".getBytes(StandardCharsets.UTF_8);

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostPkcs12Mac.verify(
                                data.getMacData(), wrongPassword, data.getAuthSafeRawContent()),
                "пароль, отличающийся одной перестановкой, должен отвергаться");
    }
}
