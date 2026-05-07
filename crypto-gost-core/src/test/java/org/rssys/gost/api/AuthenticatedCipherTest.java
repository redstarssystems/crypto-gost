package org.rssys.gost.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты для AuthenticatedCipher.
 *
 * <p>Тест-векторы для OpenSSL-совместимости вычислены и верифицированы через:
 * <pre>
 *   openssl enc -kuznyechik-ctr -nosalt -nopad -d -K &lt;key&gt; -iv &lt;iv&gt; ...
 *   openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc -macopt hexkey:&lt;key&gt; ...
 * </pre>
 */
@DisplayName("AuthenticatedCipher Tests")
class AuthenticatedCipherTest {

    /** Ключ для тестов: байты 0x01..0x20 */
    private static final byte[] KEY_BYTES = new byte[32];
    static {
        for (int i = 0; i < 32; i++) KEY_BYTES[i] = (byte)(i + 1);
    }

    private static SymmetricKey testKey() {
        return new SymmetricKey(KEY_BYTES);
    }

    private static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    // -----------------------------------------------------------------------
    // Roundtrip — одноключевой API
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("seal/open roundtrip — одноключевой API")
    void testSealOpenRoundtrip() throws Exception {
        byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes("UTF-8");
        SymmetricKey key = testKey();

        byte[] packet   = AuthenticatedCipher.seal(plaintext, key);
        byte[] restored = AuthenticatedCipher.open(packet, key);

        assertArrayEquals(plaintext, restored);
    }

    @Test
    @DisplayName("seal: каждый вызов даёт разный пакет (случайный IV)")
    void testSealRandomIV() throws Exception {
        byte[] plaintext = "hello".getBytes("UTF-8");
        SymmetricKey key = testKey();

        byte[] p1 = AuthenticatedCipher.seal(plaintext, key);
        byte[] p2 = AuthenticatedCipher.seal(plaintext, key);

        assertFalse(Arrays.equals(p1, p2), "IV случаен — пакеты должны отличаться");
    }

    @Test
    @DisplayName("seal: длина пакета = 16 + длина plaintext")
    void testPacketLength() {
        byte[] plaintext = new byte[43];
        SymmetricKey key = testKey();
        byte[] packet = AuthenticatedCipher.seal(plaintext, key);
        assertEquals(16 + 43, packet.length, "overhead = IV(8) + TAG(8) = 16 байт");
    }

    @Test
    @DisplayName("seal/open: пустые данные")
    void testEmptyPlaintext() throws Exception {
        byte[] packet   = AuthenticatedCipher.seal(new byte[0], testKey());
        assertEquals(16, packet.length);
        byte[] restored = AuthenticatedCipher.open(packet, testKey());
        assertArrayEquals(new byte[0], restored);
    }

    // -----------------------------------------------------------------------
    // Обнаружение нарушений целостности
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("open: подмена байта в теге → AuthenticationException")
    void testTamperedTag() {
        byte[] plaintext = "integrity test".getBytes();
        byte[] packet = AuthenticatedCipher.seal(plaintext, testKey());

        // Портим тег (байты 8..15)
        packet[8] ^= 0x01;

        assertThrows(AuthenticationException.class,
            () -> AuthenticatedCipher.open(packet, testKey()),
            "Подмена тега должна обнаруживаться");
    }

    @Test
    @DisplayName("open: подмена байта в шифртексте → AuthenticationException")
    void testTamperedCiphertext() {
        byte[] plaintext = "integrity test".getBytes();
        byte[] packet = AuthenticatedCipher.seal(plaintext, testKey());

        // Портим шифртекст (байт после IV+TAG)
        packet[16] ^= 0x42;

        assertThrows(AuthenticationException.class,
            () -> AuthenticatedCipher.open(packet, testKey()),
            "Подмена шифртекста изменит расшифрованный plaintext → CMAC не совпадёт");
    }

    @Test
    @DisplayName("open: подмена IV → AuthenticationException")
    void testTamperedIV() {
        byte[] plaintext = "integrity test".getBytes();
        byte[] packet = AuthenticatedCipher.seal(plaintext, testKey());

        // Портим IV (первые 8 байт)
        packet[0] ^= 0x01;

        assertThrows(AuthenticationException.class,
            () -> AuthenticatedCipher.open(packet, testKey()),
            "Подмена IV изменит расшифр��ванный plaintext → CMAC не совпадёт");
    }

    @Test
    @DisplayName("open: неверный ключ → AuthenticationException")
    void testWrongKey() {
        byte[] plaintext = "secret message".getBytes();
        byte[] packet = AuthenticatedCipher.seal(plaintext, testKey());

        SymmetricKey wrongKey = KeyGenerator.generateSymmetricKey();
        assertThrows(AuthenticationException.class,
            () -> AuthenticatedCipher.open(packet, wrongKey),
            "Неверный ключ → CMAC не совпадёт");
        wrongKey.destroy();
    }

    @Test
    @DisplayName("open: пакет слишком короткий → AuthenticationException")
    void testPacketTooShort() {
        byte[] shortPacket = new byte[15]; // меньше MIN_PACKET_LEN = 16
        assertThrows(AuthenticationException.class,
            () -> AuthenticatedCipher.open(shortPacket, testKey()));
    }

    // -----------------------------------------------------------------------
    // Совместимость с OpenSSL (golden vector test)
    //
    // Тест-вектор вычислен и верифицирован через:
    //   key = 0x0102...20 (32 байта)
    //   openssl enc -kuznyechik-ctr -nosalt -nopad -d -K <key> -iv <iv> < ct > pt
    //   openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc -macopt hexkey:<key> pt
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("OpenSSL совместимость: CTR и CMAC на одном ключе — golden vectors")
    void testOpenSslCompatibilityGoldenVector() throws Exception {
        // key = 0x01..0x20
        SymmetricKey key = testKey();

        // plaintext = "The quick brown fox" (UTF-8)
        byte[] plaintext = "The quick brown fox".getBytes("UTF-8");
        byte[] iv        = fromHex("0102030405060708");

        // Ожидаемый шифртекст (верифицирован через openssl enc -kuznyechik-ctr -K <key> -iv <iv>)
        byte[] expectedCt   = fromHex("7169cd162a3c2f04a8fe48df31958f6b9803dd");
        // Ожидаемый CMAC (верифицирован через openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc -macopt hexkey:<key>)
        byte[] expectedCmac = fromHex("89425a02b25cf9a380b22b89ed1e74de");
        byte[] expectedTag  = Arrays.copyOf(expectedCmac, 8);

        // Проверяем CTR шифрование
        byte[] actualCt = AuthenticatedCipher.ctrEncrypt(plaintext, key, iv);
        assertArrayEquals(expectedCt, actualCt,
            "CTR шифртекст должен совпасть с openssl enc -kuznyechik-ctr");

        // Проверяем CMAC
        byte[] actualCmac = AuthenticatedCipher.computeCmac(plaintext, key);
        assertArrayEquals(expectedCmac, actualCmac,
            "CMAC должен совпасть с openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc");

        // Собираем пакет вручную и проверяем open()
        byte[] packet = new byte[8 + 8 + expectedCt.length];
        System.arraycopy(iv,          0, packet, 0,  8);
        System.arraycopy(expectedTag, 0, packet, 8,  8);
        System.arraycopy(expectedCt,  0, packet, 16, expectedCt.length);

        byte[] restored = AuthenticatedCipher.open(packet, key);
        assertArrayEquals(plaintext, restored,
            "Пакет с golden vector должен расшифровываться корректно");

        key.destroy();
    }
}
