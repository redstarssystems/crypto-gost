package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Известный ответ PBES2 {@code kuznyechik-ctr-acpkm-omac} (RFC 9337) от эталонного gost-engine
 * (master, commit "PKCS#12 RFC 9337 / RFC 9548", OpenSSL 3.6.0):
 * {@code openssl pkcs8 -topk8 -v2 kuznyechik-ctr-acpkm-omac -v2prf 1.2.643.7.1.1.4.2
 * -iter 2000 -passout pass:test123}. Файл создан движком, а не библиотекой, поэтому тест
 * проверяет формат независимо от нашего шифрования: MAC по открытому тексту, шифруется
 * {@code M ‖ MAC}. Схема Encrypt-then-MAC здесь дала бы несовпадение тега.
 */
@DisplayName("PBES2 CTR-ACPKM-OMAC: известный ответ от эталонного gost-engine")
class GostPbes2OmacReferenceKatTest {

    private static final String PASSWORD = "test123";

    /** EncryptedPrivateKeyInfo, созданный gost-engine (88 байт зашифрованных данных). */
    private static final String ENCRYPTED_PKCS8_B64 =
            "MIG9MGEGCSqGSIb3DQEFDTBUMDEGCSqGSIb3DQEFDDAkBBCmF3+uvmC43Rat+21jyqbHAgIH0DAMBggqhQMH"
                    + "AQEEAgUAMB8GCSqFAwcBAQUCAjASBBC7gGnVU3wugDFrpo10rx8ZBFj+IoFv2tPDJSA5I61A57bA8nas"
                    + "riu4EO+hRY2bNau7KVQaRnTC8KUfeMxaA+v6OlnGX9+o2ZcX3kHHqVWfgouIACqC3NxXySqoMNv4imSy"
                    + "xGYzkGvwF+6n";

    /** Тот же закрытый ключ в открытом PKCS#8 (его же вывел engine). */
    private static final String PLAIN_PKCS8_B64 =
            "MEYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEIOhAK5YdnwkGgrjFyRXrfDxxmOiaVlIn"
                    + "6c4P7h54Ev6w";

    @Test
    @DisplayName("Файл эталонного engine расшифровывается, ключ совпадает")
    void referenceFileDecrypts() {
        byte[] enc = Base64.getDecoder().decode(ENCRYPTED_PKCS8_B64);
        PrivateKeyParameters actual =
                GostPkcs12Loader.decryptPrivateKey(enc, PASSWORD.toCharArray());
        PrivateKeyParameters expected =
                GostDerCodec.decodePrivateKey(Base64.getDecoder().decode(PLAIN_PKCS8_B64));
        assertEquals(
                expected.getD(), actual.getD(), "Ключ из файла engine должен совпасть с исходным");
        actual.destroy();
        expected.destroy();
    }

    @Test
    @DisplayName("Подмена любого байта зашифрованных данных файла engine отвергается")
    void tamperedReferenceFileRejected() {
        byte[] enc = Base64.getDecoder().decode(ENCRYPTED_PKCS8_B64);
        // Зашифрованные данные - последние 88 байт файла
        for (int i = enc.length - 88; i < enc.length; i++) {
            byte[] bad = enc.clone();
            bad[i] ^= 0x01;
            int index = i;
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostPkcs12Loader.decryptPrivateKey(bad, PASSWORD.toCharArray()),
                    "Подмена байта " + index + " должна обнаруживаться");
        }
    }

    @Test
    @DisplayName("Неверный пароль для файла engine отвергается")
    void wrongPasswordRejected() {
        byte[] enc = Base64.getDecoder().decode(ENCRYPTED_PKCS8_B64);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.decryptPrivateKey(enc, "wrong".toCharArray()),
                "Неверный пароль даёт несовпадение тега");
    }
}
