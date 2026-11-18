package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Полная загрузка эталонного PFX из RFC 9548 A.2: MAC, расшифровка PBES2 (Кузнечик
 * CTR-ACPKM-OMAC), разбор ключа PKCS#8 версии 1 с {@code [1] publicKey} и сертификата.
 * <p>
 * A.3 здесь не загружается: сертификат там лежит в EncryptedData, а ключ зашифрован Магмой,
 * которую загрузчик не поддерживает (MAC этого примера проверяет {@link GostPkcs12Rfc9548MacTest}).
 */
@DisplayName("GostPkcs12Loader: полная загрузка эталонного PFX RFC 9548 A.2")
class GostPkcs12Rfc9548LoadTest {

    private static final char[] RFC_PASSWORD = "Пароль для PFX".toCharArray();

    @Test
    @DisplayName(
            "A.2: ключ и сертификат загружаются, ключ соответствует открытому ключу сертификата")
    void exampleA2LoadsFully() throws IOException {
        byte[] pfx;
        try (InputStream in = getClass().getResourceAsStream("/rfc9548/a2.pfx")) {
            assertNotNull(in, "не найден ресурс a2.pfx");
            pfx = in.readAllBytes();
        }

        GostPkcs12Loader.Result loaded = GostPkcs12Loader.load(pfx, RFC_PASSWORD, false, 1);

        PrivateKeyParameters privateKey = loaded.getPrivateKey();
        try {
            assertNotNull(privateKey, "закрытый ключ A.2 должен быть прочитан");
            assertEquals(1, loaded.getCertificateChain().size(), "в A.2 один сертификат");
            PublicKeyParameters certificateKey = loaded.getCertificateChain().get(0).getPublicKey();
            byte[] message = "RFC 9548 A.2".getBytes(StandardCharsets.UTF_8);
            byte[] signature = Signature.sign(message, privateKey);
            assertTrue(
                    Signature.verify(message, signature, certificateKey),
                    "ключ из PFX и открытый ключ сертификата должны быть парой");
        } finally {
            if (privateKey != null) {
                privateKey.destroy();
            }
        }
    }
}
