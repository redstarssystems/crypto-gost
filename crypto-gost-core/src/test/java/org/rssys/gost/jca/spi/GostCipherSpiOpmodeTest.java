package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.Cipher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;

@DisplayName("Режимы операции шифр-SPI: WRAP и UNWRAP не поддерживаются")
@ExtendWith(JcaTestSupport.class)
class GostCipherSpiOpmodeTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    private static GostSecretKey newKey() {
        return new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(
            strings = {
                "Kuznyechik/CTR/NoPadding",
                "Kuznyechik/CBC/PKCS7Padding",
                "Kuznyechik/MGM/NoPadding",
                "Kuznyechik/CTR-ACPKM/NoPadding",
                "Kuznyechik/CTR-ACPKM-OMAC/NoPadding"
            })
    @DisplayName("WRAP_MODE и UNWRAP_MODE отвергаются при init с понятным сообщением")
    void wrapAndUnwrapAreRejectedAtInit(String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, PROVIDER);
        GostSecretKey key = newKey();

        UnsupportedOperationException wrap =
                assertThrows(
                        UnsupportedOperationException.class,
                        () -> cipher.init(Cipher.WRAP_MODE, key),
                        "WRAP_MODE должен отвергаться в init, а не в wrap()");
        assertTrue(
                wrap.getMessage().contains("key wrapping"),
                "сообщение должно называть причину: " + wrap.getMessage());
        assertThrows(
                UnsupportedOperationException.class,
                () -> cipher.init(Cipher.UNWRAP_MODE, key),
                "UNWRAP_MODE не должен молча становиться расшифрованием");
    }
}
