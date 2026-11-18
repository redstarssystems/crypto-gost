package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.util.CryptoRandom;

/**
 * {@link CmsOmacHelper}: content-UKM обязан быть ровно 16 байт — короткое значение
 * молча дополнялось бы нулями в seed KDF_TREE.
 */
@DisplayName("CmsOmacHelper — длина content-UKM")
class CmsOmacHelperUkmTest {

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    @Test
    @DisplayName("encrypt и decrypt отвергают UKM не из 16 байт и null")
    void rejectsWrongUkmLength() {
        byte[] cek = random(32);
        byte[] data = random(20);
        for (int len : new int[] {0, 8, 15, 17}) {
            byte[] ukm = random(len);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> CmsOmacHelper.encrypt(data, cek, ukm),
                    "encrypt: UKM длиной " + len + " должен отвергаться");
            assertThrows(
                    IllegalArgumentException.class,
                    () -> CmsOmacHelper.decrypt(data, random(16), cek, ukm),
                    "decrypt: UKM длиной " + len + " должен отвергаться");
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> CmsOmacHelper.encrypt(data, cek, null),
                "encrypt: null UKM должен отвергаться");
    }

    @Test
    @DisplayName("UKM из 16 байт: roundtrip проходит")
    void roundTripWithValidUkm() throws Exception {
        byte[] cek = random(32);
        byte[] ukm = random(16);
        byte[] data = random(100);
        CmsOmacHelper.EncryptResult r = CmsOmacHelper.encrypt(data, cek, ukm);
        assertArrayEquals(
                data,
                CmsOmacHelper.decrypt(
                        r.encryptedContent(), r.macAttribute().encodedMac(), cek, ukm),
                "Расшифрованные данные должны совпасть");
    }
}
