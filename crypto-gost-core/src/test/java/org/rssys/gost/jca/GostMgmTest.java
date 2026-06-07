package org.rssys.gost.jca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.util.CryptoRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты JCA-интерфейса для Кузнечик-MGM.
 * <p>
 * Проверяет:
 * <ul>
 *   <li>Roundtrip через JCA Cipher</li>
 *   <li>Совместимость JCA и org.rssys.gost.api.MgmCipher</li>
 *   <li>AEADBadTagException при неверном теге</li>
 *   <li>AAD через updateAAD</li>
 *   <li>Пустой plaintext</li>
 * </ul>
 */
@DisplayName("GostMgmCipherSpi — Кузнечик-MGM через JCA Cipher")
class GostMgmTest {

    private static final String PROVIDER     = RssysGostProvider.PROVIDER_NAME;
    private static final String ALGORITHM    = "Kuznyechik-MGM";

    private static final byte[] DATA = "тест MGM через JCA".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] AAD  = "ассоциированные данные".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // Базовый roundtrip
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getInstance: провайдер предоставляет Kuznyechik-MGM")
    void testGetInstance() throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM, PROVIDER);
        assertNotNull(c);
    }

    @Test
    @DisplayName("getInstance: алиас Kuznyechik/MGM/NoPadding для режима Kuznyechik-MGM")
    void testGetInstanceAlias() throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());

        // Генерируем ICN явно, чтобы сравнить результаты обоих способов получения шифра
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F; // MSB=0 per RFC 9058

        // Шифрование через алиас Kuznyechik/MGM/NoPadding
        Cipher aliasEnc = Cipher.getInstance("Kuznyechik/MGM/NoPadding", PROVIDER);
        assertNotNull(aliasEnc);
        aliasEnc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn));
        byte[] ciphertext = aliasEnc.doFinal(DATA);

        // Расшифрование через основное имя Kuznyechik-MGM
        Cipher canonicalDec = Cipher.getInstance(ALGORITHM, PROVIDER);
        canonicalDec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        byte[] decrypted = canonicalDec.doFinal(ciphertext);

        assertArrayEquals(DATA, decrypted,
            "Алиас Kuznyechik/MGM/NoPadding должен давать тот же шифртекст что и Kuznyechik-MGM");
    }

    @Test
    @DisplayName("Roundtrip без AAD: encrypt → decrypt возвращает оригинал")
    void testRoundtripNoAad() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        // Шифрование: ICN генерируется автоматически
        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = enc.doFinal(DATA); // [CT][TAG(16)]
        byte[] icn        = enc.getIV();

        assertNotNull(icn, "ICN не должен быть null после шифрования");
        assertEquals(16, icn.length, "ICN должен быть 16 байт");
        assertEquals(DATA.length + 16, ciphertext.length,
            "Шифртекст = plaintext + 16-байтовый тег");

        // Расшифрование
        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        byte[] plaintext = dec.doFinal(ciphertext);

        assertArrayEquals(DATA, plaintext, "Расшифрованный текст должен совпасть с исходным");
    }

    @Test
    @DisplayName("Roundtrip с AAD: encrypt → decrypt возвращает оригинал")
    void testRoundtripWithAad() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key);
        enc.updateAAD(AAD);
        byte[] ciphertext = enc.doFinal(DATA);
        byte[] icn        = enc.getIV();

        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        dec.updateAAD(AAD);
        byte[] plaintext = dec.doFinal(ciphertext);

        assertArrayEquals(DATA, plaintext, "AAD roundtrip должен восстановить данные");
    }

    @Test
    @DisplayName("Пустой plaintext: шифрование даёт только тег (16 байт)")
    void testEmptyPlaintext() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key);
        enc.updateAAD(AAD);
        byte[] ciphertext = enc.doFinal(new byte[0]);

        assertEquals(16, ciphertext.length, "Пустой plaintext → только тег (16 байт)");

        // Расшифрование
        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(enc.getIV()));
        dec.updateAAD(AAD);
        byte[] plaintext = dec.doFinal(ciphertext);

        assertEquals(0, plaintext.length, "Расшифрование пустого CT → пустой PT");
    }

    // -----------------------------------------------------------------------
    // Безопасность: неверный тег
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Неверный тег: doFinal бросает AEADBadTagException")
    void testInvalidTagThrows() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = enc.doFinal(DATA);
        byte[] icn        = enc.getIV();

        // Портим последний байт тега
        ciphertext[ciphertext.length - 1] ^= 0xFF;

        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));

        assertThrows(AEADBadTagException.class,
            () -> dec.doFinal(ciphertext),
            "Неверный тег должен вызывать AEADBadTagException");
    }

    @Test
    @DisplayName("Неверный AAD: доп. данные не совпадают → AEADBadTagException")
    void testInvalidAad() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key);
        enc.updateAAD(AAD);
        byte[] ciphertext = enc.doFinal(DATA);
        byte[] icn        = enc.getIV();

        // Расшифровываем с другим AAD
        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        dec.updateAAD("неверный AAD".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        assertThrows(AEADBadTagException.class,
            () -> dec.doFinal(ciphertext),
            "Неверный AAD должен вызывать AEADBadTagException");
    }

    @Test
    @DisplayName("Слишком короткий пакет: doFinal бросает AEADBadTagException")
    void testTooShortPacket() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        // ICN = 16 нулевых байт (MSB=0 → ok)
        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));

        // 10 байт — меньше минимального (16 для тега)
        assertThrows(AEADBadTagException.class,
            () -> dec.doFinal(new byte[10]),
            "Слишком короткий пакет должен вызывать AEADBadTagException");
    }

    // -----------------------------------------------------------------------
    // Совместимость с org.rssys.gost.api.MgmCipher
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("JCA encrypt совместим с MgmCipher.open (расшифровывает API)")
    void testJcaEncryptApiDecrypt() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);

        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F; // MSB=0 per RFC 9058

        // Шифруем через JCA с явным ICN
        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn));
        enc.updateAAD(AAD);
        byte[] ctAndTag = enc.doFinal(DATA); // [CT][TAG]

        // MgmCipher.open ожидает [ICN][CT][TAG]
        byte[] packet = new byte[16 + ctAndTag.length];
        System.arraycopy(icn,       0, packet, 0,  16);
        System.arraycopy(ctAndTag,  0, packet, 16, ctAndTag.length);

        byte[] plaintext = MgmCipher.open(packet, kp, AAD);
        assertArrayEquals(DATA, plaintext,
            "JCA-зашифрованный пакет должен расшифровываться через MgmCipher.open");
    }

    @Test
    @DisplayName("MgmCipher.seal совместим с JCA decrypt (расшифровывает JCA)")
    void testApiEncryptJcaDecrypt() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F; // MSB=0 per RFC 9058

        // Шифруем через MgmCipher API
        byte[] packet = MgmCipher.sealWithIcn(DATA, kp, icn, AAD); // [ICN][CT][TAG]

        // Извлекаем [CT][TAG] для JCA (JCA не получает ICN в данных)
        byte[] ctAndTag = Arrays.copyOfRange(packet, 16, packet.length);

        // Расшифровываем через JCA
        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        dec.updateAAD(AAD);
        byte[] plaintext = dec.doFinal(ctAndTag);

        assertArrayEquals(DATA, plaintext,
            "API-зашифрованный пакет должен расшифровываться через JCA Cipher");
    }

    // -----------------------------------------------------------------------
    // Корректность обработки данных по частям через update
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Инкрементальный update + doFinal совпадает с однократным doFinal")
    void testIncrementalUpdate() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F; // MSB=0 per RFC 9058

        // Однократный вызов
        Cipher enc1 = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc1.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn));
        byte[] ct1 = enc1.doFinal(DATA);

        // Инкрементальный
        Cipher enc2 = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc2.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn));
        int half = DATA.length / 2;
        enc2.update(DATA, 0, half);
        byte[] ct2 = enc2.doFinal(DATA, half, DATA.length - half);

        assertArrayEquals(ct1, ct2, "Инкрементальный update должен дать тот же результат");
    }

    // -----------------------------------------------------------------------
    // Восстановление после AEADBadTagException
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("engineInit после failed decrypt: recovery возможен")
    void testInitAfterFailedDecrypt() throws Exception {
        SymmetricKey kp  = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", kp);
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;

        // Шифруем
        Cipher enc = Cipher.getInstance(ALGORITHM, PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn));
        enc.updateAAD(AAD);
        byte[] ctAndTag = enc.doFinal(DATA);

        // Первая попытка расшифрования с порченным тегом — fail
        ctAndTag[ctAndTag.length - 1] ^= 0xFF;
        Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        dec.updateAAD(AAD);
        assertThrows(AEADBadTagException.class,
                () -> dec.doFinal(ctAndTag),
                "Порченный тег должен вызывать AEADBadTagException");

        // Восстанавливаем тег и пробуем снова с новым engineInit
        ctAndTag[ctAndTag.length - 1] ^= 0xFF;
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
        dec.updateAAD(AAD);
        byte[] plaintext = dec.doFinal(ctAndTag);
        assertArrayEquals(DATA, plaintext,
                "После engineInit после failed decrypt расшифрование должно работать");
    }
}
