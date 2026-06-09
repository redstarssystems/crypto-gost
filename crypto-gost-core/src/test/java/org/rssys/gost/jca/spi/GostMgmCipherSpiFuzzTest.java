package org.rssys.gost.jca.spi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

/**
 * Fuzz-тесты для {@link GostMgmCipherSpi#engineDoFinal}.
 * <p>
 * Атакуем AEAD-тег MGM: противник шлёт произвольные ciphertext,
 * сервер пытается расшифровать через MGM. Fuzzer находит баги
 * в {@code doFinalDecrypt} — верификация тега, обработка коротких
 * пакетов, NPE/AIOOBE при битом входе.
 * <p>
 * Setup: engine инициализируется в DECRYPT_MODE с фиксированным ключом
 * и фиксированным ICN (16 байт, MSB=0). Затем doFinal(fuzzedBytes).
 * <p>
 * ПОЧЕМУ init сразу в DECRYPT_MODE: engineInit — полная переинициализация,
 * сбрасывающая весь state (включая ICN). Никакого «переключения» между
 * ENCRYPT_MODE и DECRYPT_MODE не существует.
 */
class GostMgmCipherSpiFuzzTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final String ALGORITHM = "Kuznyechik/MGM/NoPadding";

    private static final GostSecretKey FIXED_KEY;

    static {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
        SymmetricKey kp = KeyGenerator.generateSymmetricKey();
        FIXED_KEY = new GostSecretKey("Kuznyechik", kp);
    }

    /**
     * Фиксированный ICN: 16 байт, MSB=0 (RFC 9058 §3).
     */
    private static byte[] fixedIcn() {
        byte[] icn = new byte[16];
        Arrays.fill(icn, (byte) 0x40);
        icn[0] &= 0x7F;
        return icn;
    }

    /**
     * Подаёт произвольный ciphertext (с тегом) в engineDoFinal.
     * Путь: doFinalDecrypt → проверка длины → mgm.processBytes →
     * mgm.finishDecryption → AEAD tag verification.
     * <p>
     * Каждая итерация создаёт свежий Cipher + init — потому что
     * после doFinal буфер сбрасывается, но MGM-состояние может
     * быть частично разрушено.
     */
    @FuzzTest
    void fuzzEngineDoFinal(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
            dec.init(Cipher.DECRYPT_MODE, FIXED_KEY, new IvParameterSpec(fixedIcn()));
            dec.doFinal(input);
        } catch (AEADBadTagException e) {
            // Ожидаемо: неверный тег, короткий пакет
        } catch (IllegalArgumentException e) {
            // Ожидаемо: неверные параметры
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // Ожидаемо: JCA-обёртки
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException e) {
            // Ожидаемо: JCA-initialisation ошибки
        }
    }

    /**
     * Подаёт AAD + ciphertext в engineDoFinal.
     */
    @FuzzTest
    void fuzzEngineUpdateAadAndDoFinal(FuzzedDataProvider data) {
        int aadLen = Math.min(data.consumeInt(0, 64), data.remainingBytes());
        byte[] aad = data.consumeBytes(aadLen);
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            Cipher dec = Cipher.getInstance(ALGORITHM, PROVIDER);
            dec.init(Cipher.DECRYPT_MODE, FIXED_KEY, new IvParameterSpec(fixedIcn()));
            if (aad.length > 0) {
                dec.updateAAD(aad);
            }
            dec.doFinal(input);
        } catch (AEADBadTagException e) {
            // Ожидаемо
        } catch (IllegalArgumentException e) {
            // Ожидаемо
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // Ожидаемо
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException e) {
            // Ожидаемо: JCA-initialisation ошибки
        }
    }
}
