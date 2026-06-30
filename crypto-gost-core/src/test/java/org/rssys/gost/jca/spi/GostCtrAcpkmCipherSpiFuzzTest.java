package org.rssys.gost.jca.spi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;

/**
 * Fuzz-тесты для {@link GostCtrAcpkmCipherSpi#engineDoFinal}.
 * <p>
 * Два варианта:
 * <ul>
 *   <li>{@link GostCtrAcpkmCipherSpi.WithOmac} — с AEAD-тегом (Encrypt-then-MAC)</li>
 *   <li>{@link GostCtrAcpkmCipherSpi.WithoutOmac} — без тега, чистый CTR-ACPKM</li>
 * </ul>
 * <p>
 * ПОЧЕМУ per-iteration reinit: WithOmac обнуляет {@code keyParam = null}
 * в блоке {@code finally} после doFinal. Каждая итерация фаззинга должна
 * начинаться со свежего Cipher.getInstance + engineInit.
 */
class GostCtrAcpkmCipherSpiFuzzTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final String ALG_WITH_OMAC = "Kuznyechik/CTR-ACPKM-OMAC/NoPadding";
    private static final String ALG_WITHOUT_OMAC = "Kuznyechik/CTR-ACPKM/NoPadding";

    private static final GostSecretKey FIXED_KEY;

    static {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
        SymmetricKey kp = KeyGenerator.generateSymmetricKey();
        FIXED_KEY = new GostSecretKey("Kuznyechik", kp);
    }

    /**
     * Фиксированный UKM для WithOmac: 16 байт.
     */
    private static byte[] fixedUkm16() {
        byte[] ukm = new byte[16];
        Arrays.fill(ukm, (byte) 0x42);
        return ukm;
    }

    /**
     * Фиксированный UKM для WithoutOmac: 8 байт (минимальная длина).
     */
    private static byte[] fixedUkm8() {
        byte[] ukm = new byte[8];
        Arrays.fill(ukm, (byte) 0x42);
        return ukm;
    }

    /**
     * WithOmac: произвольный ciphertext с тегом -> engineDoFinal.
     * Путь: engineDoFinal -> проверка ctLen -> processBytes -> getMacTag ->
     * MessageDigest.isEqual.
     * <p>
     * Ожидаем: AEADBadTagException на неверном теге, IllegalArgumentException
     * на неверном UKM.
     */
    @FuzzTest
    void fuzzEngineDoFinalWithOmac(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            Cipher dec = Cipher.getInstance(ALG_WITH_OMAC, PROVIDER);
            dec.init(Cipher.DECRYPT_MODE, FIXED_KEY, new IvParameterSpec(fixedUkm16()));
            dec.doFinal(input);
        } catch (AEADBadTagException e) {
            // Ожидаемо: неверный тег или короткий пакет (<16 байт)
        } catch (IllegalArgumentException e) {
            // Ожидаемо: неверные параметры
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // Ожидаемо: JCA-обёртка
        } catch (NoSuchAlgorithmException
                | NoSuchProviderException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            // Ожидаемо: JCA-initialisation ошибки на битом входе
        }
    }

    /**
     * WithoutOmac: произвольный ciphertext -> engineDoFinal.
     * Путь: engineDoFinal -> mode.processBytes (чистое шифрование, без тега).
     * <p>
     * Ожидаем: IllegalArgumentException, IllegalBlockSizeException.
     * AEADBadTagException НЕ ожидается — WithoutOmac не проверяет тег.
     */
    @FuzzTest
    void fuzzEngineDoFinalWithoutOmac(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            Cipher dec = Cipher.getInstance(ALG_WITHOUT_OMAC, PROVIDER);
            dec.init(Cipher.DECRYPT_MODE, FIXED_KEY, new IvParameterSpec(fixedUkm8()));
            dec.doFinal(input);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: неверные параметры
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // Ожидаемо: JCA-обёртка
        } catch (NoSuchAlgorithmException
                | NoSuchProviderException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            // Ожидаемо: JCA-initialisation ошибки
        }
    }
}
