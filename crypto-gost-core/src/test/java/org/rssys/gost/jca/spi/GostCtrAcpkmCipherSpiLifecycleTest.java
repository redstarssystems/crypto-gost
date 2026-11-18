package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Состояние JCA-шифра CTR-ACPKM после {@code doFinal}: расшифрование сбрасывается в состояние
 * после init, шифрование блокируется до нового init; защита от повторного UKM.
 */
@DisplayName("GostCtrAcpkmCipherSpi — жизненный цикл после doFinal")
@ExtendWith(JcaTestSupport.class)
class GostCtrAcpkmCipherSpiLifecycleTest {

    private static final String OMAC = "Kuznyechik/CTR-ACPKM-OMAC/NoPadding";
    private static final String PLAIN = "Kuznyechik/CTR-ACPKM/NoPadding";
    private static final int TAG_LEN = 16;

    private static GostSecretKey newKey() {
        return new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
    }

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    private static Cipher cipher(String alg, int mode, GostSecretKey key, byte[] ukm)
            throws Exception {
        Cipher c = Cipher.getInstance(alg, RssysGostProvider.PROVIDER_NAME);
        c.init(mode, key, new IvParameterSpec(ukm));
        return c;
    }

    @Test
    @DisplayName("OMAC: изменение данных с тегом первого сообщения во втором doFinal отвергается")
    void omacSecondDoFinalDoesNotAcceptStaleTag() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(16);
        byte[] ct1 = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukm).doFinal(random(40));

        Cipher dec = cipher(OMAC, Cipher.DECRYPT_MODE, key, ukm);
        dec.doFinal(ct1);

        // Замена: чужой шифртекст с прежним тегом
        byte[] foreign = random(ct1.length);
        System.arraycopy(ct1, ct1.length - TAG_LEN, foreign, foreign.length - TAG_LEN, TAG_LEN);
        assertThrows(
                AEADBadTagException.class,
                () -> dec.doFinal(foreign),
                "Старый тег не должен приниматься для других данных");
    }

    @Test
    @DisplayName("OMAC: повторное расшифрование на том же объекте даёт тот же открытый текст")
    void omacDecryptRepeatsCorrectly() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(16);
        byte[] pt = random(5000);
        byte[] ct = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukm).doFinal(pt);

        Cipher dec = cipher(OMAC, Cipher.DECRYPT_MODE, key, ukm);
        assertArrayEquals(pt, dec.doFinal(ct), "Первое расшифрование");
        assertArrayEquals(pt, dec.doFinal(ct), "Повторное расшифрование без init");
    }

    @Test
    @DisplayName("OMAC: после ошибки тега расшифрование остаётся рабочим и без кешированного тега")
    void omacDecryptRecoversAfterBadTag() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(16);
        byte[] pt = random(100);
        byte[] ct = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukm).doFinal(pt);
        byte[] corrupted = ct.clone();
        corrupted[0] ^= 0x01;

        Cipher dec = cipher(OMAC, Cipher.DECRYPT_MODE, key, ukm);
        assertThrows(
                AEADBadTagException.class,
                () -> dec.doFinal(corrupted),
                "Изменение шифртекста должно обнаруживаться");
        assertArrayEquals(pt, dec.doFinal(ct), "После ошибки корректные данные расшифровываются");
        assertThrows(
                AEADBadTagException.class,
                () -> dec.doFinal(corrupted),
                "Тег прошлого успешного сообщения не должен подходить изменённым данным");
    }

    @Test
    @DisplayName("Шифрование: второй doFinal без init -> IllegalStateException (оба варианта)")
    void encryptSecondDoFinalRejected() throws Exception {
        GostSecretKey key = newKey();
        Cipher omac = cipher(OMAC, Cipher.ENCRYPT_MODE, key, random(16));
        omac.doFinal(random(10));
        assertThrows(
                IllegalStateException.class,
                () -> omac.doFinal(random(10)),
                "OMAC: повтор шифрования без init недопустим");

        Cipher plain = cipher(PLAIN, Cipher.ENCRYPT_MODE, key, random(8));
        plain.doFinal(random(10));
        assertThrows(
                IllegalStateException.class,
                () -> plain.update(random(10)),
                "CTR-ACPKM: update после doFinal без init недопустим");
        assertThrows(
                IllegalStateException.class,
                () -> plain.doFinal(random(10)),
                "CTR-ACPKM: повторный doFinal без init недопустим");
    }

    @Test
    @DisplayName("CTR-ACPKM: расшифрование после doFinal можно повторить без init")
    void plainDecryptRepeatsCorrectly() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(8);
        byte[] pt = random(300);
        byte[] ct = cipher(PLAIN, Cipher.ENCRYPT_MODE, key, ukm).doFinal(pt);

        Cipher dec = cipher(PLAIN, Cipher.DECRYPT_MODE, key, ukm);
        assertArrayEquals(pt, dec.doFinal(ct), "Первое расшифрование");
        assertArrayEquals(pt, dec.doFinal(ct), "Повторное расшифрование без init");
    }

    @Test
    @DisplayName("Повторный init на шифрование с тем же ключом и UKM отвергается")
    void reinitEncryptWithSameKeyAndUkmRejected() throws Exception {
        for (String alg : new String[] {OMAC, PLAIN}) {
            GostSecretKey key = newKey();
            byte[] ukm = random(alg.equals(OMAC) ? 16 : 8);
            Cipher c = cipher(alg, Cipher.ENCRYPT_MODE, key, ukm);
            c.doFinal(random(10));
            assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                    alg + ": повтор ключа и UKM должен отвергаться");

            byte[] otherUkm = random(ukm.length);
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(otherUkm));
            assertDoesNotThrow(() -> c.doFinal(random(10)), alg + ": новый UKM допустим");

            c.init(Cipher.ENCRYPT_MODE, newKey(), new IvParameterSpec(ukm));
            assertDoesNotThrow(() -> c.doFinal(random(10)), alg + ": новый ключ допустим");
        }
    }

    @Test
    @DisplayName("Повторный init на расшифрование с тем же ключом и UKM допустим")
    void reinitDecryptWithSameKeyAndUkmAllowed() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(16);
        byte[] pt = random(20);
        byte[] ct = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukm).doFinal(pt);
        Cipher dec = cipher(OMAC, Cipher.DECRYPT_MODE, key, ukm);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ukm));
        assertArrayEquals(pt, dec.doFinal(ct), "Расшифрование после повторного init");
    }

    @Test
    @DisplayName("ShortBufferException не продвигает гамму: повтор с большим буфером корректен")
    void shortBufferDoesNotAdvanceKeystream() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(8);
        byte[] pt = random(50);

        Cipher enc = cipher(PLAIN, Cipher.ENCRYPT_MODE, key, ukm);
        byte[] tooSmall = new byte[10];
        assertThrows(
                ShortBufferException.class,
                () -> enc.update(pt, 0, pt.length, tooSmall, 0),
                "Малый буфер update должен вызывать ShortBufferException");
        assertThrows(
                ShortBufferException.class,
                () -> enc.doFinal(pt, 0, pt.length, tooSmall, 0),
                "Малый буфер doFinal должен вызывать ShortBufferException");
        byte[] out = new byte[pt.length];
        assertEquals(pt.length, enc.doFinal(pt, 0, pt.length, out, 0), "Длина результата");

        byte[] expected = cipher(PLAIN, Cipher.DECRYPT_MODE, key, ukm).doFinal(out);
        assertArrayEquals(pt, expected, "Результат после ShortBufferException расшифровывается");
    }

    @Test
    @DisplayName("OMAC: ShortBufferException в doFinal сохраняет буфер для повтора")
    void omacShortBufferKeepsState() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(16);
        byte[] pt = random(30);
        Cipher enc = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukm);
        byte[] tooSmall = new byte[pt.length];
        assertThrows(
                ShortBufferException.class,
                () -> enc.doFinal(pt, 0, pt.length, tooSmall, 0),
                "Буфер без места под тег");
        byte[] out = new byte[pt.length + TAG_LEN];
        assertEquals(out.length, enc.doFinal(pt, 0, pt.length, out, 0), "Длина с тегом");
        assertArrayEquals(
                pt,
                cipher(OMAC, Cipher.DECRYPT_MODE, key, ukm).doFinal(out),
                "Результат расшифровывается");
    }

    @Test
    @DisplayName("Защита от повтора UKM переживает init на расшифрование")
    void reuseGuardSurvivesDecryptInit() throws Exception {
        for (String alg : new String[] {OMAC, PLAIN}) {
            GostSecretKey key = newKey();
            byte[] ukm = random(alg.equals(OMAC) ? 16 : 8);
            Cipher c = cipher(alg, Cipher.ENCRYPT_MODE, key, ukm);
            c.doFinal(random(10));

            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ukm));
            assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                    alg
                            + ": цепочка encrypt -> init(DECRYPT) -> init(ENCRYPT) не должна обходить защиту");
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(random(ukm.length)));
            assertDoesNotThrow(() -> c.doFinal(random(10)), alg + ": новый UKM допустим");
        }
    }

    @Test
    @DisplayName("Два init на шифрование подряд до использования допустимы")
    void doubleEncryptInitBeforeUseAllowed() throws Exception {
        for (String alg : new String[] {OMAC, PLAIN}) {
            GostSecretKey key = newKey();
            byte[] ukm = random(alg.equals(OMAC) ? 16 : 8);
            Cipher c = cipher(alg, Cipher.ENCRYPT_MODE, key, ukm);
            assertDoesNotThrow(
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                    alg + ": шифртекст ещё не выдан, повторный init безопасен");
            assertDoesNotThrow(
                    () -> c.doFinal(random(10)), alg + ": шифрование после повторного init");
        }
    }

    @Test
    @DisplayName("non-OMAC: init -> update (шифртекст выдан) -> init с той же парой отвергается")
    void plainUpdateCommitsPair() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(8);
        Cipher c = cipher(PLAIN, Cipher.ENCRYPT_MODE, key, ukm);
        assertTrue(c.update(random(10)).length > 0, "update должен выдать шифртекст");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                "Гамма уже выдана: повтор той же пары недопустим");
    }

    @Test
    @DisplayName("non-OMAC: update с пустым входом и doFinal без данных пару не фиксируют")
    void emptyOutputDoesNotCommitPair() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(8);
        Cipher c = cipher(PLAIN, Cipher.ENCRYPT_MODE, key, ukm);
        c.update(new byte[0]);
        c.doFinal();
        assertDoesNotThrow(
                () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                "Шифртекст не выдавался: та же пара остаётся допустимой");
    }

    @Test
    @DisplayName("ShortBufferException не фиксирует пару")
    void shortBufferDoesNotCommitPair() throws Exception {
        GostSecretKey key = newKey();
        for (String alg : new String[] {OMAC, PLAIN}) {
            byte[] ukm = random(alg.equals(OMAC) ? 16 : 8);
            Cipher c = cipher(alg, Cipher.ENCRYPT_MODE, key, ukm);
            byte[] data = random(30);
            assertThrows(
                    ShortBufferException.class,
                    () -> c.doFinal(data, 0, data.length, new byte[1], 0),
                    alg + ": малый буфер");
            assertDoesNotThrow(
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                    alg + ": шифртекст не выдан, пара свободна");
        }
    }

    @Test
    @DisplayName("OMAC: doFinal с пустым входом выдаёт тег и фиксирует пару")
    void omacEmptyDoFinalCommitsPair() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = random(16);
        Cipher c = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukm);
        assertEquals(TAG_LEN, c.doFinal().length, "Пустое сообщение даёт только тег");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                "Тег выдан: повтор той же пары недопустим");
    }

    @Test
    @DisplayName("Защита помнит только последнюю использованную пару (как SunJCE GCM)")
    void guardRemembersOnlyLastUsedPair() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukmA = random(16);
        byte[] ukmB = random(16);
        Cipher c = cipher(OMAC, Cipher.ENCRYPT_MODE, key, ukmA);
        c.doFinal(random(5));
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukmB));
        c.doFinal(random(5));
        // Зафиксированное ограничение: A после B уже не отслеживается
        assertDoesNotThrow(
                () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukmA)),
                "Известное ограничение: история ограничена последней парой");
    }
}
