package org.rssys.gost.crossval.kuznyechik;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.SymmetricKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.util.CryptoRandom;

/**
 * Кросс-версионная проверка: текущая реализация vs предыдущий релиз.
 *
 * Для каждого режима (CTR, CBC, CFB, OFB, MGM) и каждого размера из SIZES:
 * 1) текущая и старая версии шифруют один plaintext — сверяем шифртексты;
 * 2) старый шифртекст расшифровывается текущим кодом;
 * 3) текущий шифртекст расшифровывается старой версией.
 *
 * JAR предыдущей версии подкладывается через maven-dependency-plugin
 * и передаётся в system property {@code previous.ver}.
 *
 * <p>Предыдущая версия живёт в одном долгоживущем worker-процессе на весь класс
 * ({@link OldVersionWorker}): поднимать JVM на каждый кейс слишком дорого.
 */
class CrossVersionTest {
    private static String OLD_JAR;
    private static String COMPAT_CLASSES;
    private static OldVersionWorker worker;

    @BeforeAll
    static void startWorker() {
        String path = System.getProperty("previous.ver");
        if (path == null || !Files.exists(Path.of(path))) {
            System.err.println("=".repeat(70));
            System.err.println("  ⚠ КРОСС-ВЕРСИОННЫЕ ТЕСТЫ ПРОПУЩЕНЫ");
            System.err.println("  ⚠ JAR предыдущей версии не найден:");
            System.err.println("      " + path);
            System.err.println("  ⚠ Установи crypto-gost-core в ~/.m2/repository");
            System.err.println("=".repeat(70));
            fail("JAR не найден: " + path + " — кросс-версионные тесты пропущены");
        }
        OLD_JAR = path;
        try {
            COMPAT_CLASSES = CrossVersionTool.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI()
                    .getPath();
        } catch (Exception e) {
            fail("Не удалось определить путь к классам compat", e);
        }
        try {
            worker = new OldVersionWorker(OLD_JAR, COMPAT_CLASSES);
        } catch (IOException e) {
            fail("Не удалось запустить worker предыдущей версии", e);
        }
    }

    @AfterAll
    static void stopWorker() {
        if (worker != null) {
            worker.close();
        }
    }

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.kuznyechik.TestData#cipherModeParams")
    @DisplayName("Кросс-версионная проверка {0} size={1}")
    void crossVersion(Cipher.Mode mode, int size) throws Exception {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        byte[] plaintext = TestData.randomBytes(size, CryptoRandom.INSTANCE);

        SymmetricKey symmetricKey = new SymmetricKey(key);
        try {
            Cipher.Padding padding = TestData.paddingFor(mode);
            String kv = "key=" + CrossValUtils.toHex(key) + " iv=" + CrossValUtils.toHex(iv);
            byte[] ivForGost = mode == Cipher.Mode.CTR ? Arrays.copyOf(iv, 8) : iv;

            byte[] ciphertextCurrent = Cipher.encrypt(plaintext, symmetricKey, ivForGost, mode, padding);
            byte[] ciphertextOld = worker.call(mode, "encrypt", key, iv, plaintext);

            assertArrayEquals(ciphertextCurrent, ciphertextOld,
                    () -> "Несовпадение шифртекста: mode=" + mode + " size=" + size
                            + " " + CrossValUtils.diffContext(ciphertextCurrent, ciphertextOld) + " " + kv);
            byte[] decryptedOld = Cipher.decrypt(ciphertextOld, symmetricKey, ivForGost, mode, padding);
            assertArrayEquals(plaintext, decryptedOld,
                    () -> "Ошибка расшифровки шифртекста предыдущей версии: mode=" + mode + " size=" + size
                            + " " + CrossValUtils.diffContext(plaintext, decryptedOld) + " " + kv);
            byte[] decryptedCurrent = worker.call(mode, "decrypt", key, iv, ciphertextCurrent);
            assertArrayEquals(plaintext, decryptedCurrent,
                    () -> "Предыдущая версия не может расшифровать наш шифртекст: mode=" + mode + " size=" + size
                            + " " + CrossValUtils.diffContext(plaintext, decryptedCurrent) + " " + kv);
        } finally {
            symmetricKey.destroy();
            Arrays.fill(key, (byte) 0);
        }
    }

    static Stream<Integer> mgmParams() {
        return Arrays.stream(TestData.SIZES).boxed();
    }

    @ParameterizedTest
    @MethodSource("mgmParams")
    @DisplayName("Кросс-версионная проверка MGM size={0}")
    void crossVersionMgm(int size) throws Exception {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;

        byte[] plaintext = TestData.randomBytes(size, CryptoRandom.INSTANCE);
        SymmetricKey symmetricKey = new SymmetricKey(key);

        try {
            String kicn = "key=" + CrossValUtils.toHex(key) + " icn=" + CrossValUtils.toHex(icn);
            // Для пустого открытого текста обе стороны используют непустой AAD (RFC 9058 §6)
            byte[] aad = CrossVersionTool.mgmAadFor(size);
            byte[] mgmPacketCurrent = MgmCipher.sealWithIcn(plaintext, symmetricKey, icn, aad);
            byte[] mgmPacketOld = worker.callMgm("seal", key, icn, plaintext);

            assertArrayEquals(mgmPacketCurrent, mgmPacketOld,
                    () -> "Несовпадение пакета MGM: size=" + size
                            + " " + CrossValUtils.diffContext(mgmPacketCurrent, mgmPacketOld) + " " + kicn);
            byte[] openedOld = MgmCipher.open(mgmPacketOld, symmetricKey, aad);
            assertArrayEquals(plaintext, openedOld,
                    () -> "Ошибка расшифрования MGM-пакета предыдущей версии: size=" + size
                            + " " + CrossValUtils.diffContext(plaintext, openedOld) + " " + kicn);
            byte[] openedCurrent = worker.callMgm("open", key, icn, mgmPacketCurrent);
            assertArrayEquals(plaintext, openedCurrent,
                    () -> "Предыдущая версия не может расшифровать наш MGM-пакет: size=" + size
                            + " " + CrossValUtils.diffContext(plaintext, openedCurrent) + " " + kicn);
        } finally {
            symmetricKey.destroy();
            Arrays.fill(key, (byte) 0);
        }
    }
}
