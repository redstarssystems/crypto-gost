package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты CTR-ACPKM для PBES2 (RFC 9337 §7.3) для Кузнечика.
 * <p>
 * Два варианта: без OMAC (чистый CTR) и с OMAC (MAC-then-Encrypt по RFC 9337 §5.1.1).
 */
@DisplayName("CtrAcpkmMode: шифрование и расшифрование")
class CtrAcpkmModeTest {

    private static final int KEY_LEN = 32;
    private static final int UKM_LEN = 16;
    private static final int TAG_LEN = 16;

    private SymmetricKey key;
    private byte[] ukm;

    @BeforeEach
    void setUp() {
        key = new SymmetricKey(randomBytes(KEY_LEN));
        ukm = randomBytes(UKM_LEN);
    }

    // ========================================================================
    // Без OMAC — roundtrip через прямое инстанциирование
    // ========================================================================

    @Test
    @DisplayName("Без OMAC: roundtrip 1 байт")
    void testNoOmacRoundtrip1() {
        roundtripNoOmac(key, ukm, new byte[] {0x42});
    }

    @Test
    @DisplayName("Без OMAC: roundtrip 16 байт (ровно блок)")
    void testNoOmacRoundtrip16() {
        roundtripNoOmac(key, ukm, randomBytes(16));
    }

    @Test
    @DisplayName("Без OMAC: roundtrip 31 байт (не кратно блоку)")
    void testNoOmacRoundtrip31() {
        roundtripNoOmac(key, ukm, randomBytes(31));
    }

    @Test
    @DisplayName("Без OMAC: roundtrip 1024 байта")
    void testNoOmacRoundtrip1024() {
        roundtripNoOmac(key, ukm, randomBytes(1024));
    }

    @Test
    @DisplayName("Без OMAC: нулевые данные -> пустой выход")
    void testNoOmacEmpty() {
        CtrAcpkmMode enc = new CtrAcpkmMode(new Kuznyechik(), false);
        enc.init(true, new ParametersWithIV(key, ukm));
        byte[] out = new byte[0];
        int len = enc.processBytes(new byte[0], 0, 0, out, 0);
        assertEquals(0, len);
    }

    @Test
    @DisplayName("Без OMAC: одинаковые UKM[0..7] -> одинаковый шифртекст")
    void testNoOmacSameUkm() {
        byte[] ukmA = ukm;
        byte[] ukmB = Arrays.copyOf(ukmA, UKM_LEN);
        // Меняем только байты 8..15
        ukmB[8] ^= 0xFF;
        ukmB[9] ^= 0xFF;

        byte[] plaintext = randomBytes(32);
        byte[] ctA = encryptNoOmac(key, ukmA, plaintext);
        byte[] ctB = encryptNoOmac(key, ukmB, plaintext);
        // IV (первые 8 байт UKM) одинаковые -> шифртекст одинаковый
        assertArrayEquals(ctA, ctB);
    }

    @Test
    @DisplayName("Без OMAC: разные UKM[0..7] -> разные шифртексты")
    void testNoOmacDifferentUkm() {
        byte[] ukmA = ukm;
        byte[] ukmB = Arrays.copyOf(ukmA, UKM_LEN);
        ukmB[0] ^= 0xFF; // меняем первый байт -> другой CTR-IV

        byte[] plaintext = randomBytes(32);
        byte[] ctA = encryptNoOmac(key, ukmA, plaintext);
        byte[] ctB = encryptNoOmac(key, ukmB, plaintext);
        assertFalse(Arrays.equals(ctA, ctB));
    }

    @Test
    @DisplayName("Без OMAC: детерминизм при одинаковых параметрах")
    void testNoOmacDeterminism() {
        byte[] plaintext = randomBytes(32);
        byte[] ct1 = encryptNoOmac(key, ukm, plaintext);
        byte[] ct2 = encryptNoOmac(key, ukm, plaintext);
        assertArrayEquals(ct1, ct2);
    }

    // ========================================================================
    // С OMAC — roundtrip через статические методы
    // ========================================================================

    @Test
    @DisplayName("С OMAC: roundtrip 1 байт")
    void testOmacRoundtrip1() throws Exception {
        roundtripOmac(key, ukm, new byte[] {0x42});
    }

    @Test
    @DisplayName("С OMAC: roundtrip 16 байт")
    void testOmacRoundtrip16() throws Exception {
        roundtripOmac(key, ukm, randomBytes(16));
    }

    @Test
    @DisplayName("С OMAC: roundtrip 31 байт")
    void testOmacRoundtrip31() throws Exception {
        roundtripOmac(key, ukm, randomBytes(31));
    }

    @Test
    @DisplayName("С OMAC: roundtrip 1024 байта")
    void testOmacRoundtrip1024() throws Exception {
        roundtripOmac(key, ukm, randomBytes(1024));
    }

    @Test
    @DisplayName("С OMAC: нулевые данные -> 16 байт (только MAC)")
    void testOmacEmpty() throws Exception {
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, new byte[0]);
        assertEquals(TAG_LEN, ct.length);

        byte[] pt = CtrAcpkmMode.decryptWithMac(key, ukm, ct);
        assertEquals(0, pt.length);
    }

    @Test
    @DisplayName("С OMAC: разные UKM -> разные шифртексты")
    void testOmacDifferentUkm() {
        byte[] ukmB = Arrays.copyOf(ukm, UKM_LEN);
        ukmB[8] ^= 0xFF; // меняем seed KDF_TREE

        byte[] plaintext = randomBytes(32);
        byte[] ctA = CtrAcpkmMode.encryptWithMac(key, ukm, plaintext);
        byte[] ctB = CtrAcpkmMode.encryptWithMac(key, ukmB, plaintext);
        assertFalse(Arrays.equals(ctA, ctB));
    }

    // ========================================================================
    // Негативные сценарии — OMAC
    // ========================================================================

    @Test
    @DisplayName("С OMAC: данные короче 16 байт -> AuthenticationException")
    void testOmacDataTooShort() {
        byte[] tooShort = new byte[TAG_LEN - 1];
        assertThrows(
                AuthenticationException.class,
                () -> CtrAcpkmMode.decryptWithMac(key, ukm, tooShort));
    }

    @Test
    @DisplayName("С OMAC: повреждённый шифртекст -> AuthenticationException")
    void testOmacTagMismatch() throws Exception {
        byte[] plaintext = randomBytes(64);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, plaintext);
        // Повреждаем байт шифртекста (не тега)
        ct[0] ^= 0xFF;
        assertThrows(
                AuthenticationException.class, () -> CtrAcpkmMode.decryptWithMac(key, ukm, ct));
    }

    @Test
    @DisplayName("С OMAC: повреждённый тег -> AuthenticationException")
    void testOmacTagCorrupted() throws Exception {
        byte[] plaintext = randomBytes(64);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, plaintext);
        // Повреждаем байт в теге (последний байт)
        ct[ct.length - 1] ^= 0xFF;
        assertThrows(
                AuthenticationException.class, () -> CtrAcpkmMode.decryptWithMac(key, ukm, ct));
    }

    @Test
    @DisplayName("С OMAC: неверный ключ -> AuthenticationException")
    void testOmacWrongKey() throws Exception {
        byte[] plaintext = randomBytes(32);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, plaintext);

        SymmetricKey wrongKey = new SymmetricKey(randomBytes(KEY_LEN));
        assertThrows(
                AuthenticationException.class,
                () -> CtrAcpkmMode.decryptWithMac(wrongKey, ukm, ct));
    }

    // ========================================================================
    // Разделение ключей K(1)/K(2) — независимый оракул тега (RFC 9337 §5.1.1)
    // ========================================================================

    @Test
    @DisplayName(
            "С OMAC: результат совпадает с независимым оракулом RFC 9337 (MAC по открытому тексту)")
    void testOmacMatchesIndependentOracle() {
        // Оракул: K(1), K(2) из KDF_TREE; tag = CMAC(K(2), M); CTR(K(1)) по M || tag.
        // Размеры секции подобраны так, чтобы тег попадал на границу и за границу секции.
        int[] sections = {64, 4096};
        int[] lengths = {0, 1, 16, 31, 48, 49, 63, 64, 65, 80, 4080, 4096, 4097, 9000};
        for (int section : sections) {
            for (int len : lengths) {
                byte[] data = randomBytes(len);
                byte[] actual = CtrAcpkmMode.encryptWithMac(key, ukm, data, section);
                byte[] expected = oracleOmac(key.getKey(), ukm, data, section);
                assertArrayEquals(
                        expected,
                        actual,
                        "OMAC не совпал с оракулом (len=" + len + ", section=" + section + ")");
            }
        }
    }

    @Test
    @DisplayName("С OMAC: тег считается по открытому тексту и зашифрован, под K(2), не под K(1)")
    void testOmacTagIsOverPlaintextUnderMacKey() {
        byte[] data = randomBytes(100);
        byte[] out = CtrAcpkmMode.encryptWithMac(key, ukm, data);
        assertEquals(data.length + TAG_LEN, out.length, "Длина: данные + 16 байт тега");

        byte[] derived = deriveKeys(key.getKey(), ukm);
        byte[] k1 = Arrays.copyOfRange(derived, 0, KEY_LEN);
        byte[] k2 = Arrays.copyOfRange(derived, KEY_LEN, KEY_LEN * 2);
        byte[] all = CtrAcpkmMode.decryptOnly(new SymmetricKey(k1), ukm, out);
        byte[] plain = Arrays.copyOf(all, data.length);
        byte[] tag = Arrays.copyOfRange(all, data.length, all.length);

        assertArrayEquals(data, plain, "Открытый текст после расшифрования потоком K(1)");
        assertArrayEquals(cmacTag(k2, data), tag, "Тег = CMAC(K(2), открытый текст)");
        assertFalse(Arrays.equals(cmacTag(k1, data), tag), "Ключи K(1) и K(2) разделены");
        assertFalse(
                Arrays.equals(cmacTag(k2, Arrays.copyOf(out, data.length)), tag),
                "Тег не должен совпадать с CMAC по шифртексту (старая схема)");
    }

    @Test
    @DisplayName("С OMAC: roundtrip на границах секции и сообщения больше секции")
    void testOmacRoundtripAcrossSections() throws Exception {
        for (int section : new int[] {64, 4096}) {
            for (int len : new int[] {0, 47, 48, 49, 63, 64, 65, 200, 4097, 10000}) {
                byte[] data = randomBytes(len);
                byte[] out = CtrAcpkmMode.encryptWithMac(key, ukm, data, section);
                assertArrayEquals(
                        data,
                        CtrAcpkmMode.decryptWithMac(key, ukm, out, section),
                        "roundtrip len=" + len + ", section=" + section);
            }
        }
    }

    @Test
    @DisplayName("С OMAC: сообщение 256 КБ + хвост (секция CMS) совпадает с оракулом")
    void testOmacLargeMessageCmsSection() throws Exception {
        byte[] data = randomBytes(AcpkmSectionSize.CMS + 100);
        byte[] actual = CtrAcpkmMode.encryptWithMac(key, ukm, data, AcpkmSectionSize.CMS);
        assertArrayEquals(
                oracleOmac(key.getKey(), ukm, data, AcpkmSectionSize.CMS),
                actual,
                "Большое сообщение должно совпасть с оракулом");
        assertArrayEquals(
                data, CtrAcpkmMode.decryptWithMac(key, ukm, actual, AcpkmSectionSize.CMS));
    }

    @Test
    @DisplayName("С OMAC: input == output при шифровании и расшифровании")
    void testOmacInPlace() throws Exception {
        for (int len : new int[] {0, 5, 16, 100, 4100}) {
            byte[] data = randomBytes(len);
            byte[] expected = CtrAcpkmMode.encryptWithMac(key, ukm, data);

            byte[] buf = Arrays.copyOf(data, len + TAG_LEN);
            CtrAcpkmMode enc = new CtrAcpkmMode(new Kuznyechik(), true);
            enc.init(true, new ParametersWithIV(key, ukm));
            enc.processBytes(buf, 0, len, buf, 0);
            byte[] tag = enc.finishEncryption();
            System.arraycopy(tag, 0, buf, len, TAG_LEN);
            assertArrayEquals(expected, buf, "Шифрование на месте, len=" + len);

            CtrAcpkmMode dec = new CtrAcpkmMode(new Kuznyechik(), true);
            dec.init(false, new ParametersWithIV(key, ukm));
            byte[] inPlace = expected.clone();
            dec.processBytes(inPlace, 0, len, inPlace, 0);
            dec.verifyEncryptedTag(Arrays.copyOfRange(inPlace, len, len + TAG_LEN));
            assertArrayEquals(
                    data, Arrays.copyOf(inPlace, len), "Расшифрование на месте, len=" + len);
        }
    }

    @Test
    @DisplayName("С OMAC: чужой UKM (seed) -> AuthenticationException")
    void testOmacWrongUkm() {
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, randomBytes(40));
        byte[] other = ukm.clone();
        other[12] ^= 0x01;
        assertThrows(
                AuthenticationException.class, () -> CtrAcpkmMode.decryptWithMac(key, other, ct));
    }

    @Test
    @DisplayName("С OMAC: изменение любого байта шифртекста или тега -> AuthenticationException")
    void testOmacAnyByteChangeRejected() {
        byte[] out = CtrAcpkmMode.encryptWithMac(key, ukm, randomBytes(40));
        for (int i = 0; i < out.length; i++) {
            byte[] bad = out.clone();
            bad[i] ^= 0x01;
            assertThrows(
                    AuthenticationException.class,
                    () -> CtrAcpkmMode.decryptWithMac(key, ukm, bad),
                    "Изменение байта " + i + " должно обнаруживаться");
        }
    }

    @Test
    @DisplayName("С OMAC: вход ровно 16 байт (пустое сообщение) расшифровывается, короче - отказ")
    void testOmacBoundarySizes() throws Exception {
        byte[] empty = CtrAcpkmMode.encryptWithMac(key, ukm, new byte[0]);
        assertEquals(TAG_LEN, empty.length, "Пустое сообщение даёт только тег");
        assertEquals(0, CtrAcpkmMode.decryptWithMac(key, ukm, empty).length);
        assertThrows(
                AuthenticationException.class,
                () -> CtrAcpkmMode.decryptWithMac(key, ukm, new byte[0]));
        assertThrows(
                AuthenticationException.class,
                () -> CtrAcpkmMode.decryptWithMac(key, ukm, new byte[TAG_LEN - 1]));
    }

    @Test
    @DisplayName("С OMAC: verifyEncryptedTag с тегом неверной длины -> AuthenticationException")
    void testVerifyTagWrongLength() {
        CtrAcpkmMode dec = new CtrAcpkmMode(new Kuznyechik(), true);
        dec.init(false, new ParametersWithIV(key, ukm));
        assertThrows(AuthenticationException.class, () -> dec.verifyEncryptedTag(new byte[15]));
        assertThrows(AuthenticationException.class, () -> dec.verifyEncryptedTag(null));
    }

    /**
     * Независимый оракул RFC 9337 §5.1.1: K(1), K(2) из KDF_TREE;
     * {@code tag = CMAC(K(2), M)}; результат - CTR по {@code M || tag} ключом K(1).
     * CTR берётся из не-OMAC режима, CMAC - из отдельного экземпляра.
     */
    private static byte[] oracleOmac(byte[] dk, byte[] u, byte[] data, int sectionSize) {
        byte[] derived = deriveKeys(dk, u);
        byte[] k1 = Arrays.copyOfRange(derived, 0, KEY_LEN);
        byte[] k2 = Arrays.copyOfRange(derived, KEY_LEN, KEY_LEN * 2);
        byte[] body = Arrays.copyOf(data, data.length + TAG_LEN);
        System.arraycopy(cmacTag(k2, data), 0, body, data.length, TAG_LEN);
        return CtrAcpkmMode.encryptOnly(new SymmetricKey(k1), u, body, sectionSize);
    }

    /** KDF_TREE(DK, "kdf tree", ukm[8..16], 2, 32) -> K(1)||K(2) (RFC 9337 §5.1.1). */
    private static byte[] deriveKeys(byte[] dk, byte[] u) {
        byte[] label = "kdf tree".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = Arrays.copyOfRange(u, 8, 16);
        return KdfTreeGostR3411_2012_256.generate(dk, label, seed, 2, KEY_LEN);
    }

    /** CMAC над данными с отдельным экземпляром Kuznyechik под заданным ключом. */
    private static byte[] cmacTag(byte[] macKey, byte[] data) {
        Cmac cmac = new Cmac(new Kuznyechik());
        cmac.init(new SymmetricKey(macKey));
        cmac.update(data, 0, data.length);
        byte[] out = new byte[TAG_LEN];
        cmac.doFinal(out, 0);
        return out;
    }

    // ========================================================================
    // Исключения — init
    // ========================================================================

    @Test
    @DisplayName("Инициализация с null cipher -> IllegalArgumentException")
    void testNullCipher() {
        assertThrows(IllegalArgumentException.class, () -> new CtrAcpkmMode(null, false));
    }

    @Test
    @DisplayName("OMAC без UKM -> IllegalArgumentException")
    void testOmacNoUkm() {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), true);
        assertThrows(IllegalArgumentException.class, () -> mode.init(true, key));
    }

    @Test
    @DisplayName("OMAC с UKM не 16 байт -> IllegalArgumentException")
    void testOmacWrongUkmLen() {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), true);
        assertThrows(
                IllegalArgumentException.class,
                () -> mode.init(true, new ParametersWithIV(key, new byte[8])));
    }

    @Test
    @DisplayName("Без OMAC: переполнение 64-битного счётчика (0xFF···FF -> 0x00···00)")
    void testNoOmacCounterOverflow() {
        // IV: первые 8 байт (S') произвольные, последние 8 байт (счётчик) = 0xFF···FF
        byte[] overflowUkm = randomBytes(16);
        Arrays.fill(overflowUkm, 8, 16, (byte) 0xFF);

        // Шифруем 32 байта — гарантированный инкремент через границу (1 блок = 16 байт,
        // второй блок инкрементирует счётчик с 0xFF···FF до 0x00···00)
        byte[] plaintext = randomBytes(32);
        byte[] ct = encryptNoOmac(key, overflowUkm, plaintext);
        byte[] decrypted = decryptNoOmac(key, overflowUkm, ct);
        assertArrayEquals(plaintext, decrypted, "roundtrip после переполнения счётчика");
    }

    @Test
    @DisplayName("processBytes до init() -> IllegalStateException")
    void testNotInitialized() {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false);
        assertThrows(
                IllegalStateException.class,
                () -> mode.processBytes(new byte[1], 0, 1, new byte[1], 0));
    }

    // ========================================================================
    // helpers
    // ========================================================================

    private static void roundtripNoOmac(SymmetricKey k, byte[] u, byte[] pt) {
        assertArrayEquals(pt, decryptNoOmac(k, u, encryptNoOmac(k, u, pt)));
    }

    private static byte[] encryptNoOmac(SymmetricKey k, byte[] u, byte[] pt) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false);
        mode.init(true, new ParametersWithIV(k, u));
        byte[] ct = new byte[pt.length];
        mode.processBytes(pt, 0, pt.length, ct, 0);
        return ct;
    }

    private static byte[] decryptNoOmac(SymmetricKey k, byte[] u, byte[] ct) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false);
        mode.init(false, new ParametersWithIV(k, u));
        byte[] pt = new byte[ct.length];
        mode.processBytes(ct, 0, ct.length, pt, 0);
        return pt;
    }

    private static void roundtripOmac(SymmetricKey k, byte[] u, byte[] pt) throws Exception {
        byte[] ct = CtrAcpkmMode.encryptWithMac(k, u, pt);
        assertArrayEquals(pt, CtrAcpkmMode.decryptWithMac(k, u, ct));
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    // ========================================================================
    // ACPKM-рекейинг: граничные тесты
    // ========================================================================

    /**
     * Тестовый размер секции — 32 байта (2 блока), чтобы границы были легко достижимы.
     */
    private static final int TEST_SECTION = 32;

    @Test
    @DisplayName("ACPKM: sectionSize не кратен BLOCK_SIZE -> IllegalArgumentException")
    void testSectionSizeNotMultipleOfBlock() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new CtrAcpkmMode(new Kuznyechik(), false, 17));
        assertThrows(
                IllegalArgumentException.class,
                () -> new CtrAcpkmMode(new Kuznyechik(), false, 31));
        assertThrows(
                IllegalArgumentException.class, () -> new CtrAcpkmMode(new Kuznyechik(), false, 8));
    }

    @Test
    @DisplayName("ACPKM: sectionSize = 16 (минимум) принимается")
    void testSectionSizeMinimal() {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false, 16);
        mode.init(true, new ParametersWithIV(key, ukm));
        byte[] pt = randomBytes(16);
        byte[] ct = new byte[16];
        mode.processBytes(pt, 0, 16, ct, 0);
        byte[] dec = new byte[16];
        mode.init(false, new ParametersWithIV(key, ukm));
        mode.processBytes(ct, 0, 16, dec, 0);
        assertArrayEquals(pt, dec);
    }

    @Test
    @DisplayName("ACPKM: roundtrip на границе sectionSize - 1 (рекейинг не срабатывает)")
    void testAcpkmBoundaryBelow() {
        byte[] data = randomBytes(TEST_SECTION - 1);
        byte[] ct = encryptNoOmac(key, ukm, data, TEST_SECTION);
        byte[] pt = decryptNoOmac(key, ukm, ct, TEST_SECTION);
        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("ACPKM: roundtrip на границе sectionSize (ровно одна секция)")
    void testAcpkmBoundaryExact() {
        byte[] data = randomBytes(TEST_SECTION);
        byte[] ct = encryptNoOmac(key, ukm, data, TEST_SECTION);
        byte[] pt = decryptNoOmac(key, ukm, ct, TEST_SECTION);
        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("ACPKM: roundtrip на границе sectionSize + 1 (пересечение секции)")
    void testAcpkmBoundaryAbove() {
        byte[] data = randomBytes(TEST_SECTION + 1);
        byte[] ct = encryptNoOmac(key, ukm, data, TEST_SECTION);
        byte[] pt = decryptNoOmac(key, ukm, ct, TEST_SECTION);
        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("ACPKM: roundtrip через 3 секции")
    void testAcpkmMultipleSections() {
        byte[] data = randomBytes(TEST_SECTION * 3 - 5);
        byte[] ct = encryptNoOmac(key, ukm, data, TEST_SECTION);
        byte[] pt = decryptNoOmac(key, ukm, ct, TEST_SECTION);
        assertArrayEquals(data, pt);
    }

    // ========================================================================
    // ACPKM-рекейинг: потоковая подача чанками
    // ========================================================================

    @Test
    @DisplayName("ACPKM: потоковые чанки через границу секции — результат совпадает с монолитным")
    void testAcpkmStreamingChunksMatchMonolithic() {
        int chunkSize = 5;
        byte[] data = randomBytes(TEST_SECTION * 2 + 7);

        byte[] ctMonolithic = encryptNoOmac(key, ukm, data, TEST_SECTION);

        byte[] ctStreaming = encryptNoOmacStreaming(key, ukm, data, TEST_SECTION, chunkSize);

        assertArrayEquals(
                ctMonolithic,
                ctStreaming,
                "потоковая подача чанками должна давать тот же шифртекст, что и монолитная");
    }

    @Test
    @DisplayName("ACPKM: чанки по 1 байту через 3 секции")
    void testAcpkmStreamingByteByByte() {
        byte[] data = randomBytes(TEST_SECTION * 2 + 7);
        byte[] ctMonolithic = encryptNoOmac(key, ukm, data, TEST_SECTION);
        byte[] ctByteByByte = encryptNoOmacStreaming(key, ukm, data, TEST_SECTION, 1);
        assertArrayEquals(ctMonolithic, ctByteByByte);
    }

    @Test
    @DisplayName("ACPKM: чанки ровно по границе секции")
    void testAcpkmStreamingExactSectionChunks() {
        byte[] data = randomBytes(TEST_SECTION * 3);
        byte[] ctMonolithic = encryptNoOmac(key, ukm, data, TEST_SECTION);
        byte[] ctBySection = encryptNoOmacStreaming(key, ukm, data, TEST_SECTION, TEST_SECTION);
        assertArrayEquals(ctMonolithic, ctBySection);
    }

    // ========================================================================
    // PKCS12/PBES2 регресс на границе 4096 (дефолтный sectionSize)
    // ========================================================================

    @Test
    @DisplayName("PKCS12/PBES2: encryptWithMac/decryptWithMac roundtrip на границе 4096 байт")
    void testPbes2Boundary4096() throws Exception {
        byte[] data = randomBytes(4096);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, data);
        byte[] pt = CtrAcpkmMode.decryptWithMac(key, ukm, ct);
        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName(
            "PKCS12/PBES2: encryptWithMac/decryptWithMac roundtrip 4097 байт (пересечение секции)")
    void testPbes2Boundary4097() throws Exception {
        byte[] data = randomBytes(4097);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, data);
        byte[] pt = CtrAcpkmMode.decryptWithMac(key, ukm, ct);
        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("PKCS12/PBES2: encryptWithMac/decryptWithMac roundtrip 8192 байта (2 секции)")
    void testPbes2Boundary8192() throws Exception {
        byte[] data = randomBytes(8192);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, data);
        byte[] pt = CtrAcpkmMode.decryptWithMac(key, ukm, ct);
        assertArrayEquals(data, pt);
    }

    // ========================================================================
    // ACPKM-рекейинг: helpers с sectionSize
    // ========================================================================

    private static byte[] encryptNoOmac(SymmetricKey k, byte[] u, byte[] pt, int sectionSize) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false, sectionSize);
        mode.init(true, new ParametersWithIV(k, u));
        byte[] ct = new byte[pt.length];
        mode.processBytes(pt, 0, pt.length, ct, 0);
        return ct;
    }

    private static byte[] decryptNoOmac(SymmetricKey k, byte[] u, byte[] ct, int sectionSize) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false, sectionSize);
        mode.init(false, new ParametersWithIV(k, u));
        byte[] pt = new byte[ct.length];
        mode.processBytes(ct, 0, ct.length, pt, 0);
        return pt;
    }

    /**
     * Шифрует данные, подавая их в processBytes() чанками заданного размера.
     */
    private static byte[] encryptNoOmacStreaming(
            SymmetricKey k, byte[] u, byte[] pt, int sectionSize, int chunkSize) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false, sectionSize);
        mode.init(true, new ParametersWithIV(k, u));
        byte[] ct = new byte[pt.length];
        int pos = 0;
        while (pos < pt.length) {
            int len = Math.min(chunkSize, pt.length - pos);
            mode.processBytes(pt, pos, len, ct, pos);
            pos += len;
        }
        return ct;
    }

    @Test
    @DisplayName(
            "С OMAC: после затирания при ошибке тега успешный roundtrip возвращает исходные данные")
    void decryptWithMacKeepsPlaintextOnSuccessAndFailsOnBadTag() throws Exception {
        byte[] data = randomBytes(100);
        byte[] ct = CtrAcpkmMode.encryptWithMac(key, ukm, data);

        assertArrayEquals(
                data,
                CtrAcpkmMode.decryptWithMac(key, ukm, ct),
                "Успешное расшифрование должно вернуть исходный открытый текст, а не нули");

        byte[] corrupted = ct.clone();
        corrupted[ct.length - 1] ^= 0x01;
        assertThrows(
                AuthenticationException.class,
                () -> CtrAcpkmMode.decryptWithMac(key, ukm, corrupted),
                "Изменённый тег должен отвергаться");

        assertArrayEquals(
                data,
                CtrAcpkmMode.decryptWithMac(key, ukm, ct),
                "После ошибки расшифрование корректных данных по-прежнему работает");
    }
}
