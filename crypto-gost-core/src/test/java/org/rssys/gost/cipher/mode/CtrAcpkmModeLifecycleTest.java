package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Жизненный цикл {@link CtrAcpkmMode}: повторная инициализация, reset, финализация MAC,
 * обязательность UKM.
 */
@DisplayName("CtrAcpkmMode — жизненный цикл и валидация UKM")
class CtrAcpkmModeLifecycleTest {

    private static final int SECTION = 64;

    private SymmetricKey key;
    private byte[] ukm;

    @BeforeEach
    void setUp() {
        key = new SymmetricKey(random(32));
        ukm = random(16);
    }

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    private static byte[] run(CtrAcpkmMode mode, byte[] data) {
        byte[] out = new byte[data.length];
        mode.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    private CtrAcpkmMode newMode(boolean omac) {
        return new CtrAcpkmMode(new Kuznyechik(), omac, SECTION);
    }

    @Test
    @DisplayName("init без UKM отвергается: нулевой IV недопустим")
    void initWithoutUkmRejected() {
        CtrAcpkmMode mode = newMode(false);
        assertThrows(
                IllegalArgumentException.class,
                () -> mode.init(true, key),
                "Ключ без UKM должен отвергаться");
    }

    @Test
    @DisplayName("Статические encryptOnly/decryptOnly с ukm=null отвергаются")
    void staticMethodsRejectNullUkm() {
        byte[] data = random(10);
        assertThrows(
                IllegalArgumentException.class,
                () -> CtrAcpkmMode.encryptOnly(key, null, data),
                "encryptOnly(null UKM) должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> CtrAcpkmMode.decryptOnly(key, null, data),
                "decryptOnly(null UKM) должен отвергаться");
    }

    @Test
    @DisplayName("OMAC требует UKM ровно 16 байт, без OMAC — не короче 8")
    void ukmLengthByProfile() {
        CtrAcpkmMode omac = newMode(true);
        assertThrows(
                IllegalArgumentException.class,
                () -> omac.init(true, new ParametersWithIV(key, random(15))),
                "OMAC с UKM 15 байт должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> omac.init(true, new ParametersWithIV(key, random(17))),
                "OMAC с UKM 17 байт должен отвергаться");
        CtrAcpkmMode plain = newMode(false);
        assertThrows(
                IllegalArgumentException.class,
                () -> plain.init(true, new ParametersWithIV(key, random(7))),
                "CTR-ACPKM с UKM 7 байт должен отвергаться");
        assertDoesNotThrow(
                () -> plain.init(true, new ParametersWithIV(key, random(8))),
                "CTR-ACPKM с UKM 8 байт допустим");
    }

    @Test
    @DisplayName("Повторный init после неполного блока даёт тот же результат, что новый объект")
    void reinitAfterPartialBlockMatchesFreshObject() {
        byte[] data = random(100);
        CtrAcpkmMode fresh = newMode(false);
        fresh.init(true, new ParametersWithIV(key, ukm));
        byte[] expected = run(fresh, data);

        CtrAcpkmMode reused = newMode(false);
        reused.init(true, new ParametersWithIV(key, ukm));
        run(reused, random(5));
        reused.init(true, new ParametersWithIV(key, ukm));
        assertArrayEquals(
                expected,
                run(reused, data),
                "Остаток прежней гаммы не должен влиять на новый сеанс");
    }

    @Test
    @DisplayName("init после destroy даёт тот же результат, что новый объект")
    void reinitAfterDestroyMatchesFreshObject() {
        byte[] data = random(100);
        CtrAcpkmMode fresh = newMode(false);
        fresh.init(true, new ParametersWithIV(key, ukm));
        byte[] expected = run(fresh, data);

        CtrAcpkmMode reused = newMode(false);
        reused.init(true, new ParametersWithIV(key, ukm));
        run(reused, random(5));
        reused.destroy();
        reused.init(true, new ParametersWithIV(key, ukm));
        assertArrayEquals(
                expected,
                run(reused, data),
                "Состояние до destroy не должно просачиваться в новый сеанс");
    }

    @Test
    @DisplayName("reset после границы секции восстанавливает исходный ключ")
    void resetRestoresInitialKeyAfterSectionBoundary() {
        // Данных больше секции: к моменту reset в шифре лежит производный ключ ACPKM.
        byte[] data = random(SECTION * 3 + 7);
        CtrAcpkmMode mode = newMode(false);
        mode.init(true, new ParametersWithIV(key, ukm));
        byte[] first = run(mode, data);
        mode.reset();
        assertArrayEquals(
                first, run(mode, data), "После reset результат должен совпадать с первым проходом");
    }

    @Test
    @DisplayName("reset в OMAC-варианте даёт тот же шифртекст и зашифрованный тег")
    void resetOmacRestoresStreamAndTag() {
        byte[] data = random(SECTION * 2 + 3);
        CtrAcpkmMode mode = newMode(true);
        mode.init(true, new ParametersWithIV(key, ukm));
        byte[] ct1 = run(mode, data);
        byte[] tag1 = mode.finishEncryption();
        mode.reset();
        byte[] ct2 = run(mode, data);
        assertArrayEquals(ct1, ct2, "Шифртекст после reset должен совпасть");
        assertArrayEquals(tag1, mode.finishEncryption(), "Тег после reset должен совпасть");
    }

    @Test
    @DisplayName(
            "processBytes после finishEncryption/verifyEncryptedTag запрещён, reset снимает запрет")
    void processBytesAfterTagFinalizedRejected() throws Exception {
        CtrAcpkmMode enc = newMode(true);
        enc.init(true, new ParametersWithIV(key, ukm));
        byte[] ct = run(enc, random(20));
        byte[] encTag = enc.finishEncryption();
        assertThrows(
                IllegalStateException.class,
                () -> run(enc, random(4)),
                "Данные после финализации MAC не должны приниматься");
        assertThrows(
                IllegalStateException.class,
                enc::finishEncryption,
                "Повторная финализация без reset недопустима");
        enc.reset();
        assertDoesNotThrow(() -> run(enc, random(4)), "После reset обработка снова доступна");

        CtrAcpkmMode dec = newMode(true);
        dec.init(false, new ParametersWithIV(key, ukm));
        run(dec, ct);
        dec.verifyEncryptedTag(encTag);
        assertThrows(
                IllegalStateException.class,
                () -> run(dec, random(4)),
                "Данные после проверки тега не должны приниматься");
        dec.reset();
        assertDoesNotThrow(() -> run(dec, ct), "После reset расшифрование снова доступно");
    }

    @Test
    @DisplayName(
            "finishEncryption/verifyEncryptedTag работают после reset и не смешивают направления")
    void tagStagesAfterResetAndDirection() throws Exception {
        byte[] data = random(SECTION + 5);
        CtrAcpkmMode enc = newMode(true);
        enc.init(true, new ParametersWithIV(key, ukm));
        byte[] ct = run(enc, data);
        byte[] encTag = enc.finishEncryption();
        assertThrows(
                IllegalStateException.class,
                () -> enc.verifyEncryptedTag(encTag),
                "verifyEncryptedTag недопустим в режиме шифрования");

        CtrAcpkmMode dec = newMode(true);
        dec.init(false, new ParametersWithIV(key, ukm));
        assertThrows(
                IllegalStateException.class,
                dec::finishEncryption,
                "finishEncryption недопустим в режиме расшифрования");
        run(dec, ct);
        dec.verifyEncryptedTag(encTag);
        dec.reset();
        run(dec, ct);
        assertDoesNotThrow(() -> dec.verifyEncryptedTag(encTag), "Проверка тега после reset");
    }

    @Test
    @DisplayName("finishEncryption без OMAC -> IllegalStateException")
    void tagStageRequiresOmac() {
        CtrAcpkmMode mode = newMode(false);
        mode.init(true, new ParametersWithIV(key, ukm));
        assertThrows(IllegalStateException.class, mode::finishEncryption);
    }

    @Test
    @DisplayName("reset без init -> IllegalStateException")
    void resetWithoutInitRejected() {
        assertThrows(
                IllegalStateException.class,
                () -> newMode(false).reset(),
                "reset до init недопустим");
    }
}
