package org.rssys.gost.tls13.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * Тесты TLS 1.3 Key Schedule (RFC 8446 §7.1) с ГОСТ-примитивами.
 *
 * Проверяется:
 *   — вычисление early secret (режим без PSK: HKDF-Extract(0, 0))
 *   — вычисление handshake secret из ECDHE общего секрета
 *   — вычисление master secret
 *   — handshake и прикладные traffic keys (серверные/клиентские)
 *   — Finished verify_data
 *   — детерминированность, различие ключей, жизненный цикл destroy
 */
@DisplayName("Расписание ключей TLS 1.3: early/handshake/master секрет, ключи трафика, finished")
class TlsKeyScheduleTest {

    private static byte[] hash256(byte[] msg) {
        Digest d = new Streebog256();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    /** Создаёт TlsKeySchedule (256-бит) с уже вычисленным handshake secret */
    private static TlsKeySchedule createKeySchedule256() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.deriveHandshakeSecret(new byte[32]);
        return ks;
    }

    private static TlsTrafficKeys deriveKeys(TlsKeySchedule ks, byte[] secret) {
        TlsTrafficKeys keys = ks.deriveTrafficKeys(secret);
        TlsUtils.wipeArray(secret);
        return keys;
    }

    // -----------------------------------------------------------------------
    // Early secret (режим без PSK: HKDF-Extract(0, 0))
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Вычисление handshake secret
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("handshake secret: null sharedSecret -> исключение")
    void testhandshakeSecretRequiresNonNullSharedSecret() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalArgumentException.class, () -> ks.deriveHandshakeSecret(null));
    }

    // -----------------------------------------------------------------------
    // Вычисление master secret
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("master secret: требуется handshake secret -> исключение")
    void testmasterSecretRequiresHandshakeSecret() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalStateException.class, ks::deriveMasterSecret);
    }

    // -----------------------------------------------------------------------
    // Handshake-ключи шифрования
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Прикладные ключи шифрования
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Геттеры traffic secret (для использования в Finished)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Finished verify_data
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Жизненный цикл: уничтожение
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("destroy: запрещает дальнейшее использование")
    void testdestroyPreventsUsage() {
        TlsKeySchedule ks = createKeySchedule256();
        ks.deriveHandshakeSecret(new byte[32]);
        ks.deriveMasterSecret();
        ks.destroy();
        assertTrue(ks.isDestroyed());
        assertThrows(IllegalStateException.class, ks::getEarlySecret);
    }

    @Test
    @DisplayName("destroy: идемпотентность")
    void testdestroyIdempotent() {
        TlsKeySchedule ks = createKeySchedule256();
        ks.destroy();
        ks.destroy(); // не должно бросить исключение
        assertTrue(ks.isDestroyed());
    }

    // -----------------------------------------------------------------------
    // Полный поток key schedule (256-бит)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Граничные случаи
    // -----------------------------------------------------------------------

    // =======================================================================
    // Crash paths: traffic secret getters before derive*()
    // =======================================================================

    @Test
    @DisplayName("getServerHandshakeTrafficSecret до deriveHandshakeSecret -> исключение")
    void testServerHandshakeTrafficSecretBeforeDerive() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] transcript = hash256("transcript".getBytes());
        assertThrows(
                IllegalArgumentException.class,
                () -> ks.getServerHandshakeTrafficSecret(transcript));
    }

    @Test
    @DisplayName("getClientHandshakeTrafficSecret до deriveHandshakeSecret -> исключение")
    void testClientHandshakeTrafficSecretBeforeDerive() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] transcript = hash256("transcript".getBytes());
        assertThrows(
                IllegalArgumentException.class,
                () -> ks.getClientHandshakeTrafficSecret(transcript));
    }

    @Test
    @DisplayName("getServerApplicationTrafficSecret до deriveMasterSecret -> исключение")
    void testServerApplicationTrafficSecretBeforeDerive() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] transcript = hash256("transcript".getBytes());
        assertThrows(
                IllegalArgumentException.class,
                () -> ks.getServerApplicationTrafficSecret(transcript));
    }

    @Test
    @DisplayName("getClientApplicationTrafficSecret до deriveMasterSecret -> исключение")
    void testClientApplicationTrafficSecretBeforeDerive() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] transcript = hash256("transcript".getBytes());
        assertThrows(
                IllegalArgumentException.class,
                () -> ks.getClientApplicationTrafficSecret(transcript));
    }

    @Test
    @DisplayName("deriveHandshakeSecret после destroy -> исключение")
    void testDeriveHandshakeAfterDestroy() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.destroy();
        assertThrows(IllegalStateException.class, () -> ks.deriveHandshakeSecret(new byte[32]));
    }

    @Test
    @DisplayName("deriveMasterSecret после destroy -> исключение")
    void testDeriveMasterAfterDestroy() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.destroy();
        assertThrows(IllegalStateException.class, ks::deriveMasterSecret);
    }

    @Test
    @DisplayName("computeVerifyData после destroy -> исключение")
    void testComputeVerifyDataAfterDestroy() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.destroy();
        assertThrows(
                IllegalStateException.class,
                () -> ks.computeVerifyData(new byte[32], new byte[32]));
    }

    @Test
    @DisplayName("пустой sharedSecret -> исключение")
    void testEmptySharedSecretThrows() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalArgumentException.class, () -> ks.deriveHandshakeSecret(new byte[0]));
    }

    // =======================================================================
    // TrafficKeys lifecycle
    // =======================================================================

    @Test
    @DisplayName("TrafficKeys: getKey/getIV возвращают копию")
    void testTrafficKeysReturnsCopy() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("transcript".getBytes());
        TlsTrafficKeys tk = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));

        byte[] key = tk.getKey();
        byte[] iv = tk.getIv();
        // модификация полученных массивов не должна влиять на TrafficKeys
        key[0] ^= 0xFF;
        iv[0] ^= 0xFF;
        assertFalse(Arrays.equals(key, tk.getKey()));
        assertFalse(Arrays.equals(iv, tk.getIv()));
    }

    @Test
    @DisplayName("TrafficKeys: destroy зануляет ключ и IV")
    void testTrafficKeysDestroy() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("transcript".getBytes());
        TlsTrafficKeys tk = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));

        byte[] keyBefore = tk.getKey();
        byte[] ivBefore = tk.getIv();
        assertFalse(allZeros(keyBefore));
        assertFalse(allZeros(ivBefore));

        tk.destroy();

        byte[] keyAfter = tk.getKey();
        byte[] ivAfter = tk.getIv();
        assertTrue(allZeros(keyAfter), "Ключ должен быть занулён после destroy");
        assertTrue(allZeros(ivAfter), "IV должен быть занулён после destroy");
    }

    @Test
    @DisplayName("TrafficKeys: destroy идемпотентен")
    void testTrafficKeysDestroyIdempotent() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("transcript".getBytes());
        TlsTrafficKeys tk = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));

        tk.destroy();
        assertDoesNotThrow(tk::destroy);
    }

    @Test
    @DisplayName("null cipher suite -> исключение")
    void testnullCiphersuiteThrows() {
        assertThrows(IllegalArgumentException.class, () -> new TlsKeySchedule(null));
    }

    // =======================================================================
    // PSK (Pre-Shared Key) key schedule — RFC 8446 §7.1
    // =======================================================================

    @Test
    @DisplayName("deriveEarlySecret: PSK даёт non-zero early secret, отличный от no-PSK")
    void testDeriveEarlySecretWithPsk() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] psk = new byte[32];
        Arrays.fill(psk, (byte) 0x42);
        ks.deriveEarlySecret(psk);

        byte[] earlyWithPsk = ks.getEarlySecret();
        assertFalse(allZeros(earlyWithPsk), "EarlySecret на основе PSK должен быть ненулевым");

        // без PSK — другой early secret
        TlsKeySchedule ksNoPsk =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertFalse(Arrays.equals(earlyWithPsk, ksNoPsk.getEarlySecret()));
    }

    @Test
    @DisplayName("deriveEarlySecret: разные PSK -> разные early secret")
    void testDeriveEarlySecretDifferentPsk() {
        TlsKeySchedule ks1 =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsKeySchedule ks2 =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] psk1 = new byte[32];
        Arrays.fill(psk1, (byte) 0x01);
        byte[] psk2 = new byte[32];
        Arrays.fill(psk2, (byte) 0x02);

        ks1.deriveEarlySecret(psk1);
        ks2.deriveEarlySecret(psk2);
        assertFalse(Arrays.equals(ks1.getEarlySecret(), ks2.getEarlySecret()));
    }

    @Test
    @DisplayName("deriveEarlySecret: null -> исключение")
    void testDeriveEarlySecretNullPsk() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalArgumentException.class, () -> ks.deriveEarlySecret(null));
        assertThrows(IllegalArgumentException.class, () -> ks.deriveEarlySecret(new byte[0]));
    }

    @Test
    @DisplayName("getResumptionMasterSecret: длина 32, детерминированность, требует master")
    void testResumptionMasterSecret() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.deriveHandshakeSecret(new byte[32]);
        ks.deriveMasterSecret();
        byte[] transcript = new byte[32];
        transcript[0] = 0x01; // непустой транскрипт

        byte[] resMaster1 = ks.getResumptionMasterSecret(transcript);
        assertEquals(32, resMaster1.length);
        assertFalse(allZeros(resMaster1));

        // детерминированность
        byte[] resMaster2 = ks.getResumptionMasterSecret(transcript);
        assertArrayEquals(resMaster1, resMaster2);

        // другой транскрипт -> другой RMS (регрессионная защита от computeEmptyHash)
        byte[] transcript2 = new byte[32];
        transcript2[0] = 0x02;
        assertFalse(Arrays.equals(resMaster1, ks.getResumptionMasterSecret(transcript2)));

        // без master secret -> исключение
        TlsKeySchedule ksNoMaster =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(
                IllegalStateException.class,
                () -> ksNoMaster.getResumptionMasterSecret(transcript));
    }

    private static boolean allZeros(byte[] data) {
        for (byte b : data) {
            if (b != 0) return false;
        }
        return true;
    }
}
