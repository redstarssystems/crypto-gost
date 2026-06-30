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

    @Test
    @DisplayName("early secret: длина 32 байта (256-битный cipher suite)")
    void testearlySecretLength256() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] secret = ks.getEarlySecret();
        assertEquals(32, secret.length);
    }

    @Test
    @DisplayName("early secret: детерминированность")
    void testearlySecretDeterministic() {
        TlsKeySchedule ks1 =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsKeySchedule ks2 =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertArrayEquals(ks1.getEarlySecret(), ks2.getEarlySecret());
    }

    // -----------------------------------------------------------------------
    // Вычисление handshake secret
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("handshake secret: длина 32 байта (256-бит)")
    void testhandshakeSecretDerivation256() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] sharedSecret = new byte[32];
        Arrays.fill(sharedSecret, (byte) 0xAB);
        ks.deriveHandshakeSecret(sharedSecret);
        byte[] transcript = hash256("test".getBytes());
        byte[] secret = ks.getServerHandshakeTrafficSecret(transcript);
        TlsTrafficKeys keys = ks.deriveTrafficKeys(secret);
        assertEquals(32, keys.getKey().length);
        TlsUtils.wipeArray(secret);
    }

    @Test
    @DisplayName("handshake secret: разные ECDHE -> разные handshake secret")
    void testhandshakeSecretDifferentSharedSecrets() {
        TlsKeySchedule ks1 =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        TlsKeySchedule ks2 =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        byte[] ss1 = new byte[32];
        Arrays.fill(ss1, (byte) 0x01);
        byte[] ss2 = new byte[32];
        Arrays.fill(ss2, (byte) 0x02);
        ks1.deriveHandshakeSecret(ss1);
        ks2.deriveHandshakeSecret(ss2);
        byte[] transcript = hash256("test".getBytes());
        byte[] secret1 = ks1.getServerHandshakeTrafficSecret(transcript);
        byte[] secret2 = ks2.getServerHandshakeTrafficSecret(transcript);
        assertFalse(
                Arrays.equals(
                        ks1.deriveTrafficKeys(secret1).getKey(),
                        ks2.deriveTrafficKeys(secret2).getKey()));
        TlsUtils.wipeArray(secret1);
        TlsUtils.wipeArray(secret2);
    }

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
    @DisplayName("master secret: длина 32 байта")
    void testmasterSecretDerivation256() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.deriveHandshakeSecret(new byte[32]);
        ks.deriveMasterSecret();
        byte[] transcript = hash256("test".getBytes());
        byte[] secret = ks.getServerApplicationTrafficSecret(transcript);
        TlsTrafficKeys keys = ks.deriveTrafficKeys(secret);
        assertEquals(32, keys.getKey().length);
        TlsUtils.wipeArray(secret);
    }

    @Test
    @DisplayName("master secret: требуется handshake secret -> исключение")
    void testmasterSecretRequiresHandshakeSecret() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalStateException.class, ks::deriveMasterSecret);
    }

    @Test
    @DisplayName("master secret: отличается от handshake secret")
    void testmasterSecretDifferentFromHandshakeSecret() {
        TlsKeySchedule ks =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        ks.deriveHandshakeSecret(new byte[32]);
        byte[] transcript = hash256("test".getBytes());
        byte[] hsSecret = ks.getServerHandshakeTrafficSecret(transcript);
        ks.deriveMasterSecret();
        byte[] apSecret = ks.getServerApplicationTrafficSecret(transcript);
        assertFalse(
                Arrays.equals(
                        ks.deriveTrafficKeys(hsSecret).getKey(),
                        ks.deriveTrafficKeys(apSecret).getKey()));
        TlsUtils.wipeArray(hsSecret);
        TlsUtils.wipeArray(apSecret);
    }

    // -----------------------------------------------------------------------
    // Handshake-ключи шифрования
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("handshake traffic keys: размеры (key=32, iv=16), 256-бит")
    void testhandshakeTrafficKeysSizes256() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("handshake messages".getBytes());

        TlsTrafficKeys serverKeys = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));
        assertEquals(32, serverKeys.getKey().length);
        assertEquals(16, serverKeys.getIv().length);

        TlsTrafficKeys clientKeys = deriveKeys(ks, ks.getClientHandshakeTrafficSecret(transcript));
        assertEquals(32, clientKeys.getKey().length);
        assertEquals(16, clientKeys.getIv().length);
    }

    @Test
    @DisplayName("handshake: серверные и клиентские ключи различаются")
    void testhandshakeTrafficKeysServerVsClient() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("transcript data".getBytes());

        TlsTrafficKeys serverKeys = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));
        TlsTrafficKeys clientKeys = deriveKeys(ks, ks.getClientHandshakeTrafficSecret(transcript));

        // серверные и клиентские ключи должны различаться
        assertFalse(Arrays.equals(serverKeys.getKey(), clientKeys.getKey()));
        assertFalse(Arrays.equals(serverKeys.getIv(), clientKeys.getIv()));
    }

    @Test
    @DisplayName("handshake traffic keys: детерминированность")
    void testhandshakeTrafficKeysDeterministic() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("deterministic transcript".getBytes());

        TlsTrafficKeys k1 = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));
        TlsTrafficKeys k2 = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript));

        assertArrayEquals(k1.getKey(), k2.getKey());
        assertArrayEquals(k1.getIv(), k2.getIv());
    }

    @Test
    @DisplayName("handshake traffic keys: разный transcript -> разные ключи")
    void testhandshakeTrafficKeysDifferentTranscript() {
        TlsKeySchedule ks = createKeySchedule256();

        byte[] transcript1 = hash256("transcript A".getBytes());
        byte[] transcript2 = hash256("transcript B".getBytes());

        TlsTrafficKeys k1 = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript1));
        TlsTrafficKeys k2 = deriveKeys(ks, ks.getServerHandshakeTrafficSecret(transcript2));

        assertFalse(Arrays.equals(k1.getKey(), k2.getKey()));
    }

    // -----------------------------------------------------------------------
    // Прикладные ключи шифрования
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("application traffic keys: размеры (key=32, iv=16)")
    void testapplicationTrafficKeysSizes256() {
        TlsKeySchedule ks = createKeySchedule256();
        ks.deriveMasterSecret();
        byte[] transcript = hash256("full handshake transcript".getBytes());

        TlsTrafficKeys serverKeys =
                deriveKeys(ks, ks.getServerApplicationTrafficSecret(transcript));
        assertEquals(32, serverKeys.getKey().length);
        assertEquals(16, serverKeys.getIv().length);

        TlsTrafficKeys clientKeys =
                deriveKeys(ks, ks.getClientApplicationTrafficSecret(transcript));
        assertEquals(32, clientKeys.getKey().length);
        assertEquals(16, clientKeys.getIv().length);
    }

    @Test
    @DisplayName("application ключи отличаются от handshake ключей")
    void testapplicationKeysDifferFromHandshakeKeys() {
        TlsKeySchedule ks = createKeySchedule256();

        byte[] hsTranscript = hash256("handshake transcript".getBytes());
        TlsTrafficKeys hsServerKeys =
                deriveKeys(ks, ks.getServerHandshakeTrafficSecret(hsTranscript));
        ks.deriveMasterSecret();

        byte[] apTranscript = hash256("application transcript".getBytes());
        TlsTrafficKeys apServerKeys =
                deriveKeys(ks, ks.getServerApplicationTrafficSecret(apTranscript));

        assertFalse(Arrays.equals(hsServerKeys.getKey(), apServerKeys.getKey()));
        assertFalse(Arrays.equals(hsServerKeys.getIv(), apServerKeys.getIv()));
    }

    @Test
    @DisplayName("application: серверные и клиентские ключи различаются")
    void testapplicationTrafficKeysServerVsClient() {
        TlsKeySchedule ks = createKeySchedule256();
        ks.deriveMasterSecret();
        byte[] transcript = hash256("transcript".getBytes());

        assertFalse(
                Arrays.equals(
                        deriveKeys(ks, ks.getServerApplicationTrafficSecret(transcript)).getKey(),
                        deriveKeys(ks, ks.getClientApplicationTrafficSecret(transcript)).getKey()));
    }

    @Test
    @DisplayName("application traffic keys: детерминированность")
    void testapplicationTrafficKeysDeterministic() {
        TlsKeySchedule ks = createKeySchedule256();
        ks.deriveMasterSecret();
        byte[] transcript = hash256("transcript".getBytes());

        TlsTrafficKeys k1 = deriveKeys(ks, ks.getServerApplicationTrafficSecret(transcript));
        TlsTrafficKeys k2 = deriveKeys(ks, ks.getServerApplicationTrafficSecret(transcript));

        assertArrayEquals(k1.getKey(), k2.getKey());
        assertArrayEquals(k1.getIv(), k2.getIv());
    }

    @Test
    @DisplayName("application keys: разный transcript -> разные ключи")
    void testapplicationTrafficKeysDifferentTranscript() {
        TlsKeySchedule ks = createKeySchedule256();
        ks.deriveMasterSecret();

        byte[] t1 = hash256("transcript X".getBytes());
        byte[] t2 = hash256("transcript Y".getBytes());

        assertFalse(
                Arrays.equals(
                        deriveKeys(ks, ks.getServerApplicationTrafficSecret(t1)).getKey(),
                        deriveKeys(ks, ks.getServerApplicationTrafficSecret(t2)).getKey()));
    }

    // -----------------------------------------------------------------------
    // Геттеры traffic secret (для использования в Finished)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("handshake traffic secrets: длина 32 байта")
    void testhandshakeTrafficSecretsLength() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("transcript".getBytes());

        assertEquals(32, ks.getServerHandshakeTrafficSecret(transcript).length);
        assertEquals(32, ks.getClientHandshakeTrafficSecret(transcript).length);
    }

    @Test
    @DisplayName("handshake traffic secrets: серверный ≠ клиентский")
    void testhandshakeTrafficSecretsServerVsClient() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("same transcript".getBytes());

        assertFalse(
                Arrays.equals(
                        ks.getServerHandshakeTrafficSecret(transcript),
                        ks.getClientHandshakeTrafficSecret(transcript)));
    }

    // -----------------------------------------------------------------------
    // Finished verify_data
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("computeVerifyData: длина 32 байта (256-бит)")
    void testcomputeVerifyDataLength256() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("handshake up to finished".getBytes());
        byte[] trafficSecret = ks.getServerHandshakeTrafficSecret(transcript);

        byte[] verifyData = ks.computeVerifyData(trafficSecret, transcript);
        assertEquals(32, verifyData.length);
    }

    @Test
    @DisplayName("computeVerifyData: детерминированность")
    void testcomputeVerifyDataDeterministic() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("finished test".getBytes());
        byte[] trafficSecret = ks.getServerHandshakeTrafficSecret(transcript);

        byte[] vd1 = ks.computeVerifyData(trafficSecret, transcript);
        byte[] vd2 = ks.computeVerifyData(trafficSecret, transcript);
        assertArrayEquals(vd1, vd2);
    }

    @Test
    @DisplayName("computeVerifyData: разный transcript -> разные verify_data")
    void testcomputeVerifyDataDifferentTranscript() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] trafficSecret = ks.getServerHandshakeTrafficSecret(hash256("t1".getBytes()));

        byte[] vd1 = ks.computeVerifyData(trafficSecret, hash256("transcript A".getBytes()));
        byte[] vd2 = ks.computeVerifyData(trafficSecret, hash256("transcript B".getBytes()));
        assertFalse(Arrays.equals(vd1, vd2));
    }

    @Test
    @DisplayName("серверный и клиентский Finished различаются")
    void testserverAndClientFinishedDiffer() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] transcript = hash256("same handshake".getBytes());

        byte[] serverSecret = ks.getServerHandshakeTrafficSecret(transcript);
        byte[] clientSecret = ks.getClientHandshakeTrafficSecret(transcript);

        byte[] serverFinished = ks.computeVerifyData(serverSecret, transcript);
        byte[] clientFinished = ks.computeVerifyData(clientSecret, transcript);
        assertFalse(Arrays.equals(serverFinished, clientFinished));
    }

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

    @Test
    @DisplayName("полный flow key schedule: все ключи различны, 256-бит")
    void testfullKeyScheduleFlow256() {
        TlsKeySchedule ks = createKeySchedule256();
        byte[] sharedSecret = new byte[32];
        Arrays.fill(sharedSecret, (byte) 0x42);

        // этап 1: early secret
        assertEquals(32, ks.getEarlySecret().length);

        // этап 2: handshake secret + handshake-ключи
        ks.deriveHandshakeSecret(sharedSecret);

        byte[] hsTranscript = hash256("ClientHelloServerHello".getBytes());
        TlsTrafficKeys hsServerKeys =
                deriveKeys(ks, ks.getServerHandshakeTrafficSecret(hsTranscript));
        TlsTrafficKeys hsClientKeys =
                deriveKeys(ks, ks.getClientHandshakeTrafficSecret(hsTranscript));
        assertNotNull(hsServerKeys);
        assertNotNull(hsClientKeys);

        // этап 3: master secret + прикладные ключи
        ks.deriveMasterSecret();

        byte[] fullTranscript = hash256("full handshake".getBytes());
        TlsTrafficKeys apServerKeys =
                deriveKeys(ks, ks.getServerApplicationTrafficSecret(fullTranscript));
        TlsTrafficKeys apClientKeys =
                deriveKeys(ks, ks.getClientApplicationTrafficSecret(fullTranscript));
        assertNotNull(apServerKeys);
        assertNotNull(apClientKeys);

        // все четыре ключа должны быть разными
        assertFalse(Arrays.equals(hsServerKeys.getKey(), hsClientKeys.getKey()));
        assertFalse(Arrays.equals(hsServerKeys.getKey(), apServerKeys.getKey()));
        assertFalse(Arrays.equals(hsServerKeys.getKey(), apClientKeys.getKey()));
        assertFalse(Arrays.equals(hsClientKeys.getKey(), apServerKeys.getKey()));
        assertFalse(Arrays.equals(hsClientKeys.getKey(), apClientKeys.getKey()));
        assertFalse(Arrays.equals(apServerKeys.getKey(), apClientKeys.getKey()));
    }

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

        byte[] resMaster1 = ks.getResumptionMasterSecret();
        assertEquals(32, resMaster1.length);
        assertFalse(allZeros(resMaster1));

        // детерминированность
        byte[] resMaster2 = ks.getResumptionMasterSecret();
        assertArrayEquals(resMaster1, resMaster2);

        // без master secret -> исключение
        TlsKeySchedule ksNoMaster =
                new TlsKeySchedule(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertThrows(IllegalStateException.class, ksNoMaster::getResumptionMasterSecret);
    }

    private static boolean allZeros(byte[] data) {
        for (byte b : data) {
            if (b != 0) return false;
        }
        return true;
    }
}
