package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.CryptoRandom;

/**
 * Модульные тесты диспетчеров дайджеста {@link GostSignatureHelper}: {@code digestByOid},
 * {@code keySizeToDigestOid}, {@code digestAlgByHlen}, {@code doHash}.
 *
 * <p>Фиксируют byte-for-byte эквивалентность единых хелперов прежним разрозненным развилкам
 * (тому же результату, что давали {@code Digest.digest256/512} напрямую) — защита от регрессии
 * при унификации хелперов; проверяют fail-closed поведение на неизвестном дискриминаторе.
 */
@DisplayName("GostSignatureHelper: диспетчеризация дайджеста")
class GostSignatureHelperDigestTest {

    private static byte[] randomData() {
        byte[] data = new byte[97];
        CryptoRandom.INSTANCE.nextBytes(data);
        return data;
    }

    @Test
    @DisplayName("digestByOid эквивалентен прямому Digest.digest256/512 (byte-for-byte)")
    void digestByOidMatchesDirect() {
        byte[] data = randomData();
        assertArrayEquals(
                Digest.digest256(data),
                GostSignatureHelper.digestByOid(GostOids.DIGEST_256, data),
                "digestByOid(DIGEST_256) должен совпадать с Digest.digest256");
        assertArrayEquals(
                Digest.digest512(data),
                GostSignatureHelper.digestByOid(GostOids.DIGEST_512, data),
                "digestByOid(DIGEST_512) должен совпадать с Digest.digest512");
    }

    @Test
    @DisplayName("digestByOid: неизвестный OID -> IllegalArgumentException (fail-closed)")
    void digestByOidFailsClosed() {
        byte[] data = randomData();
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.digestByOid("1.2.3.4.5", data),
                "неизвестный OID дайджеста должен бросать исключение, а не молчаливо брать 256");
    }

    @Test
    @DisplayName("keySizeToDigestOid: 256/512 -> корректный OID, иначе fail-closed")
    void keySizeToDigestOidMapping() {
        assertEquals(GostOids.DIGEST_256, GostSignatureHelper.keySizeToDigestOid(256));
        assertEquals(GostOids.DIGEST_512, GostSignatureHelper.keySizeToDigestOid(512));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.keySizeToDigestOid(384),
                "неподдерживаемый размер ключа должен бросать исключение");
    }

    @Test
    @DisplayName("digestAlgByHlen: 32/64 -> корректный алгоритм, иначе fail-closed")
    void digestAlgByHlenMapping() {
        assertEquals(
                Digest.Algorithm.STREEBOG_256,
                GostSignatureHelper.digestAlgByHlen(GostOids.STREEBOG_256_HASH_LEN));
        assertEquals(
                Digest.Algorithm.STREEBOG_512,
                GostSignatureHelper.digestAlgByHlen(GostOids.STREEBOG_512_HASH_LEN));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.digestAlgByHlen(48),
                "неподдерживаемая длина хэша должна бросать исключение");
    }

    @Test
    @DisplayName("digestAlgByHlen согласован с digestByOid и прямым Digest (byte-for-byte)")
    void digestAlgByHlenConsistentWithOneShot() {
        byte[] data = randomData();
        byte[] viaAlg256 =
                new Digest(GostSignatureHelper.digestAlgByHlen(GostOids.STREEBOG_256_HASH_LEN))
                        .update(data)
                        .digest();
        byte[] viaAlg512 =
                new Digest(GostSignatureHelper.digestAlgByHlen(GostOids.STREEBOG_512_HASH_LEN))
                        .update(data)
                        .digest();
        assertArrayEquals(Digest.digest256(data), viaAlg256);
        assertArrayEquals(Digest.digest512(data), viaAlg512);
    }

    @Test
    @DisplayName("doHash: fail-closed на неизвестной длине хэша")
    void doHashFailsClosed() {
        byte[] data = randomData();
        assertArrayEquals(Digest.digest256(data), GostSignatureHelper.doHash(data, 32));
        assertArrayEquals(Digest.digest512(data), GostSignatureHelper.doHash(data, 64));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.doHash(data, 48),
                "doHash больше не должен молча трактовать неизвестную длину как 256-бит");
    }
}
