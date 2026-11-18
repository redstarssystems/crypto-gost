package org.rssys.gost.tls13.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.util.CryptoRandom;

/**
 * Статические выводы {@link TlsKeySchedule}: они нужны движку после завершения рукопожатия, когда
 * экземпляр key schedule уже уничтожен. Ожидаемые значения считаются независимо, через
 * строковые перегрузки {@link HkdfStreebog} с литеральными метками, а не через код под тестом.
 */
@DisplayName("TlsKeySchedule: статические выводы без экземпляра")
class TlsKeyScheduleStaticDerivationTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int HASH_LEN = SUITE.getHashLen();

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    @Test
    @DisplayName("nextTrafficSecret = Expand-Label(secret, \"traffic upd\"), входной секрет цел")
    void nextTrafficSecretMatchesIndependentDerivation() {
        byte[] secret = random(HASH_LEN);
        byte[] original = secret.clone();

        byte[] next = TlsKeySchedule.nextTrafficSecret(secret, HASH_LEN);

        assertArrayEquals(
                HkdfStreebog.expandLabel(
                        original, "traffic upd", HkdfStreebog.EMPTY_CONTEXT, HASH_LEN, HASH_LEN),
                next,
                "Следующий секрет совпал с независимым расчётом");
        assertArrayEquals(original, secret, "Хелпер не затирает и не меняет входной секрет");
        assertNotEquals(
                java.util.Arrays.toString(original),
                java.util.Arrays.toString(next),
                "Следующий секрет отличается от текущего");
    }

    @Test
    @DisplayName("Статический deriveTrafficKeys совпадает с экземплярным и с ручным расчётом")
    void staticTrafficKeysMatchInstanceAndManualDerivation() {
        byte[] secret = random(HASH_LEN);

        TlsTrafficKeys fromStatic = TlsKeySchedule.deriveTrafficKeys(secret, SUITE);
        TlsTrafficKeys fromInstance = new TlsKeySchedule(SUITE).deriveTrafficKeys(secret);

        assertArrayEquals(
                HkdfStreebog.expandLabel(
                        secret, "key", HkdfStreebog.EMPTY_CONTEXT, SUITE.getKeyLen(), HASH_LEN),
                fromStatic.getKey(),
                "Ключ совпал с независимым расчётом");
        assertArrayEquals(
                HkdfStreebog.expandLabel(
                        secret, "iv", HkdfStreebog.EMPTY_CONTEXT, SUITE.getIvLen(), HASH_LEN),
                fromStatic.getIv(),
                "IV совпал с независимым расчётом");
        assertArrayEquals(
                fromInstance.getKey(), fromStatic.getKey(), "Ключи обоих вариантов равны");
        assertArrayEquals(fromInstance.getIv(), fromStatic.getIv(), "IV обоих вариантов равны");
    }

    @Test
    @DisplayName("finishedMac = HMAC(Expand-Label(secret, \"finished\"), data) и равен verify_data")
    void finishedMacMatchesIndependentDerivationAndVerifyData() {
        byte[] secret = random(HASH_LEN);
        byte[] transcript = random(HASH_LEN);

        byte[] finishedKey =
                HkdfStreebog.expandLabel(
                        secret, "finished", HkdfStreebog.EMPTY_CONTEXT, HASH_LEN, HASH_LEN);
        Hmac hmac = HkdfStreebog.newHmac(HASH_LEN);
        hmac.init(finishedKey);
        hmac.update(transcript, 0, transcript.length);
        byte[] expected = new byte[HASH_LEN];
        hmac.doFinal(expected, 0);

        assertArrayEquals(
                expected,
                TlsKeySchedule.finishedMac(secret, transcript, HASH_LEN),
                "Общий вывод совпал с независимым расчётом");
        assertArrayEquals(
                expected,
                new TlsKeySchedule(SUITE).computeVerifyData(secret, transcript),
                "verify_data экземпляра считается тем же выводом");
    }

    @Test
    @DisplayName("derivePsk = Expand-Label(rms, \"resumption\", nonce); обёртка TlsPskHelper равна")
    void derivePskMatchesIndependentDerivation() {
        byte[] rms = random(HASH_LEN);
        byte[] nonce = random(8);

        byte[] expected = HkdfStreebog.expandLabel(rms, "resumption", nonce, HASH_LEN, HASH_LEN);

        assertArrayEquals(
                expected,
                TlsKeySchedule.derivePsk(rms, nonce, HASH_LEN),
                "PSK совпал с независимым расчётом");
        assertArrayEquals(
                expected,
                org.rssys.gost.tls13.psk.TlsPskHelper.derivePsk(rms, nonce, HASH_LEN),
                "Публичная обёртка делегирует тому же выводу");
    }
}
