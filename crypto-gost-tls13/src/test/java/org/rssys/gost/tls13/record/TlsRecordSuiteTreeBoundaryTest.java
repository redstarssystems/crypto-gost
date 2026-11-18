package org.rssys.gost.tls13.record;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Наборы L и S дают одинаковые ключи записей на номерах 0-7 и разные начиная с 8: у S маска C3
 * равна ...FFF8 (смена ключа каждые 8 записей), у L ...E000 (каждые 8192). Тест фиксирует, почему
 * несогласованный набор шифров на одной из сторон ломает соединение именно на 9-й записи.
 */
@DisplayName("TlsRecord: границы TLSTREE у наборов L и S")
class TlsRecordSuiteTreeBoundaryTest {

    private static final TlsCiphersuite SUITE_L =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final TlsCiphersuite SUITE_S =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

    private static final byte[] PAYLOAD = {1, 2, 3, 4, 5};

    @Test
    @DisplayName("номер 7: записи L и S совместимы, ключи ещё совпадают")
    void sequenceSeven_suitesInteroperate() throws Exception {
        byte[] key = randomBytes(TlsConstants.KUZNYECHIK_KEY_SIZE);
        byte[] iv = randomBytes(TlsConstants.MGM_IV_SIZE);
        // Записи свежие, неиспользованные: setSequenceNumber допустим только в таком состоянии
        TlsRecord writer =
                new TlsRecord(key.clone(), iv.clone(), TlsConstants.MGM_TAG_SIZE, SUITE_S);
        TlsRecord reader =
                new TlsRecord(key.clone(), iv.clone(), TlsConstants.MGM_TAG_SIZE, SUITE_L);
        writer.setSequenceNumber(7);
        reader.setSequenceNumber(7);

        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, PAYLOAD);

        assertArrayEquals(
                PAYLOAD,
                reader.unprotect(record).getData(),
                "До границы TLSTREE ключи L и S должны совпадать");
    }

    @Test
    @DisplayName("номер 8: S сменила ключ, L нет — запись S не проходит проверку у L")
    void sequenceEight_suitesDiverge() {
        byte[] key = randomBytes(TlsConstants.KUZNYECHIK_KEY_SIZE);
        byte[] iv = randomBytes(TlsConstants.MGM_IV_SIZE);
        TlsRecord writer =
                new TlsRecord(key.clone(), iv.clone(), TlsConstants.MGM_TAG_SIZE, SUITE_S);
        TlsRecord reader =
                new TlsRecord(key.clone(), iv.clone(), TlsConstants.MGM_TAG_SIZE, SUITE_L);
        writer.setSequenceNumber(8);
        reader.setSequenceNumber(8);

        byte[] record = writer.protect(TlsConstants.CT_APPLICATION_DATA, PAYLOAD);

        assertThrows(
                AuthenticationException.class,
                () -> reader.unprotect(record),
                "С номера 8 у S другой ключ записи, чем у L");
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }
}
