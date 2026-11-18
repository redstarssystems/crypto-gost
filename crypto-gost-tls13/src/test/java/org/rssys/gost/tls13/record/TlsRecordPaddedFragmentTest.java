package org.rssys.gost.tls13.record;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.crypto.TlsTree;

/**
 * Приём записи с дополнением при согласованном {@code max_fragment_length}. Ограничение RFC 6066
 * §4 относится к открытому тексту, а нулевое дополнение TLSInnerPlaintext ограничено только
 * общим пределом записи (RFC 8446 §5.4): собеседник вправе дополнить запись и сверх запаса,
 * который когда-то предполагался приёмником.
 */
@DisplayName("TlsRecord: запись с дополнением при max_fragment_length")
class TlsRecordPaddedFragmentTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int TAG_LEN = TlsConstants.MGM_TAG_SIZE;
    private static final int FRAGMENT_512 = 512;
    private static final int LARGE_PADDING = 300;

    private static byte[] key() {
        byte[] key = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
        Arrays.fill(key, (byte) 0xAB);
        return key;
    }

    private static byte[] iv() {
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0xCD);
        iv[0] &= 0x7F;
        return iv;
    }

    /** Строит запись с seqNum = 0: данные, тип содержимого, затем нулевое дополнение. */
    private static byte[] paddedRecord(byte[] data, int paddingLen) throws Exception {
        int innerLen = data.length + 1 + paddingLen;
        int payloadLen = innerLen + TAG_LEN;
        byte[] inner = new byte[innerLen];
        System.arraycopy(data, 0, inner, 0, data.length);
        inner[data.length] = TlsConstants.CT_APPLICATION_DATA;

        byte[] nonce = iv();
        byte[] perRecordKey =
                TlsTree.tlstree(key(), 0, SUITE.getC1(), SUITE.getC2(), SUITE.getC3());
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + payloadLen];
        record[0] = TlsConstants.CT_APPLICATION_DATA;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (payloadLen >>> 8);
        record[4] = (byte) payloadLen;

        Mgm mgm = new Mgm(new Kuznyechik(), TAG_LEN);
        SymmetricKey symKey = new SymmetricKey(perRecordKey);
        mgm.init(true, new ParametersWithIV(symKey, nonce));
        symKey.destroy();
        mgm.updateAAD(record, 0, TlsConstants.RECORD_HEADER_SIZE);
        byte[] ciphertext = new byte[innerLen];
        mgm.processBytes(inner, 0, innerLen, ciphertext, 0);
        byte[] tag = new byte[TAG_LEN];
        mgm.finishEncryption(tag, 0);
        System.arraycopy(ciphertext, 0, record, TlsConstants.RECORD_HEADER_SIZE, innerLen);
        System.arraycopy(tag, 0, record, TlsConstants.RECORD_HEADER_SIZE + innerLen, TAG_LEN);
        return record;
    }

    private static TlsRecord readerWithFragment512() {
        TlsRecord reader = new TlsRecord(key(), iv(), TAG_LEN, SUITE);
        reader.setMaxFragmentLength(TlsConstants.MAX_FRAG_LEN_512);
        return reader;
    }

    @Test
    @DisplayName("полный фрагмент 512 байт с дополнением 300 принимается")
    void paddingBeyondOldSlackAccepted() throws Exception {
        byte[] data = new byte[FRAGMENT_512];
        Arrays.fill(data, (byte) 0x5A);
        byte[] record = paddedRecord(data, LARGE_PADDING);

        TlsParsedRecord parsed = readerWithFragment512().unprotect(record);

        assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
        assertArrayEquals(data, parsed.getData(), "Дополнение не влияет на открытый текст");
    }

    @Test
    @DisplayName("открытый текст 513 байт при лимите 512 -> record_overflow, дополнение не спасает")
    void plaintextAboveLimitRejected() throws Exception {
        byte[] record = paddedRecord(new byte[FRAGMENT_512 + 1], LARGE_PADDING);

        TlsRecord reader = readerWithFragment512();
        TlsException e = assertThrows(TlsException.class, () -> reader.unprotect(record));

        assertEquals(TlsConstants.ALERT_RECORD_OVERFLOW, e.getAlertCode());
    }
}
