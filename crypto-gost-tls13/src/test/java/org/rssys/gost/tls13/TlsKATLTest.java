package org.rssys.gost.tls13;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.tls13.psk.*;
import org.rssys.gost.tls13.crypto.*;
import org.rssys.gost.tls13.config.*;
import org.rssys.gost.tls13.cert.*;
import org.rssys.gost.tls13.record.*;
import org.rssys.gost.tls13.message.*;
import org.rssys.gost.tls13.engine.*;
import org.rssys.gost.cipher.mode.Mgm;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsTestHelper.hex;
import static org.rssys.gost.tls13.TlsTestHelper.hexStr;

/**
 * KAT для Kuznyechik_MGM_L (0xC103).
 * <p>
 * Группа 1: key schedule не зависит от cipher suite — значения из RFC 9367 Appendix A.1.
 * Группа 2: TLSTREE-L — regression (no external KAT available).
 * Группа 3: cross-check L vs S (инварианты масок).
 * Группа 4: AEAD с per-record ключом от TLSTREE-L.
 */
public class TlsKATLTest {

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    // hex/hexStr утилиты вынесены в TlsTestHelper

    // ========================================================================
    // Константы cipher suite L
    // ========================================================================

    private static final TlsCiphersuite CS_L =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static final long C1_L = CS_L.getC1(); // 0xF800000000000000
    private static final long C2_L = CS_L.getC2(); // 0xFFFFFFF000000000
    private static final long C3_L = CS_L.getC3(); // 0xFFFFFFFFFFFFE000

    private static final TlsCiphersuite CS_S =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

    private static final long C1_S = CS_S.getC1();
    private static final long C2_S = CS_S.getC2();
    private static final long C3_S = CS_S.getC3();

    private static final byte[] ZERO_KEY = new byte[32];

    // ========================================================================
    // Группа 1: Key schedule для L совпадает с RFC 9367 A.1
    // ========================================================================
    //
    // Key schedule не зависит от cipher suite — зависит только от hash.
    // При одинаковых входах (ECDHE, transcript) L даёт те же значения, что S.
    // Все expected взяты из RFC 9367 Appendix A.1 — это настоящий KAT.
    //
    // ========================================================================

    // Input data from A.1
    private static final byte[] ECDHE = hex(
            "4DE60D21EA8FB9220D146423B490DA40CCEBC43BC589DB79B831A47D6B063007"
                    + "DD03405A1B7976B623DCAA69B011AE106E7E4174385F8626E121B5994363C99F");

    private static final byte[] HM1 = hex(
            "993BA722124AF3CBFD4771E7FAE32AC1D0E9278CF7843FCBC620E1A0085A87A1");

    private static final byte[] HM2 = hex(
            "9EBC5FBE32D9F40D48F8EECEBB6231A533C2C0EF243277B96D6F7AD3BBFD1494");

    private static final byte[] HM_FINISHED = hex(
            "03EC9B1D0B3741424572BAC9DF3AA52C03EFE9E958076943AFD85819BC602F46");

    // Expected from A.1
    private static final byte[] EARLY_SECRET = hex(
            "FBDEFBE527FEEA665AAB9277A2163B8343084FD191C46066260FAC6FD1436C72");

    private static final byte[] HANDSHAKE_SECRET = hex(
            "44245E2C4332D1F78B0F8D16F403EB69ED2A4053847CDC39FA8B3D2974F745E7");

    private static final byte[] MAIN_SECRET = hex(
            "31BB1D612CCD5332688A551A48CA250F24783D4AB0B4A76D3FE5067A2616A4A3");

    private static final byte[] SHTS = hex(
            "70A5F2463DF60DBAA2368B67FD45AEFF7C1A0BA42D8ABD72415ECD1D94E9EF54");
    private static final byte[] CHTS = hex(
            "B3F7113D3526554FE655E56FAB79B1A03DE33596E33088C7783719A9A4B0DCCD");
    private static final byte[] SATS = hex(
            "87734F4B4CFD17B97B834D822D9D7379F6F5E03B80B52AEB2AFF510EDD83DBD2");
    private static final byte[] CATS = hex(
            "8ACF746BEC31176CBD142C75806C270A0AEF6FC38E0D8FDCB5A88525363ADE81");

    private static final byte[] SWK_HS = hex(
            "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01");
    private static final byte[] SIV_HS = hex(
            "6969FFAAA4525281EEBBEB4CBD0B640E");
    private static final byte[] CWK_HS = hex(
            "581688D76EFE122BB55F62B38EF01BCC8C88DB83E9EA4D55D3898C53721FC384");
    private static final byte[] CIV_HS = hex(
            "439A07453D0BEA0C1D1BEB738EB5B8DD");

    private static final byte[] SWK_AP = hex(
            "475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C");
    private static final byte[] SIV_AP = hex(
            "AFE91F7118354026317E1AB4D82217B8");
    private static final byte[] CWK_AP = hex(
            "7BE64E2C12787B5B8C8756C43D92FAEF64F15A3A3C1081AD34BCA506F0322415");
    private static final byte[] CIV_AP = hex(
            "310957EF71314433F576CC9B00AD9354");

    private static final byte[] SERVER_VERIFY_DATA = hex(
            "E0BAA33614E069697E4DFAB071B9725773F8FE1A326A662D0F52309B45B6E031");
    private static final byte[] CLIENT_VERIFY_DATA = hex(
            "085FC7FD79B6D111CD8D3FF6B23A065A7AF7A6387342A5F3576814CD004719D2");

    @Test
    @DisplayName("Key schedule: L cipher suite даёт те же значения, что RFC 9367 A.1")
    void testKeyScheduleL_MatchesA1() {
        TlsKeySchedule ks = new TlsKeySchedule(CS_L);

        // 1. Early Secret (без PSK — одинаков для L и S)
        assertArrayEquals(EARLY_SECRET, ks.getEarlySecret(), "EarlySecret");

        // 2. Handshake Secret
        ks.deriveHandshakeSecret(ECDHE);

        // 3. Handshake traffic secrets
        assertArrayEquals(SHTS, ks.getServerHandshakeTrafficSecret(HM1), "SHTS");
        assertArrayEquals(CHTS, ks.getClientHandshakeTrafficSecret(HM1), "CHTS");

        // 4. Handshake traffic keys
        byte[] shSecret = ks.getServerHandshakeTrafficSecret(HM1);
        TlsTrafficKeys shKeys = ks.deriveTrafficKeys(shSecret);
        assertArrayEquals(SWK_HS, shKeys.getKey(), "server_write_key_hs");
        assertArrayEquals(SIV_HS, shKeys.getIv(), "server_write_iv_hs");
        TlsUtils.wipeArray(shSecret);
        shKeys.destroy();

        byte[] chSecret = ks.getClientHandshakeTrafficSecret(HM1);
        TlsTrafficKeys chKeys = ks.deriveTrafficKeys(chSecret);
        assertArrayEquals(CWK_HS, chKeys.getKey(), "client_write_key_hs");
        assertArrayEquals(CIV_HS, chKeys.getIv(), "client_write_iv_hs");
        TlsUtils.wipeArray(chSecret);
        chKeys.destroy();

        // 5. Master Secret
        ks.deriveMasterSecret();

        // 6. Application traffic keys
        byte[] saSecret = ks.getServerApplicationTrafficSecret(HM2);
        TlsTrafficKeys saKeys = ks.deriveTrafficKeys(saSecret);
        assertArrayEquals(SWK_AP, saKeys.getKey(), "server_write_key_ap");
        assertArrayEquals(SIV_AP, saKeys.getIv(), "server_write_iv_ap");
        TlsUtils.wipeArray(saSecret);
        saKeys.destroy();

        byte[] caSecret = ks.getClientApplicationTrafficSecret(HM2);
        TlsTrafficKeys caKeys = ks.deriveTrafficKeys(caSecret);
        assertArrayEquals(CWK_AP, caKeys.getKey(), "client_write_key_ap");
        assertArrayEquals(CIV_AP, caKeys.getIv(), "client_write_iv_ap");
        TlsUtils.wipeArray(caSecret);
        caKeys.destroy();

        // 7. Verify data (Finished keys are internal — проверяем через computeVerifyData)
        assertArrayEquals(SERVER_VERIFY_DATA,
                ks.computeVerifyData(SHTS, HM_FINISHED), "server verify_data");
        assertArrayEquals(CLIENT_VERIFY_DATA,
                ks.computeVerifyData(CHTS, HM2), "client verify_data");
    }

    // ========================================================================
    // Группа 2: TLSTREE-L regression tests
    //
    // Regression only. No external KAT for Kuznyechik_L TLSTREE constants.
    // Update only if external source (Росстандарт Р 1323565.1.030-2018 /
    // КриптоПро / gost-engine) provides verified vectors.
    // ========================================================================

    // Первичный прогон → эталон. ZERO_KEY, seq=0
    // Regression only. No external KAT for Kuznyechik_L TLSTREE constants.
    private static final byte[] TLSTREE_L_SEQ0 = hex(
            "F797256845F36CF075603445CD322BACC3834032BC425E4D3C8495236F7B6CAF");
    // Первичный прогон → эталон. ZERO_KEY, seq=1 (0&1&C3=0 → ключ как seq=0)
    private static final byte[] TLSTREE_L_SEQ1 = hex(
            "F797256845F36CF075603445CD322BACC3834032BC425E4D3C8495236F7B6CAF");
    // Первичный прогон → эталон. ZERO_KEY, seq=8191 (перед границей C3, &C3=0)
    private static final byte[] TLSTREE_L_C3_LO = hex(
            "F797256845F36CF075603445CD322BACC3834032BC425E4D3C8495236F7B6CAF");
    // Первичный прогон → эталон. ZERO_KEY, seq=8192 (после границы C3)
    private static final byte[] TLSTREE_L_C3_HI = hex(
            "122CB2B5124F0BE01357810FBD63F1BBE7A1C6D73A3DDD8CD20A861D536B5E04");
    // Первичный прогон → эталон. ZERO_KEY, seq=(1<<36)-1 (перед границей C2)
    private static final byte[] TLSTREE_L_C2_LO = hex(
            "9709B581503B455B944C0E0A254567D3FECB35393C4CE2541E2C746696977DE5");
    // Первичный прогон → эталон. ZERO_KEY, seq=1<<36 (после границы C2)
    private static final byte[] TLSTREE_L_C2_HI = hex(
            "79B473D5176DDD026BF683875C3D2536998FB40E70630501D12395713F2BFD6F");

    @Test
    @DisplayName("TLSTREE-L: ZERO_KEY, seq=0")
    void testTlstreeL_Seq0() {
        byte[] actual = TlsTree.deriveKey(ZERO_KEY, 0, C1_L, C2_L, C3_L, 32);
        assertArrayEquals(TLSTREE_L_SEQ0, actual,
                () -> "Seq=0: ожидал " + hexStr(TLSTREE_L_SEQ0) + ", получил " + hexStr(actual));
    }

    @Test
    @DisplayName("TLSTREE-L: ZERO_KEY, seq=1")
    void testTlstreeL_Seq1() {
        byte[] actual = TlsTree.deriveKey(ZERO_KEY, 1, C1_L, C2_L, C3_L, 32);
        assertArrayEquals(TLSTREE_L_SEQ1, actual,
                () -> "Seq=1: ожидал " + hexStr(TLSTREE_L_SEQ1) + ", получил " + hexStr(actual));
    }

    @Test
    @DisplayName("TLSTREE-L: граница C3 (seq=8191 vs seq=8192)")
    void testTlstreeL_C3Boundary() {
        byte[] lo = TlsTree.deriveKey(ZERO_KEY, 8191L, C1_L, C2_L, C3_L, 32);
        byte[] hi = TlsTree.deriveKey(ZERO_KEY, 8192L, C1_L, C2_L, C3_L, 32);
        assertArrayEquals(TLSTREE_L_C3_LO, lo,
                () -> "Seq=8191: ожидал " + hexStr(TLSTREE_L_C3_LO) + ", получил " + hexStr(lo));
        assertArrayEquals(TLSTREE_L_C3_HI, hi,
                () -> "Seq=8192: ожидал " + hexStr(TLSTREE_L_C3_HI) + ", получил " + hexStr(hi));
        assertNotEquals(lo, hi, "Ключи по разные стороны границы C3 должны различаться");
    }

    @Test
    @DisplayName("TLSTREE-L: граница C2 (seq=(1<<36)-1 vs seq=1<<36)")
    void testTlstreeL_C2Boundary() {
        long c2b = 1L << 36;
        byte[] lo = TlsTree.deriveKey(ZERO_KEY, c2b - 1, C1_L, C2_L, C3_L, 32);
        byte[] hi = TlsTree.deriveKey(ZERO_KEY, c2b, C1_L, C2_L, C3_L, 32);
        assertArrayEquals(TLSTREE_L_C2_LO, lo,
                () -> "Seq=C2-1: ожидал " + hexStr(TLSTREE_L_C2_LO) + ", получил " + hexStr(lo));
        assertArrayEquals(TLSTREE_L_C2_HI, hi,
                () -> "Seq=C2: ожидал " + hexStr(TLSTREE_L_C2_HI) + ", получил " + hexStr(hi));
        assertNotEquals(lo, hi, "Ключи по разные стороны границы C2 должны различаться");
    }

    // ========================================================================
    // Группа 3: Cross-check L vs S
    // ========================================================================

    @Test
    @DisplayName("TLSTREE: seq=0 — L и S одинаковы (0 & любая маска = 0)")
    void testTlstreeL_Seq0_Equals_S_Seq0() {
        byte[] l = TlsTree.deriveKey(ZERO_KEY, 0, C1_L, C2_L, C3_L, 32);
        byte[] s = TlsTree.deriveKey(ZERO_KEY, 0, C1_S, C2_S, C3_S, 32);
        assertArrayEquals(l, s, "seq=0: L и S должны давать одинаковый ключ");
    }

    @Test
    @DisplayName("TLSTREE: seq=1<<35 — L и S различаются (L.C1 обнуляет, S.C1 сохраняет)")
    void testTlstreeL_SeqN_NotEquals_S_SeqN() {
        long n = 1L << 35;
        // L.C1 = 0xF800000000000000 — бит 35 < 59 → маскирует seqNum полностью → 0
        // S.C1 = 0xFFFFFFFFE0000000 — бит 35 >= 29 → seqNum & C1 = seqNum
        byte[] l = TlsTree.deriveKey(ZERO_KEY, n, C1_L, C2_L, C3_L, 32);
        byte[] s = TlsTree.deriveKey(ZERO_KEY, n, C1_S, C2_S, C3_S, 32);
        assertNotEquals(l, s, "seq=2^35: L и S должны давать разные ключи");
    }

    // ========================================================================
    // Группа 4: AEAD запись с per-record ключом от TLSTREE-L
    //
    // Regression only — no external KAT for Kuznyechik_L AEAD.
    // Используем server handshake key из A.1, но TLSTREE-L для per-record key.
    // ========================================================================

    // Первичный прогон → эталон (seq=0 → perRecordKey и ciphertext совпадают с A.1)
    // Regression only. No external KAT for Kuznyechik_L AEAD.
    private static final byte[] L_EE_CIPHERTEXT = hex("940E5D2C753AE5");

    @Test
    @DisplayName("EncryptedExtensions (seq=0): per-record ключ от TLSTREE-L")
    void testL_EncryptedExtensionsRecord() {
        // 1. Per-record ключ через TLSTREE-L (отличается от S!)
        byte[] perRecordKey = TlsTree.deriveKey(
                SWK_HS, 0, C1_L, C2_L, C3_L, 32);

        // 2. Nonce = server_write_iv_hs с MSB cleared (seq=0 → nonce не XORится с 0)
        byte[] nonce = SIV_HS.clone();
        nonce[0] &= 0x7F;

        // 3. AAD: outer_type(23) || legacy_version(0x0303) || payload_len
        byte[] plaintext = new byte[]{0x08, 0x00, 0x00, 0x02, 0x00, 0x00, TlsConstants.CT_HANDSHAKE};
        byte[] aad = new byte[]{TlsConstants.CT_APPLICATION_DATA,
                TlsConstants.LEGACY_VERSION_MAJOR, TlsConstants.LEGACY_VERSION_MINOR,
                0x00, (byte) (plaintext.length + 16)};

        // 4. MGM-Encrypt
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(perRecordKey), nonce));
        mgm.updateAAD(aad, 0, aad.length);
        byte[] ciphertext = new byte[plaintext.length];
        mgm.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        byte[] tag = new byte[16];
        mgm.finishEncryption(tag, 0);

        assertArrayEquals(L_EE_CIPHERTEXT, ciphertext,
                () -> "Ожидал " + hexStr(L_EE_CIPHERTEXT) + ", получил " + hexStr(ciphertext));
    }

    // ========================================================================
    // Группа 4b: AEAD на границе C3 (seq=8192) — реальные handshake ключи
    //
    // TLSTREE-L на seq=8192 пересекает границу C3, поэтому per-record ключ
    // отличается от SWK_HS. Проверяет интеграцию TLSTREE → MGM на не-нулевом
    // уровне дерева. Первичный прогон → эталон.
    // ========================================================================

    private static final byte[] L_EE_CIPHERTEXT_SEQ8192 = hex("E5A3C309430309");
    private static final byte[] L_EE_TAG_SEQ8192 = hex("2F0A278493FD384D568EF8FA4F6B9712");

    @Test
    @DisplayName("EncryptedExtensions (seq=8192): per-record ключ от TLSTREE-L, граница C3")
    void testL_EncryptedExtensionsRecord_Seq8192() {
        // 1. Per-record ключ через TLSTREE-L на seq=8192 (первое пересечение C3)
        byte[] perRecordKey = TlsTree.deriveKey(
                SWK_HS, 8192L, C1_L, C2_L, C3_L, 32);

        // 2. Nonce = IV XOR seqNum (big-endian), затем MSB cleared
        byte[] nonce = SIV_HS.clone();
        nonce[14] ^= 0x20;
        nonce[0] &= 0x7F;

        // 3. Те же plaintext и aad, что в testL_EncryptedExtensionsRecord
        byte[] plaintext = new byte[]{0x08, 0x00, 0x00, 0x02, 0x00, 0x00, TlsConstants.CT_HANDSHAKE};
        byte[] aad = new byte[]{TlsConstants.CT_APPLICATION_DATA,
                TlsConstants.LEGACY_VERSION_MAJOR, TlsConstants.LEGACY_VERSION_MINOR,
                0x00, (byte) (plaintext.length + 16)};

        // 4. MGM-Encrypt
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(perRecordKey), nonce));
        mgm.updateAAD(aad, 0, aad.length);
        byte[] ciphertext = new byte[plaintext.length];
        mgm.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        byte[] tag = new byte[16];
        mgm.finishEncryption(tag, 0);

        assertArrayEquals(L_EE_CIPHERTEXT_SEQ8192, ciphertext, () ->
                "C3 seq=8192 ct: ожидал " + hexStr(L_EE_CIPHERTEXT_SEQ8192) + ", получил " + hexStr(ciphertext));
        assertArrayEquals(L_EE_TAG_SEQ8192, tag, () ->
                "C3 seq=8192 tag: ожидал " + hexStr(L_EE_TAG_SEQ8192) + ", получил " + hexStr(tag));
    }
}
