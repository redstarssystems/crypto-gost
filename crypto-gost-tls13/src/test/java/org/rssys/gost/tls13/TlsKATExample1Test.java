package org.rssys.gost.tls13;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.psk.*;
import org.rssys.gost.tls13.crypto.*;
import org.rssys.gost.tls13.config.*;
import org.rssys.gost.tls13.cert.*;
import org.rssys.gost.tls13.record.*;
import org.rssys.gost.tls13.message.*;
import org.rssys.gost.tls13.engine.*;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsTestHelper.hex;
import static org.rssys.gost.tls13.TlsTestHelper.hexStr;

/**
 * Known Answer Tests из RFC 9367 Appendix A.1.
 * <p>
 * Полный TLS handshake с TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S (0xC105)
 * на кривой GC512C, аутентификация сервера по gostr34102012_256b.
 * <p>
 * Все hex-значения из RFC 9367, раздел A.1.2.
 */
public class TlsKATExample1Test {

    // hex/hexStr утилиты вынесены в TlsTestHelper

    // ========================================================================
    // Исходные данные (RFC 9367 A.1.2)
    // ========================================================================

    // ECDHE общий секрет — X-координата в LE, 64 байта для GC512C
    private static final byte[] ECDHE = hex(
            "4DE60D21EA8FB9220D146423B490DA40CCEBC43BC589DB79B831A47D6B063007"
                    + "DD03405A1B7976B623DCAA69B011AE106E7E4174385F8626E121B5994363C99F");

    // Transcript-Hash HM1 = Hash(ClientHello || ServerHello)
    private static final byte[] HM1 = hex(
            "993BA722124AF3CBFD4771E7FAE32AC1D0E9278CF7843FCBC620E1A0085A87A1");

    // Transcript-Hash HM2 = Hash(ClientHello..Server Finished)
    private static final byte[] HM2 = hex(
            "9EBC5FBE32D9F40D48F8EECEBB6231A533C2C0EF243277B96D6F7AD3BBFD1494");

    // Hash("") для Derive-Secret с пустыми сообщениями
    private static final byte[] EMPTY_HASH = hex(
            "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB");

    // ========================================================================
    // Ожидаемые выходы (RFC 9367 A.1.2)
    // ========================================================================

    // Шаг 1: EarlySecret = HKDF-Extract(0^32, 0^32)
    private static final byte[] EARLY_SECRET = hex(
            "FBDEFBE527FEEA665AAB9277A2163B8343084FD191C46066260FAC6FD1436C72");

    // Derive-Secret(EarlySecret, "derived", "")
    private static final byte[] DERIVED_0 = hex(
            "DBC3C826D877A3B7D2D2453DBFDC6CFBFB1151B3E84F0C8F26011D8D5BF3EDF7");

    // Шаг 2: HandshakeSecret = HKDF-Extract(Derived0, ECDHE)
    private static final byte[] HANDSHAKE_SECRET = hex(
            "44245E2C4332D1F78B0F8D16F403EB69ED2A4053847CDC39FA8B3D2974F745E7");

    // Derive-Secret(HandshakeSecret, "derived", "")
    private static final byte[] DERIVED_1 = hex(
            "EA3C54BBD14EF9D750776FABE395BE2ABDDBBBB71C13C2BD609E3515794AFA02");

    // Шаг 3: MainSecret = HKDF-Extract(Derived1, 0^32)
    private static final byte[] MAIN_SECRET = hex(
            "31BB1D612CCD5332688A551A48CA250F24783D4AB0B4A76D3FE5067A2616A4A3");

    // Traffic secrets (Derive-Secret от HandshakeSecret / MainSecret)
    private static final byte[] SHTS = hex(
            "70A5F2463DF60DBAA2368B67FD45AEFF7C1A0BA42D8ABD72415ECD1D94E9EF54");
    private static final byte[] CHTS = hex(
            "B3F7113D3526554FE655E56FAB79B1A03DE33596E33088C7783719A9A4B0DCCD");
    private static final byte[] SATS = hex(
            "87734F4B4CFD17B97B834D822D9D7379F6F5E03B80B52AEB2AFF510EDD83DBD2");
    private static final byte[] CATS = hex(
            "8ACF746BEC31176CBD142C75806C270A0AEF6FC38E0D8FDCB5A88525363ADE81");

    // Finished keys (HKDF-Expand-Label от traffic secret, "finished", "")
    private static final byte[] SERVER_FINISHED_KEY = hex(
            "53F1C0388F8A70C0BCA0DD21A030F2381C3437CD0E7EC93D0A965E25632DD79A");
    private static final byte[] CLIENT_FINISHED_KEY = hex(
            "2F21548CF5277869AE490DE7BC15ACE639F657E3582A5A634B0A915695D54C42");

    // Handshake write keys/IVs (HKDF-Expand-Label от SHTS/CHTS)
    private static final byte[] SWK_HS = hex(
            "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01");
    private static final byte[] SIV_HS = hex(
            "6969FFAAA4525281EEBBEB4CBD0B640E");
    private static final byte[] CWK_HS = hex(
            "581688D76EFE122BB55F62B38EF01BCC8C88DB83E9EA4D55D3898C53721FC384");
    private static final byte[] CIV_HS = hex(
            "439A07453D0BEA0C1D1BEB738EB5B8DD");

    // Application write keys/IVs (HKDF-Expand-Label от SATS/CATS)
    private static final byte[] SWK_AP = hex(
            "475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C");
    private static final byte[] SIV_AP = hex(
            "AFE91F7118354026317E1AB4D82217B8");
    private static final byte[] CWK_AP = hex(
            "7BE64E2C12787B5B8C8756C43D92FAEF64F15A3A3C1081AD34BCA506F0322415");
    private static final byte[] CIV_AP = hex(
            "310957EF71314433F576CC9B00AD9354");

    // ========================================================================
    // Фаза 1: HKDF (RFC 5869 + RFC 8446 §7.1)
    // ========================================================================

    // ---- HKDF-Extract ----

    @Test
    @DisplayName("EarlySecret = HKDF-Extract(0^32, 0^32)")
    void testEarlySecret() {
        byte[] salt = new byte[32];
        byte[] ikm = new byte[32];
        byte[] actual = HkdfStreebog.extract(salt, ikm, 32);
        assertArrayEquals(EARLY_SECRET, actual);
    }

    @Test
    @DisplayName("HandshakeSecret = HKDF-Extract(Derived0, ECDHE)")
    void testHandshakeSecret() {
        byte[] actual = HkdfStreebog.extract(DERIVED_0, ECDHE, 32);
        assertArrayEquals(HANDSHAKE_SECRET, actual);
    }

    @Test
    @DisplayName("MainSecret = HKDF-Extract(Derived1, 0^32)")
    void testMainSecret() {
        byte[] salt = DERIVED_1;
        byte[] ikm = new byte[32];
        byte[] actual = HkdfStreebog.extract(salt, ikm, 32);
        assertArrayEquals(MAIN_SECRET, actual);
    }

    // ---- Derive-Secret (для derived и traffic secrets) ----

    @Test
    @DisplayName("Derived #0 = Derive-Secret(EarlySecret, \"derived\", Hash(\"\"))")
    void testDerived0() {
        byte[] actual = HkdfStreebog.deriveSecret(
                EARLY_SECRET, "derived", EMPTY_HASH, 32);
        assertArrayEquals(DERIVED_0, actual);
    }

    @Test
    @DisplayName("Derived #1 = Derive-Secret(HandshakeSecret, \"derived\", Hash(\"\"))")
    void testDerived1() {
        byte[] actual = HkdfStreebog.deriveSecret(
                HANDSHAKE_SECRET, "derived", EMPTY_HASH, 32);
        assertArrayEquals(DERIVED_1, actual);
    }

    @Test
    @DisplayName("server_handshake_traffic_secret = Derive-Secret(HS, \"s hs traffic\", HM1)")
    void testServerHandshakeTrafficSecret() {
        byte[] actual = HkdfStreebog.deriveSecret(
                HANDSHAKE_SECRET, "s hs traffic", HM1, 32);
        assertArrayEquals(SHTS, actual);
    }

    @Test
    @DisplayName("client_handshake_traffic_secret = Derive-Secret(HS, \"c hs traffic\", HM1)")
    void testClientHandshakeTrafficSecret() {
        byte[] actual = HkdfStreebog.deriveSecret(
                HANDSHAKE_SECRET, "c hs traffic", HM1, 32);
        assertArrayEquals(CHTS, actual);
    }

    @Test
    @DisplayName("server_application_traffic_secret = Derive-Secret(MS, \"s ap traffic\", HM2)")
    void testServerAppTrafficSecret() {
        byte[] actual = HkdfStreebog.deriveSecret(
                MAIN_SECRET, "s ap traffic", HM2, 32);
        assertArrayEquals(SATS, actual);
    }

    @Test
    @DisplayName("client_application_traffic_secret = Derive-Secret(MS, \"c ap traffic\", HM2)")
    void testClientAppTrafficSecret() {
        byte[] actual = HkdfStreebog.deriveSecret(
                MAIN_SECRET, "c ap traffic", HM2, 32);
        assertArrayEquals(CATS, actual);
    }

    // ---- HKDF-Expand-Label (finished keys, record keys/IVs) ----

    @Test
    @DisplayName("server_finished_key = HKDF-Expand-Label(SHTS, \"finished\", \"\", 32)")
    void testServerFinishedKey() {
        byte[] actual = HkdfStreebog.expandLabel(
                SHTS, "finished", new byte[0], 32, 32);
        assertArrayEquals(SERVER_FINISHED_KEY, actual);
    }

    @Test
    @DisplayName("client_finished_key = HKDF-Expand-Label(CHTS, \"finished\", \"\", 32)")
    void testClientFinishedKey() {
        byte[] actual = HkdfStreebog.expandLabel(
                CHTS, "finished", new byte[0], 32, 32);
        assertArrayEquals(CLIENT_FINISHED_KEY, actual);
    }

    @Test
    @DisplayName("server_write_key_hs = HKDF-Expand-Label(SHTS, \"key\", \"\", 32)")
    void testServerHandshakeWriteKey() {
        byte[] actual = HkdfStreebog.expandLabel(
                SHTS, "key", new byte[0], 32, 32);
        assertArrayEquals(SWK_HS, actual);
    }

    @Test
    @DisplayName("server_write_iv_hs = HKDF-Expand-Label(SHTS, \"iv\", \"\", 16)")
    void testServerHandshakeWriteIv() {
        byte[] actual = HkdfStreebog.expandLabel(
                SHTS, "iv", new byte[0], 16, 32);
        assertArrayEquals(SIV_HS, actual);
    }

    @Test
    @DisplayName("client_write_key_hs = HKDF-Expand-Label(CHTS, \"key\", \"\", 32)")
    void testClientHandshakeWriteKey() {
        byte[] actual = HkdfStreebog.expandLabel(
                CHTS, "key", new byte[0], 32, 32);
        assertArrayEquals(CWK_HS, actual);
    }

    @Test
    @DisplayName("client_write_iv_hs = HKDF-Expand-Label(CHTS, \"iv\", \"\", 16)")
    void testClientHandshakeWriteIv() {
        byte[] actual = HkdfStreebog.expandLabel(
                CHTS, "iv", new byte[0], 16, 32);
        assertArrayEquals(CIV_HS, actual);
    }

    @Test
    @DisplayName("server_write_key_ap = HKDF-Expand-Label(SATS, \"key\", \"\", 32)")
    void testServerAppWriteKey() {
        byte[] actual = HkdfStreebog.expandLabel(
                SATS, "key", new byte[0], 32, 32);
        assertArrayEquals(SWK_AP, actual);
    }

    @Test
    @DisplayName("server_write_iv_ap = HKDF-Expand-Label(SATS, \"iv\", \"\", 16)")
    void testServerAppWriteIv() {
        byte[] actual = HkdfStreebog.expandLabel(
                SATS, "iv", new byte[0], 16, 32);
        assertArrayEquals(SIV_AP, actual);
    }

    @Test
    @DisplayName("client_write_key_ap = HKDF-Expand-Label(CATS, \"key\", \"\", 32)")
    void testClientAppWriteKey() {
        byte[] actual = HkdfStreebog.expandLabel(
                CATS, "key", new byte[0], 32, 32);
        assertArrayEquals(CWK_AP, actual);
    }

    @Test
    @DisplayName("client_write_iv_ap = HKDF-Expand-Label(CATS, \"iv\", \"\", 16)")
    void testClientAppWriteIv() {
        byte[] actual = HkdfStreebog.expandLabel(
                CATS, "iv", new byte[0], 16, 32);
        assertArrayEquals(CIV_AP, actual);
    }

    // ========================================================================
    // Фаза 2: TLSTREE (RFC 9367 §4.1.2)
    // ========================================================================

    // TLSTREE-ключи для серверных handshake-записей (root = SWK_HS)
    // C1/C2/C3 для KUZNYECHIK_MGM_S
    private static final long C1 =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getC1();
    private static final long C2 =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getC2();
    private static final long C3 =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getC3();

    // Ожидаемые TLSTREE-выходы
    // server handshake, seqNum 0 (root = SWK_HS)
    private static final byte[] TLSTREE_SRV_HS_0 = hex(
            "56EE1813727249C9DCDF3513787EDB93DF62C61EE7B126C50F26C0AAAF AE00E1"
                    .replaceAll("\\s+", ""));
    // server application, seqNum 0 (root = SWK_AP)
    private static final byte[] TLSTREE_SRV_AP_0 = hex(
            "C8FC93D7C586F2B0A3101BAA6A979E4E3886706551E81187E97880409C7E8EE9");
    // server application, seqNum 8 (root = SWK_AP, меняется на уровне 3)
    private static final byte[] TLSTREE_SRV_AP_8 = hex(
            "D3CD87D5687407823978344C06B928A85898B739A31D3DE5FF2B788EF39196ED");
    // client handshake, seqNum 0 (root = CWK_HS)
    private static final byte[] TLSTREE_CLI_HS_0 = hex(
            "E1C59B4169D896107F78456893A3751E1573543DAD8CB74069E6814A513BBB1C");
    // client application, seqNum 0 (root = CWK_AP)
    private static final byte[] TLSTREE_CLI_AP_0 = hex(
            "D49A571549E748949FA24B8834232CA875D37A26C4BB5C62A261DAB372650526");
    // client application, seqNum 8 (root = CWK_AP)
    private static final byte[] TLSTREE_CLI_AP_8 = hex(
            "B82D7825D15FAE18A7013228B31CB0C59752C6409C5F7899ECC6950F7463C090");

    @Test
    @DisplayName("TLSTREE: server handshake seqNum=0")
    void testTlstreeServerHandshakeSeq0() {
        byte[] actual = TlsTree.deriveKey(SWK_HS, 0, C1, C2, C3, 32);
        assertArrayEquals(TLSTREE_SRV_HS_0, actual,
                () -> "Ожидал " + hexStr(TLSTREE_SRV_HS_0) + ", получил " + hexStr(actual));
    }

    @Test
    @DisplayName("TLSTREE: server application seqNum=0")
    void testTlstreeServerAppSeq0() {
        byte[] actual = TlsTree.deriveKey(SWK_AP, 0, C1, C2, C3, 32);
        assertArrayEquals(TLSTREE_SRV_AP_0, actual);
    }

    @Test
    @DisplayName("TLSTREE: server application seqNum=8 (C3 меняет вывод)")
    void testTlstreeServerAppSeq8() {
        byte[] actual = TlsTree.deriveKey(SWK_AP, 8, C1, C2, C3, 32);
        assertArrayEquals(TLSTREE_SRV_AP_8, actual);
    }

    @Test
    @DisplayName("TLSTREE: seqNum=0 и seqNum=1 дают одинаковый ключ (C1 маскирует)")
    void testTlstreeServerAppSeq0Equals1() {
        byte[] k0 = TlsTree.deriveKey(SWK_AP, 0, C1, C2, C3, 32);
        byte[] k1 = TlsTree.deriveKey(SWK_AP, 1, C1, C2, C3, 32);
        assertArrayEquals(k0, k1);
    }

    @Test
    @DisplayName("TLSTREE: client handshake seqNum=0")
    void testTlstreeClientHandshakeSeq0() {
        byte[] actual = TlsTree.deriveKey(CWK_HS, 0, C1, C2, C3, 32);
        assertArrayEquals(TLSTREE_CLI_HS_0, actual);
    }

    @Test
    @DisplayName("TLSTREE: client application seqNum=0")
    void testTlstreeClientAppSeq0() {
        byte[] actual = TlsTree.deriveKey(CWK_AP, 0, C1, C2, C3, 32);
        assertArrayEquals(TLSTREE_CLI_AP_0, actual);
    }

    @Test
    @DisplayName("TLSTREE: client application seqNum=8")
    void testTlstreeClientAppSeq8() {
        byte[] actual = TlsTree.deriveKey(CWK_AP, 8, C1, C2, C3, 32);
        assertArrayEquals(TLSTREE_CLI_AP_8, actual);
    }

    // ========================================================================
    // Фаза 3: Finished verify_data (RFC 8446 §4.4.4)
    // ========================================================================

    // Transcript-Hash HMFinished = Hash(ClientHello..CertificateVerify)
    private static final byte[] HM_FINISHED = hex(
            "03EC9B1D0B3741424572BAC9DF3AA52C03EFE9E958076943AFD85819BC602F46");

    // Server Finished verify_data = HMAC(server_finished_key, HM_FINISHED)
    private static final byte[] SERVER_VERIFY_DATA = hex(
            "E0BAA33614E069697E4DFAB071B9725773F8FE1A326A662D0F52309B45B6E031");

    // Client Finished verify_data = HMAC(client_finished_key, TH2)
    private static final byte[] CLIENT_VERIFY_DATA = hex(
            "085FC7FD79B6D111CD8D3FF6B23A065A7AF7A6387342A5F3576814CD004719D2");

    @Test
    @DisplayName("verify_data сервера = HMAC(server_finished_key, HMFinished)")
    void testServerVerifyData() {
        org.rssys.gost.mac.Hmac hmac = new org.rssys.gost.mac.Hmac(
                new org.rssys.gost.digest.Streebog256());
        hmac.init(SERVER_FINISHED_KEY);
        hmac.update(HM_FINISHED, 0, HM_FINISHED.length);
        byte[] actual = new byte[32];
        hmac.doFinal(actual, 0);
        hmac.clear();
        assertArrayEquals(SERVER_VERIFY_DATA, actual);
    }

    @Test
    @DisplayName("verify_data клиента = HMAC(client_finished_key, HM2)")
    void testClientVerifyData() {
        org.rssys.gost.mac.Hmac hmac = new org.rssys.gost.mac.Hmac(
                new org.rssys.gost.digest.Streebog256());
        hmac.init(CLIENT_FINISHED_KEY);
        hmac.update(HM2, 0, HM2.length);
        byte[] actual = new byte[32];
        hmac.doFinal(actual, 0);
        hmac.clear();
        assertArrayEquals(CLIENT_VERIFY_DATA, actual);
    }

    // ========================================================================
    // Фаза 4: MGM record encryption (RFC 9367 §4.1.1)
    // ========================================================================

    // Ожидаемый ciphertext для EncryptedExtensions (seqNum=0, handshake key)
    // protect(CT_HANDSHAKE, {0x08,0x00,0x00,0x02,0x00,0x00})
    private static final byte[] EE_CIPHERTEXT = hex(
            "940E5D2C753AE5");

    @Test
    @DisplayName("EncryptedExtensions (seqNum=0): защита записи по RFC")
    void testEncryptedExtensionsRecord() {
        // 1. Per-record ключ через TLSTREE (RFC 9367 §4.1)
        byte[] perRecordKey = TlsTree.deriveKey(
                SWK_HS, 0, C1, C2, C3, TlsConstants.KUZNYECHIK_KEY_SIZE);

        // 2. Nonce = sender_write_iv XOR seqNum (RFC 8446 §5.3)
        //    Для seqNum=0: nonce = SIV_HS с MSB cleared
        byte[] nonce = SIV_HS.clone();
        nonce[0] &= 0x7F;

        // 3. AAD: outer_type(23) || legacy_version(0x0303) || payload_len(23)
        byte[] plaintext = new byte[]{0x08, 0x00, 0x00, 0x02, 0x00, 0x00, TlsConstants.CT_HANDSHAKE};
        byte[] aad = new byte[]{TlsConstants.CT_APPLICATION_DATA,
                TlsConstants.LEGACY_VERSION_MAJOR, TlsConstants.LEGACY_VERSION_MINOR,
                0x00, (byte) (plaintext.length + TlsConstants.MGM_TAG_SIZE)};

        // 4. MGM-Encrypt
        org.rssys.gost.cipher.mode.Mgm mgm = new org.rssys.gost.cipher.mode.Mgm(
                new org.rssys.gost.cipher.Kuznyechik());
        mgm.init(true, new org.rssys.gost.cipher.ParametersWithIV(
                new org.rssys.gost.cipher.SymmetricKey(perRecordKey), nonce));
        mgm.updateAAD(aad, 0, aad.length);
        byte[] ciphertext = new byte[plaintext.length];
        mgm.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        byte[] tag = new byte[TlsConstants.MGM_TAG_SIZE];
        mgm.finishEncryption(tag, 0);

        assertArrayEquals(EE_CIPHERTEXT, ciphertext,
                () -> "Ожидал " + hexStr(EE_CIPHERTEXT) + ", получил " + hexStr(ciphertext));
    }

    // ========================================================================
    // Фаза 5: Полный key schedule chain (RFC 9367 Appendix A.1, §3.3/§7.1)
    // ========================================================================

    @Test
    @DisplayName("Full key schedule chain: все outputs совпадают с RFC 9367")
    void testFullKeyScheduleChain() {
        TlsCiphersuite cs =
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
        TlsKeySchedule ks = new TlsKeySchedule(cs);

        // 1. Early Secret = HKDF-Extract(0^32, 0^32)
        assertArrayEquals(EARLY_SECRET, ks.getEarlySecret(),
                "EarlySecret");

        // 2. Handshake Secret = HKDF-Extract(Derive-Secret(early, \"derived\", \"\"), ECDHE)
        ks.deriveHandshakeSecret(ECDHE);

        // 3. Handshake traffic secrets
        assertArrayEquals(SHTS, ks.getServerHandshakeTrafficSecret(HM1),
                "SHTS");
        assertArrayEquals(CHTS, ks.getClientHandshakeTrafficSecret(HM1),
                "CHTS");

        // 4. Handshake traffic keys (key + IV)
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

        // 5. Master Secret = HKDF-Extract(Derive-Secret(hs, \"derived\", \"\"), 0^32)
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

        // 7. Finished verify_data
        assertArrayEquals(SERVER_VERIFY_DATA,
                ks.computeVerifyData(SHTS, HM_FINISHED),
                "server verify_data");
        assertArrayEquals(CLIENT_VERIFY_DATA,
                ks.computeVerifyData(CHTS, HM2),
                "client verify_data");
    }

    // ========================================================================
    // Фаза 6: ECDHE shared secret (RFC 9367 §6.1.1)
    // ========================================================================

    // Example 2: GC256B, d_C = 0x02×32
    private static final BigInteger D_C_GC256B = new BigInteger(
            1, hex("0202020202020202020202020202020202020202020202020202020202020202"));

    // Q_S для GC256B (LE X || LE Y, 64 байта)
    private static final byte[] Q_S_LE_GC256B = hex(
            "3D2FB067E106CC9980FB8842811164BA708BBB5038D5EDFBEE1D5E5DFBE6F74F"
                    + "1931217C67C2BDF46253DB9CE3487241F2DBD84E2DABDF65455851B0B19AEFEC");

    // Пример 2: ожидаемый ECDHE shared secret (LE X, 32 байта)
    private static final byte[] ECDHE_GC256B = hex(
            "985A8659D55A8D48E0E6771396580B2CDCDA37E92AEE1814D10E1BF2A44F0D24");
    @Test
    @DisplayName("ECDHE shared secret: Example 2, GC256B")
    void testEcdheExample2() throws Exception {
        int hlen = 32;
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters clientPriv = new PrivateKeyParameters(D_C_GC256B, params);

        byte[] xLe = new byte[hlen];
        byte[] yLe = new byte[hlen];
        System.arraycopy(Q_S_LE_GC256B, 0, xLe, 0, hlen);
        System.arraycopy(Q_S_LE_GC256B, hlen, yLe, 0, hlen);
        byte[] xBe = org.rssys.gost.util.Pack.reverseBytes(xLe);
        byte[] yBe = org.rssys.gost.util.Pack.reverseBytes(yLe);
        ECPoint serverQ = ECPoint.affine(
                new BigInteger(1, xBe), new BigInteger(1, yBe), params);
        PublicKeyParameters serverPub = new PublicKeyParameters(serverQ, params);

        byte[] shared = computeEcdheShared(
                clientPriv, serverPub, hlen);
        assertArrayEquals(ECDHE_GC256B, shared,
                () -> "Ожидал " + hexStr(ECDHE_GC256B) + ", получил " + hexStr(shared));
    }

    // Локальная копия метода, удалённого из TlsEncoding при реструктуризации
    private static byte[] computeEcdheShared(PrivateKeyParameters myPriv,
                                              PublicKeyParameters peerPub,
                                              int hashLen) throws Exception {
        org.rssys.gost.signature.ECPoint shared = peerPub.getQ().multiply(myPriv.getD());
        shared = shared.normalize();
        if (shared.isInfinity()) {
            throw new TlsException(TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "ECDHE shared secret is point at infinity");
        }
        java.math.BigInteger x = shared.getX();
        byte[] xRawBe = toFixedLengthBytes(x, hashLen);
        byte[] xRawLe = org.rssys.gost.util.Pack.reverseBytes(xRawBe);
        return xRawLe;
    }

    private static byte[] toFixedLengthBytes(java.math.BigInteger value, int len) {
        byte[] raw = value.toByteArray();
        if (raw.length == len) return raw;
        byte[] result = new byte[len];
        if (raw.length < len) {
            System.arraycopy(raw, 0, result, len - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - len, result, 0, len);
        }
        return result;
    }
}
