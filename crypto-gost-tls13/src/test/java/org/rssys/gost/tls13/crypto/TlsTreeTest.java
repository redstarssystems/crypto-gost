package org.rssys.gost.tls13.crypto;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsCiphersuite.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.*;

@DisplayName("TLSTREE — ре-кейинг (RFC 9367 §4.2)")
class TlsTreeTest {

    private static final byte[] ZERO_KEY = new byte[32];

    private static TlsCiphersuite csL() {
        return TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsCiphersuite csS() {
        return TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
    }

    @Test
    @DisplayName("deriveKey: возвращает 32 байта для L")
    void testDeriveKeyLengthL() {
        byte[] key =
                TlsTree.deriveKey(
                        ZERO_KEY,
                        0,
                        csL().getC1(),
                        csL().getC2(),
                        csL().getC3(),
                        csL().getKeyLen());
        assertEquals(32, key.length);
    }

    @Test
    @DisplayName("deriveKey: детерминизм")
    void testDeriveKeyDeterminism() {
        TlsCiphersuite cs = csL();
        byte[] k1 =
                TlsTree.deriveKey(ZERO_KEY, 42, cs.getC1(), cs.getC2(), cs.getC3(), cs.getKeyLen());
        byte[] k2 =
                TlsTree.deriveKey(ZERO_KEY, 42, cs.getC1(), cs.getC2(), cs.getC3(), cs.getKeyLen());
        assertArrayEquals(k1, k2);
    }

    @Test
    @DisplayName("deriveKey: разные seqNum дают разные ключи")
    void testDeriveKeyDifferentSeqNum() {
        TlsCiphersuite cs = csL();
        // seqNum=0 и seqNum с битом 59 (C1 = 0xf800...) дают разный K_1
        byte[] k0 =
                TlsTree.deriveKey(ZERO_KEY, 0L, cs.getC1(), cs.getC2(), cs.getC3(), cs.getKeyLen());
        byte[] k1 =
                TlsTree.deriveKey(
                        ZERO_KEY,
                        0x0800000000000000L,
                        cs.getC1(),
                        cs.getC2(),
                        cs.getC3(),
                        cs.getKeyLen());
        assertFalse(Arrays.equals(k0, k1));
    }

    @Test
    @DisplayName("deriveKey: разные startKey дают разные ключи")
    void testDeriveKeyDifferentStartKeys() {
        TlsCiphersuite cs = csL();
        byte[] sk2 = new byte[32];
        sk2[0] = 1;
        assertFalse(
                Arrays.equals(
                        TlsTree.deriveKey(
                                ZERO_KEY, 0, cs.getC1(), cs.getC2(), cs.getC3(), cs.getKeyLen()),
                        TlsTree.deriveKey(
                                sk2, 0, cs.getC1(), cs.getC2(), cs.getC3(), cs.getKeyLen())));
    }

    @Test
    @DisplayName("L и S константы дают разные ключи")
    void testLvsS() {
        TlsCiphersuite csL = csL();
        TlsCiphersuite csS = csS();
        // seqNum=0 для обеих масок даёт 0 на всех уровнях -> ключи совпадут.
        // Выбираем seqNum=1L<<32: L C1=0xf8... (маска 63:59) не затрагивается,
        // S C1=0xff...e0 (маска 63:29) затрагивается -> разные K_1.
        long seqNum = 1L << 32;
        byte[] keyL =
                TlsTree.deriveKey(
                        ZERO_KEY, seqNum, csL.getC1(), csL.getC2(), csL.getC3(), csL.getKeyLen());
        byte[] keyS =
                TlsTree.deriveKey(
                        ZERO_KEY, seqNum, csS.getC1(), csS.getC2(), csS.getC3(), csS.getKeyLen());
        assertFalse(Arrays.equals(keyL, keyS));
    }

    @Test
    @DisplayName("deriveKey: seqNum с одинаковой маской level-1, разной level-2")
    void testTreeLevels() {
        TlsCiphersuite cs = csL();
        long c1 = cs.getC1(); // 0xf800000000000000
        long c2 = cs.getC2(); // 0xfffffff000000000
        long c3 = cs.getC3(); // 0xffffffffffffe000
        // seq0 = 0, seq1 = 1L << 60 (влияет на level-1, т.к. маска 0xf8...)
        long seq0 = 0L;
        long seq1 = 1L << 60;
        byte[] k0 = TlsTree.deriveKey(ZERO_KEY, seq0, c1, c2, c3, cs.getKeyLen());
        byte[] k1 = TlsTree.deriveKey(ZERO_KEY, seq1, c1, c2, c3, cs.getKeyLen());
        assertFalse(Arrays.equals(k0, k1));
    }

    // ========================================================================
    // TLSTREE collisions: одинаковое C1-маскированное значение -> одинаковый K_1
    // ========================================================================

    @Test
    @DisplayName("TLSTREE: одинаковое C1-маскированное значение -> одинаковый level1 key")
    void testSameC1MaskProducesSameKey() {
        TlsCiphersuite cs = csL();
        long c1 = cs.getC1(); // 0xf800000000000000 — маска на биты 63:59
        // L: C2=0xFFFFFFF000000000, C3=0xFFFFFFFFFFFFE000, union of masks = bits 63:13
        // 0x0000 и 0x1FFF различаются только в битах 12:0, вне всех масок
        long seqA = 0L;
        long seqB = 0x1FFFL;
        byte[] kA = TlsTree.deriveKey(ZERO_KEY, seqA, c1, cs.getC2(), cs.getC3(), cs.getKeyLen());
        byte[] kB = TlsTree.deriveKey(ZERO_KEY, seqB, c1, cs.getC2(), cs.getC3(), cs.getKeyLen());
        assertArrayEquals(kA, kB);
    }

    @Test
    @DisplayName("TLSTREE: разные C1-маскированные значения -> разные keys")
    void testDifferentC1MaskProducesDifferentKey() {
        TlsCiphersuite cs = csL();
        long c1 = cs.getC1(); // 0xf800000000000000
        // 0x0000_0000_0000_0000 (C1 mask = 0) vs 0x0800_0000_0000_0000 (C1 mask =
        // 0x0800_0000_0000_0000)
        long seqA = 0L;
        long seqB = 0x0800000000000000L;
        byte[] kA = TlsTree.deriveKey(ZERO_KEY, seqA, c1, cs.getC2(), cs.getC3(), cs.getKeyLen());
        byte[] kB = TlsTree.deriveKey(ZERO_KEY, seqB, c1, cs.getC2(), cs.getC3(), cs.getKeyLen());
        assertFalse(Arrays.equals(kA, kB));
    }

    @Test
    @DisplayName("TLSTREE S: одинаковое C1-маскированное значение -> одинаковый level1 key")
    void testSameC1MaskS() {
        TlsCiphersuite cs = csS();
        long c1 = cs.getC1(); // 0xFFFFFFFFE0000000 — маска на биты 63:29
        // S: C2=0xFFFFFFFFFFFF0000, C3=0xFFFFFFFFFFFFFFF8, union = bits 63:3
        // 0x0000 и 0x0007 различаются только в битах 2:0, вне всех масок
        long seqA = 0L;
        long seqB = 0x0000000000000007L;
        byte[] kA = TlsTree.deriveKey(ZERO_KEY, seqA, c1, cs.getC2(), cs.getC3(), cs.getKeyLen());
        byte[] kB = TlsTree.deriveKey(ZERO_KEY, seqB, c1, cs.getC2(), cs.getC3(), cs.getKeyLen());
        assertArrayEquals(kA, kB);
    }

    @Test
    @DisplayName("deriveKey: S-вариант возвращает 32 байта")
    void testDeriveKeyLengthS() {
        byte[] key =
                TlsTree.deriveKey(
                        ZERO_KEY,
                        5,
                        csS().getC1(),
                        csS().getC2(),
                        csS().getC3(),
                        csS().getKeyLen());
        assertEquals(32, key.length);
    }
}
