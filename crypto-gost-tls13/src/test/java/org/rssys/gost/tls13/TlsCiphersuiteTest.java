package org.rssys.gost.tls13;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;

import static org.junit.jupiter.api.Assertions.*;
import org.rssys.gost.tls13.psk.*;
import org.rssys.gost.tls13.crypto.*;
import org.rssys.gost.tls13.config.*;
import org.rssys.gost.tls13.cert.*;
import org.rssys.gost.tls13.record.*;
import org.rssys.gost.tls13.message.*;
import org.rssys.gost.tls13.engine.*;

/**
 * Тесты TlsCiphersuite — константы cipher suite и отображение named group <-> ECParameters.
 */
@DisplayName("TlsCiphersuite: константы и маппинг групп")
class TlsCiphersuiteTest {

    // -----------------------------------------------------------------------
    // Константы cipher suite L (Loop)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("L-вариант: все константы корректны")
    void testCiphersuiteLConstants() {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        assertEquals(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, cs.getId());
        assertEquals(32, cs.getHashLen());
        assertEquals(32, cs.getKeyLen());
        assertEquals(16, cs.getIvLen());
        assertEquals(16, cs.getTagLen());
        assertEquals(0xFFFFFFFFFFFFFFFFL, cs.getSnmax());
        assertEquals(0xF800000000000000L, cs.getC1());
        assertEquals(0xFFFFFFF000000000L, cs.getC2());
        assertEquals(0xFFFFFFFFFFFFE000L, cs.getC3());
    }

    // -----------------------------------------------------------------------
    // Константы cipher suite S (Seal)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("S-вариант: все константы корректны")
    void testCiphersuiteSConstants() {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
        assertEquals(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S, cs.getId());
        assertEquals(32, cs.getHashLen());
        assertEquals(32, cs.getKeyLen());
        assertEquals(16, cs.getIvLen());
        assertEquals(16, cs.getTagLen());
        assertEquals(0x3FFFFFFFFFFL, cs.getSnmax());
        assertEquals(0xFFFFFFFFE0000000L, cs.getC1());
        assertEquals(0xFFFFFFFFFFFF0000L, cs.getC2());
        assertEquals(0xFFFFFFFFFFFFFFF8L, cs.getC3());
    }

    @Test
    @DisplayName("L и S имеют разные SNMAX")
    void testLsSnmaxDiffer() {
        assertNotEquals(
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getSnmax(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getSnmax());
    }

    // -----------------------------------------------------------------------
    // Поиск cipher suite по ID
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("byId: L-вариант найден")
    void testByIdLookupL() {
        TlsCiphersuite cs = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        assertNotNull(cs);
    }

    @Test
    @DisplayName("byId: S-вариант найден")
    void testByIdLookupS() {
        TlsCiphersuite cs = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
        assertNotNull(cs);
    }

    @Test
    @DisplayName("byId: неизвестный ID → null")
    void testByIdUnknownReturnsNull() {
        assertNull(TlsCiphersuite.byId(0xFFFF));
    }

    @Test
    @DisplayName("values: содержит оба cipher suite (L и S)")
    void testValuesContainsBoth() {
        TlsCiphersuite[] values = TlsCiphersuite.values();
        assertEquals(2, values.length);
    }

    // -----------------------------------------------------------------------
    // Отображение named group → ECParameters
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("namedGroupToParams: все 7 групп отображаются")
    void testNamedGroupToParamsAllMappings() {
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC256A));
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC256B));
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC256C));
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC256D));
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512A));
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512B));
        assertNotNull(TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512C));
    }

    @Test
    @DisplayName("namedGroupToParams: 512-бит → hlen=64")
    void testNamedGroupToParams512Bit() {
        assertEquals(64, TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512A).hlen);
        assertEquals(64, TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512B).hlen);
        assertEquals(64, TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512C).hlen);
    }

    @Test
    @DisplayName("namedGroupToParams: неизвестная группа → исключение")
    void testNamedGroupToParamsUnknownThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> TlsCiphersuite.namedGroupToParams(0xFFFF));
    }

    // -----------------------------------------------------------------------
    // Отображение ECParameters → named group
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("paramsToNamedGroup: все 256-бит кривые")
    void testParamsToNamedGroup256() {
        assertEquals(TlsConstants.GRP_GC256A, TlsCiphersuite.paramsToNamedGroup(ECParameters.tc26a256()));
        assertEquals(TlsConstants.GRP_GC256B, TlsCiphersuite.paramsToNamedGroup(ECParameters.cryptoProA()));
        assertEquals(TlsConstants.GRP_GC256C, TlsCiphersuite.paramsToNamedGroup(ECParameters.cryptoProB()));
        assertEquals(TlsConstants.GRP_GC256D, TlsCiphersuite.paramsToNamedGroup(ECParameters.cryptoProC()));
    }

    @Test
    @DisplayName("paramsToNamedGroup: все 512-бит кривые")
    void testParamsToNamedGroup512() {
        assertEquals(TlsConstants.GRP_GC512A, TlsCiphersuite.paramsToNamedGroup(ECParameters.tc26a512()));
        assertEquals(TlsConstants.GRP_GC512B, TlsCiphersuite.paramsToNamedGroup(ECParameters.tc26b512()));
        assertEquals(TlsConstants.GRP_GC512C, TlsCiphersuite.paramsToNamedGroup(ECParameters.tc26c512()));
    }

    @Test
    @DisplayName("paramsToNamedGroup: нестандартные параметры → исключение")
    void testParamsToNamedGroupUnknownThrows() {
        ECParameters fake = new ECParameters(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
                "1", "1", "1", "1",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF01", 32, 1);
        assertThrows(IllegalArgumentException.class,
                () -> TlsCiphersuite.paramsToNamedGroup(fake));
    }
}
