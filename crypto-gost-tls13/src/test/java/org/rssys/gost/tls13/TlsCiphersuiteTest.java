package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.*;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.cert.*;
import org.rssys.gost.tls13.config.*;
import org.rssys.gost.tls13.crypto.*;
import org.rssys.gost.tls13.engine.*;
import org.rssys.gost.tls13.message.*;
import org.rssys.gost.tls13.psk.*;
import org.rssys.gost.tls13.record.*;

/**
 * Тесты TlsCiphersuite — константы cipher suite и отображение named group <-> ECParameters.
 */
@DisplayName("TlsCiphersuite: константы и маппинг групп")
class TlsCiphersuiteTest {

    // -----------------------------------------------------------------------
    // Константы cipher suite L (Loop) и S (Seal) — параметризованные
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("cipherSuiteData")
    @DisplayName("константы cipher suite корректны")
    void testCiphersuiteConstants(
            TlsCiphersuite cs,
            int expectedId,
            int hashLen,
            int keyLen,
            int ivLen,
            int tagLen,
            long snmax,
            long c1,
            long c2,
            long c3) {
        assertEquals(expectedId, cs.getId());
        assertEquals(hashLen, cs.getHashLen());
        assertEquals(keyLen, cs.getKeyLen());
        assertEquals(ivLen, cs.getIvLen());
        assertEquals(tagLen, cs.getTagLen());
        assertEquals(snmax, cs.getSnmax());
        assertEquals(c1, cs.getC1());
        assertEquals(c2, cs.getC2());
        assertEquals(c3, cs.getC3());
    }

    static Stream<Arguments> cipherSuiteData() {
        return Stream.of(
                Arguments.of(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        (int) TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        32,
                        32,
                        16,
                        16,
                        0xFFFFFFFFFFFFFFFFL,
                        0xF800000000000000L,
                        0xFFFFFFF000000000L,
                        0xFFFFFFFFFFFFE000L),
                Arguments.of(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S,
                        (int) TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S,
                        32,
                        32,
                        16,
                        16,
                        0x3FFFFFFFFFFL,
                        0xFFFFFFFFE0000000L,
                        0xFFFFFFFFFFFF0000L,
                        0xFFFFFFFFFFFFFFF8L));
    }

    @Test
    @DisplayName("L и S имеют разные SNMAX")
    void testLsSnmaxDiffer() {
        assertNotEquals(
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getSnmax(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getSnmax());
    }

    // -----------------------------------------------------------------------
    // Поиск cipher suite по ID — параметризованный
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("cipherSuiteValues")
    @DisplayName("byId: cipher suite найден по ID")
    void testByIdLookup(TlsCiphersuite cs) {
        TlsCiphersuite found = TlsCiphersuite.byId(cs.getId());
        assertNotNull(found);
        assertEquals(cs, found);
    }

    static Stream<TlsCiphersuite> cipherSuiteValues() {
        return Stream.of(TlsCiphersuite.values());
    }

    @Test
    @DisplayName("byId: неизвестный ID -> null")
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
    // Отображение named group -> ECParameters
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
    @DisplayName("namedGroupToParams: 512-бит -> hlen=64")
    void testNamedGroupToParams512Bit() {
        assertEquals(64, TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512A).hlen);
        assertEquals(64, TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512B).hlen);
        assertEquals(64, TlsCiphersuite.namedGroupToParams(TlsConstants.GRP_GC512C).hlen);
    }

    @Test
    @DisplayName("namedGroupToParams: неизвестная группа -> исключение")
    void testNamedGroupToParamsUnknownThrows() {
        assertThrows(
                IllegalArgumentException.class, () -> TlsCiphersuite.namedGroupToParams(0xFFFF));
    }

    // -----------------------------------------------------------------------
    // Отображение ECParameters -> named group — параметризованный
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("paramsToGroupData")
    @DisplayName("paramsToNamedGroup: все кривые отображаются корректно")
    void testParamsToNamedGroup(ECParameters params, int expectedGroup) {
        assertEquals(expectedGroup, TlsCiphersuite.paramsToNamedGroup(params));
    }

    static Stream<Arguments> paramsToGroupData() {
        return Stream.of(
                Arguments.of(ECParameters.tc26a256(), TlsConstants.GRP_GC256A),
                Arguments.of(ECParameters.cryptoProA(), TlsConstants.GRP_GC256B),
                Arguments.of(ECParameters.cryptoProB(), TlsConstants.GRP_GC256C),
                Arguments.of(ECParameters.cryptoProC(), TlsConstants.GRP_GC256D),
                Arguments.of(ECParameters.tc26a512(), TlsConstants.GRP_GC512A),
                Arguments.of(ECParameters.tc26b512(), TlsConstants.GRP_GC512B),
                Arguments.of(ECParameters.tc26c512(), TlsConstants.GRP_GC512C));
    }

    @Test
    @DisplayName("paramsToNamedGroup: нестандартные параметры -> исключение")
    void testParamsToNamedGroupUnknownThrows() {
        ECParameters fake =
                new ECParameters(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
                        "1",
                        "1",
                        "1",
                        "1",
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF01",
                        32,
                        1);
        assertThrows(IllegalArgumentException.class, () -> TlsCiphersuite.paramsToNamedGroup(fake));
    }
}
