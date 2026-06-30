package org.rssys.gost.jca.spec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;

@DisplayName("GostCurves — реестр кривых и OID")
class GostCurvesTest {

    @Test
    @DisplayName("oidOf() возвращает CryptoPro OID, не TC26-алиас")
    void oidOfReturnsCanonicalCryptoProOid() {
        assertEquals(
                GostCurves.OID_CRYPTOPRO_A,
                GostCurves.oidOf(ECParameters.cryptoProA()),
                "cryptoProA должен кодироваться с CryptoPro-A OID, не TC26-алиасом");
        assertEquals(
                GostCurves.OID_CRYPTOPRO_B,
                GostCurves.oidOf(ECParameters.cryptoProB()),
                "cryptoProB должен кодироваться с CryptoPro-B OID, не TC26-алиасом");
        assertEquals(
                GostCurves.OID_CRYPTOPRO_C,
                GostCurves.oidOf(ECParameters.cryptoProC()),
                "cryptoProC должен кодироваться с CryptoPro-C OID, не TC26-алиасом");
    }

    @Test
    @DisplayName("oidOf() возвращает TC26 OID для TC26-кривых")
    void oidOfReturnsTc26OidForTc26Curves() {
        assertEquals(GostCurves.OID_TC26_A_256, GostCurves.oidOf(ECParameters.tc26a256()));
        assertEquals(GostCurves.OID_TC26_A_512, GostCurves.oidOf(ECParameters.tc26a512()));
        assertEquals(GostCurves.OID_TC26_B_512, GostCurves.oidOf(ECParameters.tc26b512()));
        assertEquals(GostCurves.OID_TC26_C_512, GostCurves.oidOf(ECParameters.tc26c512()));
    }

    @Test
    @DisplayName("byName() находит TC26-алиас и возвращает те же параметры, что и CryptoPro OID")
    void byNameTc26AliasReturnsSameParamsAsCryptoPro() {
        ECParameters cpa = GostCurves.byName(GostCurves.OID_CRYPTOPRO_A);
        ECParameters t26b = GostCurves.byName(GostCurves.OID_TC26_B_256);
        assertSame(
                cpa,
                t26b,
                "TC26-B-256 должен разрешаться в тот же ECParameters, что и CryptoPro-A");

        ECParameters cpb = GostCurves.byName(GostCurves.OID_CRYPTOPRO_B);
        ECParameters t26c = GostCurves.byName(GostCurves.OID_TC26_C_256);
        assertSame(
                cpb,
                t26c,
                "TC26-C-256 должен разрешаться в тот же ECParameters, что и CryptoPro-B");

        ECParameters cpc = GostCurves.byName(GostCurves.OID_CRYPTOPRO_C);
        ECParameters t26d = GostCurves.byName(GostCurves.OID_TC26_D_256);
        assertSame(
                cpc,
                t26d,
                "TC26-D-256 должен разрешаться в тот же ECParameters, что и CryptoPro-C");
    }

    @Test
    @DisplayName("oidOf() бросает IAE для неизвестных параметров")
    void oidOfThrowsForUnknown() {
        // null
        assertThrows(IllegalArgumentException.class, () -> GostCurves.oidOf(null));
    }
}
