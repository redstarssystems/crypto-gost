package org.rssys.gost.jca.spec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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

    // -----------------------------------------------------------------------
    // Регистронезависимость имён
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "tc26-gost-A-256, 1.2.643.7.1.2.1.1.1",
        "tc26-gost-A-512, 1.2.643.7.1.2.1.2.1",
        "tc26-gost-B-512, 1.2.643.7.1.2.1.2.2",
        "tc26-gost-C-512, 1.2.643.7.1.2.1.2.3",
        "cryptopro-A, 1.2.643.2.2.35.1",
        "cryptopro-B, 1.2.643.2.2.35.2",
        "cryptopro-C, 1.2.643.2.2.35.3"
    })
    @DisplayName("имя кривой находится в любом регистре: как записано, в нижнем и в верхнем")
    void namesAreCaseInsensitive(String name, String oid) {
        ECParameters byOid = GostCurves.byName(oid);
        for (String variant : new String[] {name, name.toLowerCase(), name.toUpperCase()}) {
            assertSame(byOid, GostCurves.byName(variant), "byName(" + variant + ")");
            assertTrue(GostCurves.isSupported(variant), "isSupported(" + variant + ")");
        }
    }

    @Test
    @DisplayName("неизвестные имена и OID не поддерживаются, null отвергается")
    void unknownNamesAreRejected() {
        assertFalse(GostCurves.isSupported("cryptopro-D"));
        assertFalse(GostCurves.isSupported(null));
        assertThrows(IllegalArgumentException.class, () -> GostCurves.byName("cryptopro-D"));
        assertThrows(IllegalArgumentException.class, () -> GostCurves.byName(null));
    }

    // -----------------------------------------------------------------------
    // XchA / XchB (RFC 4357 §11.4)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "XchA = 1.2.643.2.2.36.0 -> параметры CryptoPro-A, XchB = 1.2.643.2.2.36.1 -> параметры CryptoPro-C")
    void xchOidsMapToRfc4357Curves() {
        assertEquals("1.2.643.2.2.36.0", GostCurves.OID_CRYPTOPRO_XCHA, "OID XchA");
        assertEquals("1.2.643.2.2.36.1", GostCurves.OID_CRYPTOPRO_XCHB, "OID XchB");
        assertSame(
                ECParameters.cryptoProA(),
                GostCurves.byName(GostCurves.OID_CRYPTOPRO_XCHA),
                "XchA — параметры CryptoPro-A");
        assertSame(
                ECParameters.cryptoProC(),
                GostCurves.byName(GostCurves.OID_CRYPTOPRO_XCHB),
                "XchB — параметры CryptoPro-C, а не B");
        assertEquals(
                GostCurves.DigestParamSetPolicy.REQUIRED,
                GostCurves.digestPolicyOf(GostCurves.OID_CRYPTOPRO_XCHB),
                "для XchB digestParamSet обязателен");
        // Алиасы Xch канонизируются в CryptoPro OID: при повторном кодировании OID меняется,
        // параметры те же
        assertEquals(
                GostCurves.OID_CRYPTOPRO_A,
                GostCurves.oidOf(GostCurves.byName(GostCurves.OID_CRYPTOPRO_XCHA)),
                "oidOf(XchA) — канонический OID CryptoPro-A");
        assertEquals(
                GostCurves.OID_CRYPTOPRO_C,
                GostCurves.oidOf(GostCurves.byName(GostCurves.OID_CRYPTOPRO_XCHB)),
                "oidOf(XchB) — канонический OID CryptoPro-C");
    }

    @Test
    @DisplayName(
            "1.2.643.2.2.38.0 (дуга политик CryptoPro, не кривая) не является набором параметров")
    void policyArcIsNotACurve() {
        String policyIds = "1.2.643.2.2.38.0";
        assertFalse(GostCurves.isSupported(policyIds), "38.0 не должен поддерживаться");
        assertThrows(IllegalArgumentException.class, () -> GostCurves.byName(policyIds));
        assertThrows(IllegalArgumentException.class, () -> GostCurves.digestPolicyOf(policyIds));
    }
}
