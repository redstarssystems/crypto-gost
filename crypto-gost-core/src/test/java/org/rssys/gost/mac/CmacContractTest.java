package org.rssys.gost.mac;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.cipher.Kuznyechik;

@DisplayName("Cmac: имя алгоритма и размер тега")
class CmacContractTest {

    @Test
    @DisplayName("имя берётся от исходного шифра, а не от внутреннего CBC")
    void algorithmNameIsCmac() {
        assertEquals(
                "GOST3412-2015/CMAC",
                new Cmac(new Kuznyechik()).getAlgorithmName(),
                "имя CMAC на полном теге");
        assertEquals(
                "GOST3412-2015/CMAC",
                new Cmac(new Kuznyechik(), 64).getAlgorithmName(),
                "имя CMAC на усечённом теге");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -8, -1, 7, 129, 136, Integer.MIN_VALUE})
    @DisplayName("недопустимый размер тега отвергается при создании")
    void invalidMacSizeRejected(int bits) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Cmac(new Kuznyechik(), bits),
                "размер тега " + bits + " бит должен быть отвергнут");
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 64, 128})
    @DisplayName("граничные размеры тега принимаются")
    void validMacSizeAccepted(int bits) {
        assertDoesNotThrow(() -> new Cmac(new Kuznyechik(), bits), "размер тега " + bits);
    }

    @Test
    @DisplayName("сообщения отказа по размеру тега не изменились")
    void invalidMacSizeMessages() {
        assertEquals(
                "MAC size must be positive",
                assertThrows(IllegalArgumentException.class, () -> new Cmac(new Kuznyechik(), 0))
                        .getMessage(),
                "нулевой размер");
        assertEquals(
                "MAC size must be multiple of 8",
                assertThrows(IllegalArgumentException.class, () -> new Cmac(new Kuznyechik(), 7))
                        .getMessage(),
                "размер не кратен 8");
        assertEquals(
                "MAC size must be <= 128",
                assertThrows(IllegalArgumentException.class, () -> new Cmac(new Kuznyechik(), 136))
                        .getMessage(),
                "размер больше блока");
    }
}
