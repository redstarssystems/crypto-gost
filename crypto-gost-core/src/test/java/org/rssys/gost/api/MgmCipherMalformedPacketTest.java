package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

@DisplayName("MgmCipher.open: повреждённый пакет даёт один тип отказа")
class MgmCipherMalformedPacketTest {

    private final SymmetricKey key = KeyGenerator.generateSymmetricKey();

    @Test
    @DisplayName("Пакет null отвергается как AuthenticationException, а не NullPointerException")
    void nullPacketIsAuthenticationFailure() {
        assertThrows(
                AuthenticationException.class,
                () -> MgmCipher.open(null, key),
                "пакет null приходит из недоверенного источника");
    }

    @Test
    @DisplayName("Пакет короче минимального отвергается как AuthenticationException")
    void shortPacketIsAuthenticationFailure() {
        for (int length : new int[] {0, 1, MgmCipher.MIN_PACKET_LEN - 1}) {
            byte[] packet = new byte[length];
            assertThrows(
                    AuthenticationException.class,
                    () -> MgmCipher.open(packet, key),
                    "пакет длиной " + length);
        }
    }

    @Test
    @DisplayName("Пакет со старшим битом ICN, равным 1, отвергается как AuthenticationException")
    void invalidIcnIsAuthenticationFailure() throws Exception {
        byte[] packet = MgmCipher.seal(new byte[20], key);
        packet[0] |= (byte) 0x80;
        assertThrows(
                AuthenticationException.class,
                () -> MgmCipher.open(packet, key),
                "ICN с установленным старшим битом");
    }

    @Test
    @DisplayName("Ключ null отвергается как ошибка вызывающего, а не как повреждение пакета")
    void nullKeyIsCallerError() {
        byte[] packet = MgmCipher.seal(new byte[20], key);
        assertThrows(
                IllegalArgumentException.class,
                () -> MgmCipher.open(packet, null),
                "open с ключом null");
        assertThrows(
                IllegalArgumentException.class,
                () -> MgmCipher.seal(new byte[20], null),
                "seal с ключом null");
    }

    @Test
    @DisplayName("Корректный пакет по-прежнему открывается")
    void validPacketStillOpens() throws Exception {
        byte[] plain = new byte[20];
        Arrays.fill(plain, (byte) 7);
        assertArrayEquals(plain, MgmCipher.open(MgmCipher.seal(plain, key), key), "открытый текст");
    }
}
