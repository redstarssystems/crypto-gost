package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("MgmCipher — пустые открытый текст и AAD (RFC 9058 §6)")
class MgmCipherEmptyDataTest {

    private static byte[] randomIcn() {
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        return icn;
    }

    @Test
    @DisplayName("seal пустого открытого текста без AAD отвергается")
    void sealEmptyPlaintextWithoutAadIsRejected() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();

        assertThrows(
                IllegalArgumentException.class,
                () -> MgmCipher.seal(new byte[0], key),
                "Пустой открытый текст без AAD: тег не зависел бы от ICN");
        assertThrows(
                IllegalArgumentException.class,
                () -> MgmCipher.sealWithIcn(new byte[0], key, randomIcn(), new byte[0]),
                "Пустые открытый текст и AAD должны отвергаться и с явным ICN");
    }

    @Test
    @DisplayName("пакет без шифртекста и без AAD не проходит open")
    void openPacketWithoutCiphertextAndAadIsRejected() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] icn = randomIcn();
        // [ICN][тег] без шифртекста: тег — любые 16 байт
        byte[] packet = new byte[32];
        System.arraycopy(icn, 0, packet, 0, 16);

        assertThrows(
                AuthenticationException.class,
                () -> MgmCipher.open(packet, key, new byte[0]),
                "Пустой шифртекст без AAD не должен аутентифицироваться");
    }

    @Test
    @DisplayName("пустой открытый текст с AAD: seal и open работают")
    void emptyPlaintextWithAadRoundtrips() throws AuthenticationException {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] aad = {1, 2, 3, 4};

        byte[] packet = MgmCipher.seal(new byte[0], key, aad);

        assertEquals(32, packet.length, "Только ICN и тег");
        assertEquals(0, MgmCipher.open(packet, key, aad).length, "Пустой открытый текст");
    }
}
