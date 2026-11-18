package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.util.Pack;

/**
 * Проверяет, что ECDHE рукопожатия учитывает кофактор кривой (RFC 9367 §6.1.1.1 шаг 6,
 * §6.1.1.2 шаг 5): {@code Q = (h · d) · Q_peer}. Тесты бьют по боевому
 * {@code computeEcdheShared}, а не по {@link KeyAgreement}: иначе ошибка в TLS осталась бы
 * незамеченной.
 */
class TlsHandshakeEngineEcdheCofactorTest {

    // RFC 9367 Приложение A.1.2, Пример 1 (GC512C, кофактор 4): закрытый ключ клиента.
    // Все байты равны, поэтому порядок байт не влияет на значение.
    private static final byte[] D_C = filled(64, (byte) 0x04);

    // RFC 9367 A.1.2, Пример 1: Q_S = X || Y, little-endian.
    private static final String Q_S_LE_HEX =
            "2F3C663FE74735A1C421160DF0F43266185FD30B6E5D6E88FC4061FAEACAB338"
                    + "B10A1BD20CB0B4EE757E74A0027D409FE937F01633A1E3F9A5518DEFD0F89F9D"
                    + "3D9F6CC651413DEC2C74366D83C47EE1DE4E421F65CD1163E94EA0C2E19ED45D"
                    + "35558B937D9BFDC5ECC2B2A21B4EC3D53B29579A8FD5E074811028FBCF17994F";

    // RFC 9367 A.1.2, Пример 1: ожидаемый ECDHE (X, little-endian).
    private static final String ECDHE_HEX =
            "4DE60D21EA8FB9220D146423B490DA40CCEBC43BC589DB79B831A47D6B063007"
                    + "DD03405A1B7976B623DCAA69B011AE106E7E4174385F8626E121B5994363C99F";

    // RFC 9367 A.1.2, Пример 1: закрытый ключ сервера d_S (little-endian) и Q_C = X || Y.
    private static final String D_S_LE_HEX =
            "AA3CA4F4A50AC05B3742B135B530A9F22AE4F5E185301DEC832E77BA3BCD6AF1"
                    + "8484848484848484848484848484848484848484848484848484848484848404";

    private static final String Q_C_LE_HEX =
            "05EEBDF3DDC1D2F5F3822433241284E77641487938EA88721F26203E9792B5CB"
                    + "97EB70EF02E8F72B7491D4F2CFDC332ADF7F1778E854A88DDC2113FEC527A151"
                    + "71A04CB0C573793A7AEF9BBCA486B6B046B2149B46F4332903E5B7C438ADD05E"
                    + "185EFBF45557475A8CCBF6ACED1A2EB416F916729D7CEF9CBD8334989304AFAE";

    @Test
    @DisplayName("RFC 9367 A.1.2 Пример 1 (GC512C, h=4): клиентский ECDHE совпадает с эталоном")
    void clientEcdheMatchesRfcExample1() throws Exception {
        ECParameters params = ECParameters.tc26c512();
        PrivateKeyParameters clientPriv = new PrivateKeyParameters(new BigInteger(1, D_C), params);
        PublicKeyParameters serverPub = TlsEncoding.decodePoint(hex(Q_S_LE_HEX), params);

        byte[] ecdhe = TlsHandshakeEngine.computeEcdheShared(clientPriv, serverPub);

        assertArrayEquals(
                hex(ECDHE_HEX), ecdhe, "ECDHE клиента не совпал с RFC 9367 A.1.2 Пример 1");
    }

    @Test
    @DisplayName("RFC 9367 A.1.2 Пример 1 (GC512C, h=4): серверный ECDHE совпадает с эталоном")
    void serverEcdheMatchesRfcExample1() throws Exception {
        ECParameters params = ECParameters.tc26c512();
        PrivateKeyParameters serverPriv =
                new PrivateKeyParameters(
                        new BigInteger(1, Pack.reverseBytes(hex(D_S_LE_HEX))), params);
        PublicKeyParameters clientPub = TlsEncoding.decodePoint(hex(Q_C_LE_HEX), params);

        byte[] ecdhe = TlsHandshakeEngine.computeEcdheShared(serverPriv, clientPub);

        assertArrayEquals(
                hex(ECDHE_HEX), ecdhe, "ECDHE сервера не совпал с RFC 9367 A.1.2 Пример 1");
    }

    // RFC 9367 A.1.2, Пример 2 (GC256B = CryptoPro-A, кофактор 1): d_C = 0x02 × 32.
    private static final String Q_S_LE_GC256B_HEX =
            "3D2FB067E106CC9980FB8842811164BA708BBB5038D5EDFBEE1D5E5DFBE6F74F"
                    + "1931217C67C2BDF46253DB9CE3487241F2DBD84E2DABDF65455851B0B19AEFEC";

    private static final String ECDHE_GC256B_HEX =
            "985A8659D55A8D48E0E6771396580B2CDCDA37E92AEE1814D10E1BF2A44F0D24";

    @Test
    @DisplayName("RFC 9367 A.1.2 Пример 2 (GC256B, h=1): ECDHE совпадает с эталоном")
    void clientEcdheMatchesRfcExample2() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters clientPriv =
                new PrivateKeyParameters(new BigInteger(1, filled(32, (byte) 0x02)), params);
        PublicKeyParameters serverPub = TlsEncoding.decodePoint(hex(Q_S_LE_GC256B_HEX), params);

        byte[] ecdhe = TlsHandshakeEngine.computeEcdheShared(clientPriv, serverPub);

        assertArrayEquals(
                hex(ECDHE_GC256B_HEX), ecdhe, "ECDHE клиента не совпал с RFC 9367 A.1.2 Пример 2");
    }

    @Test
    @DisplayName("GC256A (h=4): обе стороны получают один секрет, равный KeyAgreement")
    void bothSidesAgreeOnCofactorFourCurve() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair client = KeyGenerator.generateKeyPair(params);
        KeyPair server = KeyGenerator.generateKeyPair(params);

        byte[] clientSide =
                TlsHandshakeEngine.computeEcdheShared(client.getPrivate(), server.getPublic());
        byte[] serverSide =
                TlsHandshakeEngine.computeEcdheShared(server.getPrivate(), client.getPublic());

        assertArrayEquals(clientSide, serverSide, "стороны получили разные ECDHE");
        assertArrayEquals(
                KeyAgreement.computeSharedSecret(client.getPrivate(), server.getPublic()),
                clientSide,
                "ECDHE рукопожатия расходится с KeyAgreement.computeSharedSecret");
        assertEquals(params.hlen, clientSide.length, "длина ECDHE должна быть coordinate_length");
    }

    @Test
    @DisplayName("Ключи разных кривых -> handshake_failure")
    void curveMismatchIsHandshakeFailure() throws Exception {
        KeyPair mine = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        KeyPair peer = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsHandshakeEngine.computeEcdheShared(
                                        mine.getPrivate(), peer.getPublic()));

        assertEquals(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                ex.getAlertCode(),
                "ожидался alert handshake_failure");
    }

    private static byte[] filled(int len, byte value) {
        byte[] result = new byte[len];
        Arrays.fill(result, value);
        return result;
    }

    private static byte[] hex(String hex) {
        String clean = hex.replace(" ", "");
        byte[] result = new byte[clean.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(clean.substring(2 * i, 2 * i + 2), 16);
        }
        return result;
    }
}
