package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;

/**
 * Сервер отвергает ClientHello в формате выпущенных версий (v0.2.0 ... v0.7.1).
 *
 * <p>Выпущенные клиенты отправляли {@code pre_shared_key} на 2 байта короче записываемой структуры,
 * а binder затирал младший байт длины списка binders и байт длины binder; старый сервер этого не
 * замечал, потому что резал последние {@code 3 + hashLen} байт фрейма. Фрейм получен реальным кодом
 * v0.7.1 и лежит в ресурсах как неизменный эталон: его нельзя строить текущим кодом, иначе тест
 * проверял бы уже другой формат. Строгий разбор структуры (RFC 8446 §4.2.11) такой кадр не
 * принимает: {@code decode_error}, в первом ClientHello и во втором после HelloRetryRequest.
 */
@DisplayName("Сервер отвергает ClientHello с PSK в формате выпущенных версий")
class PskLegacyClientHelloTest {

    private static final String FRAME_RESOURCE = "/psk/clienthello-psk-v0.7.1.hex";
    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    private static final long OBFUSCATED_AGE = 0xC0DEL;
    private static final int KEY_BASE = 0xA0;
    private static final int TICKET_BASE = 0x40;
    private static final int HANDSHAKE_HEADER_LENGTH = 4;
    private static final int LEGACY_VERSION_AND_RANDOM_LENGTH = 2 + 32;

    /** Префикс длины identity, которого не хватало расширению в выпущенных версиях. */
    private static final int IDENTITY_LENGTH_PREFIX = 2;

    private static PkixCertTestHelper.CertBundle serverCert;
    private static byte[] legacyFrame;

    @BeforeAll
    static void setUp() throws IOException {
        serverCert = PkixCertTestHelper.createCertWithKey(PARAMS);
        legacyFrame = readFrame();
    }

    @Test
    @DisplayName("Эталонный фрейм отвергается: decode_error, PSK не принят")
    void legacyFrameIsRejected() throws Exception {
        TlsHandshakeEngine server = server(storeWithEntry());

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> server.receive(legacyFrame.clone()),
                        "ClientHello выпущенных версий нарушает структуру pre_shared_key");

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode(), "код алерта");
        assertFalse(server.isPskAccepted(), "PSK не должен быть принят");
    }

    @Test
    @DisplayName(
            "Контроль: кадр нового формата принимается, изменённый байт binder даёт decrypt_error")
    void currentFrameIsAcceptedAndCorruptedBinderIsRejected() throws Exception {
        byte[] currentFrame = currentClient().start();

        TlsHandshakeEngine accepting = server(storeWithEntry());
        accepting.receive(currentFrame.clone());
        assertTrue(
                accepting.isPskAccepted(),
                "кадр нового формата должен приниматься: иначе отказ эталонного кадра ничего не доказывает");

        byte[] corrupted = currentFrame.clone();
        corrupted[corrupted.length - 1] ^= 0x01;
        TlsHandshakeEngine rejecting = server(storeWithEntry());
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> rejecting.receive(corrupted),
                        "изменённый binder не должен приниматься");
        assertEquals(TlsConstants.ALERT_DECRYPT_ERROR, ex.getAlertCode(), "код алерта");
    }

    @Test
    @DisplayName("Старый формат во втором ClientHello после HelloRetryRequest тоже отвергается")
    void legacyLayoutIsRejectedInSecondClientHello() throws Exception {
        TlsHandshakeEngine client = currentClient();
        // Сервер предпочитает другую группу: клиент GC256A получает HRR
        TlsHandshakeEngine server = hrrServer(storeWithEntry());

        server.receive(client.start());
        client.receive(HandshakeOutputs.nextMessage(server));
        byte[] currentSecondHello = HandshakeOutputs.nextMessage(client);
        byte[] legacySecondHello = toLegacyLayout(currentSecondHello);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> server.receive(legacySecondHello),
                        "второй ClientHello выпущенного формата нарушает структуру pre_shared_key");

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode(), "код алерта");
    }

    @Test
    @DisplayName(
            "Эталонный фрейм действительно старого формата: расширение pre_shared_key на 2 байта короче нового")
    void frameIsOfLegacyLayout() throws Exception {
        TlsHandshakeEngine client = currentClient();

        byte[] currentFrame = client.start();

        // Сравнивается именно расширение, а не весь фрейм: новое расширение ClientHello
        // изменило бы длину фрейма, хотя приём выпущенного формата остался бы верным
        assertEquals(
                pskExtensionLength(currentFrame) - IDENTITY_LENGTH_PREFIX,
                pskExtensionLength(legacyFrame),
                "выпущенные версии отправляли расширение на 2 байта короче");
    }

    /** Клиент текущего формата с тем же PSK и тикетом, что у эталонного фрейма. */
    private static TlsHandshakeEngine currentClient() {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        suite,
                        new TlsMessageBuilder(
                                suite,
                                List.of(suite.getId()),
                                GROUP,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        PARAMS,
                        GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setPsk(sequence(KEY_BASE), sequence(TICKET_BASE), OBFUSCATED_AGE);
        return client;
    }

    /**
     * Приводит кадр текущего формата к раскладке выпущенных версий: расширение короче на 2 байта.
     * Binder там затирал младший байт длины списка binders и байт длины binder, поэтому эти два
     * байта вырезаются, а длины расширения, блока расширений и сообщения уменьшаются на 2. Значение
     * binder не пересчитывается: разбор структуры отказывает раньше проверки binder.
     */
    private static byte[] toLegacyLayout(byte[] frame) {
        int cut = frame.length - HASH_LEN - 2;
        byte[] legacy = new byte[frame.length - 2];
        System.arraycopy(frame, 0, legacy, 0, cut);
        System.arraycopy(frame, cut + 2, legacy, cut, frame.length - cut - 2);

        int messageLength =
                ((legacy[1] & 0xFF) << 16) | ((legacy[2] & 0xFF) << 8) | (legacy[3] & 0xFF);
        messageLength -= 2;
        legacy[1] = (byte) (messageLength >>> 16);
        legacy[2] = (byte) (messageLength >>> 8);
        legacy[3] = (byte) messageLength;

        int pos = HANDSHAKE_HEADER_LENGTH + LEGACY_VERSION_AND_RANDOM_LENGTH;
        pos += 1 + (legacy[pos] & 0xFF);
        pos += 2 + u16(legacy, pos);
        pos += 1 + (legacy[pos] & 0xFF);
        int extensionsLengthPos = pos;
        int extensionsEnd = pos + 2 + u16(legacy, pos);
        writeU16(legacy, extensionsLengthPos, u16(legacy, extensionsLengthPos) - 2);
        pos += 2;
        while (pos < extensionsEnd) {
            int type = u16(legacy, pos);
            int length = u16(legacy, pos + 2);
            if (type == TlsConstants.EXT_PRE_SHARED_KEY) {
                writeU16(legacy, pos + 2, length - 2);
                return legacy;
            }
            pos += 4 + length;
        }
        throw new AssertionError("в ClientHello нет расширения pre_shared_key");
    }

    private static void writeU16(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 8);
        data[offset + 1] = (byte) value;
    }

    /** Сервер, который предпочитает другую группу, чем клиент: рукопожатие идёт через HRR. */
    private static TlsHandshakeEngine hrrServer(InMemoryPskStore store) {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        suite,
                        new TlsMessageBuilder(
                                suite,
                                List.of(suite.getId()),
                                TlsConstants.GRP_GC256B,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        ECParameters.cryptoProA(),
                        TlsConstants.GRP_GC256B,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerPskStore(store);
        return server;
    }

    /** Заявленная длина тела расширения {@code pre_shared_key} в ClientHello. */
    private static int pskExtensionLength(byte[] frame) {
        int pos = HANDSHAKE_HEADER_LENGTH;
        pos += LEGACY_VERSION_AND_RANDOM_LENGTH;
        pos += 1 + (frame[pos] & 0xFF); // legacy_session_id
        pos += 2 + u16(frame, pos); // cipher_suites
        pos += 1 + (frame[pos] & 0xFF); // legacy_compression_methods
        int extensionsEnd = pos + 2 + u16(frame, pos);
        pos += 2;
        while (pos < extensionsEnd) {
            int type = u16(frame, pos);
            int length = u16(frame, pos + 2);
            if (type == TlsConstants.EXT_PRE_SHARED_KEY) {
                return length;
            }
            pos += 4 + length;
        }
        throw new AssertionError("в ClientHello нет расширения pre_shared_key");
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    // ------------------------------------------------------------------------

    private static InMemoryPskStore storeWithEntry() {
        byte[] psk = sequence(KEY_BASE);
        byte[] ticket = sequence(TICKET_BASE);
        InMemoryPskStore store = new InMemoryPskStore(10);
        // issueTime = сейчас и ticketAgeAdd = возраст во фрейме: возраст тикета равен нулю, отказ
        // не может быть из-за проверки возраста
        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        3600,
                        OBFUSCATED_AGE,
                        new byte[8],
                        psk,
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));
        return store;
    }

    /** Последовательность {@code base + i}: так построены PSK и тикет эталонного фрейма. */
    private static byte[] sequence(int base) {
        byte[] data = new byte[HASH_LEN];
        for (int i = 0; i < HASH_LEN; i++) {
            data[i] = (byte) (base + i);
        }
        return data;
    }

    private static TlsHandshakeEngine server(InMemoryPskStore store) {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        suite,
                        new TlsMessageBuilder(
                                suite,
                                List.of(suite.getId()),
                                GROUP,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        PARAMS,
                        GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerPskStore(store);
        return server;
    }

    private static byte[] readFrame() throws IOException {
        try (InputStream in = PskLegacyClientHelloTest.class.getResourceAsStream(FRAME_RESOURCE)) {
            String text = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            StringBuilder hex = new StringBuilder();
            for (String line : text.split("\n")) {
                if (!line.startsWith("#")) {
                    hex.append(line.trim());
                }
            }
            return HexFormat.of().parseHex(hex.toString());
        }
    }
}
