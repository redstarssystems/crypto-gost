package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.util.CryptoRandom;

/**
 * Формат расширения {@code pre_shared_key} в ClientHello клиента (RFC 8446 §4.2.11).
 *
 * <p>Разбор здесь написан независимо от {@code TlsMessageParser}: тот терпим к дефекту, при
 * котором расширение короче записываемой структуры, а сервер библиотеки сверяет binder по позиции
 * от конца и потому не замечает ошибки. Внешние реализации разбирают структуру по RFC и
 * отвечают {@code decode_error}.
 */
@DisplayName("ClientHello с PSK: структура pre_shared_key по RFC 8446 §4.2.11")
class PskClientHelloFormatTest {

    private static final ECParameters CLIENT_PARAMS = ECParameters.tc26a256();
    private static final int CLIENT_GROUP = TlsConstants.GRP_GC256A;
    private static final ECParameters SERVER_PARAMS = ECParameters.cryptoProA();
    private static final int SERVER_GROUP = TlsConstants.GRP_GC256B;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HANDSHAKE_HEADER_LENGTH = 4;
    private static final long OBFUSCATED_AGE = 0x12345678L;
    private static final byte[] TICKET = "psk-format-test-ticket-identity!!".getBytes();

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() {
        serverCert = PkixCertTestHelper.createCertWithKey(SERVER_PARAMS);
    }

    static Stream<Arguments> suites() {
        return Stream.of(
                Arguments.of(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                Arguments.of(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S));
    }

    // ------------------------------------------------------------------------
    // Первый и второй ClientHello
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    @DisplayName("Первый ClientHello: расширение разбирается по RFC, binder нетронут")
    void firstClientHelloFollowsRfcStructure(TlsCiphersuite suite) throws Exception {
        byte[] psk = randomPsk(suite);
        TlsHandshakeEngine client = pskClient(suite, CLIENT_PARAMS, CLIENT_GROUP, psk);

        byte[] frame = client.start();

        assertPskStructure(frame, suite.getHashLen());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    @DisplayName("Второй ClientHello после HelloRetryRequest: та же структура, binder пересчитан")
    void secondClientHelloFollowsRfcStructure(TlsCiphersuite suite) throws Exception {
        byte[] psk = randomPsk(suite);
        TlsHandshakeEngine client = pskClient(suite, CLIENT_PARAMS, CLIENT_GROUP, psk);
        TlsHandshakeEngine server = hrrServer(suite, psk);
        byte[] firstHello = client.start();
        server.receive(firstHello);
        byte[] helloRetryRequest = HandshakeOutputs.nextMessage(server);
        assertNotNull(
                helloRetryRequest, "сервер на другой группе обязан ответить HelloRetryRequest");

        client.receive(helloRetryRequest);
        byte[] secondHello = HandshakeOutputs.nextMessage(client);

        assertNotNull(secondHello, "клиент должен отправить второй ClientHello");
        ParsedPsk second = assertPskStructure(secondHello, suite.getHashLen());
        ParsedPsk first = parsePsk(firstHello);
        assertFalse(
                java.util.Arrays.equals(first.binder(), second.binder()),
                "binder второго ClientHello считается заново: транскрипт другой");
    }

    // ------------------------------------------------------------------------
    // Независимый разбор
    // ------------------------------------------------------------------------

    private static ParsedPsk assertPskStructure(byte[] frame, int hashLen) {
        ParsedPsk psk = parsePsk(frame);
        assertArrayEquals(TICKET, psk.identity(), "identity должен совпасть с тикетом");
        assertEquals(OBFUSCATED_AGE, psk.obfuscatedAge(), "obfuscated_ticket_age");
        assertEquals(1, psk.bindersCount(), "по одному binder на identity");
        assertEquals(
                hashLen,
                psk.binder().length,
                "длина binder равна длине хэша набора шифров, байт длины binder не затёрт");
        assertEquals(
                1 + hashLen,
                psk.bindersListLength(),
                "длина списка binders = байт длины + binder, её младший байт не затёрт");
        assertFalse(isAllZero(psk.binder()), "binder должен быть подставлен, а не остаться нулями");
        assertTrue(psk.lastExtension(), "pre_shared_key обязан быть последним расширением");
        return psk;
    }

    /** Результат независимого разбора ClientHello. */
    private record ParsedPsk(
            byte[] identity,
            long obfuscatedAge,
            int bindersCount,
            int bindersListLength,
            byte[] binder,
            boolean lastExtension) {}

    /**
     * Разбирает handshake-фрейм ClientHello строго по RFC 8446 §4.1.2 и §4.2.11; любое
     * несовпадение длин - ошибка теста, а не молчаливо принятый фрейм.
     */
    private static ParsedPsk parsePsk(byte[] frame) {
        assertEquals(TlsConstants.HT_CLIENT_HELLO, frame[0] & 0xFF, "тип сообщения");
        int bodyLength = u24(frame, 1);
        assertEquals(
                frame.length - HANDSHAKE_HEADER_LENGTH,
                bodyLength,
                "длина handshake-сообщения сходится с телом");

        int pos = HANDSHAKE_HEADER_LENGTH;
        pos += 2 + 32; // legacy_version, random
        pos += 1 + (frame[pos] & 0xFF); // legacy_session_id
        pos += 2 + u16(frame, pos); // cipher_suites
        pos += 1 + (frame[pos] & 0xFF); // legacy_compression_methods

        int extensionsLength = u16(frame, pos);
        pos += 2;
        assertEquals(
                frame.length,
                pos + extensionsLength,
                "длина блока расширений доходит ровно до конца фрейма");

        int extensionsEnd = pos + extensionsLength;
        byte[] identity = null;
        long age = -1;
        int bindersCount = 0;
        int bindersListLength = -1;
        byte[] binder = null;
        boolean lastExtension = false;
        while (pos < extensionsEnd) {
            int type = u16(frame, pos);
            int length = u16(frame, pos + 2);
            int dataStart = pos + 4;
            int dataEnd = dataStart + length;
            assertTrue(
                    dataEnd <= extensionsEnd,
                    "расширение 0x" + Integer.toHexString(type) + " выходит за блок расширений");
            if (type == TlsConstants.EXT_PRE_SHARED_KEY) {
                lastExtension = dataEnd == extensionsEnd;
                int p = dataStart;
                int identitiesLength = u16(frame, p);
                p += 2;
                int identitiesEnd = p + identitiesLength;
                int identityLength = u16(frame, p);
                identity = java.util.Arrays.copyOfRange(frame, p + 2, p + 2 + identityLength);
                age = u32(frame, p + 2 + identityLength);
                p += 2 + identityLength + 4;
                assertEquals(identitiesEnd, p, "список identities занимает ровно заявленную длину");
                bindersListLength = u16(frame, p);
                p += 2;
                int bindersEnd = p + bindersListLength;
                assertTrue(
                        bindersEnd <= dataEnd,
                        "список binders выходит за расширение: заявленная длина "
                                + bindersListLength);
                List<byte[]> binders = new ArrayList<>();
                while (p < bindersEnd) {
                    int binderLength = frame[p] & 0xFF;
                    assertTrue(
                            p + 1 + binderLength <= bindersEnd,
                            "binder выходит за заявленный список binders: длина " + binderLength);
                    binders.add(java.util.Arrays.copyOfRange(frame, p + 1, p + 1 + binderLength));
                    p += 1 + binderLength;
                }
                assertEquals(bindersEnd, p, "список binders занимает ровно заявленную длину");
                assertEquals(dataEnd, p, "расширение заканчивается списком binders");
                bindersCount = binders.size();
                binder = binders.isEmpty() ? new byte[0] : binders.get(0);
            }
            pos = dataEnd;
        }
        assertEquals(extensionsEnd, pos, "разбор расширений закончился ровно в конце блока");
        assertNotNull(identity, "расширение pre_shared_key должно присутствовать");
        return new ParsedPsk(identity, age, bindersCount, bindersListLength, binder, lastExtension);
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int u24(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16) | u16(data, offset + 1);
    }

    private static long u32(byte[] data, int offset) {
        return ((long) u16(data, offset) << 16) | u16(data, offset + 2);
    }

    private static boolean isAllZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------------
    // Движки
    // ------------------------------------------------------------------------

    private static byte[] randomPsk(TlsCiphersuite suite) {
        byte[] psk = new byte[suite.getHashLen()];
        CryptoRandom.INSTANCE.nextBytes(psk);
        return psk;
    }

    private static TlsHandshakeEngine pskClient(
            TlsCiphersuite suite, ECParameters params, int group, byte[] psk) {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        suite,
                        new TlsMessageBuilder(
                                suite,
                                List.of(suite.getId()),
                                group,
                                SIG_SCHEME,
                                null,
                                null,
                                suite.getHashLen()),
                        params,
                        group,
                        SIG_SCHEME,
                        suite.getHashLen(),
                        null,
                        false,
                        null);
        client.setPsk(psk, TICKET, OBFUSCATED_AGE);
        return client;
    }

    /** Сервер, у которого группа отличается от группы key_share клиента: ответит HRR. */
    private static TlsHandshakeEngine hrrServer(TlsCiphersuite suite, byte[] psk) {
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        suite,
                        new TlsMessageBuilder(
                                suite,
                                List.of(suite.getId()),
                                SERVER_GROUP,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                suite.getHashLen()),
                        SERVER_PARAMS,
                        SERVER_GROUP,
                        SIG_SCHEME,
                        suite.getHashLen(),
                        null,
                        false,
                        null);
        server.setServerPsk(psk);
        return server;
    }
}
