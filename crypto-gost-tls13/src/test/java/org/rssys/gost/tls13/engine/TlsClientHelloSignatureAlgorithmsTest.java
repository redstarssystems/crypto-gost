package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.assertAlert;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.fixtureWith;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.known;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.receiveRejected;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.server;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.storeWith;
import static org.rssys.gost.tls13.engine.TlsHandshakeEnginePskSelectionTest.stranger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Строгий разбор {@code signature_algorithms} в ClientHello (RFC 8446 §4.2.3, §9.2).
 *
 * <p>Структура расширения проверяется всегда: пустой список, нечётная длина и несовпадение длин
 * дают {@code decode_error} независимо от PSK и от того, нужна ли серверу схема подписи.
 * Отсутствие расширения допустимо только для ClientHello с {@code pre_shared_key}, и только если
 * сервер принял PSK: иначе сертификат пришлось бы подписывать без согласия клиента.
 */
@DisplayName("ClientHello: строгий разбор signature_algorithms")
class TlsClientHelloSignatureAlgorithmsTest {

    private static final int EXT = TlsConstants.EXT_SIGNATURE_ALGORITHMS;

    @BeforeAll
    static void setUp() {
        // сертификат сервера общий с тестом выбора PSK: помощники берут его оттуда
        TlsHandshakeEnginePskSelectionTest.setUp();
    }

    /** Тела расширения с нарушением структуры. */
    private static byte[][] malformedBodies() {
        return new byte[][] {
            // пустой список: algLen == 0, RFC 8446 §4.2.3 требует не меньше одной схемы
            {0x00, 0x00},
            // нечётная длина списка
            {0x00, 0x03, 0x07, 0x09, 0x07},
            // длина списка больше фактической
            {0x00, 0x04, 0x07, 0x09},
            // мусор в хвосте расширения: algLen + 2 != len
            {0x00, 0x02, 0x07, 0x09, 0x07},
            // расширение из одного байта
            {0x07}
        };
    }

    @Test
    @DisplayName("битый список без PSK: decode_error")
    void malformedListIsRejectedWithoutPsk() throws Exception {
        for (byte[] body : malformedBodies()) {
            byte[] frame =
                    fixtureWith(known(1))
                            .withoutPskExtension()
                            .replaceBaseExtension(EXT, body)
                            .build();

            TlsException error = receiveRejected(server(storeWith()), frame);

            assertAlert(TlsConstants.ALERT_DECODE_ERROR, error);
        }
    }

    @Test
    @DisplayName("битый список при принятом PSK: decode_error (раньше принимался молча)")
    void malformedListIsRejectedWithAcceptedPsk() throws Exception {
        for (byte[] body : malformedBodies()) {
            byte[] frame = fixtureWith(known(1)).replaceBaseExtension(EXT, body).build();

            TlsException error = receiveRejected(server(storeWith(known(1))), frame);

            assertAlert(TlsConstants.ALERT_DECODE_ERROR, error);
        }
    }

    @Test
    @DisplayName("парсер без цепочки сервера тоже проверяет структуру: decode_error")
    void malformedListIsRejectedWhenNoSchemeIsNeeded() throws Exception {
        for (byte[] body : malformedBodies()) {
            byte[] frame =
                    fixtureWith(known(1))
                            .withoutPskExtension()
                            .replaceBaseExtension(EXT, body)
                            .build();
            byte[] chBody = java.util.Arrays.copyOfRange(frame, 4, frame.length);

            TlsException error =
                    org.junit.jupiter.api.Assertions.assertThrows(
                            TlsException.class,
                            () ->
                                    TlsMessageParser.parseClientHello(
                                            chBody, TlsConstants.GRP_GC256A, null, 0));

            assertEquals(TlsConstants.ALERT_DECODE_ERROR, error.getAlertCode());
        }
    }

    @Test
    @DisplayName("нет ни PSK, ни signature_algorithms: missing_extension")
    void absentWithoutPskIsRejected() throws Exception {
        byte[] frame =
                fixtureWith(known(1)).withoutPskExtension().withoutBaseExtension(EXT).build();

        TlsException error = receiveRejected(server(storeWith()), frame);

        assertAlert(TlsConstants.ALERT_MISSING_EXTENSION, error);
    }

    @Test
    @DisplayName("PSK принят, signature_algorithms нет: рукопожатие продолжается (RFC 8446 §9.2)")
    void absentWithAcceptedPskIsAllowed() throws Exception {
        byte[] frame = fixtureWith(known(1)).withoutBaseExtension(EXT).build();
        TlsHandshakeEngine server = server(storeWith(known(1)));

        server.receive(frame);

        assertTrue(server.isPskAccepted(), "PSK должен быть принят");
    }

    @Test
    @DisplayName("PSK предложен, но отвергнут, signature_algorithms нет: missing_extension")
    void absentWithRejectedPskIsRejected() throws Exception {
        byte[] frame = fixtureWith(stranger()).withoutBaseExtension(EXT).build();

        TlsException error = receiveRejected(server(storeWith(known(1))), frame);

        assertAlert(TlsConstants.ALERT_MISSING_EXTENSION, error);
    }

    @Test
    @DisplayName("корректный список по-прежнему принимается")
    void wellFormedListIsAccepted() throws Exception {
        byte[] frame = fixtureWith(known(1)).withoutPskExtension().build();
        TlsHandshakeEngine server = server(storeWith());

        server.receive(frame);

        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
    }
}
