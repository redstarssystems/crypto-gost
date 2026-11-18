package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.engine.HandshakeOutput;
import org.rssys.gost.tls13.engine.HandshakeOutputs;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * Клиентский цикл приёма рукопожатия при нестандартной нарезке зашифрованного полёта сервера на
 * записи.
 *
 * <p>Собственный отправитель никогда не склеивает сообщения и режет их только по размеру записи,
 * поэтому такие раскладки приходят лишь от чужих узлов. Зашифрованные записи нельзя перекроить на
 * уровне транспорта (у каждой свой тег и номер), так что сервером служит настоящий
 * {@link TlsHandshakeEngine}, а тест сам шифрует его полёт и режет по нужной схеме.
 */
@DisplayName("TlsSession: раскладка зашифрованного полёта сервера по записям")
class TlsSessionServerFlightLayoutTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";

    /** Как зашифрованные сообщения полёта (EE, Certificate, CV, Finished) разложены по записям. */
    enum Layout {
        /** Всё в одной записи: четыре сообщения склеены. */
        ALL_IN_ONE_RECORD,
        /** Граница записи посреди 4-байтного заголовка второго сообщения. */
        CUT_INSIDE_SECOND_MESSAGE_HEADER,
        /** Каждая запись несёт один байт: заголовки и тела разорваны везде. */
        ONE_BYTE_RECORDS
    }

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() {
        serverCert =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {HOST});
    }

    /**
     * Транспорт сервера: на ClientHello клиента отвечает полётом, который строит движок и
     * шифрует тест. Остальное, что шлёт клиент (его Finished), игнорируется: клиентскому
     * рукопожатию после отправки Finished ответа не нужно.
     */
    private static final class EngineServerTransport implements TlsTransport {
        private final TlsHandshakeEngine server;
        private final Layout layout;
        private final ArrayDeque<byte[]> toClient = new ArrayDeque<>();
        private boolean clientHelloSeen;

        EngineServerTransport(TlsHandshakeEngine server, Layout layout) {
            this.server = server;
            this.layout = layout;
        }

        @Override
        public void sendRecord(byte[] record) throws IOException {
            if (clientHelloSeen) {
                return;
            }
            clientHelloSeen = true;
            try {
                answerClientHello(record);
            } catch (Exception e) {
                throw new IOException("тестовый сервер не смог ответить на ClientHello", e);
            }
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            byte[] record = toClient.poll();
            if (record == null) {
                throw new IOException("тестовый сервер: записи кончились");
            }
            return record;
        }

        @Override
        public void close() {}

        private void answerClientHello(byte[] clientHelloRecord) throws Exception {
            byte[] clientHello =
                    Arrays.copyOfRange(
                            clientHelloRecord,
                            TlsConstants.RECORD_HEADER_SIZE,
                            clientHelloRecord.length);
            server.receive(clientHello);

            // Поток сервера: ServerHello, смена ключа на ключи рукопожатия, затем полёт
            HandshakeOutput.Message serverHello = (HandshakeOutput.Message) server.poll();
            toClient.add(
                    TlsMessageBuilder.buildPlaintextRecord(
                            TlsConstants.CT_HANDSHAKE, serverHello.frame()));
            if (server.takeServerCompatCcs()) {
                toClient.add(TlsUtils.buildCompatibilityCcsRecord());
            }
            TlsTrafficKeys writeKeys = ((HandshakeOutput.WriteKeyChange) server.poll()).keys();
            server.acknowledgeReadKeyChange();

            List<Integer> frameLengths = new ArrayList<>();
            ByteArrayOutputStream flight = new ByteArrayOutputStream();
            byte[] frame;
            while ((frame = HandshakeOutputs.nextMessage(server)) != null) {
                frameLengths.add(frame.length);
                flight.write(frame);
            }
            assertEquals(4, frameLengths.size(), "полёт: EE, Certificate, CV, Finished");

            TlsRecord writer =
                    new TlsRecord(writeKeys.getKey(), writeKeys.getIv(), SUITE.getTagLen(), SUITE);
            byte[] data = flight.toByteArray();
            for (int[] part : partition(data.length, frameLengths.get(0))) {
                toClient.add(writer.protect(TlsConstants.CT_HANDSHAKE, data, part[0], part[1]));
            }
        }

        /** Разбивает {@code total} байт полёта на записи: пары {смещение, длина}. */
        private List<int[]> partition(int total, int firstFrameLength) {
            List<int[]> parts = new ArrayList<>();
            switch (layout) {
                case ALL_IN_ONE_RECORD:
                    parts.add(new int[] {0, total});
                    break;
                case CUT_INSIDE_SECOND_MESSAGE_HEADER:
                    int cut = firstFrameLength + TlsConstants.HANDSHAKE_HEADER_SIZE / 2;
                    parts.add(new int[] {0, cut});
                    parts.add(new int[] {cut, total - cut});
                    break;
                case ONE_BYTE_RECORDS:
                    for (int offset = 0; offset < total; offset++) {
                        parts.add(new int[] {offset, 1});
                    }
                    break;
            }
            return parts;
        }
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Layout.class)
    @DisplayName("Клиент завершает рукопожатие при любой раскладке полёта по записям")
    void clientHandshakeSurvivesAnyFlightLayout(Layout layout) throws Exception {
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        SUITE,
                        new TlsMessageBuilder(
                                SUITE,
                                List.of(SUITE.getId()),
                                TlsConstants.GRP_GC256A,
                                TlsConstants.SIG_GOST_TC26_A_256,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                TlsConstants.STREEBOG_256_HASH_LEN),
                        ECParameters.tc26a256(),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        TlsConstants.STREEBOG_256_HASH_LEN,
                        null,
                        false,
                        null);
        EngineServerTransport transport = new EngineServerTransport(server, layout);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(serverCert.cert))
                                .withServerHostname(HOST)
                                // Группа как у сервера, иначе придёт HelloRetryRequest
                                // и не будет полёта, который нарезает тест
                                .withSelectedNamedGroup(TlsConstants.GRP_GC256A),
                        transport);
        try {
            client.handshakeAsClient();

            assertTrue(client.isHandshakeDone(), "Клиент завершил рукопожатие");
            assertEquals(1, client.getPeerCertificates().size(), "Получена цепочка сервера");
            assertArrayEquals(
                    serverCert.cert.getEncoded(),
                    client.getPeerCertificates().get(0).getEncoded(),
                    "Сертификат, собранный из записей, совпадает с отправленным");
        } finally {
            client.close();
        }
    }
}
