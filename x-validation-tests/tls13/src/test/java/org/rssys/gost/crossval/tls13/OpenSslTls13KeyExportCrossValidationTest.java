package org.rssys.gost.crossval.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.tls13.OpenSslTls13CrossValidationTest.CurveSpec;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

/**
 * Экспорт ключевого материала (RFC 8446 §7.5) crypto-gost и OpenSSL (gostprov, TLS 1.3).
 *
 * <p>Для ГОСТ-наборов RFC 9367 экспорт не определяет, тестовых векторов нет, поэтому совпадение с
 * {@code -keymatexport} OpenSSL единственная внешняя проверка выведенного секрета. Командная
 * строка OpenSSL не задаёт контекст, значит, проверяется пустой контекст.
 */
@DisplayName("TLS 1.3: экспорт ключевого материала crypto-gost <-> OpenSSL")
class OpenSslTls13KeyExportCrossValidationTest {

    private static final String SUITE_NAME = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final int SUITE_ID = 0xC103;
    private static final String CURVE = "GC256B";
    private static final String LABEL = "EXPORTER-Channel-Binding";
    private static final int EXPORT_LENGTH = 32;
    private static final long TIMEOUT_MS = 30_000;
    private static final int ACCEPT_TIMEOUT_MS = 30_000;
    private static final int PEER_IO_TIMEOUT_MS = 15_000;
    private static final long SERVER_JOIN_MS = 10_000;
    private static final long OUTPUT_WAIT_MS = 10_000;
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final Pattern KEYING_MATERIAL =
            Pattern.compile("Keying material: ([0-9A-Fa-f]+)");

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslTls13Helper.assumeGostTls13();
    }

    private static String[] keyExportArgs() {
        return new String[] {
            "-keymatexport", LABEL, "-keymatexportlen", String.valueOf(EXPORT_LENGTH)
        };
    }

    private static String keyingMaterialOf(String output) {
        Matcher matcher = KEYING_MATERIAL.matcher(output);
        assertTrue(matcher.find(), "OpenSSL не напечатал Keying material:\n" + output);
        return matcher.group(1).toLowerCase();
    }

    @Test
    @DisplayName("клиент crypto-gost + s_server: экспортированные значения совпадают")
    void clientExportMatchesOpenSslServer() throws Exception {
        CurveSpec curve = OpenSslTls13ResumptionCrossValidationTest.curve(CURVE);
        int port = OpenSslTls13Helper.findFreePort();
        TempDirUtils.withTempDir(
                "tls13-export-client-",
                tmpDir -> {
                    OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
                    String[] serverArgs = new String[6];
                    serverArgs[0] = "-sigalgs";
                    serverArgs[1] = curve.sigalgsName();
                    System.arraycopy(keyExportArgs(), 0, serverArgs, 2, 4);
                    try (TracedServer server =
                            new TracedServer(
                                    OpenSslTls13Helper.startSServerWithoutWww(
                                            port,
                                            SUITE_NAME,
                                            curve.ianaName(),
                                            tmpDir.resolve("cert.pem").toString(),
                                            tmpDir.resolve("key.pem").toString(),
                                            serverArgs))) {
                        assertTrue(server.awaitOutput("ACCEPT", 10_000), "s_server не запустился");
                        GostCertificate serverCert =
                                GostCertificate.fromPemOrDer(
                                        Files.readAllBytes(tmpDir.resolve("cert.pem")));
                        String ours = exportAsClient(port, serverCert);

                        assertTrue(
                                server.awaitMatches(KEYING_MATERIAL, 1, OUTPUT_WAIT_MS) >= 1,
                                "s_server не напечатал Keying material:\n" + server.output);
                        assertEquals(
                                keyingMaterialOf(server.output.toString()),
                                ours,
                                "значения клиента crypto-gost и s_server должны совпасть");
                    }
                    return null;
                });
    }

    private static String exportAsClient(int port, GostCertificate serverCert) throws Exception {
        TlsClientConfig config =
                new TlsClientConfig(
                                TlsCiphersuite.byId(SUITE_ID), TrustAnchors.ofCertificate(serverCert))
                        .withoutHostnameVerification();
        try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                SocketTlsTransport transport = new SocketTlsTransport(socket);
                TlsSession client = TlsSession.createClient(config, transport)) {
            socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
            client.handshakeAsClient();
            byte[] value = client.exportKeyingMaterial(LABEL, null, EXPORT_LENGTH);
            // s_server без -www ответа не шлёт: данные нужны только затем, чтобы он завершил
            // разбор соединения и напечатал значение
            client.write("ping\n".getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(value);
        }
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client: значения совпадают и после возобновления по тикету")
    void serverExportMatchesOpenSslClientIncludingResumption() throws Exception {
        CurveSpec curve = OpenSslTls13ResumptionCrossValidationTest.curve(CURVE);
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params());
        TlsServerConfig config =
                new TlsServerConfig(
                        TlsCiphersuite.byId(SUITE_ID),
                        Collections.singletonList(bundle.cert),
                        bundle.priv);
        InMemoryPskStore store = new InMemoryPskStore(10);
        List<String> ourValues = new CopyOnWriteArrayList<>();
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener = new ServerSocket(port, 5, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Thread serverThread =
                    Thread.ofVirtual()
                            .start(
                                    () ->
                                            serveTwice(
                                                    listener,
                                                    config,
                                                    store,
                                                    ourValues,
                                                    resumed,
                                                    serverError));
            TempDirUtils.withTempDir(
                    "tls13-export-server-",
                    tmpDir -> {
                        Path session = tmpDir.resolve("session.pem");
                        String[] first = new String[6];
                        first[0] = "-sess_out";
                        first[1] = session.toString();
                        System.arraycopy(keyExportArgs(), 0, first, 2, 4);
                        String[] second = first.clone();
                        second[0] = "-sess_in";

                        String firstOutput =
                                OpenSslTls13Helper.runSClientWithHttpGet(
                                        port, SUITE_NAME, curve.ianaName(), TIMEOUT_MS, first);
                        String secondOutput =
                                OpenSslTls13Helper.runSClientWithHttpGet(
                                        port, SUITE_NAME, curve.ianaName(), TIMEOUT_MS, second);

                        serverThread.join(SERVER_JOIN_MS);
                        assertNull(serverError.get(), "ошибка сервера: " + serverError.get());
                        assertEquals(List.of(false, true), resumed, "второе соединение возобновлено");
                        assertEquals(2, ourValues.size(), "сервер экспортировал оба соединения");
                        assertEquals(
                                keyingMaterialOf(firstOutput),
                                ourValues.get(0),
                                "полное рукопожатие: значения сервера и s_client должны совпасть");
                        assertEquals(
                                keyingMaterialOf(secondOutput),
                                ourValues.get(1),
                                "возобновление: значения сервера и s_client должны совпасть");
                        assertNotEquals(
                                ourValues.get(0),
                                ourValues.get(1),
                                "значение привязано к соединению, а не к сессии");
                        return null;
                    });
        }
    }

    private static void serveTwice(
            ServerSocket listener,
            TlsServerConfig config,
            InMemoryPskStore store,
            List<String> values,
            List<Boolean> resumed,
            AtomicReference<Throwable> serverError) {
        try {
            for (int i = 0; i < 2; i++) {
                try (Socket socket = listener.accept();
                        SocketTlsTransport transport = new SocketTlsTransport(socket);
                        TlsSession session = TlsSession.createServer(config, transport)) {
                    socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
                    session.setPskStore(store);
                    session.handshakeAsServer();
                    byte[] value = session.exportKeyingMaterial(LABEL, null, EXPORT_LENGTH);
                    values.add(HexFormat.of().formatHex(value));
                    resumed.add(session.wasResumed());
                    session.read();
                    session.write(RESPONSE_MARKER.getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable e) {
            serverError.set(e);
        }
    }
}
