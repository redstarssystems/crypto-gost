package org.rssys.gost.crossval.jsse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.jsse.OpenSslJsseCrossValidationTest.CurveSpec;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Возобновление по PSK клиента jsse ({@link GostSSLEngine}) с сервером OpenSSL ({@code s_server}).
 *
 * <p>Клиент jsse строит ClientHello тем же сборщиком, что и клиент tls13: по ошибке в формате
 * расширения {@code pre_shared_key} внешний сервер рвал второе соединение фатальным
 * {@code decode_error}. Оба соединения идут без HelloRetryRequest: группа key_share клиента
 * совпадает с группой сервера (по умолчанию клиент начинает с GC256B, для остальных кривых группа
 * задаётся {@code setClientNamedGroup}). Возобновление через HelloRetryRequest здесь не
 * проверяется: binder второго ClientHello считается иначе, чем у внешних реализаций.
 */
@DisplayName("jsse: возобновление по PSK клиента GostSSLEngine <-> OpenSSL s_server")
class OpenSslJsseResumptionCrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String SUITE_S = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";
    private static final int SOCKET_TIMEOUT_MS = 15_000;
    private static final long ACCEPT_TIMEOUT_MS = 10_000;
    private static final String REQUEST = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslJsseHelper.assumeGostTls13();
        Security.addProvider(new RssysGostJsseProvider());
    }

    static Stream<Arguments> suitesAndCurves() {
        return Stream.of("GC256B", "GC256A")
                .flatMap(curve -> Stream.of(
                        Arguments.of(SUITE_L, curve),
                        Arguments.of(SUITE_S, curve)));
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("suitesAndCurves")
    @DisplayName("клиент GostSSLEngine + s_server: второе соединение возобновляется по тикету")
    void clientResumesAgainstOpenSslServer(String suiteName, String curveName) throws Exception {
        CurveSpec curve = findCurve(curveName);
        TlsCiphersuite suite = suiteName.equals(SUITE_L)
                ? TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L
                : TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
        int port = OpenSslJsseHelper.findFreePort();

        TempDirUtils.withTempDir("jsse-resume-client-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
            Process sServer = OpenSslJsseHelper.startSServer(port, suiteName, curve.ianaName(),
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName());
            try {
                assertTrue(OpenSslJsseHelper.waitForString(sServer, "ACCEPT", ACCEPT_TIMEOUT_MS),
                        "s_server не запустился");

                // Тикет привязан к экземпляру менеджера доверия и к контексту сессий: оба
                // соединения используют одни и те же объекты
                GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
                GostSSLSessionContext sessions =
                        new GostSSLSessionContext(suite);

                boolean first = connectAndRequest(port, trust, sessions, curve);
                assertFalse(first, "первое соединение полное: тикета ещё нет");
                assertTrue(sessions.getPskStore().size() > 0,
                        "тикеты s_server должны быть сохранены клиентом после первого соединения");

                boolean second = connectAndRequest(port, trust, sessions, curve);
                assertTrue(second, "второе соединение должно возобновиться по тикету s_server");
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            return null;
        });
    }

    @DisplayName("клиент GostSSLEngine + s_server: тикет из рукопожатия с HelloRetryRequest"
            + " возобновляется без него")
    @org.junit.jupiter.api.Test
    void ticketFromHrrHandshakeResumes() throws Exception {
        CurveSpec curve = findCurve("GC256A");
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        int port = OpenSslJsseHelper.findFreePort();

        TempDirUtils.withTempDir("jsse-resume-hrr-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
            Process sServer = OpenSslJsseHelper.startSServer(port, SUITE_L, curve.ianaName(),
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName());
            try {
                assertTrue(OpenSslJsseHelper.waitForString(sServer, "ACCEPT", ACCEPT_TIMEOUT_MS),
                        "s_server не запустился");
                GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
                GostSSLSessionContext sessions =
                        new GostSSLSessionContext(suite);

                // Первое рукопожатие: клиент начинает с GC256B, s_server требует GC256A -> HRR.
                // Resumption master secret считается по транскрипту после HRR (message_hash).
                boolean first = connectAndRequest(port, trust, sessions, null);
                assertFalse(first, "первое соединение полное");
                assertTrue(sessions.getPskStore().size() > 0, "тикеты должны быть сохранены");

                // Возобновление: клиент сразу предлагает GC256A, HRR нет
                boolean second = connectAndRequest(port, trust, sessions, curve);
                assertTrue(second,
                        "тикет из рукопожатия с HRR должен возобновляться: RMS после HRR верен");
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            return null;
        });
    }

    /**
     * Одно соединение клиента jsse; возвращает true, если оно возобновлено по PSK.
     *
     * @param startGroup кривая, группу которой клиент предлагает сразу; {@code null} или GC256B -
     *                   группа по умолчанию
     */
    private static boolean connectAndRequest(int port, GostX509TrustManager trust,
                                             GostSSLSessionContext sessions, CurveSpec startGroup)
            throws Exception {
        try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            GostSSLEngine client = GostSSLEngine.createForClientNoHostnameCheck(
                    new GostX509KeyManager(), trust, "localhost", port, sessions);
            // Клиент начинает с группы сервера: иначе s_server ответит HelloRetryRequest
            // (группа клиента по умолчанию GC256B)
            if (startGroup != null && startGroup.groupId() != TlsConstants.GRP_GC256B) {
                client.setClientNamedGroup(startGroup.groupId());
            }
            client.beginHandshake();
            OpenSslJsseHelper.doEngineHandshakeOverTcp(client, socket);

            // чтение ответа заодно обрабатывает NewSessionTicket сервера
            byte[] response = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(
                    client, REQUEST.getBytes(StandardCharsets.UTF_8), socket);
            String text = new String(response, StandardCharsets.UTF_8);
            assertTrue(text.contains("TLS") || text.contains("HTTP"),
                    "ответ s_server должен содержать данные соединения");
            return client.wasResumed();
        }
    }

    private static CurveSpec findCurve(String ianaName) {
        return OpenSslJsseCrossValidationTest.ALL_CURVES.stream()
                .filter(c -> c.ianaName().equals(ianaName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve: " + ianaName));
    }
}
