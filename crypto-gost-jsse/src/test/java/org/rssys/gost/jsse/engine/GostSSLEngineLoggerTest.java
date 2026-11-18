package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

@DisplayName("GostSSLEngine: записи журнала")
class GostSSLEngineLoggerTest {

    private LogCapture log;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
    }

    @BeforeEach
    void captureLogger() {
        log = LogCapture.start(LogCapture.JSSE);
    }

    @AfterEach
    void restoreLogger() {
        log.close();
    }

    @Test
    @DisplayName("Лог: handshake start DEBUG при beginHandshake")
    void testHandshakeStartLogged() throws Exception {
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "example.com",
                        443,
                        true);

        clientEngine.beginHandshake();

        assertFalse(ownMessages(Level.FINE).isEmpty(), "Должен быть хотя бы один DEBUG лог");
        assertTrue(
                log.loggerNames().contains(GostSSLEngine.class.getName()),
                "имя логгера равно имени класса: " + log.loggerNames());
        assertTrue(
                containsMessage("Handshake started"),
                "Должен содержать 'Handshake started' в любом сообщении");
    }

    // Фрагмент именно handshake-предупреждения (отличается от создания "created WITHOUT")
    private static final String HANDSHAKE_NO_HOSTNAME =
            "Client TLS handshake without hostname verification";

    // предупреждение контекста сессий о режиме DISABLED
    private static final String DISABLED_MODE_WARNING = "Hostname verification is DISABLED";

    @Test
    @DisplayName("Серверный режим без host не пишет ложное предупреждение про PSK")
    void serverModeWithoutHostDoesNotWarnAboutPsk() {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "",
                        -1,
                        true);

        engine.setUseClientMode(false);

        assertTrue(
                ownMessages(Level.WARNING).isEmpty(),
                "сервер ищет тикет по идентификатору, а не по host: предупреждения быть не должно");
    }

    @Test
    @DisplayName(
            "Лог: режим DISABLED — один WARNING при включении, ноль при создании и рукопожатии")
    void testDisabledModeLogsOnceOnEnable() throws Exception {
        GostSSLSessionContext sc =
                new GostSSLSessionContext(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);

        sc.setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        // повторное включение того же режима нового сигнала не даёт
        sc.setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);

        assertEquals(
                1,
                countWarningsContaining(DISABLED_MODE_WARNING),
                "Ровно один WARNING при включении режима на контексте");
        assertTrue(
                log.loggerNames().contains(GostSSLSessionContext.class.getName()),
                "имя логгера равно имени класса: " + log.loggerNames());

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "example.com",
                        443,
                        sc);
        clientEngine.beginHandshake();

        assertEquals(
                1,
                countWarningsContaining(DISABLED_MODE_WARNING),
                "Создание engine не должно добавлять предупреждений");
        assertEquals(
                0,
                countWarningsContaining(HANDSHAKE_NO_HOSTNAME),
                "Opt-out контекста не должен давать handshake-WARNING");
    }

    private long countWarningsContaining(String fragment) {
        return ownMessages(Level.WARNING).stream().filter(m -> m.contains(fragment)).count();
    }

    @Test
    @DisplayName(
            "Лог: осознанный opt-out (createForClientNoHostnameCheck) не даёт handshake-WARNING")
    void testExplicitNoHostnameCheckSuppressesHandshakeWarning() throws Exception {
        // намерение объявлено разово при создании — повтор на каждом соединении избыточен
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClientNoHostnameCheck(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "example.com",
                        443,
                        null);

        clientEngine.beginHandshake();

        assertFalse(
                containsMessage(HANDSHAKE_NO_HOSTNAME),
                "explicit opt-out не должен логировать handshake-WARNING о проверке hostname");
    }

    @Test
    @DisplayName("Лог: снятый safe-default (setSSLParameters null) даёт handshake-WARNING")
    void testClearedSafeDefaultWarnsPerHandshake() throws Exception {
        // safe-default HTTPS, затем очистка через setSSLParameters(null) — тревожный сигнал
        GostSSLEngine clientEngine =
                GostSSLEngine.createForContextClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "example.com",
                        443,
                        null,
                        null);
        javax.net.ssl.SSLParameters p = clientEngine.getSSLParameters();
        p.setEndpointIdentificationAlgorithm(null);
        clientEngine.setSSLParameters(p);

        clientEngine.beginHandshake();

        assertTrue(
                containsMessage(HANDSHAKE_NO_HOSTNAME),
                "снятый safe-default должен логировать handshake-WARNING per-connection");
    }

    @Test
    @DisplayName("Лог: активная проверка hostname (safe-default) не даёт handshake-WARNING")
    void testActiveVerificationNoWarning() throws Exception {
        GostSSLEngine clientEngine =
                GostSSLEngine.createForContextClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "example.com",
                        443,
                        null,
                        null);

        clientEngine.beginHandshake();

        assertFalse(
                containsMessage(HANDSHAKE_NO_HOSTNAME),
                "при активной проверке hostname handshake-WARNING не нужен");
    }

    private static GostSSLEngine plainClient() {
        return new GostSSLEngine(
                new GostX509KeyManager(),
                GostX509TrustManager.insecureTrustAll(),
                "example.com",
                443,
                true);
    }

    @Test
    @DisplayName("Лог close_notify: запись собрана - «queued», ложного «not sent» нет")
    void closeNotifyQueuedIsLoggedWhenRecordBuilt() {
        GostSSLEngine engine = plainClient();

        engine.closeOutbound();

        assertTrue(containsMessage("close_notify queued"));
        assertFalse(containsMessage("close_notify not sent"));
    }

    @Test
    @DisplayName(
            "Лог close_notify: отвечать нечем (после closeInbound) - «not sent», а не «queued»")
    void closeNotifyNotSentIsLoggedWithoutWriteKeys() throws Exception {
        GostSSLEngine engine = plainClient();
        engine.closeInbound();

        engine.closeOutbound();

        assertTrue(containsMessage("close_notify not sent"));
        assertFalse(
                containsMessage("close_notify queued"),
                "журнал не должен сообщать об отправке, которой не было");
    }

    @Test
    @DisplayName("Два движка получают разные метки conn#")
    void connectionLabelsAreUnique() throws Exception {
        GostSSLEngine first = plainClient();
        GostSSLEngine second = plainClient();

        first.beginHandshake();
        second.beginHandshake();

        assertNotNull(first.getConnectionLabel(), "метка первого движка");
        assertNotNull(second.getConnectionLabel(), "метка второго движка");
        assertNotEquals(
                first.getConnectionLabel(), second.getConnectionLabel(), "метки не совпадают");
        assertTrue(
                first.getConnectionLabel().matches("conn#\\d+"),
                "формат метки: " + first.getConnectionLabel());
    }

    @Test
    @DisplayName("Отказ сертификата пира: одна DEBUG-запись, без WARNING и без стека")
    void peerCertificateRejectionIsOneDebugRecord() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle serverRoot = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle foreignRoot = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        serverRoot.priv,
                        serverRoot.cert.getPublicKey(),
                        serverRoot.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        null,
                        null,
                        false,
                        null);

        GostX509KeyManager serverKeys = new GostX509KeyManager();
        serverKeys.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, serverRoot.cert)),
                serverCert.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKeys, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(foreignRoot.cert)),
                        "localhost",
                        0,
                        true);

        // Проверка hostname включена явно: иначе движок на каждом рукопожатии предупреждает
        // о выключенной проверке, и это предупреждение не относится к отказу сертификата
        javax.net.ssl.SSLParameters paramsWithHttps = client.getSSLParameters();
        paramsWithHttps.setEndpointIdentificationAlgorithm("HTTPS");
        client.setSSLParameters(paramsWithHttps);
        log.clear();

        assertThrows(
                Exception.class,
                () ->
                        GostSSLEngineLoopbackTest.doLoopback(
                                client, server, InMemoryTlsTransport.newPair()),
                "сертификат сервера не должен проходить проверку у клиента");

        List<String> debug = log.messages(Level.FINE, "GostSSLEngine");
        assertTrue(
                debug.stream().anyMatch(m -> m.contains("Peer certificate rejected")),
                "отказ сертификата пира на DEBUG: " + debug);
        assertTrue(
                debug.stream().anyMatch(m -> m.contains("stage=") && m.contains("alert=")),
                "в записи есть стадия и код alert: " + debug);
        assertEquals(
                List.of(),
                log.messages(Level.WARNING, "GostSSLEngine"),
                "отказ собеседника не пишется на WARNING");
        assertEquals(List.of(), log.thrown(), "исключение со стеком в журнал не попадает");
    }

    /** Записи движка и контекста сессий: других классов модуля (менеджер доверия) здесь не ждём. */
    private List<String> ownMessages(Level level) {
        List<String> own = new ArrayList<>(log.messages(level, "GostSSLEngine"));
        own.addAll(log.messages(level, "GostSSLSessionContext"));
        return own;
    }

    /** Есть ли среди записей любого уровня движка и контекста текст с фрагментом. */
    private boolean containsMessage(String fragment) {
        List<String> own = new ArrayList<>(log.allMessages("GostSSLEngine"));
        own.addAll(log.allMessages("GostSSLSessionContext"));
        return own.stream().anyMatch(m -> m.contains(fragment));
    }
}
