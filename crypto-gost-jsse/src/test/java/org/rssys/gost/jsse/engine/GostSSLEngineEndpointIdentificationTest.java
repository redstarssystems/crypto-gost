package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.jsse.EndpointIdentification;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Флаг {@code preserveEndpointIdentificationOnNull}, неподдерживаемые алгоритмы проверки имени
 * и единая точка валидации в trust manager.
 */
@DisplayName("GostSSLEngine: алгоритм проверки имени (endpoint identification)")
class GostSSLEngineEndpointIdentificationTest {

    private static final String WRONG_HOST = "wronghost.invalid";

    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostCertificate caCert;
    private static PkixCertTestHelper.CertBundle serverCertLocalhost;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        caCert = rootCa.cert;
        serverCertLocalhost =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    // ========================================================================
    // Матрица null / "" на контексте с флагом и без него
    // ========================================================================

    @Test
    @DisplayName("Флаг по умолчанию выключен")
    void flagIsOffByDefault() throws Exception {
        GostSSLSessionContext ctx = clientSessionContext(newClientContext());
        assertEquals(
                EndpointIdentificationMode.DEFAULT,
                ctx.getEndpointIdentificationMode(),
                "по умолчанию режим DEFAULT");
    }

    @Test
    @DisplayName("Контекст без флага: null очищает HTTPS (контракт JSSE)")
    void nullClearsWithoutFlag() throws Exception {
        SSLEngine engine = newClientContext().createSSLEngine("localhost", 8443);
        applyAlgorithm(engine, null);
        assertNull(algorithmOf(engine), "без флага null должен отключать проверку имени");
    }

    @Test
    @DisplayName("Контекст с флагом: null не меняет HTTPS")
    void nullKeepsHttpsWithFlag() throws Exception {
        SSLEngine engine = engineWithFlag("localhost", 8443);
        applyAlgorithm(engine, null);
        assertEquals("HTTPS", algorithmOf(engine), "с флагом null не должен снимать HTTPS");
    }

    @Test
    @DisplayName("Контекст с флагом: пустая строка явно отключает, последующий null это сохраняет")
    void emptyStringDisablesAndStaysWithFlag() throws Exception {
        SSLEngine engine = engineWithFlag("localhost", 8443);
        applyAlgorithm(engine, "");
        assertTrue(
                EndpointIdentification.isDisabled(algorithmOf(engine)),
                "пустая строка должна отключать проверку");
        applyAlgorithm(engine, null);
        assertTrue(
                EndpointIdentification.isDisabled(algorithmOf(engine)),
                "null после пустой строки не должен возвращать HTTPS");
    }

    @Test
    @DisplayName("Контекст с флагом: явный LDAPS остаётся после null")
    void explicitLdapsStaysWithFlag() throws Exception {
        SSLEngine engine = engineWithFlag("localhost", 8443);
        applyAlgorithm(engine, "LDAPS");
        applyAlgorithm(engine, null);
        assertEquals("LDAPS", algorithmOf(engine), "явный LDAPS должен сохраниться");
    }

    @Test
    @DisplayName("Контекст без флага: явный HTTPS после null очищается")
    void explicitHttpsClearedByNullWithoutFlag() throws Exception {
        SSLEngine engine = newClientContext().createSSLEngine("localhost", 8443);
        applyAlgorithm(engine, "HTTPS");
        applyAlgorithm(engine, null);
        assertNull(algorithmOf(engine), "без флага null очищает даже явный HTTPS");
    }

    @Test
    @DisplayName("Флаг, включённый после создания engine, действует на последующий null")
    void flagAfterEngineCreationAffectsNextNull() throws Exception {
        SSLContext ctx = newClientContext();
        SSLEngine engine = ctx.createSSLEngine("localhost", 8443);
        clientSessionContext(ctx).setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        applyAlgorithm(engine, null);
        assertEquals("HTTPS", algorithmOf(engine), "флаг должен действовать на следующий null");
    }

    @Test
    @DisplayName("Публичный конструктор без sessionContext: null не вызывает NPE и отключает")
    void publicConstructorWithoutSessionContext() {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        8443,
                        true);
        assertDoesNotThrow(() -> applyAlgorithm(engine, null));
        assertNull(algorithmOf(engine), "без контекста null присваивается как раньше");
    }

    @Test
    @DisplayName("Флаг + opt-out контекста: HTTPS не ставится, null оставляет null")
    void disabledContextKeepsNull() throws Exception {
        SSLContext ctx = newClientContext();
        GostSSLSessionContext sessionContext = clientSessionContext(ctx);
        sessionContext.setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        SSLEngine engine = ctx.createSSLEngine("localhost", 8443);
        assertNull(algorithmOf(engine), "при opt-out HTTPS не ставится при создании");
        applyAlgorithm(engine, null);
        assertNull(algorithmOf(engine), "null оставляет отключённую проверку");
    }

    @Test
    @DisplayName("Opt-out без флага: явный HTTPS после null очищается")
    void optOutContextExplicitHttpsClearedByNull() throws Exception {
        SSLContext ctx = newClientContext();
        clientSessionContext(ctx)
                .setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        SSLEngine engine = ctx.createSSLEngine("localhost", 8443);
        applyAlgorithm(engine, "HTTPS");
        assertEquals("HTTPS", algorithmOf(engine), "явная настройка применяется");
        applyAlgorithm(engine, null);
        assertNull(algorithmOf(engine), "на opt-out-контексте флага нет, null очищает");
    }

    @Test
    @DisplayName("disabled=true после создания engine не снимает уже поставленный HTTPS")
    void disabledAfterCreationDoesNotClearHttps() throws Exception {
        SSLContext ctx = newClientContext();
        SSLEngine engine = ctx.createSSLEngine("localhost", 8443);
        clientSessionContext(ctx)
                .setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        assertEquals("HTTPS", algorithmOf(engine), "созданный engine не должен меняться");
    }

    @Test
    @DisplayName("createSSLEngine() без host и blank host: HTTPS не ставится")
    void noHostAndBlankHostGetNoHttps() throws Exception {
        SSLContext ctx = newClientContext();
        assertNull(algorithmOf(ctx.createSSLEngine()), "без host проверять нечего");
        assertNull(algorithmOf(ctx.createSSLEngine(" ", 8443)), "blank host равен отсутствию host");
        assertNull(algorithmOf(ctx.createSSLEngine(null, 8443)), "null host равен отсутствию host");
    }

    @Test
    @DisplayName("Строгий режим без host и с blank host: отказ на beginHandshake до ClientHello")
    void strictModeWithoutHostRejectsAtBeginHandshake() throws Exception {
        for (String host : new String[] {null, " ", ""}) {
            SSLContext ctx = newClientContext();
            clientSessionContext(ctx)
                    .setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
            SSLEngine client =
                    host == null ? ctx.createSSLEngine() : ctx.createSSLEngine(host, 8443);
            applyAlgorithm(client, null);
            assertEquals(
                    "HTTPS", algorithmOf(client), "в строгом режиме HTTPS ставится и без host");
            SSLException e = assertThrows(SSLException.class, client::beginHandshake);
            assertTrue(
                    e.getMessage().contains("Peer host is required"),
                    "ожидался отказ из-за отсутствия host, получено: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("Строгий режим без host: явное отключение пустой строкой допускает рукопожатие")
    void strictModeWithoutHostAllowsExplicitDisable() throws Exception {
        SSLContext ctx = newClientContext();
        clientSessionContext(ctx).setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        GostSSLEngine client = (GostSSLEngine) ctx.createSSLEngine();
        applyAlgorithm(client, "");
        assertDoesNotThrow(
                () -> doLoopback(client, newServerEngine()),
                "явный opt-out пустой строкой не должен требовать host");
    }

    @Test
    @DisplayName("Строгий режим: серверный engine без host рукопожатие проходит")
    void strictModeDoesNotAffectServerEngine() throws Exception {
        SSLContext ctx = newClientContext();
        clientSessionContext(ctx).setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        GostSSLEngine server = (GostSSLEngine) ctx.createSSLEngine();
        server.setUseClientMode(false);
        assertDoesNotThrow(server::beginHandshake, "сервер имя клиента не сверяет");
    }

    @Test
    @DisplayName("setUseClientMode: роль переключается туда и обратно вместе с контекстом сессий")
    void useClientModeSwitchesSessionContextBothWays() throws Exception {
        SSLContext ctx = newClientContext();
        clientSessionContext(ctx).setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        SSLEngine engine = ctx.createSSLEngine();

        // Серверная роль не знает строгого режима клиентского контекста
        engine.setUseClientMode(false);
        // Возврат к клиентской роли возвращает и клиентский контекст: иначе строгий режим
        // молча пропал бы, а PSK брались бы из серверного хранилища
        engine.setUseClientMode(true);

        SSLException e = assertThrows(SSLException.class, engine::beginHandshake);
        assertTrue(
                e.getMessage().contains("Peer host is required"),
                "после возврата в клиентскую роль действует клиентский контекст: "
                        + e.getMessage());
    }

    @Test
    @DisplayName("Режим DISABLED без host: HTTPS не ставится, рукопожатие проходит")
    void disabledModeWithoutHostAllowsHandshake() throws Exception {
        SSLContext ctx = newClientContext();
        clientSessionContext(ctx)
                .setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        GostSSLEngine client = (GostSSLEngine) ctx.createSSLEngine();
        assertNull(algorithmOf(client), "при отключении HTTPS не ставится даже без host");
        assertDoesNotThrow(() -> doLoopback(client, newServerEngine()));
    }

    @Test
    @DisplayName("setEndpointIdentificationMode(null) отвергается")
    void nullModeRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> newSessionContext().setEndpointIdentificationMode(null));
    }

    @Test
    @DisplayName(
            "createForClient с пустым и blank host: рукопожатие падает на «peer host is missing»")
    void createForClientWithBlankHostFailsClosed() throws Exception {
        for (String host : new String[] {"", " "}) {
            GostSSLEngine client =
                    GostSSLEngine.createForClient(
                            new GostX509KeyManager(),
                            GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(caCert)),
                            host,
                            8443,
                            newSessionContext());
            assertEquals("HTTPS", algorithmOf(client), "createForClient ставит HTTPS всегда");
            CertificateException direct =
                    assertThrows(
                            CertificateException.class,
                            () -> GostX509TrustManager.requireHostnameForEndpointId(client),
                            "пустой host при HTTPS должен отклоняться trust manager");
            assertTrue(
                    direct.getMessage().contains("peer host is missing"),
                    "ожидалась ошибка «peer host is missing», получено: " + direct.getMessage());
            RuntimeException failure =
                    assertThrows(
                            RuntimeException.class, () -> doLoopback(client, newServerEngine()));
            assertInstanceOf(
                    SSLException.class,
                    failure.getCause(),
                    "рукопожатие должно завершаться SSLException, а не NPE");
        }
    }

    @Test
    @DisplayName("createForClientNoHostnameCheck: явный HTTPS остаётся после null только при флаге")
    void noHostnameCheckExplicitHttpsDependsOnFlag() throws Exception {
        for (boolean flag : new boolean[] {true, false}) {
            GostSSLSessionContext sessionContext = newSessionContext();
            sessionContext.setEndpointIdentificationMode(
                    flag ? EndpointIdentificationMode.STRICT : EndpointIdentificationMode.DEFAULT);
            GostSSLEngine client =
                    GostSSLEngine.createForClientNoHostnameCheck(
                            new GostX509KeyManager(),
                            GostX509TrustManager.insecureTrustAll(),
                            "localhost",
                            8443,
                            sessionContext);
            assertNull(algorithmOf(client), "NoHostnameCheck не ставит HTTPS");
            applyAlgorithm(client, null);
            assertNull(algorithmOf(client), "без явного HTTPS null оставляет null");
            applyAlgorithm(client, "HTTPS");
            applyAlgorithm(client, null);
            assertEquals(
                    flag ? "HTTPS" : null,
                    algorithmOf(client),
                    "явный HTTPS после null: остаётся только при флаге");
        }
    }

    // ========================================================================
    // Неподдерживаемые алгоритмы: beginHandshake и trust manager
    // ========================================================================

    @Test
    @DisplayName("beginHandshake: LDAP, мусор и пробел отвергаются до отправки ClientHello")
    void beginHandshakeRejectsUnsupportedAlgorithm() throws Exception {
        for (String algorithm : new String[] {"LDAP", "garbage", " "}) {
            SSLEngine engine = newClientContext().createSSLEngine("localhost", 8443);
            applyAlgorithm(engine, algorithm);
            SSLException e = assertThrows(SSLException.class, engine::beginHandshake);
            assertTrue(
                    e.getMessage().contains("Unsupported endpoint identification algorithm"),
                    "ожидалась ошибка алгоритма, получено: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("beginHandshake: пустая строка не бросает, отключённая проверка допустима")
    void beginHandshakeAcceptsEmptyAlgorithm() throws Exception {
        SSLEngine engine = newClientContext().createSSLEngine("localhost", 8443);
        applyAlgorithm(engine, "");
        assertDoesNotThrow(engine::beginHandshake);
    }

    @Test
    @DisplayName(
            "beginHandshake: неподдерживаемый алгоритм отвергается и при explicitNoHostnameCheck")
    void beginHandshakeRejectsUnsupportedWithExplicitNoCheck() {
        GostSSLEngine engine =
                GostSSLEngine.createForClientNoHostnameCheck(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        8443,
                        newSessionContext());
        applyAlgorithm(engine, "LDAP");
        assertThrows(SSLException.class, engine::beginHandshake);
    }

    @Test
    @DisplayName("beginHandshake: ошибки состояния не маскируются проверкой алгоритма")
    void stateErrorsAreNotMasked() throws Exception {
        GostSSLEngine engine = (GostSSLEngine) newClientContext().createSSLEngine("localhost", 1);
        engine.beginHandshake();
        applyAlgorithm(engine, "LDAP");
        SSLException e = assertThrows(SSLException.class, engine::beginHandshake);
        assertEquals(
                "Handshake already started",
                e.getMessage(),
                "повторный старт должен давать ошибку состояния, а не ошибку алгоритма");
    }

    @Test
    @DisplayName("Implicit-start из wrap: неподдерживаемый алгоритм отвергается")
    void implicitStartFromWrapRejectsUnsupportedAlgorithm() throws Exception {
        GostSSLEngine engine = (GostSSLEngine) newClientContext().createSSLEngine("localhost", 1);
        applyAlgorithm(engine, "LDAP");
        assertThrows(
                SSLException.class,
                () -> engine.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(20000)),
                "первый wrap() запускает рукопожатие и должен отвергать LDAP");
    }

    @Test
    @DisplayName(
            "Socket: requireHostnameForEndpointId отвергает LDAP и пробел, пустую строку пропускает")
    void socketRequireHostnameValidatesAlgorithm() throws Exception {
        try (java.net.ServerSocket listener = new java.net.ServerSocket(0);
                java.net.Socket underlying =
                        new java.net.Socket("127.0.0.1", listener.getLocalPort())) {
            GostSSLSocket socket =
                    new GostSSLSocket(
                            underlying,
                            "localhost",
                            8443,
                            false,
                            new GostX509KeyManager(),
                            GostX509TrustManager.insecureTrustAll(),
                            newSessionContext());
            for (String bad : new String[] {"LDAP", " ", "garbage"}) {
                SSLParameters params = socket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm(bad);
                socket.setSSLParameters(params);
                CertificateException e =
                        assertThrows(
                                CertificateException.class,
                                () ->
                                        GostX509TrustManager.requireHostnameForEndpointId(
                                                (java.net.Socket) socket),
                                "'" + bad + "' должно отвергаться");
                assertTrue(e.getMessage().contains("Unsupported endpoint identification"));
            }
            SSLParameters empty = socket.getSSLParameters();
            empty.setEndpointIdentificationAlgorithm("");
            socket.setSSLParameters(empty);
            assertNull(
                    GostX509TrustManager.requireHostnameForEndpointId((java.net.Socket) socket),
                    "пустая строка отключает проверку");
        }
    }

    @Test
    @DisplayName("Сервер: неподдерживаемый алгоритм beginHandshake не затрагивает")
    void serverIgnoresUnsupportedAlgorithm() throws Exception {
        GostSSLEngine server = newServerEngine();
        applyAlgorithm(server, "LDAP");
        assertDoesNotThrow(server::beginHandshake);
    }

    @ParameterizedTest(
            name =
                    "флаг сохранения: {0}, алгоритм: \"{1}\", затем null: {2} -> проверка имени: {3}")
    @CsvSource(
            value = {
                "false, <null>, false, false",
                "false, '', false, false",
                "true, <null>, false, true",
                "true, '', false, false",
                "true, '', true, false"
            },
            nullValues = "<null>")
    @DisplayName(
            "Чужое имя узла: null отключает проверку на прямом контексте и не отключает на"
                    + " контексте с флагом (Netty); пустая строка отключает всегда, в том числе"
                    + " после последующего null")
    void wrongHostAfterAlgorithm(
            boolean preserveOnNull, String algorithm, boolean thenNull, boolean verified)
            throws Exception {
        SSLContext ctx = newClientContext();
        if (preserveOnNull) {
            clientSessionContext(ctx)
                    .setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        }
        GostSSLEngine client = (GostSSLEngine) ctx.createSSLEngine(WRONG_HOST, 0);
        applyAlgorithm(client, algorithm);
        if (thenNull) {
            applyAlgorithm(client, null);
        }

        if (verified) {
            RuntimeException ex =
                    assertThrows(
                            RuntimeException.class,
                            () -> doLoopback(client, newServerEngine()),
                            "чужое имя должно отвергаться, несмотря на null от Netty");
            // отказ должен быть именно TLS-отказом, а не истёкшим сроком или закрытым транспортом
            assertInstanceOf(SSLException.class, ex.getCause(), "ожидается отказ TLS-рукопожатия");
        } else {
            assertDoesNotThrow(
                    () -> doLoopback(client, newServerEngine()),
                    "проверка имени отключена, рукопожатие должно пройти");
        }
    }

    // ========================================================================
    // GostX509TrustManager: единая точка валидации алгоритма
    // ========================================================================

    @Test
    @DisplayName("requireHostnameForEndpointId: матрица алгоритмов")
    void requireHostnameMatrix() throws Exception {
        assertNull(requireFor(null, "localhost"), "null отключает проверку");
        assertNull(requireFor("", "localhost"), "пустая строка отключает проверку");
        assertEquals("localhost", requireFor("https", "localhost"), "регистр не учитывается");
        assertEquals("localhost", requireFor("HTTPS", "localhost"));
        assertEquals("localhost", requireFor("LDAPS", "localhost"));
        for (String bad : new String[] {"LDAP", "garbage", " "}) {
            CertificateException e =
                    assertThrows(CertificateException.class, () -> requireFor(bad, "localhost"));
            assertTrue(
                    e.getMessage().contains("Unsupported endpoint identification algorithm"),
                    "ожидалась ошибка алгоритма для '" + bad + "': " + e.getMessage());
        }
    }

    @Test
    @DisplayName(
            "requireHostnameForEndpointId: ошибка алгоритма приоритетнее «peer host is missing»")
    void unsupportedAlgorithmBeatsMissingHost() {
        CertificateException unsupported =
                assertThrows(CertificateException.class, () -> requireFor("LDAP", ""));
        assertTrue(unsupported.getMessage().contains("Unsupported endpoint identification"));
        CertificateException missing =
                assertThrows(CertificateException.class, () -> requireFor("HTTPS", ""));
        assertTrue(missing.getMessage().contains("peer host is missing"));
        CertificateException missingLdaps =
                assertThrows(CertificateException.class, () -> requireFor("LDAPS", " "));
        assertTrue(missingLdaps.getMessage().contains("peer host is missing"));
    }

    @Test
    @DisplayName("Сообщение об неподдерживаемом алгоритме не падает на null")
    void unsupportedMessageToleratesNull() {
        assertTrue(
                EndpointIdentification.unsupportedMessage(null).contains("Unsupported"),
                "null не должен давать NPE");
    }

    @Test
    @DisplayName("Сообщение об ошибке алгоритма: усечено до 32 символов и без управляющих символов")
    void unsupportedMessageIsSanitized() {
        String mixedInput = "A\nB\u0000C" + "x".repeat(100);
        String message = EndpointIdentification.unsupportedMessage(mixedInput);
        assertFalse(message.contains("\n"), "перевод строки не должен попасть в сообщение");
        assertFalse(message.contains("\u0000"), "NUL не должен попасть в сообщение");
        assertTrue(message.contains("A?B?C"), "управляющие символы заменяются на '?'");
        assertTrue(message.length() < 120, "значение должно быть усечено: " + message.length());
    }

    @Test
    @DisplayName("Режим проверки имени не копируется redirectToSharedState")
    void redirectDoesNotCopyMode() {
        GostSSLSessionContext shared = newSessionContext();
        shared.setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        GostSSLSessionContext target = newSessionContext();
        target.redirectToSharedState(shared);
        assertEquals(
                EndpointIdentificationMode.DEFAULT,
                target.getEndpointIdentificationMode(),
                "режим проверки имени не разделяемое состояние");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static String requireFor(String algorithm, String peerHost)
            throws CertificateException {
        return GostX509TrustManager.requireHostnameForEndpointId(
                clientEngineWithAlgorithm(algorithm, peerHost));
    }

    private static GostSSLEngine clientEngineWithAlgorithm(String algorithm, String peerHost) {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        peerHost,
                        8443,
                        true);
        applyAlgorithm(engine, algorithm);
        return engine;
    }

    private static void applyAlgorithm(SSLEngine engine, String algorithm) {
        SSLParameters params = engine.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(algorithm);
        engine.setSSLParameters(params);
    }

    private static String algorithmOf(SSLEngine engine) {
        return engine.getSSLParameters().getEndpointIdentificationAlgorithm();
    }

    private static GostSSLSessionContext newSessionContext() {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        return new GostSSLSessionContext(cs);
    }

    private static GostSSLSessionContext clientSessionContext(SSLContext ctx) {
        return (GostSSLSessionContext) ctx.getClientSessionContext();
    }

    private SSLEngine engineWithFlag(String host, int port) throws Exception {
        SSLContext ctx = newClientContext();
        clientSessionContext(ctx).setEndpointIdentificationMode(EndpointIdentificationMode.STRICT);
        return ctx.createSSLEngine(host, port);
    }

    private SSLContext newClientContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(
                new KeyManager[] {new GostX509KeyManager()},
                new TrustManager[] {
                    GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert))
                },
                null);
        return ctx;
    }

    private GostSSLEngine newServerEngine() throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertLocalhost.cert, rootCa.cert)),
                serverCertLocalhost.priv);
        return new GostSSLEngine(
                skm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    private void doLoopback(GostSSLEngine client, GostSSLEngine server) throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
    }
}
