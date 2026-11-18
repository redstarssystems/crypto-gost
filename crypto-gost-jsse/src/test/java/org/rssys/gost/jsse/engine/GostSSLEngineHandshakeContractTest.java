package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Контракт handshake-ветки {@code wrap()} и статуса {@code FINISHED}.
 *
 * <p>Проверяется, что нехватка места в выходном буфере не меняет состояние
 * (очередь, seqNum, writerRecord) и что {@code FINISHED} отдаётся ровно один
 * раз на сторону, а не через {@code getHandshakeStatus()}.
 */
@DisplayName("GostSSLEngine: контракт рукопожатия SSLEngine")
class GostSSLEngineHandshakeContractTest {

    private static final int DEFAULT_CAP =
            TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM;

    /** Селектор: подставить минимальный dst, если есть неотправленный фрагмент. */
    private static final int TINY_IF_FRAGMENT = -2;

    private static final DstSelector FULL = call -> -1;

    private static final byte[] REQUEST =
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] REQUEST_TAIL =
            "second-record-after-finished".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SERVER_RESPONSE =
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle clientCert;
    private static ECParameters params;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        PublicKeyParameters caPub = rootCa.cert.getPublicKey();
        serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        clientCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    @Test
    @DisplayName(
            "FINISHED отдаётся ровно один раз на сторону, getHandshakeStatus его не возвращает")
    void finishedExactlyOncePerSide() throws Exception {
        for (TlsCiphersuite suite :
                new TlsCiphersuite[] {
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S
                }) {
            for (boolean mtls : new boolean[] {false, true}) {
                Run run = run(suite, mtls, 0, FULL, FULL);
                String ctx = "suite=" + suite.getIanaName() + ", mtls=" + mtls;
                assertEquals(1, run.clientFinished, "FINISHED клиента: " + ctx);
                assertEquals(1, run.serverFinished, "FINISHED сервера: " + ctx);
                assertTrue(run.overflows.isEmpty(), "неожиданный BUFFER_OVERFLOW: " + ctx);
            }
        }
    }

    @Test
    @DisplayName(
            "BUFFER_OVERFLOW на любом этапе handshake не меняет состояние и повтор завершает рукопожатие")
    void overflowAtEveryStageKeepsState() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        Run probe = run(suite, false, 0, FULL, FULL);

        String[][] stages = {
            {"ClientHello", "true", "1"},
            {"ServerHello", "false", "1"},
            {"Зашифрованный фрейм сервера", "false", "2"},
            {"Finished сервера", "false", "5"},
            {"Finished клиента", "true", "2"}
        };

        for (String[] stage : stages) {
            String name = stage[0];
            boolean clientSide = Boolean.parseBoolean(stage[1]);
            int call = Integer.parseInt(stage[2]);
            String key = (clientSide ? "C" : "S") + call;
            String retryKey = (clientSide ? "C" : "S") + (call + 1);
            int needed = probe.lengths.get(key);

            DstSelector tiny = selectorFor(clientSide, call, 1);
            Run overflowed =
                    run(suite, false, 0, clientSide ? tiny : FULL, clientSide ? FULL : tiny);
            assertTrue(
                    overflowed.overflows.contains(key),
                    name
                            + ": ожидался BUFFER_OVERFLOW на "
                            + key
                            + ", были "
                            + overflowed.overflows);
            assertEquals(
                    needed,
                    overflowed.lengths.get(retryKey),
                    name + ": повтор должен дать тот же размер");
            assertEquals(1, overflowed.clientFinished, name + ": FINISHED клиента");
            assertEquals(1, overflowed.serverFinished, name + ": FINISHED сервера");

            DstSelector oneLess = selectorFor(clientSide, call, needed - 1);
            Run boundary =
                    run(suite, false, 0, clientSide ? oneLess : FULL, clientSide ? FULL : oneLess);
            assertTrue(
                    boundary.overflows.contains(key),
                    name + ": dst на 1 байт меньше должен дать BUFFER_OVERFLOW");
            assertEquals(needed, boundary.lengths.get(retryKey), name + ": повтор после границы");

            DstSelector exact = selectorFor(clientSide, call, needed);
            Run ok = run(suite, false, 0, clientSide ? exact : FULL, clientSide ? FULL : exact);
            assertTrue(
                    ok.overflows.isEmpty(),
                    name + ": dst ровно нужного размера не должен переполняться");
            assertEquals(needed, ok.lengths.get(key), name + ": размер ровно по формуле");
            assertEquals(1, ok.clientFinished, name + ": FINISHED клиента после точного размера");
            assertEquals(1, ok.serverFinished, name + ": FINISHED сервера после точного размера");
        }
    }

    @Test
    @DisplayName(
            "Нулевой dst на последнем handshake-фрейме: BUFFER_OVERFLOW, затем успешный повтор")
    void zeroDstOnLastHandshakeFrame() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        DstSelector zero = selectorFor(true, 2, 0);
        Run run = run(suite, false, 0, zero, FULL);
        assertTrue(run.overflows.contains("C2"), "нулевой dst должен дать BUFFER_OVERFLOW");
        assertEquals(1, run.clientFinished, "FINISHED клиента ровно один");
        assertEquals(1, run.serverFinished, "FINISHED сервера ровно один");
    }

    @Test
    @DisplayName("Фрагментация max_fragment_length: FINISHED не раньше последнего фрагмента")
    void fragmentedHandshakeHasNoEarlyFinished() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        Run run = run(suite, false, 1, FULL, FULL);
        assertTrue(run.sawFragment, "ожидалась фрагментация handshake-фреймов");
        assertEquals(1, run.clientFinished, "FINISHED клиента ровно один");
        assertEquals(1, run.serverFinished, "FINISHED сервера ровно один");

        // Переполнение именно на неотправленном фрагменте: фрейм уже извлечён
        // из очереди, поэтому addFirst() недопустим — проверяем сохранность.
        Run fragmentedOverflow = run(suite, false, 1, FULL, call -> TINY_IF_FRAGMENT);
        assertTrue(
                fragmentedOverflow.overflowWithFragment,
                "ожидался BUFFER_OVERFLOW при наличии pendingHsFragment");
        assertEquals(
                1,
                fragmentedOverflow.clientFinished,
                "FINISHED клиента после фрагментного overflow");
        assertEquals(
                1,
                fragmentedOverflow.serverFinished,
                "FINISHED сервера после фрагментного overflow");
    }

    @Test
    @DisplayName("Finished клиента и AppData в одном буфере: данные не теряются, FINISHED один")
    void clientFinishedAndAppDataInSameBuffer() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        byte[] payload =
                "app-data-after-finished".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Run run = run(suite, false, 0, FULL, FULL, payload);
        assertArrayEquals(
                payload, run.serverApp.toByteArray(), "AppData после Finished потерялись");
        assertEquals(1, run.clientFinished, "FINISHED клиента ровно один");
        assertEquals(1, run.serverFinished, "FINISHED сервера ровно один");
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Билет в очереди: Finished клиента и запись данных одним буфером")
    void ticketQueuedFinishedAndAppDataTogether(boolean resumed) throws Exception {
        Scenario scenario = ticketScenario(resumed);
        scenario.appAfterFinished = List.of(REQUEST);
        assertTicketPathDelivers(scenario, resumed, REQUEST);
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Билет в очереди: за Finished две записи данных подряд, вторая не теряется")
    void ticketQueuedTwoAppRecordsAfterFinished(boolean resumed) throws Exception {
        Scenario scenario = ticketScenario(resumed);
        scenario.appAfterFinished = List.of(REQUEST, REQUEST_TAIL);
        assertTicketPathDelivers(scenario, resumed, concat(REQUEST, REQUEST_TAIL));
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Билет в очереди: запись данных разрезана между двумя буферами")
    void ticketQueuedAppRecordSplit(boolean resumed) throws Exception {
        Scenario scenario = ticketScenario(resumed);
        scenario.appAfterFinished = List.of(REQUEST);
        scenario.splitFirstAppRecordAt = 7;
        assertTicketPathDelivers(scenario, resumed, REQUEST);
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Билет в очереди: dst в 1 байт даёт BUFFER_OVERFLOW, повтор доставляет данные")
    void ticketQueuedTinyAppDst(boolean resumed) throws Exception {
        Scenario scenario = ticketScenario(resumed);
        scenario.appAfterFinished = List.of(REQUEST);
        scenario.serverAppCapacity = 1;
        assertTicketPathDelivers(scenario, resumed, REQUEST);
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Билет в очереди: повторный unwrap до wrap ничего не потребляет и не выдаёт")
    void ticketQueuedRepeatedUnwrapBeforeWrap(boolean resumed) throws Exception {
        Scenario scenario = ticketScenario(resumed);
        scenario.appAfterFinished = List.of(REQUEST);
        scenario.repeatUnwrapBeforeWrap = true;
        Run run = run(scenario);
        assertEquals(1, run.repeatedUnwraps, "повтор должен состояться: запись осталась в src");
        assertDelivered(run, REQUEST);
    }

    @ParameterizedTest(name = "возобновление: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Билет в очереди: dst ровно по размеру данных записи")
    void ticketQueuedExactAppDst(boolean resumed) throws Exception {
        Scenario scenario = ticketScenario(resumed);
        scenario.appAfterFinished = List.of(REQUEST);
        scenario.serverAppCapacity = REQUEST.length;
        assertTicketPathDelivers(scenario, resumed, REQUEST);
    }

    @Test
    @DisplayName("mTLS без билета: запись данных за Finished разрезана, данные доставлены")
    void mtlsWithoutTicketAppRecordSplit() throws Exception {
        Scenario scenario = ticketScenario(false);
        scenario.mtls = true;
        scenario.appAfterFinished = List.of(REQUEST);
        scenario.splitFirstAppRecordAt = 7;
        Run run = run(scenario);
        assertDelivered(run, REQUEST);
        // При mTLS сервер билет не выдаёт: следующее соединение идёт полным рукопожатием
        Scenario next = sameSessions(scenario);
        next.mtls = true;
        assertFalse(run(next).serverResumed, "mTLS не должен давать возобновления");
    }

    @Test
    @DisplayName("Размер записи считается через ciphersuite.getTagLen() для обоих ГОСТ-наборов")
    void recordSizeUsesCiphersuiteTagLen() throws Exception {
        for (TlsCiphersuite suite :
                new TlsCiphersuite[] {
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S
                }) {
            Run probe = run(suite, false, 0, FULL, FULL);

            int shFrame = probe.frameLengths.get("S1");
            int shRecord = TlsConstants.RECORD_HEADER_SIZE + shFrame;
            Run shOk = run(suite, false, 0, FULL, selectorFor(false, 1, shRecord));
            assertTrue(shOk.overflows.isEmpty(), "ServerHello plaintext должен уложиться ровно");
            assertEquals(shRecord, shOk.lengths.get("S1"), "размер plaintext-записи ServerHello");

            int eeFrame = probe.frameLengths.get("S2");
            int eeRecord = TlsConstants.RECORD_HEADER_SIZE + eeFrame + 1 + suite.getTagLen();
            Run eeOk = run(suite, false, 0, FULL, selectorFor(false, 2, eeRecord));
            assertTrue(eeOk.overflows.isEmpty(), "зашифрованный фрейм должен уложиться ровно");
            assertEquals(eeRecord, eeOk.lengths.get("S2"), "размер зашифрованной записи");

            Run eeShort = run(suite, false, 0, FULL, selectorFor(false, 2, eeRecord - 1));
            assertTrue(eeShort.overflows.contains("S2"), "на 1 байт меньше — BUFFER_OVERFLOW");
        }
    }

    // ========================================================================
    // Мини-стенд: два GostSSLEngine, один поток, детерминированные буферы
    // ========================================================================

    /**
     * Сервер и клиент с контекстами сессий: сервер ставит билет в очередь после Finished клиента.
     * Для возобновления сначала проходит одно полное соединение, чтобы клиент получил билет.
     */
    private static Scenario ticketScenario(boolean resumed) throws Exception {
        Scenario scenario = new Scenario();
        scenario.clientSessions = new GostSSLSessionContext(scenario.suite);
        scenario.serverSessions = new GostSSLSessionContext(scenario.suite);
        scenario.clientTrust = GostX509TrustManager.insecureTrustAll();
        if (resumed) {
            Run first = run(sameSessions(scenario));
            assertFalse(first.serverResumed, "первое соединение должно быть полным");
            assertArrayEquals(
                    SERVER_RESPONSE, first.clientApp.toByteArray(), "ответ первого соединения");
        }
        return scenario;
    }

    private static Scenario sameSessions(Scenario source) {
        Scenario copy = new Scenario();
        copy.suite = source.suite;
        copy.clientSessions = source.clientSessions;
        copy.serverSessions = source.serverSessions;
        copy.clientTrust = source.clientTrust;
        return copy;
    }

    /**
     * Данные доставлены, FINISHED по одному на сторону, вид рукопожатия тот, что ожидался, а билет
     * этого соединения дошёл до клиента: следующее соединение возобновляется. Последнее
     * подтверждает, что прогон шёл по пути с билетом в очереди, а не мимо него.
     */
    private static void assertTicketPathDelivers(
            Scenario scenario, boolean resumed, byte[] expected) throws Exception {
        Run run = run(scenario);
        assertEquals(resumed, run.serverResumed, "вид рукопожатия");
        assertDelivered(run, expected);
        if (scenario.serverAppCapacity >= 0 && scenario.serverAppCapacity < expected.length) {
            assertTrue(run.serverAppOverflows > 0, "ожидался BUFFER_OVERFLOW на малом dst");
        }
        assertTrue(
                run(sameSessions(scenario)).serverResumed,
                "билет этого соединения не дошёл до клиента");
    }

    private static void assertDelivered(Run run, byte[] expected) {
        assertArrayEquals(expected, run.serverApp.toByteArray(), "данные клиента после Finished");
        assertArrayEquals(SERVER_RESPONSE, run.clientApp.toByteArray(), "ответ сервера");
        assertEquals(1, run.clientFinished, "FINISHED клиента ровно один");
        assertEquals(1, run.serverFinished, "FINISHED сервера ровно один");
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static DstSelector selectorFor(boolean clientSide, int call, int capacity) {
        return callIndex -> callIndex == call ? capacity : -1;
    }

    private static Run run(
            TlsCiphersuite suite,
            boolean mtls,
            int mfl,
            DstSelector clientSelector,
            DstSelector serverSelector)
            throws Exception {
        return run(suite, mtls, mfl, clientSelector, serverSelector, null);
    }

    private static Run run(
            TlsCiphersuite suite,
            boolean mtls,
            int mfl,
            DstSelector clientSelector,
            DstSelector serverSelector,
            byte[] clientAppAfterFinished)
            throws Exception {
        Scenario scenario = new Scenario();
        scenario.suite = suite;
        scenario.mtls = mtls;
        scenario.mfl = mfl;
        scenario.clientSelector = clientSelector;
        scenario.serverSelector = serverSelector;
        if (clientAppAfterFinished != null) {
            scenario.appAfterFinished = List.of(clientAppAfterFinished);
        }
        return run(scenario);
    }

    private static Run run(Scenario scenario) throws Exception {
        GostX509KeyManager serverKeys = new GostX509KeyManager();
        serverKeys.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        // Без контекста сессий сервер билет не выдаёт; с ним билет встаёт в очередь
        // после Finished клиента, как у серверов приложений
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        serverKeys,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        scenario.serverSessions);
        server.setEnabledCipherSuites(new String[] {scenario.suite.getIanaName()});
        if (scenario.mtls) server.setNeedClientAuth(true);

        GostX509KeyManager clientKeys = new GostX509KeyManager();
        if (scenario.mtls) {
            clientKeys.addKeyEntry(
                    "client",
                    CertificateBridge.toJca(List.of(clientCert.cert, rootCa.cert)),
                    clientCert.priv);
        }
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        clientKeys,
                        scenario.clientTrust != null
                                ? scenario.clientTrust
                                : GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        scenario.clientSessions != null ? PskTestSupport.BINDING_PORT : 0,
                        scenario.clientSessions);
        client.setEnabledCipherSuites(new String[] {scenario.suite.getIanaName()});
        if (scenario.mfl > 0) client.setClientMaxFragLenRequest(scenario.mfl);

        return new Harness(client, server, scenario).execute();
    }

    /** Условия одного прогона стенда. */
    private static final class Scenario {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        boolean mtls;
        int mfl;
        DstSelector clientSelector = FULL;
        DstSelector serverSelector = FULL;

        /** Записи данных, которые клиент отправляет сразу за своим Finished, одним буфером. */
        List<byte[]> appAfterFinished = List.of();

        /** Смещение разреза внутри первой записи данных; -1 — без разреза. */
        int splitFirstAppRecordAt = -1;

        /** Ёмкость dst при unwrap на сервере; -1 — с запасом. */
        int serverAppCapacity = -1;

        /**
         * Сервер повторяет unwrap по остатку, не отправив ожидающее (контракт этого не запрещает):
         * повтор не должен ничего потреблять и выдавать.
         */
        boolean repeatUnwrapBeforeWrap;

        GostSSLSessionContext clientSessions;
        GostSSLSessionContext serverSessions;

        /**
         * Менеджер доверия клиента, общий для соединений сценария: билет привязан к экземпляру
         * менеджера, и с другим экземпляром клиент его не предложит.
         */
        GostX509TrustManager clientTrust;
    }

    @FunctionalInterface
    private interface DstSelector {
        /**
         * @param callIndex номер вызова wrap() для данной стороны (с 1)
         * @return размер dst; -1 — по умолчанию; {@link #TINY_IF_FRAGMENT} — 1,
         *     если есть неотправленный фрагмент
         */
        int capacity(int callIndex);
    }

    private static final class Run {
        final Map<String, Integer> lengths = new HashMap<>();
        final Map<String, Integer> frameLengths = new HashMap<>();
        final List<String> overflows = new ArrayList<>();
        final ByteArrayOutputStream serverApp = new ByteArrayOutputStream();
        final ByteArrayOutputStream clientApp = new ByteArrayOutputStream();
        int clientFinished;
        int serverFinished;
        int serverAppOverflows;
        int repeatedUnwraps;
        boolean sawFragment;
        boolean overflowWithFragment;
        boolean serverResumed;
    }

    private static final class Harness {
        private final GostSSLEngine client;
        private final GostSSLEngine server;
        private final DstSelector clientSelector;
        private final DstSelector serverSelector;
        private final Scenario scenario;
        private final Run run = new Run();
        private boolean serverResponded;
        private final Deque<byte[]> c2s = new ArrayDeque<>();
        private final Deque<byte[]> s2c = new ArrayDeque<>();
        private int clientWrapCalls;
        private int serverWrapCalls;
        private boolean clientDone;
        private boolean serverDone;
        private boolean fragmentOverflowDone;

        Harness(GostSSLEngine client, GostSSLEngine server, Scenario scenario) {
            this.client = client;
            this.server = server;
            this.clientSelector = scenario.clientSelector;
            this.serverSelector = scenario.serverSelector;
            this.scenario = scenario;
        }

        Run execute() throws Exception {
            client.beginHandshake();
            server.beginHandshake();
            for (int i = 0; i < 4000; i++) {
                boolean clientStep = step(true);
                boolean serverStep = step(false);
                if (clientDone && serverDone) {
                    drainAfterHandshake();
                    run.serverResumed = server.wasResumed();
                    return run;
                }
                if (!clientStep && !serverStep) {
                    throw new IllegalStateException(
                            "handshake stalled: client="
                                    + client.getHandshakeStatus()
                                    + ", server="
                                    + server.getHandshakeStatus());
                }
            }
            throw new IllegalStateException("handshake не завершился за 4000 итераций");
        }

        private boolean step(boolean isClient) throws Exception {
            GostSSLEngine engine = isClient ? client : server;
            if (isClient ? clientDone : serverDone) {
                return false;
            }
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            assertNotEquals(
                    SSLEngineResult.HandshakeStatus.FINISHED,
                    hs,
                    "getHandshakeStatus() не должен возвращать FINISHED");
            switch (hs) {
                case NEED_WRAP:
                    wrapOnce(isClient);
                    return true;
                case NEED_UNWRAP:
                    return unwrapOnce(isClient);
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    return true;
                case NOT_HANDSHAKING:
                    markDone(isClient);
                    return true;
                default:
                    return false;
            }
        }

        private void wrapOnce(boolean isClient) throws Exception {
            GostSSLEngine engine = isClient ? client : server;
            int call = isClient ? ++clientWrapCalls : ++serverWrapCalls;
            String key = (isClient ? "C" : "S") + call;

            long seqBefore = writerSequence(engine);
            int queueBefore = engine.queuedHandshakeFramesForTest();
            boolean fragmentBefore = engine.hasPendingHandshakeFragmentForTest();
            int frameLength = engine.firstQueuedHandshakeFrameLengthForTest();
            if (frameLength >= 0) {
                run.frameLengths.put(key, frameLength);
            }

            DstSelector selector = isClient ? clientSelector : serverSelector;
            int capacity = selector.capacity(call);
            if (capacity == TINY_IF_FRAGMENT) {
                capacity =
                        (!fragmentOverflowDone && engine.hasPendingHandshakeFragmentForTest())
                                ? 1
                                : DEFAULT_CAP;
            } else if (capacity < 0) {
                capacity = DEFAULT_CAP;
            }

            ByteBuffer dst = ByteBuffer.allocate(capacity);
            SSLEngineResult result = engine.wrap(ByteBuffer.allocate(0), dst);
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                assertEquals(
                        seqBefore, writerSequence(engine), key + ": seqNum изменился при overflow");
                assertEquals(
                        queueBefore,
                        engine.queuedHandshakeFramesForTest(),
                        key + ": очередь изменилась при overflow");
                assertEquals(
                        fragmentBefore,
                        engine.hasPendingHandshakeFragmentForTest(),
                        key + ": фрагмент изменился при overflow");
                run.overflows.add(key);
                if (fragmentBefore) {
                    run.overflowWithFragment = true;
                    fragmentOverflowDone = true;
                }
                return;
            }

            int produced = result.bytesProduced();
            run.lengths.put(key, produced);
            boolean fragmentAfter = engine.hasPendingHandshakeFragmentForTest();
            if (fragmentAfter) {
                run.sawFragment = true;
                assertNotEquals(
                        SSLEngineResult.HandshakeStatus.FINISHED,
                        result.getHandshakeStatus(),
                        key + ": FINISHED до отправки последнего фрагмента");
            }
            if (engine.queuedHandshakeFramesForTest() > 0) {
                assertNotEquals(
                        SSLEngineResult.HandshakeStatus.FINISHED,
                        result.getHandshakeStatus(),
                        key + ": FINISHED при непустой очереди handshake-фреймов");
            }

            byte[] record = new byte[produced];
            dst.flip();
            dst.get(record);
            Deque<byte[]> outQueue = isClient ? c2s : s2c;
            if (record.length > 0) {
                outQueue.addLast(record);
            }

            boolean finished =
                    result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED;
            if (finished) {
                if (isClient) {
                    run.clientFinished++;
                } else {
                    run.serverFinished++;
                }
                markDone(isClient);
                if (isClient && !scenario.appAfterFinished.isEmpty()) {
                    appendClientAppData();
                }
            }
        }

        /**
         * Склеивает Finished клиента и записи данных в один буфер, как при одной записи в сокет.
         * С разрезом первая запись данных делится между двумя буферами.
         */
        private void appendClientAppData() throws Exception {
            byte[] finishedRecord = c2s.pollLast();
            assertNotNull(finishedRecord, "не найден только что отправленный Finished");
            ByteArrayOutputStream wire = new ByteArrayOutputStream();
            wire.write(finishedRecord);
            for (byte[] payload : scenario.appAfterFinished) {
                ByteBuffer dst = ByteBuffer.allocate(DEFAULT_CAP);
                SSLEngineResult appResult = client.wrap(ByteBuffer.wrap(payload), dst);
                assertEquals(
                        SSLEngineResult.Status.OK,
                        appResult.getStatus(),
                        "AppData после Finished должна отправляться без ошибки");
                wire.write(dst.array(), 0, appResult.bytesProduced());
            }
            byte[] combined = wire.toByteArray();
            if (scenario.splitFirstAppRecordAt < 0) {
                c2s.addLast(combined);
                return;
            }
            int cut = finishedRecord.length + scenario.splitFirstAppRecordAt;
            c2s.addLast(Arrays.copyOfRange(combined, 0, cut));
            c2s.addLast(Arrays.copyOfRange(combined, cut, combined.length));
        }

        /**
         * После рукопожатия: сервер дочитывает остаток, отвечает одной записью (вместе с ней
         * уходит и билет, если ждёт в очереди), клиент читает билет и ответ.
         */
        private void drainAfterHandshake() throws Exception {
            for (int i = 0; i < 100; i++) {
                boolean progress = false;
                if (server.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    wrapOnce(false);
                    progress = true;
                }
                if (unwrapOnce(false)) {
                    progress = true;
                }
                if (!serverResponded && c2s.isEmpty()) {
                    respondFromServer();
                    progress = true;
                }
                if (unwrapOnce(true)) {
                    progress = true;
                }
                if (!progress) {
                    return;
                }
            }
            fail("дочитывание после рукопожатия не завершилось");
        }

        private void respondFromServer() throws Exception {
            serverResponded = true;
            ByteBuffer dst = ByteBuffer.allocate(DEFAULT_CAP);
            // Ответ может потребовать нескольких wrap: сначала сообщения после рукопожатия
            ByteBuffer response = ByteBuffer.wrap(SERVER_RESPONSE);
            for (int i = 0; i < 4 && (response.hasRemaining() || hasQueuedOutput()); i++) {
                dst.clear();
                SSLEngineResult result = server.wrap(response, dst);
                assertEquals(SSLEngineResult.Status.OK, result.getStatus(), "ответ сервера");
                if (result.bytesProduced() > 0) {
                    s2c.addLast(Arrays.copyOf(dst.array(), result.bytesProduced()));
                }
            }
            assertFalse(response.hasRemaining(), "ответ сервера не отправлен");
        }

        private boolean hasQueuedOutput() {
            return server.queuedHandshakeFramesForTest() > 0;
        }

        private boolean unwrapOnce(boolean isClient) throws Exception {
            GostSSLEngine engine = isClient ? client : server;
            Deque<byte[]> inQueue = isClient ? s2c : c2s;
            if (inQueue.isEmpty()) {
                return false;
            }
            byte[] record = inQueue.pollFirst();
            ByteBuffer src = ByteBuffer.wrap(record);
            int capacity =
                    !isClient && scenario.serverAppCapacity >= 0
                            ? scenario.serverAppCapacity
                            : TlsConstants.MAX_PLAINTEXT_LENGTH * 2;
            ByteBuffer app = ByteBuffer.allocate(capacity);
            SSLEngineResult result = engine.unwrap(src, app);
            assertNoAppDataWithPendingHandshake(isClient, result, app);
            if (!isClient
                    && scenario.repeatUnwrapBeforeWrap
                    && result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP
                    && src.hasRemaining()) {
                int before = src.remaining();
                SSLEngineResult repeat = engine.unwrap(src, app);
                assertNoAppDataWithPendingHandshake(false, repeat, app);
                assertEquals(
                        SSLEngineResult.HandshakeStatus.NEED_WRAP,
                        repeat.getHandshakeStatus(),
                        "повторный unwrap до wrap: статус");
                assertEquals(0, repeat.bytesConsumed(), "повторный unwrap до wrap потребил байты");
                assertEquals(before, src.remaining(), "повторный unwrap до wrap сдвинул src");
                run.repeatedUnwraps++;
            }
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                // Потребитель увеличивает буфер и повторяет вызов (контракт SSLEngine)
                if (!isClient) {
                    run.serverAppOverflows++;
                }
                app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH * 2);
                result = engine.unwrap(src, app);
                assertNoAppDataWithPendingHandshake(isClient, result, app);
            }

            app.flip();
            if (app.hasRemaining()) {
                byte[] data = new byte[app.remaining()];
                app.get(data);
                (isClient ? run.clientApp : run.serverApp).write(data);
            }
            if (src.hasRemaining()) {
                byte[] rest = new byte[src.remaining()];
                src.get(rest);
                inQueue.addFirst(rest);
            }
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                // Неполная запись: потребитель дочитывает из сети и повторяет
                if (inQueue.size() < 2) {
                    return false;
                }
                byte[] head = inQueue.pollFirst();
                byte[] next = inQueue.pollFirst();
                byte[] merged = Arrays.copyOf(head, head.length + next.length);
                System.arraycopy(next, 0, merged, head.length, next.length);
                inQueue.addFirst(merged);
                return true;
            }

            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                if (isClient) {
                    run.clientFinished++;
                } else {
                    run.serverFinished++;
                }
                markDone(isClient);
            }
            return true;
        }

        /**
         * Контракт потребителя: результат, который просит продолжить рукопожатие, не несёт данных
         * приложения. Undertow на NEED_WRAP возвращает читателю 0 и выданные байты теряет.
         */
        private static void assertNoAppDataWithPendingHandshake(
                boolean isClient, SSLEngineResult result, ByteBuffer app) {
            SSLEngineResult.HandshakeStatus hs = result.getHandshakeStatus();
            boolean pending =
                    hs == SSLEngineResult.HandshakeStatus.NEED_WRAP
                            || hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                            || hs == SSLEngineResult.HandshakeStatus.NEED_TASK;
            if (pending) {
                String side = isClient ? "клиент" : "сервер";
                assertEquals(
                        0,
                        result.bytesProduced(),
                        side + ": " + hs + " вместе с данными приложения (" + result + ")");
                assertEquals(0, app.position(), side + ": " + hs + " и запись в dst");
            }
        }

        private void markDone(boolean isClient) {
            if (isClient) {
                clientDone = true;
            } else {
                serverDone = true;
            }
        }

        private static long writerSequence(GostSSLEngine engine) {
            org.rssys.gost.tls13.record.TlsRecord writer = engine.getWriterRecordForTest();
            return writer == null ? -1 : writer.getSequenceNumber();
        }
    }
}
