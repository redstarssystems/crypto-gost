package org.rssys.gost.jsse.ocsp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.security.Security;
import java.time.Duration;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.internal.net.SlowServers;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.signature.ECParameters;

/**
 * Контракт обоих OCSP-загрузчиков: параметры проверяются при создании, общий срок соблюдается, а
 * {@code fetch} никогда не бросает исключений (любая ошибка - {@code null}).
 */
@DisplayName("OCSP-загрузчики: проверка параметров, общий срок, fetch не бросает исключений")
class OcspFetcherContractTest {

    enum Kind {
        JDK_HTTP(
                (t, m) -> new JdkHttpOcspFetcher(t, m, true),
                (t, m) -> new JdkHttpOcspFetcher(t, m)),
        URL_CONNECTION(
                (t, m) -> new UrlConnectionOcspFetcher(t, m, true),
                (t, m) -> new UrlConnectionOcspFetcher(t, m));

        final BiFunction<Duration, Integer, OcspFetcher> local;
        final BiFunction<Duration, Integer, OcspFetcher> publicCtor;

        Kind(
                BiFunction<Duration, Integer, OcspFetcher> local,
                BiFunction<Duration, Integer, OcspFetcher> publicCtor) {
            this.local = local;
            this.publicCtor = publicCtor;
        }
    }

    private static byte[] certDer;
    private static byte[] issuerDer;

    private SlowServers servers;

    @BeforeAll
    static void setUpCerts() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        null,
                        null,
                        null,
                        false,
                        null);
        certDer = leaf.cert.getEncoded();
        issuerDer = root.cert.getEncoded();
    }

    @BeforeEach
    void setUp() throws Exception {
        servers = new SlowServers();
    }

    @AfterEach
    void tearDown() {
        servers.close();
    }

    private OcspFetcher fetcher(Kind kind) {
        return kind.local.apply(Duration.ofSeconds(1), 262_144);
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Конструктор делегирует проверку срока и размера: по одному значению на границу, таблица в"
                    + " DeadlineTest")
    void constructorValidation(Kind kind) {
        for (Duration bad :
                new Duration[] {
                    null, Duration.ofNanos(500_000), Deadline.MAX_FETCH_TIMEOUT.plusNanos(1)
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> kind.publicCtor.apply(bad, 1024),
                    kind + ": срок " + bad + " должен отвергаться");
        }
        for (int badSize : new int[] {0, -1}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> kind.publicCtor.apply(Duration.ofSeconds(5), badSize),
                    kind + ": предел размера " + badSize + " должен отвергаться");
        }
        assertDoesNotThrow(
                () -> kind.publicCtor.apply(Deadline.MIN_TIMEOUT, 1), "ровно 1 мс и 1 байт");
        assertDoesNotThrow(
                () -> kind.publicCtor.apply(Deadline.MAX_FETCH_TIMEOUT, Integer.MAX_VALUE),
                "ровно предел срока");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Запрос к серверу, возвращающему тело: ответ и nonce")
    void successfulFetch(Kind kind) {
        OcspFetchResult result =
                fetcher(kind).fetchWithNonce(certDer, issuerDer, servers.base + "/echo");

        assertNotNull(result.response(), "эхо-сервер возвращает тело запроса");
        assertNotNull(result.nonce(), "nonce запроса должен вернуться вместе с ответом");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Капля тела: fetch возвращает null в пределах срока")
    void dripReturnsNullWithinDeadline(Kind kind) {
        long start = System.nanoTime();

        byte[] response = fetcher(kind).fetch(certDer, issuerDer, servers.base + "/fastdrip");

        assertNull(response, "по сроку ответа нет");
        long elapsed = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsed < 2_500, kind + ": fetch занял " + elapsed + " мс при сроке 1000 мс");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Крайние входы дают null, но не исключение")
    void edgeInputsNeverThrow(Kind kind) {
        OcspFetcher f = fetcher(kind);
        String[] uris = {
            servers.base + "/rbad",
            servers.base + "/rfile",
            servers.base + "/rftp",
            servers.base + "/rnoloc",
            servers.base + "/declaredbig",
            servers.base + "/chunkedbig",
            servers.base + "/error500drip",
            "http:///x",
            "http://",
            "http://[bad",
            "http://127.0.0.1:1/",
            "ftp://example.com/x",
            "file:///etc/hostname",
            "https://example.com/",
            "",
            "not a uri"
        };
        for (String uri : uris) {
            assertNull(
                    assertDoesNotThrow(
                            () -> f.fetch(certDer, issuerDer, uri),
                            kind + " " + uri + ": исключение"),
                    kind + " " + uri + ": ожидался null");
            assertNull(
                    assertDoesNotThrow(
                                    () -> f.fetchWithNonce(certDer, issuerDer, uri),
                                    kind + " " + uri + ": исключение (с nonce)")
                            .response());
        }
        assertNull(assertDoesNotThrow(() -> f.fetch(null, issuerDer, servers.base + "/ok")));
        assertNull(assertDoesNotThrow(() -> f.fetch(certDer, null, servers.base + "/ok")));
        assertNull(assertDoesNotThrow(() -> f.fetch(certDer, issuerDer, null)));
        assertNull(
                assertDoesNotThrow(
                        () -> f.fetch(new byte[] {1, 2, 3}, issuerDer, servers.base + "/ok"),
                        "мусор вместо сертификата"));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Публичный конструктор блокирует частный адрес: null, до сервера запрос не доходит")
    void publicConstructorBlocksPrivateAddress(Kind kind) {
        // Остальные загрузчики контракта создаются с отключённой SSRF-проверкой, поэтому проводку
        // публичного конструктора проверяет только этот тест. Сервер живой и стоит на loopback:
        // без блокировки запрос до него дошёл бы и счётчик вырос; на адрес, где никто не слушает,
        // загрузчик вернул бы null и без блокировки, и тест ничего бы не охранял
        OcspFetcher f = kind.publicCtor.apply(Duration.ofSeconds(5), 65_536);

        assertNull(
                f.fetch(certDer, issuerDer, servers.base + "/ok"),
                kind + ": loopback должен блокироваться SSRF-защитой");
        assertEquals(
                0,
                servers.okRequests.get(),
                kind + ": заблокированный запрос не должен дойти до сервера");
    }

    private OcspFetcher blocking(Kind kind, Predicate<URI> blockedTarget) {
        return kind == Kind.JDK_HTTP
                ? new JdkHttpOcspFetcher(Duration.ofSeconds(1), 262_144, blockedTarget)
                : new UrlConnectionOcspFetcher(Duration.ofSeconds(1), 262_144, blockedTarget);
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("SSRF на втором переходе: заблокированный адрес перехода даёт null")
    void blockedRedirectTargetGivesNull(Kind kind) {
        // /r307 переводит POST на /echo; исходный адрес разрешён, переход блокируется
        OcspFetcher blocked = blocking(kind, uri -> "/echo".equals(uri.getPath()));
        OcspFetcher open = blocking(kind, uri -> false);

        assertNull(
                blocked.fetch(certDer, issuerDer, servers.base + "/r307"),
                kind + ": переход на заблокированный адрес");
        assertNotNull(
                open.fetch(certDer, issuerDer, servers.base + "/r307"),
                kind + ": без блокировки тот же переход выполняется");
    }
}
