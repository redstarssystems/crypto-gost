package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jsse.crl.CrlCache.CrlKey;
import org.rssys.gost.jsse.crl.CrlCache.Loaded;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.VerifiedCrl;
import org.rssys.gost.pkix.internal.net.SlowServers;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.signature.ECParameters;

/**
 * Свойство безопасности условного запроса: если на сервере появился CRL новее того, что у клиента,
 * клиент получит его не позже чем через одну перепроверку. Проверяется с недобросовестным сервером,
 * который противоречит себе (ответ 304 с датой, новее отправленной): принятая из такого ответа дата
 * увела бы валидатор вперёд без тела, и новый CRL больше не приходил бы до {@code nextUpdate}.
 * Остальные тесты условного запроса проверяют экономию, этот - свежесть.
 */
@DisplayName("Условный запрос: клиент получает новый CRL даже после противоречивого 304")
class CrlFreshnessInvariantTest {

    private static final Duration MAX_AGE = Duration.ofHours(1);
    private static final long HOUR_MS = MAX_AGE.toMillis();
    private static final String D2 = "Sun, 08 Nov 2026 03:08:46 GMT";
    private static final String D3 = "Sun, 08 Nov 2026 03:13:54 GMT";

    private static KeyPair issuer;
    private static GostCertificate issuerCert;

    private SlowServers servers;
    private final AtomicLong clock = new AtomicLong(System.currentTimeMillis());

    @BeforeAll
    static void setUpKeys() {
        issuer = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        issuerCert =
                GostCertificateBuilder.create(ECParameters.tc26a256(), "CN=CRL Test Issuer,C=RU")
                        .publicKey(issuer.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(3650)
                        .basicConstraints(true, null)
                        .sign(issuer.getPrivate());
    }

    @BeforeEach
    void setUp() throws Exception {
        servers = new SlowServers();
    }

    @AfterEach
    void tearDown() {
        servers.close();
    }

    private static byte[] crl(int number) {
        return GostCrlBuilder.create("CN=Cache Root,C=RU")
                .thisUpdate(Instant.now().minus(Duration.ofDays(2)))
                .withCrlNumber(number)
                .nextUpdate(Instant.now().plus(Duration.ofDays(30)))
                .sign(issuer.getPrivate());
    }

    private static VerifiedCrl authenticate(byte[] der) throws PkixException {
        return CrlVerifier.authenticate(
                der,
                issuerCert,
                new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, GostCrl.DEFAULT_MAX_REVOKED_ENTRIES));
    }

    @Test
    @DisplayName(
            "Противоречивый 304 с датой D3 > D2, затем CRL с датой D3: перепроверка получает новый CRL")
    void newCrlArrivesAfterContradictory304() throws Exception {
        // Движок транспорта не важен: ответы 304 с противоречивой датой для обоих движков
        // проверены в тестах транспорта pkix, здесь проверяется свойство кэша
        CrlFetcher fetcher = new JdkHttpCrlFetcher(Duration.ofSeconds(5), 262_144, true);
        String uri = servers.base + "/fresh";
        CrlCache.Loader loader =
                new CrlCache.Loader() {
                    @Override
                    public byte[] fetch() throws java.io.IOException {
                        return fetcher.fetch(uri);
                    }

                    @Override
                    public CrlFetchResult fetchConditional(String validator)
                            throws java.io.IOException {
                        return fetcher.fetchConditional(uri, validator);
                    }
                };
        CrlCache cache =
                CrlCacheTestSupport.withClock(CrlCache.DEFAULT_MAX_BYTES, MAX_AGE, clock::get);
        CrlKey key = new CrlKey(uri, "aa");

        // У клиента CRL номер 1 с датой файла D2
        servers.freshBody = crl(1);
        servers.freshModified = D2;
        Loaded first =
                cache.get(
                        key,
                        loader,
                        loader,
                        CrlFreshnessInvariantTest::authenticate,
                        Deadline.MAX_FETCH_TIMEOUT);
        assertEquals(BigInteger.ONE, first.crl().getCrlNumber());

        // Сервер врёт: на условный запрос с D2 отвечает 304, но присылает дату D3 > D2
        clock.addAndGet(HOUR_MS);
        servers.contradictDate = D3;
        servers.contradictNext.set(true);
        Loaded afterLie =
                cache.get(
                        key,
                        loader,
                        loader,
                        CrlFreshnessInvariantTest::authenticate,
                        Deadline.MAX_FETCH_TIMEOUT);
        assertTrue(afterLie.fromCache(), "противоречивый 304 запись не меняет");
        assertEquals(D2, servers.lastIfModifiedSince);

        // Затем на сервере появляется новый CRL с датой D3, и сервер отвечает по правилам
        servers.freshBody = crl(2);
        servers.freshModified = D3;
        clock.addAndGet(HOUR_MS);

        Loaded fresh =
                cache.get(
                        key,
                        loader,
                        loader,
                        CrlFreshnessInvariantTest::authenticate,
                        Deadline.MAX_FETCH_TIMEOUT);

        assertEquals(D2, servers.lastIfModifiedSince, "валидатор не уехал вперёд вместе с ложью");
        assertFalse(fresh.fromCache(), "новый CRL получен");
        assertEquals(BigInteger.TWO, fresh.crl().getCrlNumber());
    }
}
