package org.rssys.gost.jsse.ocsp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.net.URI;
import java.security.Security;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.internal.net.FetchOutcome;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.signature.ECParameters;

/**
 * Собственная логика jsse в загрузке OCSP: проверка входа и схемы и перевод исходов транспорта в
 * {@link OcspFetchResult}. Сетевое поведение проверяется в тестах транспорта pkix, поэтому здесь
 * вместо HTTP подставлена заглушка. Контракт «ошибка любого рода даёт пустой результат».
 */
@DisplayName("OcspFetchSupport: проверка входа и перевод исходов транспорта")
class OcspFetchSupportTest {

    private static final byte[] RESPONSE = {9, 8, 7};
    private static final String RESPONDER = "http://ocsp.example/";

    private static byte[] certDer;
    private static byte[] issuerDer;

    private static final FetchTransport NEVER =
            request -> {
                throw new AssertionError("запрос не должен выполняться");
            };

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

    private static OcspFetchResult run(
            byte[] cert, byte[] issuer, String responder, FetchTransport transport) {
        return OcspFetchSupport.run(
                cert, issuer, responder, Duration.ofSeconds(1), 4096, target -> false, transport);
    }

    @Test
    @DisplayName("Нет сертификата, издателя или адреса: пустой результат, запрос не выполняется")
    void missingInputGivesNothingWithoutRequest() {
        // Пустой сертификат или издатель - ошибка вызова, а не адреса
        assertEquals(FetchFailure.INTERNAL, noResponse(run(null, issuerDer, RESPONDER, NEVER)));
        assertEquals(FetchFailure.INTERNAL, noResponse(run(certDer, null, RESPONDER, NEVER)));
        assertEquals(FetchFailure.BAD_ADDRESS, noResponse(run(certDer, issuerDer, null, NEVER)));
    }

    private static FetchFailure noResponse(OcspFetchResult result) {
        assertNull(result.response(), "ответа быть не должно");
        assertNull(result.nonce(), "nonce быть не должно");
        return result.failure();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://ocsp.example/", "ftp://ocsp.example/", "file:///etc/hostname"})
    @DisplayName("Схема не http: пустой результат, запрос не выполняется")
    void onlyHttpSchemeIsAccepted(String responder) {
        OcspFetchResult result = run(certDer, issuerDer, responder, NEVER);

        assertNull(result.response(), "ответа быть не должно: " + responder);
        assertEquals(FetchFailure.UNSUPPORTED_SCHEME, result.failure(), "причина: " + responder);
    }

    @Test
    @DisplayName("Схема регистронезависима (RFC 3986 §3.1): адрес принимается")
    void schemeCaseDoesNotMatter() {
        AtomicInteger requests = new AtomicInteger();

        OcspFetchResult result =
                run(
                        certDer,
                        issuerDer,
                        "HTTP://ocsp.example/",
                        request -> {
                            requests.incrementAndGet();
                            return FetchOutcome.success(RESPONSE);
                        });

        assertEquals(1, requests.get(), "запрос должен быть выполнен");
        assertArrayEquals(RESPONSE, result.response());
    }

    @Test
    @DisplayName("Отказ транспорта (не 200): пустой результат")
    void refusalMeansNoData() {
        URI uri = URI.create(RESPONDER);

        OcspFetchResult result =
                run(
                        certDer,
                        issuerDer,
                        RESPONDER,
                        request ->
                                FetchOutcome.failure(
                                        FetchOutcome.Failure.NON_200, 500, uri, false));

        assertNull(result.response());
        assertEquals(FetchFailure.HTTP_STATUS, result.failure(), "причина для журнала");
    }

    @Test
    @DisplayName("Любая ошибка транспорта (IOException и RuntimeException): пустой результат")
    void anyTransportErrorMeansNoData() {
        OcspFetchResult ioFailure =
                run(
                        certDer,
                        issuerDer,
                        RESPONDER,
                        request -> {
                            throw new IOException("сеть недоступна");
                        });
        OcspFetchResult unexpected =
                run(
                        certDer,
                        issuerDer,
                        RESPONDER,
                        request -> {
                            throw new IllegalStateException("неожиданный сбой библиотеки HTTP");
                        });

        assertNull(ioFailure.response(), "IOException не должен выходить наружу");
        assertNull(unexpected.response(), "RuntimeException не должен выходить наружу");
        assertEquals(FetchFailure.NETWORK, ioFailure.failure(), "сеть: причина для журнала");
        assertEquals(FetchFailure.INTERNAL, unexpected.failure(), "сбой: причина для журнала");
    }
}
