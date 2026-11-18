package org.rssys.gost.jsse.ocsp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.testkit.LogSecrets;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.signature.ECParameters;

@DisplayName("OcspFetchSupport: отказ возвращается причиной, в журнал загрузчик не пишет")
class OcspFetchSupportLoggingTest {

    private static String secretUri(String scheme) {
        return LogSecrets.uri(scheme, "ocsp.example.com/ocsp");
    }

    private static byte[] certDer;
    private static byte[] issuerDer;

    @BeforeAll
    static void setUpCerts() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        certDer = root.cert.getEncoded();
        issuerDer = root.cert.getEncoded();
    }

    @Test
    @DisplayName("Неподдерживаемая схема: причина в результате, записей в журнале нет")
    void unsupportedScheme() {
        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            OcspFetchResult result =
                    OcspFetchSupport.run(
                            certDer,
                            issuerDer,
                            secretUri("https"),
                            Duration.ofSeconds(1),
                            1024,
                            uri -> false,
                            request -> {
                                throw new AssertionError("запрос не должен выполняться");
                            });

            assertEquals(FetchFailure.UNSUPPORTED_SCHEME, result.failure(), "причина отказа");
            assertEquals(List.of(), log.allMessages(), "загрузчик в журнал не пишет");
        }
    }

    @Test
    @DisplayName("Сбой загрузки: тип сбоя в результате, текст исключения и записи не нужны")
    void fetchFailure() {
        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            OcspFetchResult result =
                    OcspFetchSupport.run(
                            certDer,
                            issuerDer,
                            secretUri("http"),
                            Duration.ofSeconds(1),
                            1024,
                            uri -> false,
                            request -> {
                                throw new IOException(secretUri("http") + " connection refused");
                            });

            assertEquals(FetchFailure.NETWORK, result.failure(), "причина отказа");
            assertEquals(List.of(), log.allMessages(), "загрузчик в журнал не пишет");
        }
    }
}
