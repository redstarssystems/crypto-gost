package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.testkit.LogSecrets;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.JdkHttpFetch;
import org.rssys.gost.pkix.internal.net.SlowServers;
import org.rssys.gost.pkix.util.FetchFailure;

/**
 * Загрузчик CRL в журнал не пишет: отказ возвращается причиной в результате, а одну запись с
 * серийным номером и очищенным адресом делает менеджер доверия, который знает сертификат. Адрес из
 * CDP приходит от недоверенной стороны и может нести учётные данные, поэтому в журнал загрузчика
 * он не должен попадать вовсе.
 */
@DisplayName("CrlFetchSupport: отказ возвращается причиной, в журнал загрузчик не пишет")
class CrlFetchSupportLoggingTest {

    @Test
    @DisplayName("Неподдерживаемая схема: причина в результате, записей в журнале нет")
    void unsupportedScheme() throws Exception {
        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            CrlFetchResult result =
                    CrlFetchSupport.runConditional(
                            LogSecrets.uri("ftp", "crl.example/c.crl"),
                            null,
                            Duration.ofSeconds(1),
                            1024,
                            FetchRequest.BLOCK_PRIVATE_ADDRESSES,
                            request -> {
                                throw new AssertionError("запрос не должен выполняться");
                            });

            assertEquals(FetchFailure.UNSUPPORTED_SCHEME, result.failure(), "причина отказа");
            assertEquals(List.of(), log.allMessages(), "загрузчик в журнал не пишет");
        }
    }

    @Test
    @DisplayName("Превышение размера: исключение с пределом, записей в журнале нет")
    void sizeLimit() throws Exception {
        try (SlowServers servers = new SlowServers();
                LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            String uri =
                    LogSecrets.uri(
                            "http", servers.base.substring("http://".length()) + "/declaredbig");
            JdkHttpFetch transport = new JdkHttpFetch();

            CrlSizeLimitException e =
                    assertThrows(
                            CrlSizeLimitException.class,
                            () ->
                                    CrlFetchSupport.runConditional(
                                            uri,
                                            null,
                                            Duration.ofSeconds(5),
                                            1024,
                                            request -> false,
                                            transport::execute));

            assertEquals(1024, e.getMaxBytes(), "предел в исключении");
            assertEquals(List.of(), log.allMessages(), "загрузчик в журнал не пишет");
        }
    }
}
