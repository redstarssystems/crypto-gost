package org.rssys.gost.jsse.engine;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLException;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Fuzz-тесты для {@link GostSSLEngine#unwrap} на стороне клиента.
 * <p>
 * Клиентский engine получает произвольные байты как серверный ответ.
 * Покрывает приём ServerHello, EncryptedExtensions, Certificate,
 * CertificateVerify, Finished на стороне клиента.
 */
class GostSSLEngineUnwrapClientFuzzTest {

    private static final int PLAINTEXT_BUF = TlsConstants.MAX_PLAINTEXT_LENGTH + 64;

    @FuzzTest
    void fuzzUnwrapClient(FuzzedDataProvider data) {
        GostSSLEngine client = createClientEngine();
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        ByteBuffer src = ByteBuffer.wrap(input);
        ByteBuffer dst = ByteBuffer.allocate(PLAINTEXT_BUF);
        try {
            client.unwrap(src, dst);
        } catch (SSLException | IllegalArgumentException e) {
            // Ожидаемо для битого ввода
        }
    }

    private static GostSSLEngine createClientEngine() {
        return new GostSSLEngine(
                new GostX509KeyManager(),
                new GostX509TrustManager(null, false),
                "localhost",
                0,
                true);
    }
}
