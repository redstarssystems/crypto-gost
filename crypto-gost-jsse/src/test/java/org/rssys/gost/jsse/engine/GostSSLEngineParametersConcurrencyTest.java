package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Параллельные {@code setSSLParameters} и {@code beginHandshake}: рукопожатие снимает параметры
 * одного вызова целиком. Набор «проверка имени HTTPS и ALPN p1» чередуется с «без проверки и ALPN
 * p2»; снятые при начале рукопожатия алгоритм проверки имени и протоколы ALPN в ClientHello обязаны
 * быть из одного набора, иначе сверка сертификата шла бы по одним параметрам, а рукопожатие — по
 * другим.
 */
@DisplayName("GostSSLEngine: параметры снимаются при beginHandshake одним набором")
class GostSSLEngineParametersConcurrencyTest {

    private static final int ROUNDS = 1000;
    private static final long WARM_UP_TOGGLES = 200;
    private static final String WITH_CHECK_PROTOCOL = "p1";
    private static final String WITHOUT_CHECK_PROTOCOL = "p2";

    @BeforeAll
    static void setUp() {
        Security.addProvider(new RssysGostJsseProvider());
    }

    private static SSLParameters parameters(String endpointId, String protocol) {
        SSLParameters parameters = new SSLParameters();
        parameters.setEndpointIdentificationAlgorithm(endpointId);
        parameters.setApplicationProtocols(new String[] {protocol});
        return parameters;
    }

    @Test
    @DisplayName("Проверка имени и ALPN в ClientHello всегда из одного вызова setSSLParameters")
    void snapshotIsConsistentUnderConcurrentSetters() throws Exception {
        SSLParameters withCheck =
                parameters(GostJsseConstants.ENDPOINT_ID_HTTPS, WITH_CHECK_PROTOCOL);
        SSLParameters withoutCheck = parameters("", WITHOUT_CHECK_PROTOCOL);
        for (int round = 0; round < ROUNDS; round++) {
            GostSSLEngine client =
                    GostSSLEngine.createForClient(
                            new GostX509KeyManager(),
                            GostX509TrustManager.insecureTrustAll(),
                            "localhost",
                            0,
                            null);
            client.setSSLParameters(withCheck);
            AtomicBoolean stop = new AtomicBoolean();
            AtomicLong toggles = new AtomicLong();
            Thread toggler =
                    new Thread(
                            () -> {
                                boolean flip = false;
                                while (!stop.get()) {
                                    client.setSSLParameters(flip ? withCheck : withoutCheck);
                                    flip = !flip;
                                    toggles.incrementAndGet();
                                }
                            });
            toggler.start();
            // Рукопожатие начинается, когда переключатель уже работает в полную силу: иначе оно
            // успевало бы до его старта, и гонка не проверялась бы
            while (toggles.get() < WARM_UP_TOGGLES) {
                Thread.onSpinWait();
            }
            client.beginHandshake();
            stop.set(true);
            toggler.join();

            String snapshot = (String) field(client, "handshakeEndpointIdAlgorithm");
            List<String> offered = clientHelloAlpn(client);
            String expected =
                    GostJsseConstants.ENDPOINT_ID_HTTPS.equals(snapshot)
                            ? WITH_CHECK_PROTOCOL
                            : WITHOUT_CHECK_PROTOCOL;
            assertEquals(
                    List.of(expected),
                    offered,
                    "раунд " + round + ": проверка имени '" + snapshot + "' и ALPN " + offered);
        }
    }

    private static List<String> clientHelloAlpn(GostSSLEngine client) throws Exception {
        ByteBuffer wire =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), wire);
        wire.flip();
        byte[] record = new byte[wire.remaining()];
        wire.get(record);
        assertTrue(record.length > TlsConstants.RECORD_HEADER_SIZE, "ClientHello отправлен");
        int bodyStart = TlsConstants.RECORD_HEADER_SIZE + TlsConstants.HANDSHAKE_HEADER_SIZE;
        return TlsMessageParser.parseClientHelloAlpn(
                Arrays.copyOfRange(record, bodyStart, record.length));
    }

    private static Object field(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }
}
