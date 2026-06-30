package org.rssys.gost.tls13.engine;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.List;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Fuzz-тесты для {@link TlsHandshakeEngine#receive}.
 * <p>
 * {@code receive(byte[])} — основной entry point handshake-машины для недоверенных данных.
 * Принимает уже дешифрованные handshake-фреймы. Fuzzer подаёт произвольные байты
 * и проверяет, что машина не крашит JVM на битом входе.
 * <p>
 * ПОЧЕМУ ловим IOException: receive выбрасывает только IOException и
 * его подкласс TlsException. Любое другое исключение
 * (NPE, AIOOBE, StackOverflow) — баг.
 */
class TlsHandshakeEngineFuzzTest {

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int NAMED_GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;

    private static TlsTestHelper.CertBundle SERVER_CERT;

    static {
        SERVER_CERT = TlsTestHelper.createCertWithKey(EC_PARAMS);
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsMessageBuilder serverBuilder() {
        return new TlsMessageBuilder(
                cs(),
                List.of(cs().getId()),
                NAMED_GROUP,
                SIG_SCHEME,
                SERVER_CERT.priv,
                List.of(SERVER_CERT.cert),
                HASH_LEN);
    }

    private static TlsHandshakeEngine newServerEngine() {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                serverBuilder(),
                EC_PARAMS,
                NAMED_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    /**
     * Подаёт случайные байты в серверный engine.receive().
     * Покрывает диспетчеризацию по типу сообщения, разбор ClientHello,
     * обработку неожиданных типов в неожиданных состояниях.
     */
    @FuzzTest
    void fuzzReceive(FuzzedDataProvider data) {
        TlsHandshakeEngine engine = newServerEngine();
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            engine.receive(input);
        } catch (IOException e) {
            // Ожидаемо для битого handshake-фрейма
            // TlsException extends IOException — ловим родительский тип
        }
    }

    /**
     * Последовательность случайных фреймов на одном engine.
     * Покрывает переходы состояний: после первого успешного receive
     * engine переходит в следующее состояние, и следующий фрейм
     * обрабатывается в другом контексте.
     */
    @FuzzTest
    void fuzzReceiveSequence(FuzzedDataProvider data) {
        TlsHandshakeEngine engine = newServerEngine();
        int calls;
        try {
            calls = Math.max(1, data.consumeInt(1, 16));
        } catch (IllegalArgumentException e) {
            return;
        }
        while (calls-- > 0 && data.remainingBytes() > 0) {
            byte[] input =
                    data.consumeBytes(data.consumeInt(0, Math.min(65536, data.remainingBytes())));
            if (input.length == 0) continue;
            try {
                engine.receive(input);
            } catch (IOException e) {
                // При ошибке состояние не меняется — следующий фрейм
                // обрабатывается в том же состоянии
            }
        }
    }
}
