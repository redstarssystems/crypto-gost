package org.rssys.gost.jsse.engine;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;

import org.junit.jupiter.api.BeforeAll;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;
import java.security.Security;

/**
 * Fuzz-тесты для {@link GostSSLEngine#unwrap}.
 * <p>
 * Pre-handshake (сервер): произвольные байты подаются как TLS-запись в engine
 * без установленных ключей. Fuzzer проверяет handlePlaintextRecord() —
 * парсинг заголовка, диспетчеризацию content type, алерты.
 * <p>
 * ПОЧЕМУ только pre-handshake: post-handshake путь делегирует дешифрование
 * {@code readerRecord.unprotect()} — он уже покрыт {@code TlsRecordUnprotectFuzzTest}.
 * JSSE-прослойка (lock, dst-буферы, drain) — unit-test territory.
 * <p>
 * Ловим {@link SSLException} и {@link IllegalArgumentException}. Всё остальное
 * (NPE, AIOOBE, StackOverflow) — баги.
 */
class GostSSLEngineUnwrapFuzzTest {

    private static final int PLAINTEXT_BUF =
            TlsConstants.MAX_PLAINTEXT_LENGTH + 64;

    private static GostX509KeyManager serverKm;
    private static TlsTestHelper.CertBundle serverCert;
    private static TlsTestHelper.CertBundle rootCa;

    // ========================================================================
    // Сертификаты — один раз на весь класс
    // ========================================================================

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        rootCa = TlsTestHelper.createRootCA(params);
        PublicKeyParameters caPub = rootCa.cert.getPublicKey();

        serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "20240501120000Z", "21060101120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        serverKm = new GostX509KeyManager();
        java.security.cert.X509Certificate[] chain = CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert);
        serverKm.addKeyEntry("default", chain, serverCert.priv);
    }

    // ========================================================================
    // P2: Pre-handshake fuzz — серверный engine в INITIAL
    // ========================================================================

    /**
     * Серверный engine в INITIAL / HANDSHAKE, fuzzed plaintext TLS-запись.
     * Покрывает: BUFFER_UNDERFLOW, implicit handshake start, handlePlaintextRecord.
     */
    @FuzzTest
    void fuzzUnwrapPreHandshake(FuzzedDataProvider data) {
        GostSSLEngine engine = createServerEngine();
        byte[] input = data.consumeRemainingAsBytes();
        ByteBuffer src = ByteBuffer.wrap(input);
        ByteBuffer dst = ByteBuffer.allocate(PLAINTEXT_BUF);
        try {
            engine.unwrap(src, dst);
        } catch (SSLException | IllegalArgumentException e) {
            // ожидаемо для битого ввода
        }
    }

    /**
     * То же, но engine уже начал handshake (beginHandshake вызван).
     * Другой engineState — другой путь диспетчеризации.
     */
    @FuzzTest
    void fuzzUnwrapPreHandshakeStarted(FuzzedDataProvider data) {
        GostSSLEngine engine = createServerEngine();
        try {
            engine.beginHandshake();
        } catch (SSLException e) {
            return;
        }
        byte[] input = data.consumeRemainingAsBytes();
        ByteBuffer src = ByteBuffer.wrap(input);
        ByteBuffer dst = ByteBuffer.allocate(PLAINTEXT_BUF);
        try {
            engine.unwrap(src, dst);
        } catch (SSLException | IllegalArgumentException e) {
        }
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static GostSSLEngine createServerEngine() {
        return new GostSSLEngine(serverKm,
                new GostX509TrustManager(null, false),
                "localhost", 0, false);
    }

}
