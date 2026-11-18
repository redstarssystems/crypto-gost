package org.rssys.gost.jsse.engine;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;

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
@DisplayName("GostSSLEngine: некорректный вход unwrap у сервера")
class GostSSLEngineUnwrapFuzzTest {

    private static final int PLAINTEXT_BUF = TlsConstants.MAX_PLAINTEXT_LENGTH + 64;

    private static GostX509KeyManager serverKm;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle rootCa;

    // ========================================================================
    // Сертификаты — один раз на весь класс
    // ========================================================================

    @BeforeAll
    static void setUp() throws Exception {
        if (Security.getProvider(GostJsseConstants.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostJsseProvider());
        }
        ECParameters params = ECParameters.tc26a256();

        rootCa = PkixCertTestHelper.createRootCA(params);
        PublicKeyParameters caPub = rootCa.cert.getPublicKey();

        serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        serverKm = new GostX509KeyManager();
        java.security.cert.X509Certificate[] chain =
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert));
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
    // P2: Targeted — oversize plaintext TLS-запись
    // Предел MAX_PLAINTEXT_LENGTH (0x4000) в handlePlaintextRecord
    // ========================================================================

    /**
     * Crafted TLSPlaintext запись с oversize длиной (0xFFFF > MAX_PLAINTEXT_LENGTH).
     * Формат: [type(1)] [version(2)] [length(2)] [payload...]
     * type=0x17 (application_data), version=0x0303, length=0xFFFF.
     * Ожидаем: ALERT_RECORD_OVERFLOW -> SSLException.
     */
    @FuzzTest
    void fuzzUnwrapOversizePlaintext(FuzzedDataProvider data) {
        GostSSLEngine engine = createServerEngine();
        byte[] payload = data.consumeRemainingAsBytes();
        int headerSize = 5;
        int totalLen = headerSize + Math.min(payload.length, TlsConstants.MAX_PLAINTEXT_LENGTH);
        if (totalLen < headerSize) return;
        byte[] input = new byte[totalLen];
        input[0] = 0x17;
        input[1] = 0x03;
        input[2] = 0x03;
        int declaredLen = data.consumeInt(TlsConstants.MAX_PLAINTEXT_LENGTH + 1, 65535);
        input[3] = (byte) (declaredLen >> 8);
        input[4] = (byte) declaredLen;
        System.arraycopy(payload, 0, input, headerSize, totalLen - headerSize);
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
        return new GostSSLEngine(
                serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }
}
