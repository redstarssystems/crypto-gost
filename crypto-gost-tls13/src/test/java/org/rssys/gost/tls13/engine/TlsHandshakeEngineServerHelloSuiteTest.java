package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Клиент принимает из ServerHello только набор шифров из предложенных им самим, в том числе когда
 * сервер выбрал начальный набор клиента: приложение могло отключить его и не предлагать.
 * Кадры собирает сборщик сервера: штатный сервер набор вне предложения клиента не выбирает,
 * поэтому нарушение недостижимо через него.
 */
@DisplayName("TlsHandshakeEngine: набор шифров из ServerHello должен быть из предложенных")
class TlsHandshakeEngineServerHelloSuiteTest {

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;

    private static final TlsCiphersuite LONG_SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final TlsCiphersuite SHORT_SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

    private static PkixCertTestHelper.CertBundle serverCert;
    private static byte[] serverPoint;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
        serverPoint = TlsEncoding.encodePoint(KeyGenerator.generateKeyPair(EC_PARAMS).getPublic());
    }

    /**
     * Клиент с начальным набором L, который предлагает только указанные наборы. Для списка без L
     * начальный набор остаётся неразрешённым: так выглядит отключённый приложением набор.
     */
    private static TlsHandshakeEngine startedClientOffering(List<Integer> offeredSuiteIds)
            throws Exception {
        TlsMessageBuilder clientBuilder =
                new TlsMessageBuilder(
                        LONG_SUITE, offeredSuiteIds, GROUP, SIG_SCHEME, null, null, HASH_LEN);
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        LONG_SUITE,
                        clientBuilder,
                        EC_PARAMS,
                        GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.start();
        return client;
    }

    /** ServerHello, в котором сервер выбрал начальный набор клиента (L). */
    private static byte[] serverHelloSelectingLongSuite() {
        TlsMessageBuilder server =
                new TlsMessageBuilder(
                        LONG_SUITE,
                        List.of(LONG_SUITE.getId()),
                        GROUP,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN);
        return new TlsHandshakeMessage(
                        TlsConstants.HT_SERVER_HELLO, server.buildServerHello(serverPoint))
                .encode();
    }

    @Test
    @DisplayName("Сервер выбрал начальный набор, который клиент не предлагал: illegal_parameter")
    void suiteEqualToInitialButNotOfferedIsRejected() throws Exception {
        TlsHandshakeEngine client = startedClientOffering(List.of(SHORT_SUITE.getId()));
        byte[] hello = serverHelloSelectingLongSuite();

        TlsException failure = assertThrows(TlsException.class, () -> client.receive(hello));

        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                failure.getAlertCode(),
                "набор вне предложения клиента: " + failure.getMessage());
        assertTrue(
                failure.getMessage().contains("cipher suite"),
                "причина отказа - набор шифров: " + failure.getMessage());
    }

    @Test
    @DisplayName("Тот же ServerHello при предложенном наборе не отвергается из-за набора")
    void suiteEqualToInitialAndOfferedIsNotRejectedForTheSuite() throws Exception {
        TlsHandshakeEngine client =
                startedClientOffering(List.of(LONG_SUITE.getId(), SHORT_SUITE.getId()));
        byte[] hello = serverHelloSelectingLongSuite();

        // Набор шифров есть в списке предложенных: ServerHello принимается, машина не уходит в
        // ошибку. Проверка по тексту сообщения об отказе здесь не годится: она не поймала бы отказ
        // по этой причине после смены формулировки
        assertDoesNotThrow(() -> client.receive(hello), "набор шифров был предложен клиентом");
        assertFalse(client.isError(), "после ServerHello машина не должна быть в ошибке");
    }
}
