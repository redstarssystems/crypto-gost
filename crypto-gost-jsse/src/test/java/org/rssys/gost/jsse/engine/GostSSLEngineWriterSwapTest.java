package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Security;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.engine.HandshakeOutput;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.CryptoRandom;

/**
 * Смена ключа записи в {@link GostSSLEngine} уничтожает прежнюю запись сразу: все вызовы идут под
 * единым замком движка, идущего параллельно {@code wrap()} нет. Ни одна из прежних записей, в том
 * числе при нескольких сменах подряд, не должна остаться незатёртой.
 */
@DisplayName("GostSSLEngine: уничтожение прежних записей при нескольких сменах ключа")
class GostSSLEngineWriterSwapTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    private static GostSSLEngine engine(SSLContext context, boolean clientMode) {
        GostSSLEngine engine = (GostSSLEngine) context.createSSLEngine("localhost", 0);
        engine.setUseClientMode(clientMode);
        return engine;
    }

    private static TlsTrafficKeys randomKeys() {
        byte[] key = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
        byte[] iv = new byte[TlsConstants.MGM_IV_SIZE];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(iv);
        return new TlsTrafficKeys(key, iv);
    }

    private static TlsRecord writerRecord(GostSSLEngine engine) throws Exception {
        Field field = GostSSLEngine.class.getDeclaredField("writerRecord");
        field.setAccessible(true);
        return (TlsRecord) field.get(engine);
    }

    private static Object call(GostSSLEngine engine, String name, Class<?>[] types, Object... args)
            throws Exception {
        Method method = GostSSLEngine.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(engine, args);
    }

    private static void assertDestroyed(TlsRecord record, String message) {
        assertThrows(
                IllegalStateException.class,
                () -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}),
                message);
    }

    /** Клиентский движок после завершённого рукопожатия. */
    private static GostSSLEngine handshakenClient() throws Exception {
        GostSSLEngine server =
                engine(
                        GostSsl.builder()
                                .certificate(
                                        serverLeaf.cert.getEncoded(),
                                        GostDerCodec.encodePrivateKey(serverLeaf.priv))
                                .trustCa(root.cert.getEncoded())
                                .buildServerContext(),
                        false);
        GostSSLEngine client =
                engine(
                        GostSsl.builder().trustCa(root.cert.getEncoded()).buildClientContext(),
                        true);
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
        return client;
    }

    @Test
    @DisplayName("две смены ключа подряд: обе прежние записи уничтожены сразу")
    void twoKeyChangesBeforeWrapDestroyBothOldRecords() throws Exception {
        GostSSLEngine client = handshakenClient();

        Class<?>[] swapTypes = {TlsTrafficKeys.class, TlsCiphersuite.class};
        TlsRecord first = writerRecord(client);
        call(client, "swapWriterRecord", swapTypes, randomKeys(), SUITE);
        TlsRecord second = writerRecord(client);
        call(client, "swapWriterRecord", swapTypes, randomKeys(), SUITE);
        TlsRecord current = writerRecord(client);

        assertDestroyed(first, "Первая прежняя запись должна быть уничтожена");
        assertDestroyed(second, "Вторая прежняя запись должна быть уничтожена");
        assertDoesNotThrow(
                () -> current.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}),
                "Действующая запись должна остаться рабочей");
    }

    @Test
    @DisplayName("закрытие движка после смен ключа: уничтожены все прежние записи")
    void closeWithPendingQueueDestroysAllDeferredRecords() throws Exception {
        GostSSLEngine client = handshakenClient();

        Class<?>[] swapTypes = {TlsTrafficKeys.class, TlsCiphersuite.class};
        TlsRecord first = writerRecord(client);
        call(client, "swapWriterRecord", swapTypes, randomKeys(), SUITE);
        TlsRecord second = writerRecord(client);
        call(client, "swapWriterRecord", swapTypes, randomKeys(), SUITE);

        // Закрытие без промежуточного wrap(): записи не должны пережить движок
        call(client, "destroyAll", new Class<?>[0]);

        assertDestroyed(first, "Первая прежняя запись должна быть уничтожена при закрытии");
        assertDestroyed(second, "Вторая прежняя запись должна быть уничтожена при закрытии");
    }

    @Test
    @DisplayName("закрытие с неотправленным KeyUpdate: затираются ключи метки и само сообщение")
    void closeWithQueuedKeyChangeWipesItsKeys() throws Exception {
        GostSSLEngine client = handshakenClient();
        client.initiateKeyUpdate(false);
        // KeyUpdate ждёт в движке рукопожатия до wrap(); переносим его в очередь отправки
        call(client, "drainHandshakeOutput", new Class<?>[0]);
        TlsTrafficKeys queued = null;
        byte[] queuedMessage = null;
        Field queueField = GostSSLEngine.class.getDeclaredField("outgoingQueue");
        queueField.setAccessible(true);
        for (Object item : (Iterable<?>) queueField.get(client)) {
            if (item instanceof HandshakeOutput.WriteKeyChange change) {
                queued = change.keys();
            } else if (item instanceof HandshakeOutput.Message message) {
                queuedMessage = message.frame();
            }
        }
        assertNotNull(queued, "за KeyUpdate стоит смена ключа");

        // Закрытие без wrap(): KeyUpdate не отправлен, его ключи не должны пережить движок
        call(client, "destroyAll", new Class<?>[0]);

        for (byte b : queued.getKey()) {
            assertEquals(0, b, "Ключ в метке смены ключа должен быть затёрт при закрытии");
        }
        assertNotNull(queuedMessage, "KeyUpdate стоял в очереди");
        for (byte b : queuedMessage) {
            assertEquals(0, b, "Неотправленное сообщение тоже затирается");
        }
    }
}
