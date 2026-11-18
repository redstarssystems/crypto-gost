package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Контракт {@code KeyManagerFactorySpi}: пропуск непригодных записей, пустой менеджер при
 * {@code init(null)}, замена записей при повторном {@code init}, отказ до инициализации.
 */
@DisplayName("GostKeyManagerFactorySpi: контракт KeyManagerFactorySpi")
class GostKeyManagerFactorySpiTest {

    private static X509Certificate[] gostChain;
    private static GostECPrivateKey gostKey;

    @BeforeAll
    static void setUp() throws Exception {
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
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        gostChain = CertificateBridge.toJca(List.of(leaf.cert));
        gostKey = new GostECPrivateKey(leaf.priv);
    }

    private static KeyManagerFactory factory() throws Exception {
        return KeyManagerFactory.getInstance("GostX509", GostJsseConstants.PROVIDER_NAME);
    }

    /** Ключ другого алгоритма: для TLS с ГОСТ непригоден. */
    private record ForeignKey() implements PrivateKey {
        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    private static KeyStore keyStore() throws Exception {
        Map<String, Key> keys = new LinkedHashMap<>();
        Map<String, Certificate[]> chains = new LinkedHashMap<>();
        keys.put("gost", gostKey);
        chains.put("gost", gostChain);
        keys.put("foreign", new ForeignKey());
        chains.put("foreign", gostChain);
        keys.put("nochain", gostKey);
        chains.put("nochain", null);
        KeyStore store =
                new KeyStore(
                        new MapKeyStoreSpi(keys, chains),
                        new Provider("t", 1.0, "t") {},
                        "test") {};
        store.load(null, null);
        return store;
    }

    @Test
    @DisplayName("init(KeyStore): берутся только ключи ГОСТ с цепочкой, прочие записи пропускаются")
    void onlyUsableGostEntriesAreLoaded() throws Exception {
        KeyManagerFactory factory = factory();
        factory.init(keyStore(), new char[0]);

        GostX509KeyManager keyManager =
                assertInstanceOf(GostX509KeyManager.class, factory.getKeyManagers()[0]);

        assertArrayEquals(
                new String[] {"gost"},
                keyManager.getClientAliases(GostJsseConstants.KEY_ALG_ECGOST_2012, null),
                "ключ другого алгоритма и запись без цепочки не подходят");
    }

    @Test
    @DisplayName("init(null): менеджер без ключей, как у SunX509")
    void nullKeyStoreGivesEmptyManager() throws Exception {
        KeyManagerFactory factory = factory();
        factory.init(null, null);

        KeyManager[] managers = factory.getKeyManagers();

        assertEquals(1, managers.length);
        assertEquals(
                0,
                ((GostX509KeyManager) managers[0])
                        .getClientAliases(GostJsseConstants.KEY_ALG_ECGOST_2012, null)
                        .length,
                "ключей нет");
    }

    @Test
    @DisplayName("Повторный init заменяет записи, а не накапливает их")
    void repeatedInitReplacesEntries() throws Exception {
        KeyManagerFactory factory = factory();
        KeyStore store = keyStore();
        factory.init(store, new char[0]);
        factory.init(store, new char[0]);

        GostX509KeyManager keyManager = (GostX509KeyManager) factory.getKeyManagers()[0];

        assertEquals(
                1,
                keyManager.getClientAliases(GostJsseConstants.KEY_ALG_ECGOST_2012, null).length,
                "запись одна, а не по одной на каждый init");

        factory.init(null, null);
        assertEquals(
                0,
                ((GostX509KeyManager) factory.getKeyManagers()[0])
                        .getClientAliases(GostJsseConstants.KEY_ALG_ECGOST_2012, null)
                        .length,
                "init(null) сбрасывает прежние записи");
    }

    @Test
    @DisplayName("До init менеджеры не выдаются: IllegalStateException")
    void managersBeforeInitAreRefused() throws Exception {
        KeyManagerFactory factory = factory();

        assertThrows(IllegalStateException.class, factory::getKeyManagers);
    }

    @Test
    @DisplayName("init с ManagerFactoryParameters: InvalidAlgorithmParameterException")
    void managerFactoryParametersAreNotSupported() throws Exception {
        KeyManagerFactory factory = factory();
        ManagerFactoryParameters parameters = new ManagerFactoryParameters() {};

        assertThrows(InvalidAlgorithmParameterException.class, () -> factory.init(parameters));
    }

    /** Минимальное хранилище ключей в памяти для проверки фабрики. */
    private static final class MapKeyStoreSpi extends KeyStoreSpi {
        private final Map<String, Key> keys;
        private final Map<String, Certificate[]> chains;

        MapKeyStoreSpi(Map<String, Key> keys, Map<String, Certificate[]> chains) {
            this.keys = keys;
            this.chains = chains;
        }

        @Override
        public Enumeration<String> engineAliases() {
            return Collections.enumeration(keys.keySet());
        }

        @Override
        public boolean engineIsKeyEntry(String alias) {
            return keys.containsKey(alias);
        }

        @Override
        public Key engineGetKey(String alias, char[] password) {
            return keys.get(alias);
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            return chains.get(alias);
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            return null;
        }

        @Override
        public Date engineGetCreationDate(String alias) {
            return null;
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineDeleteEntry(String alias) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean engineContainsAlias(String alias) {
            return keys.containsKey(alias);
        }

        @Override
        public int engineSize() {
            return keys.size();
        }

        @Override
        public boolean engineIsCertificateEntry(String alias) {
            return false;
        }

        @Override
        public String engineGetCertificateAlias(Certificate cert) {
            return null;
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) {
            // данные задаются конструктором
        }
    }
}
