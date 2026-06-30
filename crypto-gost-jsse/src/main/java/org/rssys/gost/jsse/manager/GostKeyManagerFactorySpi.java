package org.rssys.gost.jsse.manager;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * KeyManagerFactorySpi для ГОСТ-ключей.
 * <p>
 * Загружает ключи из KeyStore (PKCS12) с зарегистрированным RssysGostProvider.
 * Конвертация JDK PrivateKey -> {@link PrivateKeyParameters} делегируется
 * {@link GostPkcs12Loader#adaptPrivateKey(java.security.PrivateKey)}.
 */
public final class GostKeyManagerFactorySpi extends KeyManagerFactorySpi {

    private final List<KeyStoreEntry> entries = new ArrayList<>();

    @Override
    protected void engineInit(KeyStore ks, char[] password) {
        if (ks == null) return;
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!ks.isKeyEntry(alias)) continue;

                PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
                if (pk == null || !GostJsseConstants.KEY_ALG_ECGOST_2012.equals(pk.getAlgorithm()))
                    continue;

                Certificate[] certChain = ks.getCertificateChain(alias);
                X509Certificate[] x509Chain = new X509Certificate[certChain.length];
                for (int i = 0; i < certChain.length; i++) {
                    x509Chain[i] = (X509Certificate) certChain[i];
                }

                PrivateKeyParameters keyParams = GostPkcs12Loader.adaptPrivateKey(pk);
                if (keyParams != null) {
                    entries.add(new KeyStoreEntry(alias, x509Chain, keyParams));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to init KeyManagerFactory", e);
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        GostX509KeyManager km = new GostX509KeyManager();
        for (KeyStoreEntry e : entries) {
            km.addKeyEntry(e.alias, e.chain, e.keyParams);
        }
        return new KeyManager[] {km};
    }

    private static final class KeyStoreEntry {
        final String alias;
        final X509Certificate[] chain;
        final PrivateKeyParameters keyParams;

        KeyStoreEntry(String alias, X509Certificate[] chain, PrivateKeyParameters keyParams) {
            this.alias = alias;
            this.chain = chain;
            this.keyParams = keyParams;
        }
    }
}
