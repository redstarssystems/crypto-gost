package org.rssys.gost.jsse.manager;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
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
 * <p>
 * Как и {@code SunX509} в JDK: записи, которые для TLS непригодны (не ключ ГОСТ, нет цепочки
 * X.509), пропускаются; {@code init(null, ...)} даёт менеджер без ключей; повторный {@code init}
 * заменяет прежний набор записей; до {@code init} менеджеры не выдаются.
 */
public final class GostKeyManagerFactorySpi extends KeyManagerFactorySpi {

    /** Записи последнего {@code init}; {@code null} до первой инициализации. */
    private List<KeyStoreEntry> entries;

    @Override
    protected void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        List<KeyStoreEntry> loaded = new ArrayList<>();
        if (ks != null) {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!ks.isKeyEntry(alias)) continue;
                KeyStoreEntry entry = loadEntry(ks, alias, password);
                if (entry != null) {
                    loaded.add(entry);
                }
            }
        }
        this.entries = loaded;
    }

    /** Запись хранилища для TLS или {@code null}, если она не подходит. */
    private static KeyStoreEntry loadEntry(KeyStore ks, String alias, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Key key = ks.getKey(alias, password);
        if (!(key instanceof PrivateKey privateKey)
                || !GostJsseConstants.KEY_ALG_ECGOST_2012.equals(privateKey.getAlgorithm())) {
            return null;
        }
        Certificate[] certChain = ks.getCertificateChain(alias);
        if (certChain == null || certChain.length == 0) {
            return null;
        }
        X509Certificate[] x509Chain = new X509Certificate[certChain.length];
        for (int i = 0; i < certChain.length; i++) {
            if (!(certChain[i] instanceof X509Certificate x509)) {
                return null;
            }
            x509Chain[i] = x509;
        }
        PrivateKeyParameters keyParams;
        try {
            keyParams = GostPkcs12Loader.adaptPrivateKey(privateKey);
        } catch (RuntimeException e) {
            UnrecoverableKeyException failure =
                    new UnrecoverableKeyException("Cannot use the GOST key of alias " + alias);
            failure.initCause(e);
            throw failure;
        }
        return keyParams != null ? new KeyStoreEntry(alias, x509Chain, keyParams) : null;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "GostKeyManagerFactory does not support ManagerFactoryParameters;"
                        + " use init(KeyStore, char[])");
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (entries == null) {
            throw new IllegalStateException("KeyManagerFactory is not initialized");
        }
        GostX509KeyManager keyManager = new GostX509KeyManager();
        for (KeyStoreEntry entry : entries) {
            keyManager.addKeyEntry(entry.alias, entry.chain, entry.keyParams);
        }
        return new KeyManager[] {keyManager};
    }

    private record KeyStoreEntry(
            String alias, X509Certificate[] chain, PrivateKeyParameters keyParams) {}
}
