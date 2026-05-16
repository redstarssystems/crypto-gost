package org.rssys.gost.jsse.bridge;

import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.signature.PrivateKeyParameters;

import javax.security.auth.Destroyable;
import java.security.PrivateKey;

/**
 * Адаптер: оборачивает PrivateKeyParameters в java.security.PrivateKey
 * для передачи через X509KeyManager.
 */
public final class KeyBridge {

    /**
     * Оборачивает PrivateKeyParameters в реализации PrivateKey.
     *
     * @param keyParams ключ ГОСТ (может быть null)
     * @return PrivateKey или null
     */
    public static PrivateKey toJca(PrivateKeyParameters keyParams) {
        if (keyParams == null) return null;
        return new GostPrivateKeyAdapter(keyParams);
    }

    /**
     * Извлекает PrivateKeyParameters из обёртки PrivateKey.
     *
     * @param privateKey ключ JCA
     * @return PrivateKeyParameters или null
     */
    public static PrivateKeyParameters fromJca(PrivateKey privateKey) {
        if (privateKey instanceof GostPrivateKeyAdapter) {
            return ((GostPrivateKeyAdapter) privateKey).getDelegate();
        }
        // Если privateKey пришёл из другого источника — не наш случай
        return null;
    }

    /**
     * Адаптер PrivateKeyParameters → java.security.PrivateKey.
     */
    public static final class GostPrivateKeyAdapter implements PrivateKey, Destroyable {

        private final PrivateKeyParameters delegate;
        private volatile boolean destroyed;

        GostPrivateKeyAdapter(PrivateKeyParameters delegate) {
            this.delegate = delegate;
        }

        public PrivateKeyParameters getDelegate() {
            return delegate;
        }

        @Override
        public String getAlgorithm() {
            return GostJsseConstants.KEY_ALG_ECGOST_2012;
        }

        @Override
        public String getFormat() {
            // RFC 9367: ключи передаются в PKCS#8 с ГОСТ-параметрами
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            if (destroyed) return null;
            return GostDerCodec.encodePrivateKey(delegate);
        }

        @Override
        public void destroy() {
            if (!destroyed) {
                destroyed = true;
                delegate.destroy();
            }
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }

    private KeyBridge() {}
}
