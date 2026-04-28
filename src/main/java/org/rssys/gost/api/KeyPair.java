package org.rssys.gost.api;

import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Ключевая пара ГОСТ Р 34.10-2012: закрытый и открытый ключ.
 *
 * <p>Экземпляры создаются через {@link KeyGenerator#generateKeyPair}.
 *
 * <p><b>Безопасность:</b> закрытый ключ реализует {@link javax.security.auth.Destroyable}.
 * После завершения работы с ключевой парой рекомендуется вызвать {@code getPrivate().destroy()}.
 */
public final class KeyPair {

    private final PrivateKeyParameters privateKey;
    private final PublicKeyParameters  publicKey;

    KeyPair(PrivateKeyParameters privateKey, PublicKeyParameters publicKey) {
        this.privateKey = privateKey;
        this.publicKey  = publicKey;
    }

    /** Возвращает закрытый ключ. */
    public PrivateKeyParameters getPrivate() {
        return privateKey;
    }

    /** Возвращает открытый ключ. */
    public PublicKeyParameters getPublic() {
        return publicKey;
    }
}
