package org.rssys.gost.api;

import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Дефолтная реализация {@link GostSigner} поверх закрытого ключа в памяти JVM.
 *
 * <p>Package-private: создаётся только через {@link GostSigner#of(PrivateKeyParameters)}.
 * Открытый ключ выводится eager в конструкторе (Q = d·G), пока закрытый ключ гарантированно жив.
 */
final class PrivateKeySigner implements GostSigner {

    private final PrivateKeyParameters priv;
    private final PublicKeyParameters pub;

    PrivateKeySigner(PrivateKeyParameters priv) {
        if (priv == null) throw new IllegalArgumentException("priv must not be null");
        this.priv = priv;
        // Eager-вывод открытого ключа: фиксируем его, пока ключ не уничтожен, чтобы
        // getPublicKey() оставался корректным даже после priv.destroy().
        this.pub = Signature.derivePublicKey(priv);
    }

    @Override
    public byte[] signHash(byte[] hash) {
        return Signature.signHash(hash, priv);
    }

    @Override
    public ECParameters getParams() {
        return priv.getParams();
    }

    @Override
    public PublicKeyParameters getPublicKey() {
        return pub;
    }
}
