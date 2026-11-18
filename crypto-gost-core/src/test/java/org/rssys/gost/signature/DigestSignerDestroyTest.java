package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.digest.Streebog256;

@DisplayName("DigestSigner.destroy(): затирание подписанта и дайджеста")
class DigestSignerDestroyTest {

    private static DigestSigner newSigner(PrivateKeyParameters priv) {
        DigestSigner signer =
                new DigestSigner(new ECDSASigner(Streebog256::new), new Streebog256());
        signer.init(true, priv);
        return signer;
    }

    @Test
    @DisplayName("После destroy() подпись не вырабатывается, повторный destroy безопасен")
    void signerIsUnusableAfterDestroy() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            DigestSigner signer = newSigner(pair.getPrivate());
            signer.update(new byte[] {1, 2, 3}, 0, 3);
            signer.destroy();
            assertThrows(IllegalStateException.class, signer::sign, "sign после destroy");
            assertDoesNotThrow(signer::destroy, "повторный destroy");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("destroy() не затрагивает закрытый ключ вызывающего")
    void destroyDoesNotDestroyCallerKey() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            newSigner(pair.getPrivate()).destroy();
            assertFalse(pair.getPrivate().isDestroyed(), "ключ принадлежит вызывающему");
        } finally {
            pair.getPrivate().destroy();
        }
    }
}
