package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPrivateKeySpec;
import org.rssys.gost.jca.spec.GostUkmParameterSpec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;

@DisplayName("Уничтоженный закрытый ключ на границах JCA: проверяемые исключения")
@ExtendWith(JcaTestSupport.class)
class GostKeyDestroyedBordersTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    private static GostECPrivateKey destroyedKey() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        GostECPrivateKey key = new GostECPrivateKey(pair.getPrivate());
        key.destroy();
        return key;
    }

    @Test
    @DisplayName("KeyFactory.getKeySpec уничтоженного ключа даёт InvalidKeySpecException")
    void getKeySpecOfDestroyedKey() throws Exception {
        KeyFactory factory = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPrivateKey key = destroyedKey();
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.getKeySpec(key, PKCS8EncodedKeySpec.class),
                "PKCS#8");
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.getKeySpec(key, GostECPrivateKeySpec.class),
                "GostECPrivateKeySpec");
    }

    @Test
    @DisplayName("KeyFactory.translateKey уничтоженного ключа даёт InvalidKeyException")
    void translateDestroyedKey() throws Exception {
        KeyFactory factory = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPrivateKey key = destroyedKey();
        assertThrows(InvalidKeyException.class, () -> factory.translateKey(key));
    }

    @Test
    @DisplayName("Signature.initSign с уничтоженным ключом даёт InvalidKeyException")
    void initSignWithDestroyedKey() throws Exception {
        Signature signature = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        GostECPrivateKey key = destroyedKey();
        assertThrows(InvalidKeyException.class, () -> signature.initSign(key));
    }

    @Test
    @DisplayName("KeyAgreement.init с уничтоженным ключом даёт InvalidKeyException (ECDH и VKO)")
    void keyAgreementInitWithDestroyedKey() throws Exception {
        GostECPrivateKey key = destroyedKey();
        assertThrows(
                InvalidKeyException.class,
                () -> KeyAgreement.getInstance("ECDHGOST2012", PROVIDER).init(key),
                "ECDH");
        assertThrows(
                InvalidKeyException.class,
                () ->
                        KeyAgreement.getInstance("VKOGOST3410-2012-256", PROVIDER)
                                .init(key, new GostUkmParameterSpec(BigInteger.ONE)),
                "VKO");
    }

    @Test
    @DisplayName("Закрытый ключ на незарегистрированной кривой не кодируется: getEncoded даёт null")
    void privateKeyOnUnregisteredCurveHasNoEncoding() {
        ECParameters original = ECParameters.cryptoProA();
        ECParameters copy =
                new ECParameters(
                        original.p.toString(16),
                        original.a.toString(16),
                        original.b.toString(16),
                        original.gx.toString(16),
                        original.gy.toString(16),
                        original.n.toString(16),
                        original.hlen,
                        original.cofactor);
        PrivateKeyParameters params =
                new PrivateKeyParameters(BigInteger.valueOf(123456789L), copy);
        try {
            assertNull(
                    new GostECPrivateKey(params).getEncoded(),
                    "кривая вне реестра: по контракту Key.getEncoded() вернуть null");
        } finally {
            params.destroy();
        }
    }
}
