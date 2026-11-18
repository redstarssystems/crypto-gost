package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.spec.GostUkmParameterSpec;
import org.rssys.gost.signature.ECParameters;

@DisplayName("JCA KeyAgreement: null-ключ даёт InvalidKeyException, а не NullPointerException")
@ExtendWith(JcaTestSupport.class)
class GostKeyAgreementNullKeyTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    @Test
    @DisplayName("ECDH: init(null) и doPhase(null) отвергаются")
    void ecdhRejectsNullKeys() throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDHGOST2012", PROVIDER);
        assertThrows(InvalidKeyException.class, () -> agreement.init(null), "init(null)");

        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            agreement.init(new GostECPrivateKey(pair.getPrivate()));
            assertThrows(
                    InvalidKeyException.class,
                    () -> agreement.doPhase(null, true),
                    "doPhase(null)");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("VKO-256: init(null) и doPhase(null) отвергаются")
    void vkoRejectsNullKeys() throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("VKOGOST3410-2012-256", PROVIDER);
        GostUkmParameterSpec ukm = new GostUkmParameterSpec(BigInteger.ONE);
        assertThrows(InvalidKeyException.class, () -> agreement.init(null, ukm), "init(null)");

        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            agreement.init(new GostECPrivateKey(pair.getPrivate()), ukm);
            assertThrows(
                    InvalidKeyException.class,
                    () -> agreement.doPhase(null, true),
                    "doPhase(null)");
        } finally {
            pair.getPrivate().destroy();
        }
    }
}
