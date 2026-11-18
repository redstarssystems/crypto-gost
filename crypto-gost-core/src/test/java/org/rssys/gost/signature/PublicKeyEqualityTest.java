package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;

@DisplayName("Открытые ключи: equals и hashCode по кривой и нормализованным координатам")
@ExtendWith(JcaTestSupport.class)
class PublicKeyEqualityTest {

    @Test
    @DisplayName("Одна точка в проективной и аффинной форме даёт равные ключи с одним хэшем")
    void projectiveAndAffineFormsAreEqual() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        try {
            ECPoint generator = ECPoint.affine(params.gx, params.gy, params);
            ECPoint projective = generator.multiply(pair.getPrivate().getD());
            PublicKeyParameters fromProjective = new PublicKeyParameters(projective, params);
            PublicKeyParameters fromAffine =
                    new PublicKeyParameters(projective.normalize(), params);

            ECPoint stored = fromProjective.getQ();
            assertSame(stored, stored.normalize(), "точка в ключе хранится в аффинной форме");
            assertEquals(fromAffine, fromProjective, "ключи равны независимо от формы точки");
            assertEquals(fromAffine.hashCode(), fromProjective.hashCode(), "хэши совпадают");
            assertEquals(pair.getPublic(), fromProjective, "и совпадает с выведенным ключом");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("Разные ключи и разные типы не равны")
    void differentKeysAreNotEqual() {
        KeyPair a = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        KeyPair b = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        KeyPair c = KeyGenerator.generateKeyPair(ECParameters.tc26a512());
        try {
            assertNotEquals(a.getPublic(), b.getPublic(), "разные точки");
            assertNotEquals(a.getPublic(), c.getPublic(), "разные кривые");
            assertNotEquals(a.getPublic(), null, "null");
            assertNotEquals(a.getPublic(), "ключ", "другой тип");
        } finally {
            a.getPrivate().destroy();
            b.getPrivate().destroy();
            c.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName(
            "GostECPublicKey: ключ, восстановленный из X.509, равен исходному и годится как ключ множества")
    void jcaPublicKeysAreEqualAfterRoundTrip() throws Exception {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        try {
            GostECPublicKey original = new GostECPublicKey(pair.getPublic());
            KeyFactory factory =
                    KeyFactory.getInstance("ECGOST3410-2012", RssysGostProvider.PROVIDER_NAME);
            GostECPublicKey restored =
                    (GostECPublicKey)
                            factory.generatePublic(new X509EncodedKeySpec(original.getEncoded()));

            assertEquals(original, restored, "ключ после кодирования и разбора");
            assertEquals(original.hashCode(), restored.hashCode(), "хэши совпадают");
            Set<GostECPublicKey> set = new HashSet<>();
            set.add(original);
            assertTrue(set.contains(restored), "множество находит равный ключ");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("Закрытые ключи по значению не сравниваются: равенство только по ссылке")
    void privateKeysAreComparedByIdentity() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            GostECPrivateKey first = new GostECPrivateKey(pair.getPrivate());
            GostECPrivateKey second = new GostECPrivateKey(pair.getPrivate());
            assertEquals(first, first, "тот же объект");
            assertNotEquals(first, second, "ключевой материал по значению не сравнивается");
        } finally {
            pair.getPrivate().destroy();
        }
    }
}
