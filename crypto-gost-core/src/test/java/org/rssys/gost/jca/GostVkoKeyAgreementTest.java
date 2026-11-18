package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.spec.GostUkmParameterSpec;
import org.rssys.gost.signature.ECParameters;

@DisplayName("JCA KeyAgreement: ECDH, VKO-256 и VKO-512")
@ExtendWith(JcaTestSupport.class)
class GostVkoKeyAgreementTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final BigInteger UKM = new BigInteger("1122334455667788", 16);

    private final List<KeyPair> created = new ArrayList<>();

    @AfterEach
    void destroyKeys() {
        created.forEach(pair -> pair.getPrivate().destroy());
    }

    private KeyPair keyPair(ECParameters params) {
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        created.add(pair);
        return pair;
    }

    private static byte[] agree(String algorithm, KeyPair mine, KeyPair peer, BigInteger ukm)
            throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, PROVIDER);
        if (ukm == null) {
            agreement.init(new GostECPrivateKey(mine.getPrivate()));
        } else {
            agreement.init(new GostECPrivateKey(mine.getPrivate()), new GostUkmParameterSpec(ukm));
        }
        agreement.doPhase(new GostECPublicKey(peer.getPublic()), true);
        return agreement.generateSecret();
    }

    // -----------------------------------------------------------------------
    // VKO-256 и VKO-512
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("VKO-256: секрет 32 байта, одинаков у обеих сторон и совпадает с api")
    void vko256IsSymmetricAndMatchesApi() throws Exception {
        KeyPair a = keyPair(ECParameters.cryptoProA());
        KeyPair b = keyPair(ECParameters.cryptoProA());

        byte[] fromA = agree("VKOGOST3410-2012-256", a, b, UKM);
        byte[] fromB = agree("VKOGOST3410-2012-256", b, a, UKM);

        assertEquals(32, fromA.length, "длина KEK_VKO-256");
        assertArrayEquals(fromA, fromB, "обе стороны получают один секрет");
        assertArrayEquals(
                org.rssys.gost.api.KeyAgreement.vkoGostR3410_2012_256(
                        a.getPrivate(), b.getPublic(), UKM),
                fromA,
                "JCA и api дают одно значение");
    }

    @Test
    @DisplayName("VKO-512: секрет 64 байта, одинаков у обеих сторон и совпадает с api")
    void vko512IsSymmetricAndMatchesApi() throws Exception {
        KeyPair a = keyPair(ECParameters.tc26a512());
        KeyPair b = keyPair(ECParameters.tc26a512());

        byte[] fromA = agree("VKOGOST3410-2012-512", a, b, UKM);
        byte[] fromB = agree("VKOGOST3410-2012-512", b, a, UKM);

        assertEquals(64, fromA.length, "длина KEK_VKO-512");
        assertArrayEquals(fromA, fromB, "обе стороны получают один секрет");
        assertArrayEquals(
                org.rssys.gost.api.KeyAgreement.vkoGostR3410_2012_512(
                        a.getPrivate(), b.getPublic(), UKM),
                fromA,
                "JCA и api дают одно значение");
    }

    @Test
    @DisplayName("VKO-256 принимает 512-битные ключи, VKO-512 отвергает 256-битные")
    void curveSizeRules() throws Exception {
        KeyPair big1 = keyPair(ECParameters.tc26a512());
        KeyPair big2 = keyPair(ECParameters.tc26a512());
        assertEquals(
                32, agree("VKOGOST3410-2012-256", big1, big2, UKM).length, "VKO-256 на 512 бит");

        KeyPair small1 = keyPair(ECParameters.cryptoProA());
        KeyPair small2 = keyPair(ECParameters.cryptoProA());
        assertThrows(
                InvalidKeyException.class,
                () -> agree("VKOGOST3410-2012-512", small1, small2, UKM),
                "RFC 7836 §4.3.2: вариант на 512 бит только для 512-битных ключей; отказ в init");
    }

    @Test
    @DisplayName("Ключ партнёра на другой кривой отвергается в doPhase, а не в generateSecret")
    void peerOnOtherCurveIsRejectedInDoPhase() throws Exception {
        KeyPair mine = keyPair(ECParameters.cryptoProA());
        KeyPair otherCurve = keyPair(ECParameters.cryptoProB());
        KeyPair otherSize = keyPair(ECParameters.tc26a512());

        for (String algorithm : new String[] {"ECDHGOST2012", "VKOGOST3410-2012-256"}) {
            KeyAgreement agreement = KeyAgreement.getInstance(algorithm, PROVIDER);
            if (algorithm.startsWith("VKO")) {
                agreement.init(
                        new GostECPrivateKey(mine.getPrivate()), new GostUkmParameterSpec(UKM));
            } else {
                agreement.init(new GostECPrivateKey(mine.getPrivate()));
            }
            assertThrows(
                    InvalidKeyException.class,
                    () -> agreement.doPhase(new GostECPublicKey(otherCurve.getPublic()), true),
                    algorithm + ": другая кривая того же размера");
            assertThrows(
                    InvalidKeyException.class,
                    () -> agreement.doPhase(new GostECPublicKey(otherSize.getPublic()), true),
                    algorithm + ": кривая другого размера");
            assertThrows(
                    IllegalStateException.class,
                    agreement::generateSecret,
                    algorithm + ": после отказа партнёр не принят");
        }
    }

    @Test
    @DisplayName("Алиас OID 1.2.643.7.1.1.6.2 разрешается в VKO-512, 1.2.643.7.1.1.6.1 в VKO-256")
    void oidAliases() throws Exception {
        KeyPair a = keyPair(ECParameters.tc26a512());
        KeyPair b = keyPair(ECParameters.tc26a512());
        assertEquals(64, agree("1.2.643.7.1.1.6.2", a, b, UKM).length, "OID VKO-512");
        assertEquals(32, agree("1.2.643.7.1.1.6.1", a, b, UKM).length, "OID VKO-256");
    }

    @Test
    @DisplayName("VKO без UKM и с параметрами другого типа отвергается до изменения состояния")
    void ukmIsRequired() throws Exception {
        KeyPair a = keyPair(ECParameters.cryptoProA());
        GostECPrivateKey key = new GostECPrivateKey(a.getPrivate());
        KeyAgreement agreement = KeyAgreement.getInstance("VKOGOST3410-2012-256", PROVIDER);

        assertThrows(InvalidKeyException.class, () -> agreement.init(key), "init без UKM");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> agreement.init(key, new IvParameterSpec(new byte[8])),
                "параметры не GostUkmParameterSpec");
        assertThrows(
                IllegalStateException.class,
                () -> agreement.doPhase(new GostECPublicKey(a.getPublic()), true),
                "после отказа init объект не инициализирован");
    }

    // -----------------------------------------------------------------------
    // Контракт JCA: сброс после generateSecret, имена
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "После generateSecret объект возвращается в состояние после init: UKM и ключ сохранены")
    void resetAfterGenerateSecret() throws Exception {
        KeyPair a = keyPair(ECParameters.cryptoProA());
        KeyPair b = keyPair(ECParameters.cryptoProA());
        KeyAgreement agreement = KeyAgreement.getInstance("VKOGOST3410-2012-256", PROVIDER);
        agreement.init(new GostECPrivateKey(a.getPrivate()), new GostUkmParameterSpec(UKM));
        GostECPublicKey peer = new GostECPublicKey(b.getPublic());

        agreement.doPhase(peer, true);
        byte[] first = agreement.generateSecret();
        assertThrows(
                IllegalStateException.class,
                agreement::generateSecret,
                "партнёр сброшен: без нового doPhase секрета нет");

        agreement.doPhase(peer, true);
        assertArrayEquals(
                first, agreement.generateSecret(), "тот же ключ и UKM дают тот же секрет");
    }

    @Test
    @DisplayName("ECDH: сброс после generateSecret, параметры не принимаются")
    void ecdhResetAndNoParameters() throws Exception {
        KeyPair a = keyPair(ECParameters.cryptoProA());
        KeyPair b = keyPair(ECParameters.cryptoProA());
        assertArrayEquals(
                agree("ECDHGOST2012", a, b, null),
                agree("ECDHGOST2012", b, a, null),
                "ECDH симметричен");

        KeyAgreement agreement = KeyAgreement.getInstance("ECDHGOST2012", PROVIDER);
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () ->
                        agreement.init(
                                new GostECPrivateKey(a.getPrivate()),
                                new GostUkmParameterSpec(UKM)),
                "ECDH параметров не принимает");

        agreement.init(new GostECPrivateKey(a.getPrivate()));
        agreement.doPhase(new GostECPublicKey(b.getPublic()), true);
        agreement.generateSecret();
        assertThrows(IllegalStateException.class, agreement::generateSecret, "партнёр сброшен");
    }

    @Test
    @DisplayName("generateSecret(String): имя алгоритма и RAW принимаются, чужое имя нет")
    void generateSecretByName() throws Exception {
        KeyPair a = keyPair(ECParameters.tc26a512());
        KeyPair b = keyPair(ECParameters.tc26a512());
        KeyAgreement agreement = KeyAgreement.getInstance("VKOGOST3410-2012-512", PROVIDER);
        agreement.init(new GostECPrivateKey(a.getPrivate()), new GostUkmParameterSpec(UKM));
        GostECPublicKey peer = new GostECPublicKey(b.getPublic());

        agreement.doPhase(peer, true);
        SecretKey named = agreement.generateSecret("VKOGOST3410-2012-512");
        assertEquals(64, named.getEncoded().length, "ключ из 64 байт");

        agreement.doPhase(peer, true);
        assertEquals(64, agreement.generateSecret("RAW").getEncoded().length, "RAW");

        agreement.doPhase(peer, true);
        assertThrows(
                NoSuchAlgorithmException.class,
                () -> agreement.generateSecret("AES"),
                "чужое имя алгоритма");
    }

    @Test
    @DisplayName("Не последняя фаза и открытый ключ чужого типа отвергаются")
    void phaseValidation() throws Exception {
        KeyPair a = keyPair(ECParameters.cryptoProA());
        KeyPair b = keyPair(ECParameters.cryptoProA());
        KeyAgreement agreement = KeyAgreement.getInstance("VKOGOST3410-2012-256", PROVIDER);
        agreement.init(new GostECPrivateKey(a.getPrivate()), new GostUkmParameterSpec(UKM));

        assertThrows(
                InvalidKeyException.class,
                () -> agreement.doPhase(new GostECPublicKey(b.getPublic()), false),
                "lastPhase == false");
        assertThrows(
                InvalidKeyException.class,
                () ->
                        agreement.doPhase(
                                new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"), true),
                "ключ не GostECPublicKey");
    }
}
