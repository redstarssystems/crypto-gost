package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Ключ OCSP-кэша опознаёт издателя по хешу его сертификата: серийные номера у разных УЦ
 * часто совпадают, и запись одного издателя не должна подставляться другому.
 */
@DisplayName("GostX509TrustManager: ключ OCSP-кэша")
class OcspCacheKeyTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final BigInteger ISSUER_SERIAL = BigInteger.valueOf(42);
    private static final BigInteger LEAF_SERIAL = BigInteger.valueOf(7);

    /** Самоподписанный сертификат с заданными DN, ключом и серийным номером. */
    private static GostCertificate issuer(String cn, BigInteger serial) throws Exception {
        KeyPair keyPair = KeyGenerator.generateKeyPair(PARAMS);
        return issuer(cn, serial, keyPair);
    }

    private static GostCertificate issuer(String cn, BigInteger serial, KeyPair keyPair)
            throws Exception {
        byte[] subjectDn = PkixCertTestHelper.buildDN(cn);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(keyPair.getPublic())
                        .serial(serial)
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .issuerDn(subjectDn)
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(keyPair.getPrivate()));
    }

    private static GostCertificate leaf(GostCertificate issuer, BigInteger serial)
            throws Exception {
        KeyPair keyPair = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = PkixCertTestHelper.buildDN("leaf");
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(keyPair.getPublic())
                        .serial(serial)
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .issuerDn(issuer.getSubjectDnBytes())
                        .buildTbs();
        // Подпись издателя для ключа кэша не важна: ключ строится только из DER и серийных номеров.
        return GostCertificateBuilder.sign(tbs, GostSigner.of(keyPair.getPrivate()));
    }

    @Test
    @DisplayName("Один и тот же издатель и сертификат дают одинаковый ключ")
    void sameIssuerSameKey() throws Exception {
        GostCertificate issuer = issuer("Issuer A", ISSUER_SERIAL);
        GostCertificate leaf = leaf(issuer, LEAF_SERIAL);

        assertEquals(
                GostX509TrustManager.buildCacheKey(leaf, issuer),
                GostX509TrustManager.buildCacheKey(leaf, issuer),
                "Повторный запрос по тому же издателю должен попадать в ту же запись кэша");
    }

    @Test
    @DisplayName("Разные издатели с одинаковым серийным номером дают разные ключи")
    void differentIssuersSameSerialDifferentKeys() throws Exception {
        GostCertificate issuerA = issuer("Issuer A", ISSUER_SERIAL);
        GostCertificate issuerB = issuer("Issuer B", ISSUER_SERIAL);
        GostCertificate leafA = leaf(issuerA, LEAF_SERIAL);
        GostCertificate leafB = leaf(issuerB, LEAF_SERIAL);

        assertNotEquals(
                GostX509TrustManager.buildCacheKey(leafA, issuerA),
                GostX509TrustManager.buildCacheKey(leafB, issuerB),
                "Совпадение серийных номеров у разных УЦ не должно смешивать записи кэша");
    }

    @Test
    @DisplayName("Тот же DN и серийный номер издателя, но другой ключ, дают разные ключи")
    void sameDnAndSerialDifferentPublicKeyDifferentKeys() throws Exception {
        GostCertificate issuerOld = issuer("Issuer A", ISSUER_SERIAL);
        GostCertificate issuerNew = issuer("Issuer A", ISSUER_SERIAL);
        GostCertificate leaf = leaf(issuerOld, LEAF_SERIAL);

        assertNotEquals(
                GostX509TrustManager.buildCacheKey(leaf, issuerOld),
                GostX509TrustManager.buildCacheKey(leaf, issuerNew),
                "Перевыпущенный издатель с новым ключом не должен наследовать чужой кэш");
    }

    @Test
    @DisplayName("Разные серийные номера проверяемого сертификата дают разные ключи")
    void differentLeafSerialsDifferentKeys() throws Exception {
        GostCertificate issuer = issuer("Issuer A", ISSUER_SERIAL);
        GostCertificate first = leaf(issuer, LEAF_SERIAL);
        GostCertificate second = leaf(issuer, LEAF_SERIAL.add(BigInteger.ONE));

        assertNotEquals(
                GostX509TrustManager.buildCacheKey(first, issuer),
                GostX509TrustManager.buildCacheKey(second, issuer),
                "Разные сертификаты одного издателя должны иметь разные записи кэша");
    }
}
