package org.rssys.gost.pkix.cms;

import java.math.BigInteger;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Вспомогательный класс для создания самоподписанных сертификатов в тестах CMS.
 */
public final class CmsTestUtils {

    private CmsTestUtils() {}

    /**
     * Создаёт самоподписанный сертификат с автоматически сгенерированным серийным номером.
     *
     * @param privKey закрытый ключ
     * @param pubKey  открытый ключ
     * @return самоподписанный сертификат
     */
    public static GostCertificate createSelfSignedCert(
            PrivateKeyParameters privKey, PublicKeyParameters pubKey) {
        return createSelfSignedCertWithDn(
                privKey, pubKey, BigInteger.valueOf(System.currentTimeMillis()), "Test");
    }

    /**
     * Создаёт самоподписанный сертификат с заданным серийным номером.
     *
     * @param privKey закрытый ключ
     * @param pubKey  открытый ключ
     * @param serial  серийный номер сертификата
     * @return самоподписанный сертификат
     */
    public static GostCertificate createSelfSignedCert(
            PrivateKeyParameters privKey, PublicKeyParameters pubKey, BigInteger serial) {
        return createSelfSignedCertWithDn(privKey, pubKey, serial, "Test");
    }

    /**
     * Создаёт самоподписанный сертификат с произвольным CN и заданным серийным номером.
     *
     * @param privKey    закрытый ключ
     * @param pubKey     открытый ключ
     * @param serial     серийный номер сертификата
     * @param commonName значение атрибута Common Name (CN)
     * @return самоподписанный сертификат
     */
    public static GostCertificate createSelfSignedCertWithDn(
            PrivateKeyParameters privKey,
            PublicKeyParameters pubKey,
            BigInteger serial,
            String commonName) {
        byte[] certDer = buildSelfSignedCertDer(privKey, pubKey, serial, commonName);
        return GostCertificate.fromDer(certDer);
    }

    /**
     * Формирует минимальный Distinguished Name (DN) с единственным атрибутом CN.
     *
     * @param cn значение Common Name
     * @return DER-кодированный DN
     */
    public static byte[] buildDn(String cn) {
        byte[] cnAttr =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.ATTR_CN), DerCodec.encodePrintableString(cn));
        byte[] cnSet = DerCodec.encodeSet(cnAttr);
        return DerCodec.encodeSequence(cnSet);
    }

    /**
     * Строит минимальный самоподписанный сертификат через DerCodec.
     */
    private static byte[] buildSelfSignedCertDer(
            PrivateKeyParameters privKey,
            PublicKeyParameters pubKey,
            BigInteger serial,
            String commonName) {
        byte[] spki = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(pubKey);
        byte[] issuerDn = buildDn(commonName);

        int hlen = pubKey.getParams().hlen;
        boolean is512 = hlen == GostOids.STREEBOG_512_HASH_LEN;

        byte[] version = DerCodec.encodeContextConstructed(0, DerCodec.encodeInteger(2));
        byte[] serialEnc = DerCodec.encodeInteger(serial);
        byte[] sigAlg =
                CmsAlgorithmIdentifier.encode(
                        is512 ? GostOids.SIGN_ALG_512 : GostOids.SIGN_ALG_256);
        byte[] notBefore = DerCodec.encodeTlv(DerCodec.TAG_UTC_TIME, "260101000000Z".getBytes());
        byte[] notAfter = DerCodec.encodeTlv(DerCodec.TAG_UTC_TIME, "360101000000Z".getBytes());
        byte[] validity = DerCodec.encodeSequence(notBefore, notAfter);
        byte[] subject = issuerDn.clone();

        byte[] tbsBody =
                DerCodec.encodeSequence(
                        version, serialEnc, sigAlg, issuerDn, validity, subject, spki);

        byte[] tbsHash = is512 ? Digest.digest512(tbsBody) : Digest.digest256(tbsBody);
        byte[] sigValue = Signature.signHash(tbsHash, privKey);
        byte[] sigBitString = DerCodec.encodeBitString(sigValue);

        return DerCodec.encodeSequence(tbsBody, sigAlg, sigBitString);
    }
}
