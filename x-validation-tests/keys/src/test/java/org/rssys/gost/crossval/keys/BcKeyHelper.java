package org.rssys.gost.crossval.keys;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;

/**
 * Stateless обёртка над BouncyCastle для кросс-валидации ключей ГОСТ Р 34.10-2012.
 */
public final class BcKeyHelper {

    private BcKeyHelper() {}

    /**
     * Создаёт {@link ECDomainParameters} BouncyCastle из {@link ECParameters} crypto-gost.
     */
    public static ECDomainParameters buildBcDomain(ECParameters params) {
        // BC требует явного создания кривой и точки — нет фабрики из OID
        ECCurve curve = new ECCurve.Fp(params.p, params.a, params.b);
        org.bouncycastle.math.ec.ECPoint g = curve.createPoint(params.gx, params.gy);
        return new ECDomainParameters(curve, g, params.n,
                BigInteger.valueOf(params.cofactor));
    }

    /**
     * Парсит DER-представление публичного ключа через BouncyCastle ASN.1 парсер.
     */
    public static SubjectPublicKeyInfo parseSpki(byte[] der) {
        return SubjectPublicKeyInfo.getInstance(der);
    }

    /**
     * Парсит DER-представление приватного ключа через BouncyCastle ASN.1 парсер.
     */
    public static PrivateKeyInfo parsePki(byte[] der) {
        return PrivateKeyInfo.getInstance(der);
    }

    /**
     * Извлекает OID алгоритма подписи из SubjectPublicKeyInfo.
     */
    public static String getSignAlgOid(SubjectPublicKeyInfo spki) {
        return spki.getAlgorithm().getAlgorithm().getId();
    }

    /**
     * Извлекает OID алгоритма подписи из PrivateKeyInfo.
     */
    public static String getSignAlgOid(PrivateKeyInfo pki) {
        return pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
    }

    /**
     * Извлекает OID кривой из параметров алгоритма SubjectPublicKeyInfo.
     */
    public static String getCurveOid(SubjectPublicKeyInfo spki) {
        ASN1Sequence paramsSeq = ASN1Sequence.getInstance(spki.getAlgorithm().getParameters());
        return ASN1ObjectIdentifier.getInstance(paramsSeq.getObjectAt(0)).getId();
    }

    /**
     * Извлекает OID кривой из параметров алгоритма PrivateKeyInfo.
     */
    public static String getCurveOid(PrivateKeyInfo pki) {
        ASN1Sequence paramsSeq = ASN1Sequence.getInstance(pki.getPrivateKeyAlgorithm().getParameters());
        return ASN1ObjectIdentifier.getInstance(paramsSeq.getObjectAt(0)).getId();
    }
}
