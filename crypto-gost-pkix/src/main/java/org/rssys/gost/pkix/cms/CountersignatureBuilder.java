package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель countersignature (RFC 5652 §11.4).
 *
 * <p>Countersignature — это вложенный SignerInfo, подписывающий не контент
 * документа, а содержимое октета {@code signatureValue} (s||r) родительского
 * SignerInfo. В signedAttrs включается только {@code message-digest} —
 * {@code content-type} отсутствует, поскольку countersignature не над eContent.
 */
public final class CountersignatureBuilder {

    private CountersignatureBuilder() {}

    /**
     * Строит DER-байты SignerInfo countersignature.
     *
     * <p>messageDigest вычисляется как хеш от {@code parentSignatureValue} —
     * содержимого октета подписи родителя (contents octets, без tag/length).
     *
     * @param parentSignatureValue содержимое октета signatureValue родительского
     *                            SignerInfo (s||r), без DER-обёртки tag/length
     * @param countersignerKey    приватный ключ countersigner'а
     * @param countersignerCert   сертификат countersigner'а
     * @param digestOid           OID дайджеста ({@link GostOids#DIGEST_256}
     *                            или {@link GostOids#DIGEST_512})
     * @return DER-байты SignerInfo (counter-signature)
     */
    public static byte[] buildCountersignature(
            byte[] parentSignatureValue,
            PrivateKeyParameters countersignerKey,
            GostCertificate countersignerCert,
            String digestOid) {

        boolean is512 = GostOids.DIGEST_512.equals(digestOid);

        byte[] messageDigest =
                is512
                        ? Digest.digest512(parentSignatureValue)
                        : Digest.digest256(parentSignatureValue);

        // signedAttrs: только message-digest, без content-type
        byte[] digestOctet = DerCodec.encodeOctetString(messageDigest);
        List<byte[]> attrList = new ArrayList<>();
        attrList.add(CmsAttribute.encode(GostOids.ATTR_MESSAGE_DIGEST, digestOctet));

        // SET-кодирование для хэширования (RFC 5652 §5.4)
        byte[][] sortedAttrs = attrList.toArray(new byte[0][]);
        DerCodec.sortDer(sortedAttrs);
        byte[] signedAttrsForHash = DerCodec.encodeSet(sortedAttrs);

        // [0] IMPLICIT SET OF Attribute — для включения в SignerInfo
        byte[] signedAttrsWrapped =
                DerCodec.encodeContextConstructed(0, DerCodec.concat(sortedAttrs));

        // Хеш signedAttrs и подпись
        byte[] signedAttrsHash =
                is512 ? Digest.digest512(signedAttrsForHash) : Digest.digest256(signedAttrsForHash);
        byte[] signatureValue = Signature.signHash(signedAttrsHash, countersignerKey);

        // Алгоритмы
        byte[] digestAlgIdDer = CmsAlgorithmIdentifier.encodeOnlyOid(digestOid);
        String signAlgOid = is512 ? GostOids.SIGN_ALG_512 : GostOids.SIGN_ALG_256;
        byte[] signAlgIdDer = CmsAlgorithmIdentifier.encodeOnlyOid(signAlgOid);

        // sid = IssuerAndSerialNumber
        byte[] sid =
                CmsIssuerAndSerialNumber.encode(
                        countersignerCert.getIssuerDnBytes(),
                        countersignerCert.getSerialNumberBigInt());

        // signature в OCTET STRING
        byte[] sigOctet = DerCodec.encodeOctetString(signatureValue);

        // SignerInfo SEQUENCE (без unsignedAttrs)
        byte[][] signerInfoParts = {
            DerCodec.encodeInteger(CmsConstants.SIGNER_INFO_V1),
            sid,
            digestAlgIdDer,
            signedAttrsWrapped,
            signAlgIdDer,
            sigOctet
        };
        return DerCodec.encodeSequence(signerInfoParts);
    }
}
