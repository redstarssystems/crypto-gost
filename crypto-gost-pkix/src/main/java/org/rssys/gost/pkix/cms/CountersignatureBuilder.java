package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
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
     * @param countersigner        подписант countersignature (может быть HSM-адаптером)
     * @param countersignerCert    сертификат countersigner'а
     * @param digestOid            OID дайджеста ({@link GostOids#DIGEST_256}
     *                             или {@link GostOids#DIGEST_512})
     * @return DER-байты SignerInfo (counter-signature)
     */
    public static byte[] buildCountersignature(
            byte[] parentSignatureValue,
            GostSigner countersigner,
            GostCertificate countersignerCert,
            String digestOid) {

        boolean is512 = GostOids.DIGEST_512.equals(digestOid);

        byte[] messageDigest = GostSignatureHelper.digestByOid(digestOid, parentSignatureValue);

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

        // Хеш signedAttrs и подпись с fail-closed self-verify
        byte[] signedAttrsHash = GostSignatureHelper.digestByOid(digestOid, signedAttrsForHash);
        byte[] signatureValue = GostSignatureHelper.signHashChecked(signedAttrsHash, countersigner);

        // Алгоритмы
        // digestAlgorithm с NULL-параметрами (правило id-tc26-gost3411-2012-256/512,
        // Р 1323565.1.025 §4.1/4.2; эталон openssl gost-engine кодирует NULL).
        byte[] digestAlgIdDer = CmsAlgorithmIdentifier.encode(digestOid);
        // SignerInfo.signatureAlgorithm: OID открытого ключа + NULL (RFC 4490 §3.2),
        // как в основном подписанте — единообразно и совместимо с КриптоПро/openssl.
        String signAlgOid = is512 ? GostOids.PUBLIC_KEY_512 : GostOids.PUBLIC_KEY_256;
        byte[] signAlgIdDer = CmsAlgorithmIdentifier.encode(signAlgOid);

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

    /**
     * Строит DER-байты SignerInfo countersignature (удобная перегрузка с ключом в памяти).
     *
     * <p>Делегирует в {@link #buildCountersignature(byte[], GostSigner, GostCertificate, String)}
     * через {@link GostSigner#of(PrivateKeyParameters)}.
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
        return buildCountersignature(
                parentSignatureValue,
                GostSigner.of(countersignerKey),
                countersignerCert,
                digestOid);
    }
}
