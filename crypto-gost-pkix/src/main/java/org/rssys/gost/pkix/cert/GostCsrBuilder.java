package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель PKCS#10 CSR (Certificate Signing Request, RFC 2986 §4.1).
 *
 * <p>Строит CertificationRequest: TBS-запрос + AlgorithmIdentifier подписи + подпись.
 * Атрибуты — пустые ({@code [0] IMPLICIT SET}), что разрешено RFC 2986 §4.1.</p>
 *
 * <p>Вынесен из {@code examples/tls/GenerateCsr.java}.
 * Зависимости от tls13 устранены — используется {@link GostOids#STREEBOG_512_HASH_LEN}.
 * DN строится через {@link GostDnParser#encodeDn}.</p>
 */
public final class GostCsrBuilder {

    private GostCsrBuilder() {}

    /**
     * Строит PKCS#10 CertificationRequest (подписанный DER).
     *
     * @param privKey  закрытый ключ для подписи
     * @param pubKey   открытый ключ (включается в SPKI)
     * @param subjectDn DN в строковом формате (например, "CN=Test,O=Org")
     * @return DER-кодированный CertificationRequest
     */
    public static byte[] buildCsr(
            PrivateKeyParameters privKey, PublicKeyParameters pubKey, String subjectDn) {
        ECParameters params = pubKey.getParams();
        byte[] tbs = buildTbsCertRequest(subjectDn, pubKey);
        byte[] sigValue = Signature.sign(tbs, privKey);
        return DerCodec.encodeSequence(
                tbs, GostSignatureHelper.buildAlgId(params), DerCodec.encodeBitString(sigValue));
    }

    private static byte[] buildTbsCertRequest(String subjectDn, PublicKeyParameters pub) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            byte[] spki = GostDerCodec.encodePublicKey(pub);
            out.write(DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {0x00}));
            out.write(GostDnParser.encodeDn(subjectDn));
            out.write(spki);
            out.write(DerCodec.encodeContextConstructed(0, new byte[0]));
            return DerCodec.encodeSequence(out.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
    }
}
