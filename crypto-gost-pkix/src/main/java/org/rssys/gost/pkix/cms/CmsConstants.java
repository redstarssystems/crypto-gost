package org.rssys.gost.pkix.cms;

/**
 * Константы версий для структур CMS (RFC 5652).
 */
public final class CmsConstants {

    /** SignedData version при eContentType = id-data (RFC 5652 §5.1) */
    public static final int SIGNED_DATA_V1 = 1;

    /** SignedData version при eContentType != id-data (RFC 5652 §5.1) */
    public static final int SIGNED_DATA_V3 = 3;

    /** SignerInfo version при использовании IssuerAndSerialNumber (RFC 5652 §5.3) */
    public static final int SIGNER_INFO_V1 = 1;

    /** EnvelopedData version при наличии KeyAgreeRecipientInfo (RFC 5652 §6.1) */
    public static final int ENVELOPED_DATA_V3 = 3;

    /** KeyAgreeRecipientInfo version (RFC 5652 §6.2.2) */
    public static final int KEY_AGREE_V3 = 3;

    /** Максимальная длина цепочки сертификатов в SignedData. Защита от DoS. */
    public static final int MAX_CERT_CHAIN_LENGTH = 10;

    private CmsConstants() {}
}
