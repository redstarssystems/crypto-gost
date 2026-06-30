package org.rssys.gost.pkix.cms;

import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Обёртка ContentInfo (RFC 5652 §3).
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *   contentType  OBJECT IDENTIFIER,
 *   content      [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 * </pre>
 */
public final class CmsContentInfo {

    private final String contentType;
    private final byte[] content;

    private CmsContentInfo(String contentType, byte[] content) {
        this.contentType = contentType;
        this.content = content;
    }

    /** OID типа содержимого. */
    public String contentType() {
        return contentType;
    }

    /** DER-байты вложенного содержимого или {@code null} для detached. */
    public byte[] content() {
        return content != null ? content.clone() : null;
    }

    // ========================================================================
    // Кодирование / декодирование
    // ========================================================================

    /**
     * Кодирует ContentInfo в DER.
     *
     * @param contentTypeOid OID типа содержимого
     * @param content        DER-байты содержимого или {@code null}
     * @return DER-байты ContentInfo
     */
    public static byte[] encode(String contentTypeOid, byte[] content) {
        byte[] encodedOid = DerCodec.encodeOid(contentTypeOid);
        if (content == null) {
            return DerCodec.encodeSequence(encodedOid);
        }
        byte[] wrappedContent = DerCodec.encodeContextConstructed(0, content);
        return DerCodec.encodeSequence(encodedOid, wrappedContent);
    }

    /**
     * Декодирует ContentInfo из DER (RFC 5652 §3).
     * Поддерживает как определённую (definite), так и неопределённую (BER indefinite) длину.
     *
     * @param der DER-кодированный ContentInfo
     * @return декодированный ContentInfo
     */
    public static CmsContentInfo decode(byte[] der) throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        if (parts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "ContentInfo has no contentType OID");
        }
        String oid = DerCodec.parseOid(parts[0], 0);
        byte[] content = null;
        if (parts.length > 1) {
            // parts[1] = [0] EXPLICIT { content }
            int[] lenInfo = DerCodec.decodeLength(parts[1], 1);
            int innerOff = 1 + lenInfo[1];
            if (lenInfo[0] == DerCodec.INDEFINITE_LENGTH) {
                // BER: контент до EOC (0x00 0x00), исключая сам EOC
                int eoc = DerCodec.findEoc(parts[1], innerOff);
                content = java.util.Arrays.copyOfRange(parts[1], innerOff, eoc);
            } else {
                content = java.util.Arrays.copyOfRange(parts[1], innerOff, parts[1].length);
            }
        }
        return new CmsContentInfo(oid, content);
    }
}
