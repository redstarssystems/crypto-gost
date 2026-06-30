package org.rssys.gost.pkix.cms;

import org.rssys.gost.util.DerCodec;

/**
 * AlgorithmIdentifier для CMS (RFC 5652 §10.1.2).
 *
 * <pre>
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 * </pre>
 */
public final class CmsAlgorithmIdentifier {

    private final String algorithmOid;
    private final byte[] parameters;

    private CmsAlgorithmIdentifier(String algorithmOid, byte[] parameters) {
        this.algorithmOid = algorithmOid;
        this.parameters = parameters != null ? parameters.clone() : null;
    }

    public String algorithmOid() {
        return algorithmOid;
    }

    public byte[] parameters() {
        return parameters != null ? parameters.clone() : null;
    }

    // ========================================================================
    // Кодирование / декодирование
    // ========================================================================

    /** Кодирует AlgorithmIdentifier с NULL-параметрами. */
    public static byte[] encode(String algorithmOid) {
        byte[] encodedOid = DerCodec.encodeOid(algorithmOid);
        return DerCodec.encodeSequence(encodedOid, DerCodec.encodeNull());
    }

    /** Кодирует AlgorithmIdentifier БЕЗ параметров (только OID). */
    public static byte[] encodeOnlyOid(String algorithmOid) {
        return DerCodec.encodeSequence(DerCodec.encodeOid(algorithmOid));
    }

    /** Кодирует AlgorithmIdentifier с произвольными параметрами. */
    public static byte[] encode(String algorithmOid, byte[] params) {
        byte[] encodedOid = DerCodec.encodeOid(algorithmOid);
        return DerCodec.encodeSequence(encodedOid, params);
    }

    /** Декодирует AlgorithmIdentifier из DER. */
    public static CmsAlgorithmIdentifier decode(byte[] der) {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        String oid = DerCodec.parseOid(parts[0], 0);
        byte[] params = parts.length > 1 ? parts[1] : null;
        return new CmsAlgorithmIdentifier(oid, params);
    }
}
