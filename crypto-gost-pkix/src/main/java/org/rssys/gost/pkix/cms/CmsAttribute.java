package org.rssys.gost.pkix.cms;

import org.rssys.gost.util.DerCodec;

/**
 * Атрибут signed/unsigned (RFC 5652 §5.3).
 *
 * <pre>
 * Attribute ::= SEQUENCE {
 *   attrType   OBJECT IDENTIFIER,
 *   attrValues SET OF ANY DEFINED BY attrType
 * }
 * </pre>
 */
public final class CmsAttribute {

    private final String attrType;
    private final byte[][] attrValues;

    private CmsAttribute(String attrType, byte[][] attrValues) {
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public String attrType() {
        return attrType;
    }

    public byte[][] attrValues() {
        byte[][] copy = new byte[attrValues.length][];
        for (int i = 0; i < attrValues.length; i++) {
            copy[i] = attrValues[i].clone();
        }
        return copy;
    }

    // ========================================================================
    // Кодирование / декодирование
    // ========================================================================

    /**
     * Кодирует Attribute в DER.
     */
    public static byte[] encode(String attrType, byte[]... attrValues) {
        byte[] encodedOid = DerCodec.encodeOid(attrType);
        byte[] encodedValues = DerCodec.encodeSetOf(attrValues);
        return DerCodec.encodeSequence(encodedOid, encodedValues);
    }

    /**
     * Декодирует Attribute из DER.
     */
    public static CmsAttribute decode(byte[] der) {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        String oid = DerCodec.parseOid(parts[0], 0);
        // parts[1] — SET OF, разбираем вручную через decodeLength
        byte[] setData = parts[1];
        int[] setLen = DerCodec.decodeLength(setData, 1);
        int contentStart = 1 + setLen[1];
        int contentEnd = contentStart + setLen[0];

        java.util.ArrayList<byte[]> values = new java.util.ArrayList<>();
        int pos = contentStart;
        while (pos < contentEnd) {
            int[] childLen = DerCodec.decodeLength(setData, pos + 1);
            int childTotal = 1 + childLen[1] + childLen[0];
            values.add(java.util.Arrays.copyOfRange(setData, pos, pos + childTotal));
            pos += childTotal;
        }
        return new CmsAttribute(oid, values.toArray(new byte[0][]));
    }
}
