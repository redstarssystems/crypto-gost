package org.rssys.gost.pkix.cms;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Пересборка DER EnvelopedData для тестов подмены: меняет отдельные поля контейнера и сохраняет
 * остальные как есть. Длина OID меняется, поэтому побайтовая замена невозможна — структура
 * собирается заново.
 */
final class CmsEnvelopedRewriter {

    private static final int RECIPIENT_INFO_KEY_ENCRYPTION_ALGORITHM_KTRI = 2;
    private static final int RECIPIENT_INFO_KEY_ENCRYPTION_ALGORITHM_KARI = 3;
    private static final int RECIPIENT_ENCRYPTED_KEYS = 4;
    private static final int KTRI_ENCRYPTED_KEY = 3;

    private CmsEnvelopedRewriter() {}

    /** Поля EnvelopedData: version, recipientInfos, encryptedContentInfo[, unprotectedAttrs]. */
    static byte[][] envParts(byte[] contentInfoDer) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(contentInfoDer);
        return DerCodec.parseSequenceContents(contentInfo.content(), 0);
    }

    static byte[] assemble(byte[]... envParts) {
        return CmsContentInfo.encode(
                GostOids.CMS_ENVELOPED_DATA, DerCodec.encodeSequence(envParts));
    }

    /** Подменяет OID шифра содержимого, параметры (UKM) и остальные поля сохраняются. */
    static byte[] withContentOid(byte[] contentInfoDer, String contentOid) throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        byte[][] eci = DerCodec.parseSequenceContents(env[2], 0);
        env[2] = DerCodec.encodeSequence(eci[0], replaceOid(eci[1], contentOid), eci[2]);
        return assemble(env);
    }

    /** Удаляет unprotectedAttrs, version не трогает: расшифровщик её не читает. */
    static byte[] withoutUnprotectedAttrs(byte[] contentInfoDer) throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        return assemble(Arrays.copyOf(env, 3));
    }

    /** Вставляет пустой originatorInfo [0] после version (RFC 5652 §6.1). */
    static byte[] withOriginatorInfo(byte[] contentInfoDer) throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        byte[][] shifted = new byte[env.length + 1][];
        shifted[0] = env[0];
        shifted[1] = DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, new byte[0]);
        System.arraycopy(env, 1, shifted, 2, env.length - 1);
        return assemble(shifted);
    }

    /** Подменяет внешний OID keyEncryptionAlgorithm во всех RecipientInfo (ktri и kari). */
    static byte[] withKeyEncryptionOid(byte[] contentInfoDer, String keyEncryptionOid)
            throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        byte[][] recipientInfos = DerCodec.parseSetContents(env[1], 0);
        byte[][] rewritten = new byte[recipientInfos.length][];
        for (int i = 0; i < recipientInfos.length; i++) {
            byte[] recipientInfo = recipientInfos[i];
            if ((recipientInfo[0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                // kari [1] IMPLICIT: содержимое — поля без внешней SEQUENCE
                int[] len = DerCodec.decodeLength(recipientInfo, 1);
                int start = 1 + len[1];
                byte[] content = Arrays.copyOfRange(recipientInfo, start, start + len[0]);
                byte[][] parts =
                        DerCodec.parseSequenceContents(DerCodec.encodeSequence(content), 0);
                parts[RECIPIENT_INFO_KEY_ENCRYPTION_ALGORITHM_KARI] =
                        replaceOid(
                                parts[RECIPIENT_INFO_KEY_ENCRYPTION_ALGORITHM_KARI],
                                keyEncryptionOid);
                rewritten[i] = DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, concat(parts));
            } else {
                byte[][] parts = DerCodec.parseSequenceContents(recipientInfo, 0);
                parts[RECIPIENT_INFO_KEY_ENCRYPTION_ALGORITHM_KTRI] =
                        replaceOid(
                                parts[RECIPIENT_INFO_KEY_ENCRYPTION_ALGORITHM_KTRI],
                                keyEncryptionOid);
                rewritten[i] = DerCodec.encodeSequence(parts);
            }
        }
        env[1] = DerCodec.encodeSetOf(rewritten);
        return assemble(env);
    }

    /** Содержимое unprotectedAttrs как список Attribute (внешний тег [1] IMPLICIT снимается). */
    static byte[][] unprotectedAttributes(byte[] contentInfoDer) throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        byte[] field = env[3];
        int[] len = DerCodec.decodeLength(field, 1);
        int start = 1 + len[1];
        byte[] content = Arrays.copyOfRange(field, start, start + len[0]);
        return DerCodec.parseSequenceContents(DerCodec.encodeSequence(content), 0);
    }

    /** Заменяет unprotectedAttrs набором Attribute; порядок и число атрибутов задаёт вызывающий. */
    static byte[] withUnprotectedAttributes(byte[] contentInfoDer, byte[]... attributes)
            throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        byte[][] replaced = Arrays.copyOf(env, 4);
        replaced[3] = DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, concat(attributes));
        return assemble(replaced);
    }

    /** Attribute { type, SET { OCTET STRING value } } с произвольным OID, не связанный с MAC. */
    static byte[] unrelatedAttribute(String oid, byte[] value) {
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(oid), DerCodec.encodeSetOf(DerCodec.encodeOctetString(value)));
    }

    /** Портит encryptedMac адресно: порядок полей контейнера на результат не влияет. */
    static byte[] withTamperedEncryptedMac(byte[] contentInfoDer) throws PkixException {
        byte[][] attributes = unprotectedAttributes(contentInfoDer);
        byte[][] attrParts = DerCodec.parseSequenceContents(attributes[0], 0);
        byte[][] values = DerCodec.parseSetContents(attrParts[1], 0);
        byte[] encryptedMac = DerCodec.parseOctetString(values[0], 0);
        encryptedMac[encryptedMac.length - 1] ^= 0x01;
        attributes[0] =
                DerCodec.encodeSequence(
                        attrParts[0],
                        DerCodec.encodeSetOf(DerCodec.encodeOctetString(encryptedMac)));
        return withUnprotectedAttributes(contentInfoDer, attributes);
    }

    /**
     * Портит обёрнутый CEK (выход KExp15) адресно: меняется один бит последнего байта, поэтому
     * проверка имитовставки KExp15 при разборе обязана отказать. Остальные поля контейнера
     * сохраняются.
     */
    static byte[] withCorruptedWrappedKey(byte[] contentInfoDer) throws PkixException {
        byte[][] env = envParts(contentInfoDer);
        byte[][] recipientInfos = DerCodec.parseSetContents(env[1], 0);
        byte[][] rewritten = new byte[recipientInfos.length][];
        for (int i = 0; i < recipientInfos.length; i++) {
            byte[] recipientInfo = recipientInfos[i];
            if ((recipientInfo[0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                // kari: recipientEncryptedKeys SEQUENCE OF { rid, encryptedKey OCTET STRING }
                int[] len = DerCodec.decodeLength(recipientInfo, 1);
                int start = 1 + len[1];
                byte[] content = Arrays.copyOfRange(recipientInfo, start, start + len[0]);
                byte[][] parts =
                        DerCodec.parseSequenceContents(DerCodec.encodeSequence(content), 0);
                byte[][] keys = DerCodec.parseSequenceContents(parts[RECIPIENT_ENCRYPTED_KEYS], 0);
                for (int k = 0; k < keys.length; k++) {
                    byte[][] keyParts = DerCodec.parseSequenceContents(keys[k], 0);
                    keyParts[1] = flipLastBit(keyParts[1]);
                    keys[k] = DerCodec.encodeSequence(keyParts);
                }
                parts[RECIPIENT_ENCRYPTED_KEYS] = DerCodec.encodeSequence(keys);
                rewritten[i] = DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, concat(parts));
            } else {
                // ktri: encryptedKey OCTET STRING { SEQUENCE { sessionEncryptedKey, spki, ukm } }
                byte[][] parts = DerCodec.parseSequenceContents(recipientInfo, 0);
                byte[] transport = DerCodec.parseOctetString(parts[KTRI_ENCRYPTED_KEY], 0);
                byte[][] transportParts = DerCodec.parseSequenceContents(transport, 0);
                transportParts[0] = flipLastBit(transportParts[0]);
                parts[KTRI_ENCRYPTED_KEY] =
                        DerCodec.encodeOctetString(DerCodec.encodeSequence(transportParts));
                rewritten[i] = DerCodec.encodeSequence(parts);
            }
        }
        env[1] = DerCodec.encodeSetOf(rewritten);
        return assemble(env);
    }

    /** Переворачивает младший бит последнего байта OCTET STRING, длина и тег сохраняются. */
    private static byte[] flipLastBit(byte[] octetString) {
        byte[] value = DerCodec.parseOctetString(octetString, 0);
        value[value.length - 1] ^= 0x01;
        return DerCodec.encodeOctetString(value);
    }

    /** Заменяет OID в AlgorithmIdentifier, параметры сохраняются. */
    private static byte[] replaceOid(byte[] algorithmIdentifier, String oid) {
        byte[][] parts = DerCodec.parseSequenceContents(algorithmIdentifier, 0);
        byte[][] replaced = parts.clone();
        replaced[0] = DerCodec.encodeOid(oid);
        return DerCodec.encodeSequence(replaced);
    }

    private static byte[] concat(byte[][] parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
