package org.rssys.gost.crossval.cadest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.util.DerCodec;

/**
 * Убирает {@code NULL} из {@code AlgorithmIdentifier} в служебных полях CMS.
 *
 * <p>КриптоПро кодирует идентификаторы ГОСТ-алгоритмов без параметров, и
 * {@code cryptcp -enhance} отвечает ошибкой ASN1, если за OID следует {@code NULL}. Правятся
 * ровно три места: {@code SignedData.digestAlgorithms}, {@code SignerInfo.digestAlgorithm} и
 * {@code SignerInfo.signatureAlgorithm}. Они лежат вне подписанных атрибутов, поэтому подпись не
 * ломается, а сертификаты, подписанные атрибуты и содержимое остаются побайтно прежними.
 * Это обход для инструмента получения вектора, библиотека кодирует как прежде.
 */
final class DerAlgorithmIdentifierNormalizer {

    private static final int TAG_SET = 0x31;
    private static final int TAG_NULL = 0x05;
    private static final int NULL_ENCODED_LENGTH = 2;
    private static final int ALGORITHM_IDENTIFIER_PARTS = 2;
    private static final int SIGNED_ATTRS_TAG = 0xA0;
    private static final int EXPLICIT_CONTENT_TAG = 0xA0;

    /** Позиции полей в {@code SignedData}: версия, digestAlgorithms, содержимое. */
    private static final int DIGEST_ALGORITHMS_INDEX = 1;

    /** Позиции полей в {@code SignerInfo}: версия, sid, digestAlgorithm. */
    private static final int SIGNER_DIGEST_ALGORITHM_INDEX = 2;

    private static final int SIGNER_AFTER_DIGEST_INDEX = 3;

    private DerAlgorithmIdentifierNormalizer() {}

    /** @return копия {@code ContentInfo} с {@code SignedData}, где убраны NULL в трёх полях */
    static byte[] normalizeContentInfo(byte[] contentInfoDer) {
        byte[][] parts = DerCodec.parseSequenceContents(contentInfoDer, 0);
        // [0] EXPLICIT содержит ровно один SignedData
        byte[] signedData = contentOf(parts[1]);
        byte[] normalized =
                DerCodec.encodeTlv(EXPLICIT_CONTENT_TAG, normalizeSignedData(signedData));
        return DerCodec.encodeSequence(parts[0], normalized);
    }

    /** @return копия {@code TimeStampResp}, где {@code SignedData} токена нормализован */
    static byte[] normalizeTimeStampResp(byte[] timeStampRespDer) {
        byte[][] parts = DerCodec.parseSequenceContents(timeStampRespDer, 0);
        if (parts.length < 2) {
            return timeStampRespDer.clone();
        }
        return DerCodec.encodeSequence(parts[0], normalizeContentInfo(parts[1]));
    }

    private static byte[] normalizeSignedData(byte[] signedData) {
        byte[][] fields = DerCodec.parseSequenceContents(signedData, 0);
        fields[DIGEST_ALGORITHMS_INDEX] = normalizeAlgorithmSet(fields[DIGEST_ALGORITHMS_INDEX]);
        int last = fields.length - 1;
        fields[last] = normalizeSignerInfos(fields[last]);
        return DerCodec.encodeSequence(fields);
    }

    private static byte[] normalizeSignerInfos(byte[] signerInfosSet) {
        List<byte[]> normalized = new ArrayList<>();
        for (byte[] signerInfo : DerCodec.parseSetContents(signerInfosSet, 0)) {
            normalized.add(normalizeSignerInfo(signerInfo));
        }
        return DerCodec.encodeTlv(TAG_SET, concat(normalized));
    }

    private static byte[] normalizeSignerInfo(byte[] signerInfo) {
        byte[][] fields = DerCodec.parseSequenceContents(signerInfo, 0);
        fields[SIGNER_DIGEST_ALGORITHM_INDEX] =
                stripNullParameters(fields[SIGNER_DIGEST_ALGORITHM_INDEX]);
        boolean hasSignedAttrs = (fields[SIGNER_AFTER_DIGEST_INDEX][0] & 0xFF) == SIGNED_ATTRS_TAG;
        int signatureAlgorithmIndex =
                hasSignedAttrs ? SIGNER_AFTER_DIGEST_INDEX + 1 : SIGNER_AFTER_DIGEST_INDEX;
        fields[signatureAlgorithmIndex] = stripNullParameters(fields[signatureAlgorithmIndex]);
        return DerCodec.encodeSequence(fields);
    }

    private static byte[] normalizeAlgorithmSet(byte[] algorithmSet) {
        List<byte[]> normalized = new ArrayList<>();
        for (byte[] algorithm : DerCodec.parseSetContents(algorithmSet, 0)) {
            normalized.add(stripNullParameters(algorithm));
        }
        return DerCodec.encodeTlv(TAG_SET, concat(normalized));
    }

    /** {@code SEQUENCE { OID, NULL }} -> {@code SEQUENCE { OID }}; прочие значения без изменений. */
    private static byte[] stripNullParameters(byte[] algorithmIdentifier) {
        byte[][] parts = DerCodec.parseSequenceContents(algorithmIdentifier, 0);
        if (parts.length == ALGORITHM_IDENTIFIER_PARTS
                && parts[1].length == NULL_ENCODED_LENGTH
                && (parts[1][0] & 0xFF) == TAG_NULL) {
            return DerCodec.encodeSequence(parts[0]);
        }
        return algorithmIdentifier;
    }

    private static byte[] concat(List<byte[]> items) {
        return DerCodec.concat(items.toArray(new byte[0][]));
    }

    /** Содержимое TLV без заголовка. */
    private static byte[] contentOf(byte[] tlv) {
        int[] length = DerCodec.decodeLength(tlv, 1);
        return Arrays.copyOfRange(tlv, 1 + length[1], tlv.length);
    }
}
