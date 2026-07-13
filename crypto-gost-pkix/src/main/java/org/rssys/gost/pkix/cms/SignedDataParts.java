package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Держатель raw-частей верхнего уровня CMS SignedData (RFC 5652 §5.1).
 *
 * <p>Разбирает {@code SignedData} на составные поля без интерпретации их содержимого —
 * интерпретация (сертификаты, signerInfos, атрибуты) остаётся в вызывающем коде.
 * Служит единым источником хрупкой арифметики индексов для {@code embed*}-методов
 * {@link CAdESExtender}, где ранее эта логика дублировалась трижды.
 *
 * <p>OPTIONAL-поля {@code certificates [0]} и {@code crls [1]} могут быть {@code null}.
 * Метод {@link #rebuild(byte[], byte[])} пересобирает SignedData с заменой certificates и
 * signerInfos, сохраняя остальные поля и nullable-семантику.
 *
 * <p><b>Область применения — только {@code CAdESExtender}.</b> Родственная логика разбора
 * SignedData существует также в {@code CmsSignedDataVerifier.parseSignedData} и
 * {@code GostPkcs7} (там она сложнее и уже стабилизирована кросс-валидацией), но
 * сознательно не унифицируется здесь: риск регресса в проверенном коде несоразмерен
 * выгоде. Это потенциальный объём отдельного будущего рефакторинга.
 */
record SignedDataParts(
        byte[] version,
        byte[] digestAlgs,
        byte[] encapContentInfo,
        byte[] certs,
        byte[] crls,
        byte[] signerInfosField) {

    /**
     * Разбирает тело SignedData (contents ContentInfo.content) на составные поля.
     *
     * @param signedDataBody DER-байты SignedData SEQUENCE
     * @return разобранные части
     * @throws PkixException если структура слишком коротка или отсутствуют signerInfos
     */
    static SignedDataParts parse(byte[] signedDataBody) throws PkixException {
        byte[][] sdParts = DerCodec.parseSequenceContents(signedDataBody, 0);
        if (sdParts.length < 4) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData too short: expected at least version, digestAlgorithms, "
                            + "encapContentInfo, signerInfos");
        }
        int sdIdx = 0;

        byte[] version = sdParts[sdIdx++];
        byte[] digestAlgs = sdParts[sdIdx++];
        byte[] encapContentInfo = sdParts[sdIdx++];

        byte[] certs = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 0)) {
            certs = sdParts[sdIdx++];
        }

        byte[] crls = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 1)) {
            crls = sdParts[sdIdx++];
        }

        if (sdIdx >= sdParts.length) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "SignedData too short: missing signerInfos");
        }
        byte[] signerInfosField = sdParts[sdIdx];

        return new SignedDataParts(
                version, digestAlgs, encapContentInfo, certs, crls, signerInfosField);
    }

    /**
     * Пересобирает SignedData с заменой полей certificates и signerInfos.
     *
     * @param newCerts       новое поле certificates [0] или {@code null} (поле опускается)
     * @param newSignerInfos новое поле signerInfos SET OF
     * @return DER-байты пересобранного SignedData SEQUENCE
     */
    byte[] rebuild(byte[] newCerts, byte[] newSignerInfos) {
        List<byte[]> sdElements = new ArrayList<>();
        sdElements.add(version);
        sdElements.add(digestAlgs);
        sdElements.add(encapContentInfo);
        if (newCerts != null) {
            sdElements.add(newCerts);
        }
        if (crls != null) {
            sdElements.add(crls);
        }
        sdElements.add(newSignerInfos);
        return DerCodec.encodeSequence(sdElements.toArray(new byte[0][]));
    }
}
