package org.rssys.gost.pkix.cms;

import java.math.BigInteger;
import java.util.Arrays;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.AcpkmSectionSize;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Расшифровка CMS EnvelopedData.
 *
 * <p>Поддерживает оба типа RecipientInfo:
 * <ul>
 *   <li><b>ktri</b> (KeyTransRecipientInfo, тег {@code 0x30}) —
 *       основной формат по ТК26 §8.2.1, используется КриптоПРО 5.0.</li>
 *   <li><b>kari</b> (KeyAgreeRecipientInfo, тег {@code 0xA1}) —
 *       RFC 5652 §6.2.2, VKO + KExp15.</li>
 * </ul>
 *
 * <p>Формат определяется автоматически по тегу первого байта RecipientInfo.
 *
 * <p>Поддерживаемые шифры содержимого: {@link GostOids#KUZ_CTR_ACPKM} (без имитовставки) и
 * {@link GostOids#KUZ_CTR_ACPKM_OMAC} (с имитовставкой в атрибуте content-mac). Контейнер с любым
 * другим OID шифра отвергается. {@link #decrypt} принимает только контейнеры с имитовставкой;
 * контейнеры без неё читает {@link #decryptAllowingNoIntegrity}.
 *
 * <p>KeyUsage сертификата получателя здесь намеренно не проверяется: расшифровывает владелец
 * ключа, и отказ ему ничего не защищает. Назначение ключа проверяет отправитель при
 * {@link CmsEnvelopedDataBuilder#addRecipient}; не «исправляйте» эту асимметрию.
 */
public final class CmsEnvelopedDataDecryptor {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor");

    private static final int TAG_KARI = 0xA1;
    private static final int TAG_KTRI = 0x30;
    // originatorInfo [0] IMPLICIT (RFC 5652 §6.1) сдвигает позиции recipientInfos и
    // encryptedContentInfo; поддержки у библиотеки нет, поэтому такой контейнер отвергается явно.
    private static final int TAG_ORIGINATOR_INFO = 0xA0;
    private static final int MIN_ENVELOPED_DATA_PARTS = 3;
    // version, recipientInfos, encryptedContentInfo, unprotectedAttrs: originatorInfo отвергается
    private static final int MAX_ENVELOPED_DATA_PARTS = 4;
    private static final int MIN_ENCRYPTED_CONTENT_INFO_PARTS = 3;

    // Обёртка CEK одна и без состояния: сменная реализация дала бы чужому коду открытые KEK и CEK.
    private static final CmsKeyWrap KEY_WRAP = new Kexp15CmsKeyWrap();

    /** Режим шифра содержимого, выбранный по OID контейнера. */
    private enum ContentMode {
        CTR_ACPKM,
        CTR_ACPKM_OMAC
    }

    /**
     * Проверенные параметры шифра содержимого. Разбираются один раз до перебора получателей,
     * поэтому контейнер с недопустимым шифром отвергается до операций с закрытым ключом.
     */
    private static final class ContentCipher {
        private final ContentMode mode;
        private final byte[] ukm;
        // зашифрованный MAC из content-mac: только для CTR_ACPKM_OMAC
        private final byte[] encryptedMac;
        // поле encryptedContent [0] как есть: копирование содержимого откладывается до своего
        // получателя
        private final byte[] encryptedContentField;

        private ContentCipher(
                ContentMode mode, byte[] ukm, byte[] encryptedMac, byte[] encryptedContentField) {
            this.mode = mode;
            this.ukm = ukm;
            this.encryptedMac = encryptedMac;
            this.encryptedContentField = encryptedContentField;
        }
    }

    private CmsEnvelopedDataDecryptor() {}

    /**
     * Расшифровывает EnvelopedData, требуя имитовставку содержимого (OMAC).
     *
     * <p>Принимает шифр содержимого {@link GostOids#KUZ_CTR_ACPKM_OMAC}; MAC проверяется до выдачи
     * данных. Контейнер с {@link GostOids#KUZ_CTR_ACPKM} (без имитовставки) отвергается с причиной
     * {@link PkixException.Reason#INTEGRITY_REQUIRED}: режим CTR не защищает от подмены, а
     * замена OID шифра и удаление атрибута content-mac иначе давала бы мусор вместо ошибки.
     * Контейнеры без имитовставки читает {@link #decryptAllowingNoIntegrity}. Любой другой OID
     * шифра содержимого отвергается.
     *
     * @param envelopedDataDer DER-кодированный ContentInfo(id-envelopedData)
     * @param recipientKey     закрытый ключ получателя
     * @param recipientCert    сертификат получателя (для поиска в SET OF)
     * @return расшифрованные данные
     * @throws PkixException если расшифрование не удалось или контейнер без имитовставки
     */
    public static byte[] decrypt(
            byte[] envelopedDataDer,
            PrivateKeyParameters recipientKey,
            GostCertificate recipientCert)
            throws PkixException {
        return decrypt(envelopedDataDer, recipientKey, recipientCert, true);
    }

    /**
     * Расшифровывает EnvelopedData, допуская отсутствие имитовставки содержимого.
     *
     * <p>Принимает оба шифра содержимого: {@link GostOids#KUZ_CTR_ACPKM_OMAC} и
     * {@link GostOids#KUZ_CTR_ACPKM}. Для контейнера с имитовставкой MAC проверяется всегда:
     * метод допускает отсутствие целостности, но не отключает её проверку. Для контейнера без
     * имитовставки целостность не гарантируется (CTR допускает целенаправленную подмену
     * шифртекста), поэтому метод нужен для обмена с узлами, которые шлют контейнеры без OMAC, и
     * для случаев, когда целостность обеспечивает внешняя подпись. Любой другой OID шифра
     * содержимого отвергается.
     *
     * @param envelopedDataDer DER-кодированный ContentInfo(id-envelopedData)
     * @param recipientKey     закрытый ключ получателя
     * @param recipientCert    сертификат получателя (для поиска в SET OF)
     * @return расшифрованные данные
     * @throws PkixException если расшифрование не удалось
     */
    public static byte[] decryptAllowingNoIntegrity(
            byte[] envelopedDataDer,
            PrivateKeyParameters recipientKey,
            GostCertificate recipientCert)
            throws PkixException {
        return decrypt(envelopedDataDer, recipientKey, recipientCert, false);
    }

    private static byte[] decrypt(
            byte[] envelopedDataDer,
            PrivateKeyParameters recipientKey,
            GostCertificate recipientCert,
            boolean requireIntegrity)
            throws PkixException {
        // Весь разбор недоверенного входа под одним try: непроверяемое исключение парсера
        // не должно уходить из публичного метода.
        try {
            // 1. ContentInfo -> EnvelopedData
            CmsContentInfo contentInfo = CmsContentInfo.decode(envelopedDataDer);
            if (!GostOids.CMS_ENVELOPED_DATA.equals(contentInfo.contentType())) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Invalid contentType: expected id-envelopedData");
            }
            byte[] envelopedData = contentInfo.content();
            if (envelopedData == null)
                throw new PkixException(
                        PkixException.Reason.OTHER, "ContentInfo does not contain EnvelopedData");

            byte[][] envParts = DerCodec.parseSequenceContents(envelopedData, 0);
            if (envParts.length < MIN_ENVELOPED_DATA_PARTS) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "EnvelopedData must contain version, recipientInfos and encryptedContentInfo");
            }
            // originatorInfo проверяется раньше числа элементов: с ним контейнер на один элемент
            // длиннее, и причина отказа должна называть именно его
            if ((envParts[1][0] & 0xFF) == TAG_ORIGINATOR_INFO) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "originatorInfo is not supported");
            }
            if (envParts.length > MAX_ENVELOPED_DATA_PARTS) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "EnvelopedData has unexpected trailing element(s), got "
                                + envParts.length
                                + " element(s)");
            }
            byte[] recipientInfosField = envParts[1];

            // unprotectedAttrs [1] IMPLICIT SET OF Attribute (присутствуют для OMAC)
            byte[] unprotectedAttrsField = envParts.length > 3 ? envParts[3] : null;

            // 2. Шифр содержимого и политика целостности проверяются до перебора получателей:
            // отказ дешёвый, а VKO на закрытом ключе над заведомо отвергаемым контейнером не нужен.
            ContentCipher cipher =
                    resolveContentCipher(envParts[2], unprotectedAttrsField, requireIntegrity);

            // 3. Ищем свой RecipientEncryptedKey в SET OF
            BigInteger mySerial = recipientCert.getSerialNumberBigInt();
            byte[] myIssuer = recipientCert.getIssuerDnBytes();

            byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
            for (byte[] riElem : riElems) {
                int tag = riElem[0] & 0xFF;

                if (tag == TAG_KARI) {
                    byte[] result =
                            decryptKeyAgree(riElem, recipientKey, mySerial, myIssuer, cipher);
                    if (result != null) return result;
                } else if (tag == TAG_KTRI) {
                    byte[] result =
                            decryptKeyTrans(riElem, recipientKey, mySerial, myIssuer, cipher);
                    if (result != null) return result;
                } else {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "Unsupported RecipientInfo tag 0x"
                                    + Integer.toHexString(tag).toUpperCase());
                }
            }

            throw new PkixException(PkixException.Reason.OTHER, "Recipient key not found");
        } catch (RuntimeException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Разбирает шифр содержимого и проверяет его согласованность с unprotectedAttrs и политикой.
     *
     * <p>Порядок проверок задаёт причину отказа: недопустимый OID -> длина UKM -> согласованность
     * режима с атрибутом content-mac -> требование имитовставки.
     */
    private static ContentCipher resolveContentCipher(
            byte[] encryptedContentInfo, byte[] unprotectedAttrsField, boolean requireIntegrity)
            throws PkixException {
        byte[][] eciParts = DerCodec.parseSequenceContents(encryptedContentInfo, 0);
        if (eciParts.length < MIN_ENCRYPTED_CONTENT_INFO_PARTS) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "EncryptedContentInfo must contain contentType, algorithm and encryptedContent");
        }
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);

        String contentAlgOid = DerCodec.parseOid(algParts[0], 0);
        ContentMode mode;
        if (GostOids.KUZ_CTR_ACPKM_OMAC.equals(contentAlgOid)) {
            mode = ContentMode.CTR_ACPKM_OMAC;
        } else if (GostOids.KUZ_CTR_ACPKM.equals(contentAlgOid)) {
            mode = ContentMode.CTR_ACPKM;
        } else {
            // Неизвестный OID нельзя обрабатывать как Кузнечик: результатом был бы мусор
            // вместо ошибки.
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Unsupported content encryption algorithm: " + contentAlgOid);
        }

        byte[] ukm = extractContentUkm(algParts);

        // Контейнер, в котором режим и атрибут content-mac противоречат друг другу, подменён или
        // собран некорректно.
        byte[] encryptedMac = findEncryptedMac(unprotectedAttrsField);
        if (mode == ContentMode.CTR_ACPKM_OMAC && encryptedMac == null) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "OMAC container missing content-mac attribute ("
                            + GostOids.ID_CMS_MAC_ATTR
                            + ") in unprotectedAttrs");
        }
        if (mode == ContentMode.CTR_ACPKM && encryptedMac != null) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "content-mac attribute present, but content encryption algorithm is not OMAC");
        }

        if (requireIntegrity && mode == ContentMode.CTR_ACPKM) {
            throw new PkixException(
                    PkixException.Reason.INTEGRITY_REQUIRED,
                    "Content integrity (OMAC) required, container uses " + contentAlgOid);
        }
        return new ContentCipher(mode, ukm, encryptedMac, eciParts[2]);
    }

    private static byte[] extractContentUkm(byte[][] algParts) throws PkixException {
        if (algParts.length > 1 && (algParts[1][0] & 0xFF) == DerCodec.TAG_SEQUENCE) {
            byte[][] ivSeq = DerCodec.parseSequenceContents(algParts[1], 0);
            if (ivSeq.length > 0 && (ivSeq[0][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                byte[] ukm = DerCodec.parseOctetString(ivSeq[0], 0);
                if (ukm.length != GostOids.CMS_CONTENT_UKM_LEN) {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "Content UKM must be "
                                    + GostOids.CMS_CONTENT_UKM_LEN
                                    + " bytes, got "
                                    + ukm.length);
                }
                return ukm;
            }
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "IV/UKM (OCTET STRING) not found in cipher params SEQUENCE");
        }
        throw new PkixException(
                PkixException.Reason.PARSE_ERROR, "Cipher params (SEQUENCE) not found");
    }

    // ========================================================================
    // kari (KeyAgreeRecipientInfo, тег 0xA1)
    // ========================================================================

    private static byte[] decryptKeyAgree(
            byte[] riElem,
            PrivateKeyParameters recipientKey,
            BigInteger mySerial,
            byte[] myIssuer,
            ContentCipher cipher)
            throws PkixException {

        int[] kariLen = DerCodec.decodeLength(riElem, 1);
        int off = 1 + kariLen[1];
        byte[] kariDer = Arrays.copyOfRange(riElem, off, off + kariLen[0]);

        // RecipientInfo CHOICE kari [1] IMPLICIT:
        // тег 0xA1 заменяет SEQUENCE, поэтому kariDer начинается c version INTEGER 0x02.
        // Оборачиваем обратно в SEQUENCE для совместимости с общим парсером.
        byte[] kariSeq = DerCodec.encodeSequence(kariDer);
        byte[][] kaParts = DerCodec.parseSequenceContents(kariSeq, 0);
        int idx = 0;
        idx++;

        PublicKeyParameters ephemeralPub = extractEphemeralPublicKey(kaParts[idx++]);
        byte[] ukmBytes = extractUkm(kaParts[idx++]);
        byte[] keyEncryptionAlgorithm = kaParts[idx++];

        // recipientEncryptedKeys SEQUENCE OF
        byte[][] rekSeq = DerCodec.parseSequenceContents(kaParts[idx], 0);
        for (byte[] rkDer : rekSeq) {
            byte[][] rkParts = DerCodec.parseSequenceContents(rkDer, 0);
            CmsIssuerAndSerialNumber rid = CmsIssuerAndSerialNumber.decode(rkParts[0]);
            if (!mySerial.equals(rid.serial()) || !Arrays.equals(myIssuer, rid.issuer())) {
                LOG.log(
                        Level.DEBUG,
                        "RecipientKey serial {0} does not match, skipping",
                        rid.serial().toString(16));
                continue;
            }

            // Алгоритм обёртки сверяется до VKO: закрытый ключ не работает над заведомо
            // отвергаемым получателем. Вложенный agreement-OID не проверяется: вариант VKO
            // выбирается по размеру ключа получателя.
            requireKeyWrapAlgorithm(keyEncryptionAlgorithm, "kari");

            byte[] wrappedCek = DerCodec.parseOctetString(rkParts[1], 0);

            BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
            byte[] kek =
                    (recipientKey.getParams().hlen == GostOids.STREEBOG_512_HASH_LEN)
                            ? KeyAgreement.vkoGostR3410_2012_512(recipientKey, ephemeralPub, ukm)
                            : KeyAgreement.vkoGostR3410_2012_256(recipientKey, ephemeralPub, ukm);

            // IV = UKM[24..31] (формула ТК26)
            byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);

            byte[] cek;
            try {
                cek = KEY_WRAP.unwrap(wrappedCek, kek, ukmBytes, iv);
            } finally {
                // Отказ проверки имитовставки KExp15 (намеренно испорченный wrappedCek) не должен
                // оставлять KEK и IV в памяти: затирание на любом пути выхода
                Arrays.fill(kek, (byte) 0);
                Arrays.fill(iv, (byte) 0);
            }

            try {
                byte[] decrypted = decryptContent(cipher, cek);
                // Серийный номер переводится в строку до проверки уровня внутри log: при
                // выключенном DEBUG эта работа лишняя на каждой расшифровке
                if (LOG.isLoggable(Level.DEBUG)) {
                    LOG.log(
                            Level.DEBUG,
                            "EnvelopedData (kari) decrypted successfully for recipient serial 0x{0}",
                            mySerial.toString(16));
                }
                return decrypted;
            } finally {
                Arrays.fill(cek, (byte) 0);
            }
        }
        return null;
    }

    // ========================================================================
    // ktri (KeyTransRecipientInfo, тег 0x30) — ТК26 §8.2.1
    // ========================================================================

    private static byte[] decryptKeyTrans(
            byte[] riDer,
            PrivateKeyParameters recipientKey,
            BigInteger mySerial,
            byte[] myIssuer,
            ContentCipher cipher)
            throws PkixException {

        // KeyTransRecipientInfo: SEQUENCE { version, rid, keyEncAlg, encryptedKey }
        byte[][] ktParts = DerCodec.parseSequenceContents(riDer, 0);

        // Проверка rid (RecipientIdentifier)
        byte[][] ridParts = DerCodec.parseSequenceContents(ktParts[1], 0);
        CmsIssuerAndSerialNumber rid = CmsIssuerAndSerialNumber.decode(ktParts[1]);
        if (!mySerial.equals(rid.serial()) || !Arrays.equals(myIssuer, rid.issuer())) {
            LOG.log(
                    Level.DEBUG,
                    "RecipientKey serial {0} does not match (ktri), skipping",
                    rid.serial().toString(16));
            return null;
        }

        requireKeyWrapAlgorithm(ktParts[2], "ktri");

        // encryptedKey OCTET STRING -> GostR3410-KeyTransport SEQUENCE
        byte[] encKeyDer = DerCodec.parseOctetString(ktParts[3], 0);
        byte[][] keyTransParts = DerCodec.parseSequenceContents(encKeyDer, 0);

        // [0] sessionEncryptedKey OCTET STRING (KExp15 output: 48 байт для Кузнечика)
        byte[] wrappedCek = DerCodec.parseOctetString(keyTransParts[0], 0);

        // [1] ephemeralPublicKey SubjectPublicKeyInfo
        PublicKeyParameters ephemeralPub = parseEphemeralPublicKey(keyTransParts[1]);

        // [2] ukm OCTET STRING (32 байта)
        byte[] ukmBytes = DerCodec.parseOctetString(keyTransParts[2], 0);

        // VKO + KExp15: вариант VKO (256/512) — по hlen ключа получателя.
        boolean is512 = recipientKey.getParams().hlen == GostOids.STREEBOG_512_HASH_LEN;
        BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
        byte[] kek =
                is512
                        ? KeyAgreement.vkoGostR3410_2012_512(recipientKey, ephemeralPub, ukm)
                        : KeyAgreement.vkoGostR3410_2012_256(recipientKey, ephemeralPub, ukm);

        // IV = UKM[24..31] (формула ТК26: UKM[25..24+n/2] для n=16)
        byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);

        byte[] cek;
        try {
            cek = KEY_WRAP.unwrap(wrappedCek, kek, ukmBytes, iv);
        } finally {
            // Отказ проверки имитовставки KExp15 (намеренно испорченный wrappedCek) не должен
            // оставлять KEK и IV в памяти: затирание на любом пути выхода
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(iv, (byte) 0);
        }

        try {
            byte[] decrypted = decryptContent(cipher, cek);
            // См. комментарий в ветке kari: серийный номер не переводим в строку зря
            if (LOG.isLoggable(Level.DEBUG)) {
                LOG.log(
                        Level.DEBUG,
                        "EnvelopedData (ktri) decrypted successfully for recipient serial 0x{0}",
                        mySerial.toString(16));
            }
            return decrypted;
        } finally {
            Arrays.fill(cek, (byte) 0);
        }
    }

    /**
     * Парсит SubjectPublicKeyInfo из GostR3410-KeyTransport.ephemeralPublicKey.
     *
     * <p>Формат: SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
     * Использует тот же кодировщик, что и X.509-сертификаты.
     */
    static PublicKeyParameters parseEphemeralPublicKey(byte[] spkiDer) throws PkixException {
        // Весь элемент приводится к DER: байты после внешней SEQUENCE не должны молча отбрасываться
        byte[][] spkiParts =
                DerCodec.parseStrictSequence(DerCodec.normalizeBerSequenceToDer(spkiDer));
        return decodeEphemeralPublicKey(spkiParts);
    }

    /**
     * Собирает DER SubjectPublicKeyInfo из двух элементов эфемерного ключа и декодирует его.
     * <p>
     * {@code decodePublicKey} принимает только DER, а КриптоПро кодирует AlgorithmIdentifier
     * с indefinite-length, поэтому он приводится к определённой длине заранее. BIT STRING
     * нормализации не требует: он примитивный. Лишний элемент не отбрасывается молча, а
     * отвергается: иначе одному ключу соответствовало бы несколько кодировок.
     */
    private static PublicKeyParameters decodeEphemeralPublicKey(byte[][] spkiParts)
            throws PkixException {
        if (spkiParts.length != 2) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "Invalid ephemeral public key: expected AlgorithmIdentifier and BIT STRING, got "
                            + spkiParts.length
                            + " element(s)");
        }
        byte[] algorithm = DerCodec.normalizeBerSequenceToDer(spkiParts[0]);
        byte[] spki = DerCodec.encodeSequence(algorithm, spkiParts[1]);
        return org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);
    }

    // ========================================================================
    // Общие методы
    // ========================================================================

    static PublicKeyParameters extractEphemeralPublicKey(byte[] originatorField)
            throws PkixException {
        int[] oLenInfo = DerCodec.decodeLength(originatorField, 1);
        int oStart = 1 + oLenInfo[1];
        byte[] inner = Arrays.copyOfRange(originatorField, oStart, oStart + oLenInfo[0]);

        if ((inner[0] & 0xFF) == 0xA1) {
            int[] pkLen = DerCodec.decodeLength(inner, 1);
            int pkStart = 1 + pkLen[1];
            // originatorKey [1] IMPLICIT OriginatorPublicKey (RFC 5652 §6.2.2): тег [1]
            // заменяет тег SEQUENCE, поэтому содержимое — уже конкатенация
            // { algorithm, subjectPublicKey } без внешней обёртки. Возвращаем SEQUENCE-тег
            // на место, чтобы получить корректный SubjectPublicKeyInfo.
            byte[] originatorKey = Arrays.copyOfRange(inner, pkStart, pkStart + pkLen[0]);
            byte[][] spkiParts =
                    DerCodec.parseSequenceContents(DerCodec.encodeSequence(originatorKey), 0);
            return decodeEphemeralPublicKey(spkiParts);
        }
        throw new PkixException(PkixException.Reason.PARSE_ERROR, "Unsupported originator type");
    }

    /** Внешний OID keyEncryptionAlgorithm должен быть KExp15 Кузнечика; иное — отказ. */
    private static void requireKeyWrapAlgorithm(byte[] algorithmIdentifier, String recipientType)
            throws PkixException {
        byte[][] algParts = DerCodec.parseSequenceContents(algorithmIdentifier, 0);
        String keyAlgOid = DerCodec.parseOid(algParts[0], 0);
        if (!KEY_WRAP.algorithmOid().equals(keyAlgOid)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Unsupported key encryption algorithm in " + recipientType + ": " + keyAlgOid);
        }
    }

    private static byte[] extractUkm(byte[] ukmField) {
        int[] uLenInfo = DerCodec.decodeLength(ukmField, 1);
        int uStart = 1 + uLenInfo[1];
        return DerCodec.parseOctetString(ukmField, uStart);
    }

    private static byte[] decryptContent(ContentCipher cipher, byte[] cek) throws PkixException {
        byte[] encContentField = cipher.encryptedContentField;
        int encContentTag = encContentField[0] & 0xFF;
        byte[] encryptedContent;
        if (encContentTag == DerCodec.TAG_CTX_PRIMITIVE_0) {
            // Горячий путь crypto-gost (DER): [0] IMPLICIT primitive definite-length
            int[] ecLenInfo = DerCodec.decodeLength(encContentField, 1);
            int ecStart = 1 + ecLenInfo[1];
            encryptedContent = Arrays.copyOfRange(encContentField, ecStart, ecStart + ecLenInfo[0]);
        } else if (encContentTag == DerCodec.TAG_CTX_CONSTRUCTED_0) {
            // BER КриптоПРО: [0] IMPLICIT как constructed context-тег (A0 80 ... 00 00),
            // возможна сегментация OCTET STRING — собираем и склеиваем октеты
            try {
                encryptedContent = DerCodec.collectImplicitOctets(encContentField, 0);
            } catch (IllegalArgumentException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Failed to parse constructed [0] encryptedContent: " + e.getMessage());
            }
        } else {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "encryptedContent must be [0] IMPLICIT (primitive 0x80 or constructed 0xA0), got 0x"
                            + Integer.toHexString(encContentTag).toUpperCase());
        }

        return switch (cipher.mode) {
            case CTR_ACPKM_OMAC -> decryptOmac(cipher, cek, encryptedContent);
            case CTR_ACPKM -> decryptPlain(cipher, cek, encryptedContent);
        };
    }

    private static byte[] decryptOmac(ContentCipher cipher, byte[] cek, byte[] encryptedContent)
            throws PkixException {
        try {
            return CmsOmacHelper.decrypt(encryptedContent, cipher.encryptedMac, cek, cipher.ukm);
        } catch (AuthenticationException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "OMAC verification failed: " + e.getMessage());
        }
    }

    private static byte[] decryptPlain(ContentCipher cipher, byte[] cek, byte[] encryptedContent) {
        SymmetricKey key = new SymmetricKey(cek);
        try {
            return CtrAcpkmMode.decryptOnly(
                    key, cipher.ukm, encryptedContent, AcpkmSectionSize.CMS);
        } finally {
            key.destroy();
        }
    }

    /**
     * Ищет атрибут content-mac в unprotectedAttrs и возвращает его {@code encryptedMac}.
     *
     * <p>Один и тот же разбор служит обеим проверкам согласованности: OMAC-режиму атрибут
     * обязателен, обычному режиму он запрещён.
     *
     * @param unprotectedAttrsField поле unprotectedAttrs [1] IMPLICIT SET OF Attribute, или null
     * @return 16-байтовый зашифрованный MAC, или null, если атрибута нет
     * @throws PkixException если структура атрибутов неверна
     */
    private static byte[] findEncryptedMac(byte[] unprotectedAttrsField) throws PkixException {
        if (unprotectedAttrsField == null) {
            return null;
        }

        // unprotectedAttrs — [1] IMPLICIT SET OF Attribute (контекстный constructed тег 0xA1)
        int tag = unprotectedAttrsField[0] & 0xFF;
        if (tag != DerCodec.TAG_CTX_CONSTRUCTED_1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "unprotectedAttrs must be [1] IMPLICIT, got tag 0x"
                            + Integer.toHexString(tag).toUpperCase());
        }

        // Ошибка DER-парсера внутри атрибутов — битая структура, а не программная ошибка
        try {
            int[] uaLen = DerCodec.decodeLength(unprotectedAttrsField, 1);
            int uaStart = 1 + uaLen[1];
            int uaContentLen = uaLen[0];
            if (uaContentLen == DerCodec.INDEFINITE_LENGTH) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "indefinite-length unprotectedAttrs is not supported");
            }
            // SET OF Attribute по RFC 5652 §5.3 не бывает пустым (SIZE (1..MAX))
            if (uaContentLen == 0) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "unprotectedAttrs must not be empty");
            }
            byte[] uaContent =
                    Arrays.copyOfRange(unprotectedAttrsField, uaStart, uaStart + uaContentLen);
            return findEncryptedMacIn(parseAttributes(uaContent));
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "Malformed unprotectedAttrs: " + e.getMessage(),
                    e);
        }
    }

    /**
     * Разбирает содержимое unprotectedAttrs в список Attribute.
     *
     * <p>[1] IMPLICIT SET OF Attribute — тег 0xA1 заменяет тег SET OF, содержимое — непосредственно
     * Attribute SEQUENCE (без явного 0x31). Поддерживается и вариант с явным SET внутри (старая
     * кодировка); хвост после него отвергается, как и в ветке без SET.
     */
    private static byte[][] parseAttributes(byte[] uaContent) throws PkixException {
        if ((uaContent[0] & 0xFF) == DerCodec.TAG_SET) {
            int[] setLen = DerCodec.decodeLength(uaContent, 1);
            if (setLen[0] != DerCodec.INDEFINITE_LENGTH
                    && 1 + setLen[1] + setLen[0] != uaContent.length) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "unprotectedAttrs contains data after the SET OF Attribute");
            }
            return DerCodec.parseSetContents(uaContent, 0);
        }
        // Общий разбор SEQUENCE сам продвигается по данным и отвергает усечённый или лишний хвост;
        // ручной цикл по смещениям здесь уже приводил к бесконечному росту списка на входе,
        // доступном без ключа получателя.
        return DerCodec.parseSequenceContents(DerCodec.encodeSequence(uaContent), 0);
    }

    private static byte[] findEncryptedMacIn(byte[][] attributes) throws PkixException {
        byte[] encryptedMac = null;
        for (byte[] attrDer : attributes) {
            if ((attrDer[0] & 0xFF) != DerCodec.TAG_SEQUENCE) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "unprotectedAttrs element must be Attribute SEQUENCE, got tag 0x"
                                + Integer.toHexString(attrDer[0] & 0xFF).toUpperCase());
            }
            byte[][] attrParts = DerCodec.parseSequenceContents(attrDer, 0);
            String attrOid = DerCodec.parseOid(attrParts[0], 0);
            if (!GostOids.ID_CMS_MAC_ATTR.equals(attrOid)) {
                continue;
            }
            // Два content-mac неоднозначны: какой из них проверять, решал бы порядок в контейнере
            if (encryptedMac != null) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "unprotectedAttrs contains more than one content-mac attribute");
            }

            // attrParts[1] = SET { OCTET STRING }
            byte[][] setValues = DerCodec.parseSetContents(attrParts[1], 0);
            if (setValues.length != 1) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "content-mac attribute: expected 1 value, got " + setValues.length);
            }
            encryptedMac = DerCodec.parseOctetString(setValues[0], 0);
        }

        return encryptedMac;
    }
}
