package org.rssys.gost.tls13.cert;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

import java.util.Arrays;
import java.util.Date;

/**
 * Верификация CRL (Certificate Revocation List, RFC 5280 §5) для TLS 1.3.
 * <p>
 * Предполагается direct CRL (issuer CRL == issuer сертификата, RFC 5280 §5.2.5).
 * Indirect CRL (issuingDistributionPoint с indirectCRL) не поддерживается.
 * Partial CRL (issuingDistributionPoint с onlyContains...) не поддерживается.
 * <p>
 * Порядок проверки (fail-closed):
 * <ol>
 *   <li>Подпись CRL — до сканирования revoked-списка</li>
 *   <li>Срок действия (thisUpdate/nextUpdate)</li>
 *   <li>Отклонение issuingDistributionPoint (partial/indirect CRL)</li>
 *   <li>Сканирование revokedCertificates</li>
 * </ol>
 */
public final class TlsCrlVerifier {

    private TlsCrlVerifier() {}

    /**
     * Проверяет CRL: подпись, срок, отсутствие indirect/partial, и отзыв сертификата.
     *
     * @param crlDer       DER-encoded CertificateList (RFC 5280 §5.1)
     * @param certSerial   серийный номер проверяемого сертификата (raw DER INTEGER value)
     * @param caKey        открытый ключ CA, подписавшего CRL (должен совпадать с issuer сертификата)
     * @throws TlsException если CRL невалиден (подпись, срок, indirect) или сертификат отозван
     */
    public static void verify(byte[] crlDer, byte[] certSerial,
                               PublicKeyParameters caKey) throws TlsException {
        if (crlDer == null) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "CRL is null");
        }
        try {
            // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
            int[] clSeq = TlsDerParser.parseSequence(crlDer, 0);
            int clEnd = clSeq[1];
            int clPos = clSeq[0];

            // tbsCertList ::= SEQUENCE
            int[] tbsCertListSeq = TlsDerParser.parseSequence(crlDer, clPos);
            int tbsStart = clPos;                  // начало tbsCertList (весь SEQUENCE TLV)
            int tbsEnd = tbsCertListSeq[1];        // конец value tbsCertList
            int tbPos = tbsCertListSeq[0];
            int tbEnd = tbsCertListSeq[1];

            // version INTEGER OPTIONAL (RFC 5280 §5.1.2.1 — голый INTEGER)
            if (tbPos < tbEnd && (crlDer[tbPos] & 0xFF) == TlsDerParser.TAG_INTEGER) {
                tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            } else if (tbPos < tbEnd && (crlDer[tbPos] & 0xFF) == 0xA0) {
                // Некоторые реализации ошибочно кодируют version как [0] EXPLICIT
                // (как в TBSCertificate, RFC 5280 §4.1.2.1). Fallback для совместимости.
                tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            }

            // signature AlgorithmIdentifier — пропускаем (нас интересует только подпись снаружи)
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: signature AlgorithmIdentifier missing");
            }
            tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];

            // issuer Name — пропускаем (SEQUENCE)
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: issuer Name missing");
            }
            tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];

            // thisUpdate — обязательное поле; без него нельзя определить актуальность CRL
            if (tbPos >= tbEnd) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: thisUpdate missing");
            }
            int thisUpdateTag = crlDer[tbPos] & 0xFF;
            if (thisUpdateTag != TlsDerParser.TAG_UTC_TIME
                    && thisUpdateTag != TlsDerParser.TAG_GENERALIZED_TIME) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: expected Time at thisUpdate");
            }
            tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];

            // nextUpdate — опционально; если есть и в прошлом — CRL устарел, reject
            Date nextUpdate = null;
            if (tbPos < tbEnd && ((crlDer[tbPos] & 0xFF) == TlsDerParser.TAG_UTC_TIME
                    || (crlDer[tbPos] & 0xFF) == TlsDerParser.TAG_GENERALIZED_TIME)) {
                int[] nuTlv = TlsDerParser.readTlv(crlDer, tbPos);
                nextUpdate = TlsDerParser.parseTime(crlDer, tbPos);
                if (new Date().after(nextUpdate)) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "CRL: expired (nextUpdate in the past)");
                }
                tbPos = nuTlv[1];
            }

            // --- FAIL-CLOSED: подпись CRL проверяем ДО сканирования revoked ---
            // signatureAlgorithm — пропускаем (между tbsCertList и signatureValue)
            clPos = tbsCertListSeq[1]; // после tbsCertList идёт signatureAlgorithm SEQUENCE
            if (clPos >= clEnd || (crlDer[clPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: signatureAlgorithm missing");
            }
            clPos = TlsDerParser.readTlv(crlDer, clPos)[1];

            // signatureValue BIT STRING
            if (clPos >= clEnd || (crlDer[clPos] & 0xFF) != TlsDerParser.TAG_BIT_STRING) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: signatureValue BIT STRING missing");
            }
            int[] sigBitTlv = TlsDerParser.readTlv(crlDer, clPos);
            // BIT STRING: первый байт — количество неиспользованных бит (должен быть 0)
            byte[] sigBytes = Arrays.copyOfRange(crlDer, sigBitTlv[0] + 1, sigBitTlv[1]);

            int hlen = caKey.getParams().hlen;
            Digest.Algorithm hashAlg = hlen == 64
                    ? Digest.Algorithm.STREEBOG_512
                    : Digest.Algorithm.STREEBOG_256;
            Digest digest = new Digest(hashAlg);
            digest.update(crlDer, tbsStart, tbsEnd - tbsStart);
            byte[] hash = digest.digest();

            if (!Signature.verifyHash(hash, sigBytes, caKey)) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: signature verification failed");
            }

            // --- Теперь сканируем revokedCertificates ---
            // revokedCertificates SEQUENCE OF OPTIONAL, или [0] Extensions если нет
            if (tbPos >= tbEnd) {
                return; // пустой CRL (нет revoked + нет extensions) — OK
            }

            // Если следующий тег — [0] EXPLICIT, это crlExtensions (revokedCertificates отсутствует)
            // Значит сертификатов в списке нет — OK
            if ((crlDer[tbPos] & 0xFF) == 0xA0) {
                int[] extExplTlv = TlsDerParser.readTlv(crlDer, tbPos);
                int extPos = extExplTlv[0];
                int extEnd = extExplTlv[1];
                // Проверяем issuingDistributionPoint — partial/indirect CRL
                checkNotPartialOrIndirect(crlDer, extPos, extEnd);
                return; // нет revoked сертификатов — OK
            }

            // revokedCertificates SEQUENCE OF RevokedCertificate
            if ((crlDer[tbPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "CRL: expected revokedCertificates SEQUENCE");
            }
            int[] revokedSeq = TlsDerParser.readTlv(crlDer, tbPos);
            int rvPos = revokedSeq[0];
            int rvEnd = revokedSeq[1];

            while (rvPos < rvEnd) {
                int[] rcSeq = TlsDerParser.parseSequence(crlDer, rvPos);
                int rcPos = rcSeq[0];

                // serialNumber INTEGER
                if (rcPos >= rcSeq[1] || (crlDer[rcPos] & 0xFF) != TlsDerParser.TAG_INTEGER) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "CRL: revokedCertificates serialNumber INTEGER missing");
                }
                int[] serialTlv = TlsDerParser.readTlv(crlDer, rcPos);
                byte[] revokedSerial = Arrays.copyOfRange(crlDer, serialTlv[0], serialTlv[1]);

                if (Arrays.equals(revokedSerial, certSerial)) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "Certificate is revoked per CRL");
                }

                rvPos = rcSeq[1];
            }

            // После revokedCertificates — crlExtensions [0] OPTIONAL
            if (rvPos < tbEnd && (crlDer[rvPos] & 0xFF) == 0xA0) {
                int[] extExplTlv = TlsDerParser.readTlv(crlDer, rvPos);
                int extPos = extExplTlv[0];
                int extEnd = extExplTlv[1];
                checkNotPartialOrIndirect(crlDer, extPos, extEnd);
            }
        } catch (RuntimeException e) {
            throw new TlsException(TlsConstants.ALERT_DECODE_ERROR,
                    "Failed to parse CRL DER", e);
        }
    }

    /**
     * Парсит nextUpdate из CRL без полной верификации (для кэша).
     * <p>
     * В отличие от {@link #verify(byte[], byte[], PublicKeyParameters)}, этот метод
     * не проверяет подпись и не сканирует revoked-список — только извлекает дату
     * истечения срока действия CRL. Нужен {@link org.rssys.gost.jsse.crl.CrlCache}
     * чтобы определить момент инвалидации кэша.
     *
     * @param crlDer DER-encoded CertificateList
     * @return nextUpdate Date или null если поле отсутствует
     */
    public static Date extractNextUpdate(byte[] crlDer) {
        if (crlDer == null) {
            return null;
        }
        try {
            int[] clSeq = TlsDerParser.parseSequence(crlDer, 0);
            int[] tbsSeq = TlsDerParser.parseSequence(crlDer, clSeq[0]);
            int tbPos = tbsSeq[0];
            int tbEnd = tbsSeq[1];

            // Пропускаем поля TBSCertList header до nextUpdate: чтобы не парсить
            // весь сертификат и не верифицировать подпись
            if (tbPos < tbEnd && (crlDer[tbPos] & 0xFF) == TlsDerParser.TAG_INTEGER) {
                tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            } else if (tbPos < tbEnd && (crlDer[tbPos] & 0xFF) == 0xA0) {
                tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            }
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) return null;
            tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) return null;
            tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd) return null;
            int tag = crlDer[tbPos] & 0xFF;
            if (tag != TlsDerParser.TAG_UTC_TIME && tag != TlsDerParser.TAG_GENERALIZED_TIME) return null;
            tbPos = TlsDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd) return null;
            tag = crlDer[tbPos] & 0xFF;
            if (tag != TlsDerParser.TAG_UTC_TIME && tag != TlsDerParser.TAG_GENERALIZED_TIME) return null;
            int tagPos = tbPos;
            TlsDerParser.readTlv(crlDer, tbPos);
            return TlsDerParser.parseTime(crlDer, tagPos);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Проверяет extensions на наличие issuingDistributionPoint (2.5.29.28).
     * <p>
     * Если расширение присутствует — reject (partial/indirect CRL не поддерживается).
     */
    private static void checkNotPartialOrIndirect(byte[] der, int extPos, int extEnd)
            throws TlsException {
        if (extPos >= extEnd || (der[extPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) {
            return;
        }
        int[] extSeq = TlsDerParser.readTlv(der, extPos);
        int pos = extSeq[0];
        int end = extSeq[1];
        while (pos < end) {
            int[] extTlv = TlsDerParser.parseSequence(der, pos);
            int oc = extTlv[0];
            int oce = extTlv[1];
            if (oc < oce && (der[oc] & 0xFF) == TlsDerParser.TAG_OID) {
                int[] oidTlv = TlsDerParser.readTlv(der, oc);
                if (TlsDerParser.matchesOid(der, oidTlv[0],
                        oidTlv[1] - oidTlv[0], TlsDerParser.IDP_OID_BYTES)) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "CRL: issuingDistributionPoint extension present "
                            + "(partial/indirect CRL not supported)");
                }
            }
            pos = extTlv[1];
        }
    }
}
