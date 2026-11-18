package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.readTlv;

import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

/**
 * Кодек расширения id-pkix-ocsp-nonce (RFC 8954 §2.1).
 *
 * <p>Значение расширения имеет тип {@code Nonce ::= OCTET STRING (SIZE(1..32))}, а
 * {@code Extension.extnValue} по общему правилу X.509 (RFC 5280 §4.1) содержит DER значения
 * этого типа. На проводе получается двойная обёртка:
 *
 * <pre>
 * Extension ::= SEQUENCE { OID, extnValue OCTET STRING { Nonce OCTET STRING { nonce } } }
 *                                          04 LL         04 NN  байты nonce
 * </pre>
 *
 * <p>Во всей библиотеке «nonce» означает только сырые байты значения {@code Nonce};
 * оба уровня OCTET STRING добавляются и снимаются здесь.
 */
final class OcspNonceCodec {

    /** Минимальная длина nonce по RFC 8954 (для совместимости с клиентами RFC 6960). */
    static final int MIN_LENGTH = 1;

    /** Максимальная длина nonce по RFC 8954. */
    static final int MAX_LENGTH = 32;

    /** Длина nonce, которую генерируют клиенты: RFC 8954 требует ровно 32 байта. */
    static final int GENERATED_LENGTH = 32;

    private static final int TAG_OCTET_STRING = 0x04;

    private OcspNonceCodec() {}

    /**
     * Проверяет длину nonce.
     *
     * @param nonce сырые байты nonce
     * @throws IllegalArgumentException если nonce равен {@code null} или длина вне диапазона
     *                                  {@value #MIN_LENGTH}..{@value #MAX_LENGTH}
     */
    static void requireValidLength(byte[] nonce) {
        if (nonce == null || nonce.length < MIN_LENGTH || nonce.length > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "OCSP nonce length must be in range "
                            + MIN_LENGTH
                            + ".."
                            + MAX_LENGTH
                            + " bytes");
        }
    }

    /**
     * Кодирует расширение nonce целиком: {@code SEQUENCE { OID, extnValue }}.
     *
     * @param nonce сырые байты nonce длиной 1..32
     * @return DER расширения для вставки в {@code requestExtensions} / {@code responseExtensions}
     * @throws IllegalArgumentException если длина nonce вне допустимого диапазона
     */
    static byte[] encodeExtension(byte[] nonce) {
        requireValidLength(nonce);
        byte[] oid = DerCodec.encodeOid(GostOids.OCSP_NONCE);
        byte[] nonceValue = DerCodec.encodeOctetString(nonce);
        // extnValue — это OCTET STRING, внутри которого DER типа Nonce (тоже OCTET STRING)
        byte[] extnValue = DerCodec.encodeOctetString(nonceValue);
        return DerCodec.encodeSequence(oid, extnValue);
    }

    /**
     * Снимает внутренний слой: из содержимого {@code extnValue} извлекает байты nonce.
     *
     * <p>Предусловие: вызывающий парсер уже убедился, что сам {@code extnValue} — OCTET STRING,
     * и передал границы его содержимого. Здесь проверяется только внутренний слой: ровно один
     * OCTET STRING без хвоста и длина 1..32. Одноуровневый (сырой) формат прежних версий
     * библиотеки явно не поддерживается; значения, которые структурно совпадают с корректным
     * {@code Nonce}, от него неотличимы и принимаются.
     *
     * @param der          DER-поток
     * @param contentStart смещение первого байта содержимого {@code extnValue}
     * @param contentEnd   смещение за последним байтом содержимого {@code extnValue}
     * @return копия байт nonce
     * @throws PkixException если внутренняя структура некорректна или длина вне диапазона
     */
    static byte[] parseExtnValue(byte[] der, int contentStart, int contentEnd)
            throws PkixException {
        if (contentStart >= contentEnd || (der[contentStart] & 0xFF) != TAG_OCTET_STRING) {
            throw malformed(null);
        }
        int[] nonceTlv;
        try {
            nonceTlv = readTlv(der, contentStart);
        } catch (IllegalArgumentException e) {
            // Только IAE от readTlv — это битый DER; остальные RuntimeException — баги, их не
            // маскируем
            throw malformed(e);
        }
        if (nonceTlv[1] != contentEnd) {
            throw malformed(null);
        }
        int length = nonceTlv[1] - nonceTlv[0];
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw malformed(null);
        }
        byte[] nonce = new byte[length];
        System.arraycopy(der, nonceTlv[0], nonce, 0, length);
        return nonce;
    }

    private static PkixException malformed(Throwable cause) {
        return cause == null
                ? new PkixException("OCSP: malformed nonce extension")
                : new PkixException("OCSP: malformed nonce extension", cause);
    }
}
