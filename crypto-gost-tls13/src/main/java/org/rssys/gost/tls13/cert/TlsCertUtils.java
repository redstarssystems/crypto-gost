package org.rssys.gost.tls13.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.math.BigInteger;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Статические TLS-утилиты для работы с сертификатами ({@link GostCertificate}).
 * <p>
 * TLS-специфичная логика живёт здесь, чистые PKIX-операции — напрямую
 * на {@link GostCertificate}.
 */
public final class TlsCertUtils {

    /** OID известных X.509v3 расширений для oid_filters matching (RFC 8446 §4.2.5). */
    static final Set<String> KNOWN_EXTENSION_OIDS =
            Set.of(
                    GostOids.EXT_SKI,
                    GostOids.EXT_KU,
                    GostOids.EXT_SAN,
                    GostOids.EXT_BC,
                    GostOids.EXT_CDP,
                    GostOids.EXT_CP,
                    GostOids.EXT_AKI,
                    GostOids.EXT_EKU,
                    GostOids.EXT_AIA,
                    GostOids.EXT_NAME_CONSTRAINTS);

    private TlsCertUtils() {}

    /**
     * Проверяет, относится ли схема подписи к ключу сертификата (RFC 9367 §5 / §6.3.4).
     * <p>
     * Строгое соответствие: схема обязана совпадать с той, что соответствует
     * кривой сертификата (RFC 9367 §5: каждая схема — пара «алгоритм, кривая»).
     * <p>
     * {@code interopAcceptGostBaseSigScheme} — обход известного бага
     * openssl-gost-provider (версия 3.6.0): сервер всегда шлёт базовую
     * схему для каждого размера ключа: 0x0709 (gostr34102012_256a / GC256A)
     * для 256-битных и 0x070D (gostr34102012_512a / GC512A) для 512-битных,
     * независимо от фактической кривой сертификата (GC256B/C/D, GC512B/C).
     * RFC 9367 формально требует точного соответствия (Section 5, Table 4),
     * поэтому флаг по умолчанию выключен. Включение — осознанное решение
     * разработчика для совместимости с конкретной версией openssl-gost.
     *
     * @param pubKey открытый ключ сертификата
     * @param scheme схема подписи из CertificateVerify
     * @return true если схема соответствует длине ключа
     */
    public static boolean hasSignatureScheme(PublicKeyParameters pubKey, int scheme) {
        return hasSignatureScheme(pubKey, scheme, false);
    }

    /**
     * Перегрузка с флагом совместимости openssl-gost-provider.
     *
     * @see #hasSignatureScheme(PublicKeyParameters, int)
     */
    public static boolean hasSignatureScheme(
            PublicKeyParameters pubKey, int scheme, boolean interopAcceptGostBaseSigScheme) {
        int certNamedGroup = TlsCiphersuite.paramsToNamedGroup(pubKey.getParams());
        int expectedScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
        if (scheme == expectedScheme) return true;
        if (interopAcceptGostBaseSigScheme) {
            int hlen = pubKey.getParams().hlen;
            if (hlen == TlsConstants.STREEBOG_256_HASH_LEN
                    && scheme == TlsConstants.SIG_GOST_TC26_A_256) return true;
            if (hlen == TlsConstants.STREEBOG_512_HASH_LEN
                    && scheme == TlsConstants.SIG_GOST_TC26_512_A) return true;
        }
        return false;
    }

    /**
     * TLS named group (RFC 9367 §3.1) по параметрам открытого ключа.
     *
     * @param pubKey открытый ключ сертификата
     * @return идентификатор named group
     */
    public static int getNamedGroup(PublicKeyParameters pubKey) {
        return TlsCiphersuite.paramsToNamedGroup(pubKey.getParams());
    }

    /**
     * Входит ли схема подписи в список, присланный сервером в CertificateRequest.
     *
     * @param offered схемы из CertificateRequest
     * @param scheme  проверяемая схема
     * @return true, если схема есть в списке
     */
    public static boolean isSchemeOffered(int[] offered, int scheme) {
        for (int candidate : offered) {
            if (candidate == scheme) {
                return true;
            }
        }
        return false;
    }

    /**
     * Схема подписи CertificateVerify для ключа листа клиентской цепочки (по кривой ключа,
     * RFC 9367 §5).
     * <p>
     * RFC 8446 §4.4.3 требует, чтобы эта схема входила в {@code signature_algorithms} запроса, а
     * §4.4.2.3 при её отсутствии велит отправить пустой Certificate.
     *
     * @param chain клиентская цепочка, лист первым
     * @return код схемы подписи
     * @throws IllegalArgumentException если кривая ключа листа не поддерживается
     */
    public static int leafSignatureScheme(List<GostCertificate> chain) {
        return schemeOfKeyCurve(chain.get(0));
    }

    /**
     * Схемы подписей сертификатов цепочки, которых нет в списке сервера.
     * <p>
     * Подпись {@code chain[i]} проверяется ключом {@code chain[i + 1]}, поэтому её схема
     * определяется кривой следующего сертификата. Издателя последнего сертификата в цепочке нет
     * (корень обычно не отправляется), его подпись не сверяется. Без
     * {@code signature_algorithms_cert} тот же список относится и к подписям в сертификатах
     * цепочки (RFC 8446 §4.2.3).
     *
     * @param chain   клиентская цепочка, лист первым
     * @param offered схемы подписи сертификатов из CertificateRequest
     *                ({@code signature_algorithms_cert}, а без него {@code signature_algorithms})
     * @return не предложенные схемы без повторов в порядке цепочки; пусто, если цепочка из одного
     *         сертификата или все схемы предложены
     */
    public static List<Integer> unofferedChainSchemes(List<GostCertificate> chain, int[] offered) {
        Set<Integer> missing = new LinkedHashSet<>();
        for (int i = 0; i + 1 < chain.size(); i++) {
            int scheme = schemeOfKeyCurve(chain.get(i + 1));
            if (!isSchemeOffered(offered, scheme)) {
                missing.add(scheme);
            }
        }
        return List.copyOf(missing);
    }

    private static int schemeOfKeyCurve(GostCertificate certificate) {
        return TlsCiphersuite.namedGroupToSignatureScheme(
                getNamedGroup(certificate.getPublicKey()));
    }

    /**
     * Верифицирует OCSP-ответ для сертификата (RFC 6960).
     * <p>
     * Проверяет подпись, статус, EKU делегированных responder'ов,
     * CertID — всё встроенно. Оборачивает {@link PkixException}
     * в {@link TlsException} с alert-кодом
     * {@link TlsConstants#ALERT_BAD_CERTIFICATE}.
     *
     * @param cert   сертификат с прикреплённым OCSP-ответом
     * @param issuer сертификат издателя
     * @throws TlsException при ошибке верификации OCSP
     */
    public static void verifyOcspResponse(GostCertificate cert, GostCertificate issuer)
            throws TlsException {
        verifyOcspResponse(cert, issuer, GostOids.MAX_OCSP_AGE_MS, null);
    }

    /**
     * Верифицирует OCSP-ответ с настраиваемой политикой свежести (RFC 6960 §2.4).
     * <p>
     * Перегрузка для проброса локальной политики свежести relying party из
     * вышестоящего слоя (JSSE TrustManager). Семантика параметров идентична
     * {@link OcspVerifier#verify(byte[], byte[], GostCertificate, byte[], long, Duration)}.
     *
     * @param cert             сертификат с прикреплённым OCSP-ответом
     * @param issuer           сертификат издателя
     * @param maxOcspAgeMs     максимальный возраст ответа без {@code nextUpdate} в мс
     * @param maxThisUpdateAge необязательный предел возраста {@code thisUpdate} для всех
     *                         ответов или {@code null}
     * @throws TlsException при ошибке верификации OCSP
     * @throws IllegalArgumentException если {@code maxThisUpdateAge} нулевой или отрицательный
     */
    public static void verifyOcspResponse(
            GostCertificate cert,
            GostCertificate issuer,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws TlsException {
        byte[] serialCopy = cert.getSerialNumber();
        byte[] ocspResp = cert.getOcspResponse();
        byte[] nonce = cert.getOcspNonce();
        try {
            OcspVerifier.verify(
                    ocspResp, serialCopy, issuer, nonce, maxOcspAgeMs, maxThisUpdateAge);
        } catch (PkixException e) {
            // RFC 8446 §6.2: отзыв сертификата сообщается своим кодом; исходное исключение
            // остаётся причиной
            byte alert =
                    e.reason() == PkixException.Reason.REVOKED
                            ? TlsConstants.ALERT_CERTIFICATE_REVOKED
                            : TlsConstants.ALERT_BAD_CERTIFICATE;
            String message = e.getMessage();
            if (e.reason() == PkixException.Reason.REVOKED) {
                // Текст отзыва постоянный и не называет сертификат, а оператору нужен
                // серийный номер: по нему отзыв сопоставляется с записью менеджера доверия
                message =
                        message + " (serial=0x" + new BigInteger(1, serialCopy).toString(16) + ")";
            }
            throw new TlsException(alert, message, e);
        }
    }

    /**
     * Проверяет, удовлетворяет ли сертификат OID-фильтру из {@code oid_filters}
     * расширения CertificateRequest (RFC 8446 §4.2.5).
     * <p>
     * Используется в mTLS для выбора клиентского сертификата по фильтрам сервера.
     *
     * @param cert   сертификат для проверки
     * @param filter OID-фильтр из CertificateRequest
     * @return true если сертификат удовлетворяет фильтру
     */
    public static boolean matchesOidFilter(GostCertificate cert, OIDFilter filter) {
        byte[] filterOid = filter.extensionOid();
        byte[] filterValues = filter.extensionValues();
        int keyUsageBits = cert.getKeyUsageBits();
        byte[][] ekuOids = cert.getEkuOids();
        // OID фильтра сопоставляется в точечной нотации: сырые байты OID парсер pkix не отдаёт
        String filterOidDot = oidBytesToDottedString(filterOid, 0, filterOid.length);

        if (GostOids.EXT_KU.equals(filterOidDot)) {
            // Как и у остальных расширений, пустое значение фильтра требует лишь наличия
            // расширения, а сертификат без KeyUsage не подходит под любой фильтр KeyUsage
            if (cert.getExtensionValue(GostOids.EXT_KU) == null) {
                return false;
            }
            if (filterValues.length == 0) {
                return true;
            }
            int requestedBits = keyUsageBitsOfFilter(filterValues);
            return requestedBits >= 0 && (keyUsageBits & requestedBits) == requestedBits;
        }

        if (GostOids.EXT_EKU.equals(filterOidDot)) {
            if (ekuOids == null && filterValues.length > 0) {
                return false;
            }
            if (ekuOids != null) {
                for (byte[] ekuOid : ekuOids) {
                    if (GostOids.EXT_ANY_EKU.equals(
                            oidBytesToDottedString(ekuOid, 0, ekuOid.length))) {
                        return false;
                    }
                }
            }
            if (filterValues.length == 0) {
                return ekuOids != null;
            }
            return containsAllFilterOids(filterValues, ekuOids);
        }

        // anyPolicy (2.5.29.32.0, RFC 5280 §4.2.1.4) — структурный аналог anyExtendedKeyUsage —
        // не обрабатывается отдельно; отсутствие аналогичной логики осознанно, при добавлении
        // anyPolicy-handling синхронизировать с EKU-веткой.
        if (GostOids.EXT_CP.equals(filterOidDot)) {
            byte[][] cpOids = cert.getCpOids();
            if (cpOids == null && filterValues.length > 0) {
                return false;
            }
            if (filterValues.length == 0) {
                return cpOids != null;
            }
            return containsAllFilterOids(filterValues, cpOids);
        }

        // Значение расширения берётся из строгого разбора сертификата (pkix): второго
        // независимого обхода DER здесь нет, поэтому строгость обоих не может разойтись
        byte[] certValue = cert.getExtensionValue(filterOidDot);
        if (certValue != null) {
            return filterValues.length == 0 || Arrays.equals(certValue, filterValues);
        }

        if (KNOWN_EXTENSION_OIDS.contains(filterOidDot)) {
            return false;
        }

        return true;
    }

    /**
     * Проверяет, что каждый OID из SEQUENCE значения фильтра есть среди OID сертификата
     * (RFC 8446 §4.2.5: для списковых расширений фильтр требует, чтобы сертификат содержал все
     * перечисленные значения). Нераспознаваемая рамка значения даёт false (fail-closed). Общая
     * часть фильтров ExtendedKeyUsage и CertificatePolicies.
     *
     * @param filterValues DER значения фильтра: SEQUENCE OID (не пусто)
     * @param certOids     OID расширения сертификата в DER, или null если расширения нет
     * @return true если все OID фильтра присутствуют в сертификате
     */
    private static boolean containsAllFilterOids(byte[] filterValues, byte[][] certOids) {
        if (filterValues.length < 2 || filterValues[0] != TAG_SEQUENCE) {
            return false;
        }
        int[] seqTlv = readTlv(filterValues, 0);
        int pos = seqTlv[0];
        int end = seqTlv[1];
        while (pos < end) {
            // Элементы не-OID внутри SEQUENCE пропускаются: расширяемость значения фильтра
            if ((filterValues[pos] & 0xFF) != TAG_OID) {
                pos = readTlv(filterValues, pos)[1];
                continue;
            }
            int[] oidTlv = readTlv(filterValues, pos);
            byte[] wanted = Arrays.copyOfRange(filterValues, oidTlv[0], oidTlv[1]);
            if (!containsOid(certOids, wanted)) {
                return false;
            }
            pos = oidTlv[1];
        }
        return true;
    }

    private static boolean containsOid(byte[][] certOids, byte[] oid) {
        if (certOids == null) {
            return false;
        }
        for (byte[] certOid : certOids) {
            if (matchesOid(certOid, 0, certOid.length, oid)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Разбирает значение фильтра KeyUsage: DER BIT STRING целиком (тег, длина, число
     * неиспользуемых бит, байты битов), как и у остальных расширений в {@code oid_filters}
     * (RFC 8446 §4.2.5). Определено 9 битов KeyUsage, то есть не больше двух байт; неиспользуемые
     * биты последнего байта в запрос не входят. Раскладка битов совпадает с
     * {@link GostCertificate#getKeyUsageBits()}: первый байт - младший.
     *
     * @param filterValue DER значения фильтра (не пусто)
     * @return маска запрошенных битов или -1, если значение не является корректным BIT STRING
     */
    private static int keyUsageBitsOfFilter(byte[] filterValue) {
        int maxDataBytes = 2;
        // Тег, однобайтовая длина, число неиспользуемых бит и хотя бы один байт битов
        if (filterValue.length < 4 || filterValue[0] != TAG_BIT_STRING) {
            return -1;
        }
        int contentLength = filterValue[1] & 0xFF;
        if ((filterValue[1] & 0x80) != 0 || filterValue.length != 2 + contentLength) {
            return -1;
        }
        int unusedBits = filterValue[2] & 0xFF;
        int dataBytes = contentLength - 1;
        if (unusedBits > 7 || dataBytes < 1 || dataBytes > maxDataBytes) {
            return -1;
        }
        int bits = 0;
        for (int i = 0; i < dataBytes; i++) {
            int value = filterValue[3 + i] & 0xFF;
            if (i == dataBytes - 1) {
                value &= ~((1 << unusedBits) - 1);
            }
            bits |= value << (8 * i);
        }
        return bits;
    }
}
