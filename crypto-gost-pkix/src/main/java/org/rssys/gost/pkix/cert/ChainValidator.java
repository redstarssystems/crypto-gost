package org.rssys.gost.pkix.cert;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Чистая PKIX-валидация цепочек сертификатов (RFC 5280).
 * <p>
 * Проверяет цепочку доверия: подписи, DN-совпадения, CA-флаги,
 * pathLen, NameConstraints, срок действия, algorithm consistency,
 * known critical extensions, опционально — CertificatePolicies leaf-сертификата.
 * <p>
 * Якоря доверия — только сертификаты
 * ({@link #validateChain(List, TrustAnchors, String...)}): pathLen
 * и NameConstraints локального якоря аутентифицированы и применяются, даже
 * если пир не прислал корень. Для перевыпущенного корня с тем же ключом
 * цепочка строится снизу вверх до ближайшего якоря.</p>
 * <p>
 * Не содержит TLS-специфики (алертов, CertificateVerify).
 * Все ошибки — {@link PkixException} (checked).
 * <p>
 * Не проверяет статус отзыва сертификатов (CRL/OCSP).
 * Для полной проверки с отзывом используйте {@link #validateChainWithRevocation}
 * или вызывайте {@link CrlVerifier} / {@link OcspVerifier} отдельно после этого метода.
 */
public final class ChainValidator {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.ChainValidator");

    private static final int MAX_CERT_CHAIN_LENGTH = 10;

    /** Предел эффективной цепочки: peer-лимит плюс один локальный сертификат-якорь. */
    private static final int MAX_EFFECTIVE_CERT_CHAIN_LENGTH = MAX_CERT_CHAIN_LENGTH + 1;

    private static final int IPV4_ADDRESS_LENGTH = 4;
    private static final int IPV6_ADDRESS_LENGTH = 16;

    /** Число нулевых байт в начале IPv4-mapped IPv6 (RFC 4291 §2.5.5.2), затем два байта 0xFF. */
    private static final int IPV4_MAPPED_ZERO_BYTES = 10;

    private static final byte IPV4_MAPPED_MARKER = (byte) 0xFF;

    private ChainValidator() {}

    /**
     * Строит эффективную цепочку для заданных якорей.
     *
     * <p>Идёт от leaf вверх и останавливается на ближайшем уровне, где сертификат
     * либо побайтово равен локальному якорю, либо выпущен локальным якорем. Всё,
     * что пир прислал выше, игнорируется; локальный сертификат якоря добавляется
     * в конец.</p>
     *
     * <p>Лимит {@link #MAX_CERT_CHAIN_LENGTH} применяется только к peer-цепочке:
     * добавленный локальный якорь в него не входит.</p>
     *
     * @param peerChain цепочка leaf-first от пира (не null, не пуста, не длиннее лимита)
     * @param anchors   доверенные якоря (не null, не пусто)
     * @return неизменяемая эффективная цепочка leaf-first; последний элемент —
     *         доверенный якорь
     * @throws PkixException если ни один сертификат не достигает якоря
     * @throws IllegalArgumentException если anchors null или пуст
     */
    public static List<GostCertificate> resolveChain(
            List<GostCertificate> peerChain, TrustAnchors anchors) throws PkixException {
        checkPeerChainSize(peerChain);
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("anchors must not be null or empty");
        }
        List<GostCertificate> anchorCerts = anchors.certificates();
        for (int i = 0; i < peerChain.size(); i++) {
            GostCertificate cert = peerChain.get(i);
            if (anchors.containsCertificate(cert)) {
                return List.copyOf(peerChain.subList(0, i + 1));
            }
            GostCertificate issuerAnchor = findIssuerAnchor(cert, anchorCerts);
            if (issuerAnchor != null) {
                List<GostCertificate> effective = new ArrayList<>(peerChain.subList(0, i + 1));
                effective.add(issuerAnchor);
                LOG.log(
                        Level.DEBUG,
                        "Effective chain resolved: peer={0}, effective={1}, anchor reached at cert[{2}]",
                        peerChain.size(),
                        effective.size(),
                        i);
                return List.copyOf(effective);
            }
        }
        throw new PkixException(
                PkixException.Reason.ROOT_NOT_SIGNED,
                "Certificate chain: no trusted certificate anchor reached");
    }

    /**
     * Валидирует цепочку с сертификатами-якорями и возвращает эффективную цепочку.
     *
     * <p>Сначала строит эффективную цепочку ({@link #resolveChain}),
     * поэтому ограничения и pathLen локального якоря применяются, даже если пир
     * не прислал корневой сертификат. Возвращённая цепочка нужна вызывающему для
     * дальнейших стадий (загрузка и проверка отзыва): достраивать её повторно не
     * требуется.</p>
     *
     * @param chain              peer-цепочка leaf-first
     * @param anchors            доверенные якоря (не null, не пусто)
     * @param requiredPolicyOids требуемые OID политик leaf-сертификата
     * @return неизменяемая эффективная цепочка leaf-first; последний элемент -
     *         доверенный якорь
     * @throws PkixException при ошибке валидации цепочки
     * @throws IllegalArgumentException если anchors null или пуст
     */
    public static List<GostCertificate> validateChain(
            List<GostCertificate> chain, TrustAnchors anchors, String... requiredPolicyOids)
            throws PkixException {
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("anchors must not be null or empty");
        }
        List<GostCertificate> effective = resolveChain(chain, anchors);
        validateEffective(effective, anchors, requiredPolicyOids);
        return effective;
    }

    /**
     * Валидирует уже разрешённую эффективную цепочку.
     *
     * <p>Лимит проверяется здесь повторно (защита от нарушения инварианта
     * {@link #resolveChain}): допустимо не более {@link #MAX_CERT_CHAIN_LENGTH}
     * peer-сертификатов плюс один добавленный локальный якорь; последний элемент
     * обязан совпадать с одним из якорей по полному DER.</p>
     */
    private static void validateEffective(
            List<GostCertificate> chain, TrustAnchors anchors, String... requiredPolicyOids)
            throws PkixException {
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("anchors must not be null or empty");
        }
        if (chain == null || chain.isEmpty()) {
            throw new PkixException(
                    "Certificate chain: empty chain — at least one certificate required");
        }
        int n = chain.size();
        if (n > MAX_EFFECTIVE_CERT_CHAIN_LENGTH) {
            throw new PkixException(
                    PkixException.Reason.CHAIN_TOO_LONG,
                    "Certificate chain exceeds maximum effective depth of "
                            + MAX_EFFECTIVE_CERT_CHAIN_LENGTH
                            + " (peer limit "
                            + MAX_CERT_CHAIN_LENGTH
                            + " plus local anchor)");
        }
        if (!anchors.containsCertificate(chain.get(n - 1))) {
            throw new PkixException(
                    PkixException.Reason.ROOT_NOT_SIGNED,
                    "Certificate chain: last certificate is not a trusted" + " certificate anchor");
        }
        validateResolvedChain(chain, anchors, requiredPolicyOids);
    }

    private static void checkPeerChainSize(List<GostCertificate> chain) throws PkixException {
        if (chain == null || chain.isEmpty()) {
            throw new PkixException(
                    "Certificate chain: empty chain — at least one certificate required");
        }
        if (chain.size() > MAX_CERT_CHAIN_LENGTH) {
            throw new PkixException(
                    PkixException.Reason.CHAIN_TOO_LONG,
                    "Certificate chain exceeds maximum depth of " + MAX_CERT_CHAIN_LENGTH);
        }
    }

    /**
     * Ищет локальный сертификат-якорь, выпустивший {@code cert}.
     *
     * <p>AKI/SKI используется только для приоритета среди якорей с одинаковым
     * subject DN: при перевыпуске корня с тем же ключом SKI может быть изменён
     * вручную, поэтому жёсткое требование сломало бы законный случай. Решение
     * принимается по проверке подписи.</p>
     */
    private static GostCertificate findIssuerAnchor(
            GostCertificate cert, List<GostCertificate> anchorCerts) {
        byte[] issuerDn = cert.getIssuerDnBytes();
        byte[] aki = cert.getAuthorityKeyIdentifier();
        if (aki != null) {
            for (GostCertificate anchor : anchorCerts) {
                if (!Arrays.equals(issuerDn, anchor.getSubjectDnBytes())) {
                    continue;
                }
                byte[] ski = anchor.getSubjectKeyIdentifier();
                if (ski != null
                        && Arrays.equals(ski, aki)
                        && cert.verifySignature(anchor.getPublicKey())) {
                    return anchor;
                }
            }
        }
        for (GostCertificate anchor : anchorCerts) {
            if (!Arrays.equals(issuerDn, anchor.getSubjectDnBytes())) {
                continue;
            }
            byte[] ski = anchor.getSubjectKeyIdentifier();
            if (aki != null && ski != null && Arrays.equals(ski, aki)) {
                continue;
            }
            if (cert.verifySignature(anchor.getPublicKey())) {
                return anchor;
            }
        }
        return null;
    }

    /**
     * Внутренняя валидация уже разрешённой цепочки.
     *
     * <p>Размер peer-цепочки проверяется вызывающими методами; сюда может прийти
     * эффективная цепочка длиннее {@link #MAX_CERT_CHAIN_LENGTH} на один локальный
     * якорь.</p>
     */
    private static void validateResolvedChain(
            List<GostCertificate> chain, TrustAnchors anchors, String... requiredPolicyOids)
            throws PkixException {
        int n = chain.size();
        LOG.log(
                Level.DEBUG,
                "Validating certificate chain of {0} cert(s), leaf serial=0x{1}",
                n,
                chain.get(0).getSerialNumberBigInt().toString(16));
        for (int i = 0; i < n - 1; i++) {
            GostCertificate cert = chain.get(i);
            if (cert.isExpired()) {
                throw new PkixException(
                        PkixException.Reason.EXPIRED,
                        "Certificate chain: cert[" + i + "] is expired or not yet valid");
            }
            GostCertificate issuer = chain.get(i + 1);
            if (!cert.isAlgConsistent()) {
                throw new PkixException(
                        PkixException.Reason.ALG_MISMATCH,
                        "Certificate chain: algorithm mismatch at cert[" + i + "]");
            }
            if (!cert.verifySignature(issuer.getPublicKey())) {
                throw new PkixException(
                        PkixException.Reason.SIGNATURE_INVALID,
                        "Certificate chain: cert[" + i + "] signature verification failed");
            }
            if (!Arrays.equals(cert.getIssuerDnBytes(), issuer.getSubjectDnBytes())) {
                throw new PkixException(
                        PkixException.Reason.DN_MISMATCH,
                        "Certificate chain: DN mismatch at cert[" + i + "]");
            }
            if (i > 0 && !cert.isCA()) {
                throw new PkixException(
                        PkixException.Reason.NOT_CA,
                        "Certificate chain: cert[" + i + "] is not a CA");
            }
            if (i > 0 && !cert.isKeyCertSignSet()) {
                throw new PkixException(
                        PkixException.Reason.MISSING_KEY_CERT_SIGN,
                        "Certificate chain: cert[" + i + "] missing keyCertSign");
            }
            int pl = cert.getPathLen();
            // RFC 5280 §4.2.1.9, §6.1: число не-self-issued промежуточных CA,
            // которые могут СЛЕДОВАТЬ (follow) за сертификатом в направлении leaf.
            // Self-issued (subjectDN == issuerDN, т.е. subjectDN совпадает с
            // subjectDN вышестоящего) не учитываются — countFollowingNonSelfIssuedCA
            // исключает их, сравнивая subjectDN соседних сертификатов побайтово.
            int remaining = countFollowingNonSelfIssuedCA(chain, i);
            if (pl >= 0 && remaining > pl) {
                throw new PkixException(
                        PkixException.Reason.PATH_LEN_EXCEEDED,
                        "Certificate chain: pathLen constraint exceeded at cert[" + i + "]");
            }
            if (cert.hasUnknownCriticalExtension()) {
                throw new PkixException(
                        PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                        "Certificate chain: unknown critical extension at cert[" + i + "]");
            }
        }
        GostCertificate root = chain.get(n - 1);
        // RFC 5280 §3.2: у trust anchor не проверяются CA-флаг и keyCertSign.
        // pathLen верхнего сертификата проверяем, если он задан. Для cert-якоря
        // это аутентифицированное расширение локального сертификата, поэтому
        // ограничение действует и при опущенном пиром корне.
        int rootPl = root.getPathLen();
        if (rootPl >= 0) {
            int remaining = countFollowingNonSelfIssuedCA(chain, n - 1);
            if (remaining > rootPl) {
                throw new PkixException(
                        PkixException.Reason.PATH_LEN_EXCEEDED,
                        "Certificate chain: pathLen constraint exceeded at root");
            }
        }
        // Якорь определяется по полному DER, а не по ключу: сертификат с тем же
        // ключом, но другим DER, якорем не является.
        boolean rootIsTrustAnchor = anchors.containsCertificate(root);
        if (root.isExpired()) {
            // RFC 5280 §6.1 не использует срок trust anchor. Перевыпущенный корень
            // с тем же ключом может быть уже истёкшим, но остаётся точкой доверия, если
            // политика набора не требует обратного (REJECT). DEFAULT здесь трактуется как
            // WARN: строгие потребители (CMS, CAdES) выбирают REJECT явно.
            // Для закреплённого leaf (n == 1) срок обязан проверяться как у leaf.
            if (rootIsTrustAnchor && n > 1 && anchors.expiryPolicy() != AnchorExpiryPolicy.REJECT) {
                LOG.log(
                        Level.WARNING,
                        "Trust anchor certificate is expired or not yet valid;"
                                + " continuing (RFC 5280 §6.1), serial=0x{0}",
                        root.getSerialNumberBigInt().toString(16));
            } else {
                throw new PkixException(
                        PkixException.Reason.EXPIRED,
                        "Certificate chain: root is expired or not yet valid");
            }
        }
        // resolveChain гарантирует, что верх эффективной цепочки —
        // локальный сертификат-якорь. Нарушение инварианта — fail-closed.
        if (!rootIsTrustAnchor) {
            throw new PkixException(
                    PkixException.Reason.ROOT_NOT_SIGNED,
                    "Certificate chain: root is not a trusted certificate anchor");
        }
        if (!root.isAlgConsistent()) {
            throw new PkixException(
                    PkixException.Reason.ALG_MISMATCH,
                    "Certificate chain: algorithm mismatch at root");
        }
        if (root.hasUnknownCriticalExtension()) {
            throw new PkixException(
                    PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                    "Certificate chain: unknown critical extension at root");
        }
        // Проверка CertificatePolicies leaf-сертификата.
        // Только leaf: full RFC 5280 §6.1 policy validation (valid_policy_tree,
        // PolicyMappings, PolicyConstraints, InhibitAnyPolicy) не реализован.
        if (requiredPolicyOids != null && requiredPolicyOids.length > 0) {
            GostCertificate leaf = chain.get(0);
            String[] certPolicies = leaf.getCertificatePolicies();
            if (certPolicies == null || certPolicies.length == 0) {
                throw new PkixException(
                        PkixException.Reason.POLICY_VIOLATION,
                        "Certificate chain: leaf certificate has no CertificatePolicies extension");
            }
            boolean matched = false;
            for (String cp : certPolicies) {
                if (GostOids.ANY_POLICY.equals(cp)) {
                    matched = true;
                    break;
                }
                for (String req : requiredPolicyOids) {
                    if (req.equals(cp)) {
                        matched = true;
                        break;
                    }
                }
                if (matched) {
                    break;
                }
            }
            if (!matched) {
                throw new PkixException(
                        PkixException.Reason.POLICY_VIOLATION,
                        "Certificate chain: leaf certificate policies do not match"
                                + " required OIDs");
            }
        }
        // Name Constraints pass (RFC 5280 §6.1.4(g)-(l)).
        // Обход root-to-leaf: ограничения накапливаются от верхнего сертификата
        // цепочки вниз. Верх эффективной цепочки — локальный сертификат-якорь,
        // поэтому его ограничения всегда аутентифицированы.
        validateNameConstraintsPass(chain);
        LOG.log(
                Level.DEBUG,
                "Certificate chain validation passed (leaf serial=0x{0})",
                chain.get(0).getSerialNumberBigInt().toString(16));
    }

    /**
     * Валидирует peer-цепочку с сертификатами-якорями и проверяет отзыв (OCSP/CRL).
     *
     * <p>Сначала строит эффективную цепочку и выполняет PKIX-валидацию
     * ({@link #validateChain(List, TrustAnchors, String...)}), затем
     * для каждого сертификата ниже якоря проверяет статус отзыва:</p>
     * <ol>
     *   <li>Если предоставлен OCSP-ответ — проверка через
     *       {@link OcspVerifier#verify(byte[], byte[], GostCertificate)}</li>
     *   <li>Иначе если предоставлен CRL — проверка через
     *       {@link CrlVerifier#verify(byte[], byte[], PublicKeyParameters, byte[])}</li>
     *   <li>Иначе — сертификат пропускается (warn-лог, не ошибка)</li>
     * </ol>
     *
     * <p>Свежесть OCSP-ответа проверяется политикой по умолчанию: необязательный предел
     * возраста {@code thisUpdate} ({@code maxThisUpdateAge}, Р 1323565.1.059-2024, п. 5.3)
     * этот метод не принимает и не применяет. Предел задаётся в полных перегрузках
     * {@code OcspVerifier.verify}, а в TLS и JSSE - через {@code TlsPeerPolicy} и
     * {@code GostSslBuilder}.</p>
     *
     * <p><b>null в {@code revocationData} означает пропуск проверки отзыва для
     * этого сертификата — ответственность на вызывающем.</b> Если вызывающий
     * передаёт null-записи для всех сертификатов, метод вырождается в обычную
     * проверку цепочки без отзыва.</p>
     *
     * <p>Отзыв проверяется только для сертификатов эффективной цепочки ниже якоря.
     * {@code revocationData} параллелен peer-цепочке; добавленный локальный якорь
     * не проверяется, а данные для сертификатов выше достигнутого якоря
     * игнорируются.</p>
     *
     * <p>Приоритет OCSP над CRL соответствует RFC 5280 и принятому в проекте
     * паттерну (см. {@code GostX509TrustManager.checkCrl()}). Не поддерживает
     * delegated CRL signer, delegated OCSP responder, nonce-проверку и delta CRL —
     * для этих случаев используйте {@link CrlVerifier} / {@link OcspVerifier}
     * напрямую.</p>
     *
     * @param peerChain      peer-цепочка leaf-first
     * @param anchors        доверенные якоря (не null, не пусто)
     * @param revocationData данные отзыва, параллельно peer-цепочке; null-элемент —
     *                       «нет данных для этого индекса»
     * @throws PkixException          при ошибке валидации цепочки или обнаружении отзыва
     * @throws IllegalArgumentException если anchors пуст/null или размер
     *                                  revocationData не совпадает с peer-цепочкой
     */
    public static void validateChainWithRevocation(
            List<GostCertificate> peerChain,
            TrustAnchors anchors,
            List<CertRevocationData> revocationData)
            throws PkixException {
        validateChainWithRevocation(peerChain, anchors, revocationData, CrlLimits.DEFAULT);
    }

    /**
     * То же, что {@link #validateChainWithRevocation(List, TrustAnchors, List)}, с заданными
     * пределами размера и числа записей CRL. Превышение даёт {@code PkixException} с причиной
     * {@link PkixException.Reason#CRL_LIMIT_EXCEEDED}: этот путь не пропускает такой CRL.
     *
     * @param peerChain      peer-цепочка leaf-first
     * @param anchors        доверенные якоря (не null, не пусто)
     * @param revocationData данные отзыва, параллельно peer-цепочке
     * @param limits         пределы размера и числа записей CRL (не null)
     * @throws PkixException          при ошибке валидации цепочки, обнаружении отзыва или
     *                                превышении пределов CRL
     * @throws IllegalArgumentException если anchors пуст/null, limits null или размер
     *                                  revocationData не совпадает с peer-цепочкой
     */
    public static void validateChainWithRevocation(
            List<GostCertificate> peerChain,
            TrustAnchors anchors,
            List<CertRevocationData> revocationData,
            CrlLimits limits)
            throws PkixException {
        if (limits == null) {
            throw new IllegalArgumentException("limits must not be null");
        }
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("anchors must not be null or empty");
        }
        checkPeerChainSize(peerChain);
        if (revocationData == null) {
            throw new IllegalArgumentException("revocationData must not be null");
        }
        if (revocationData.size() != peerChain.size()) {
            throw new IllegalArgumentException(
                    "revocationData size ("
                            + revocationData.size()
                            + ") must match peer chain size ("
                            + peerChain.size()
                            + ")");
        }
        List<GostCertificate> effective = validateChain(peerChain, anchors);
        checkRevocation(effective, peerChain.size(), revocationData, limits);
    }

    /**
     * Проверяет цепочку и все доказательства отзыва для CAdES-X Long.
     *
     * <p>Цепочка проверяется на текущее время (как и раньше); временное окно
     * применяется только к доказательствам отзыва. Для каждого сертификата
     * ниже якоря требуется хотя бы одно доказательство. Проверяются все
     * переданные CRL и OCSP: любой видимый отзыв или {@code unknown}
     * отклоняет, а успех возможен при наличии хотя бы одного {@code good}
     * доказательства в окне.</p>
     *
     * <p>Подпись OCSP-ответа дополнительно ищется ключами недоверенных кандидатов
     * в делегированные ответчики. Кандидаты нужны, когда ответчик не встроен в
     * OCSP-ответ (CAdES-X Long от КриптоПро кладёт его в certificate-values).
     * Кандидат обязан иметь id-kp-OCSPSigning, KeyUsage, срок действия и подпись
     * издателя проверяемого сертификата; якорем он не становится.</p>
     *
     * @param peerChain peer-цепочка leaf-first
     * @param anchors   доверенные якоря
     * @param evidence  доказательства, параллельно peer-цепочке
     * @param window    окно подписи/сбора
     * @param policy    политика свежести
     * @param untrustedResponderCandidates недоверенные сертификаты ответчиков
     *         (не null; для отсутствия кандидатов передайте {@link List#of()})
     * @return доказательства, реально прошедшие проверку, по индексам {@code 0..n-2}, где
     *         {@code n} - размер эффективной цепочки: у якоря доказательств не проверяют, а
     *         эффективная цепочка может быть короче или длиннее peer-цепочки (якорь найден
     *         внутри или достроен), поэтому список может быть префиксом переданного
     *         {@code evidence}. Дубликаты внутри записи удалены. Потребителю следует брать
     *         именно эти значения: подпись каждого проверена, а сертификат не отозван.
     *         Свежесть гарантируется на уровне сертификата (хотя бы одно значение в окне),
     *         остальные значения записи могут лежать вне окна.
     * @throws PkixException при ошибке цепочки, отзыве, отсутствии
     *         доказательств или отсутствии good-доказательства в окне
     */
    public static List<CertRevocationEvidence> validateChainWithRevocationEvidence(
            List<GostCertificate> peerChain,
            TrustAnchors anchors,
            List<CertRevocationEvidence> evidence,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            List<GostCertificate> untrustedResponderCandidates)
            throws PkixException {
        return validateChainWithRevocationEvidence(
                peerChain,
                anchors,
                evidence,
                window,
                policy,
                untrustedResponderCandidates,
                CrlLimits.DEFAULT);
    }

    /**
     * То же, что
     * {@link #validateChainWithRevocationEvidence(List, TrustAnchors, List, RevocationEvidenceWindow,
     * RevocationFreshnessPolicy, List)}, с заданными пределами размера и числа записей CRL.
     * Превышение даёт {@code PkixException} с причиной
     * {@link PkixException.Reason#CRL_LIMIT_EXCEEDED}.
     *
     * @param limits пределы размера и числа записей CRL (не null); остальные параметры - как у
     *               короткой перегрузки
     * @return доказательства, реально прошедшие проверку
     * @throws PkixException при ошибке цепочки, отзыве, нехватке доказательств или превышении
     *                       пределов CRL
     */
    public static List<CertRevocationEvidence> validateChainWithRevocationEvidence(
            List<GostCertificate> peerChain,
            TrustAnchors anchors,
            List<CertRevocationEvidence> evidence,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            List<GostCertificate> untrustedResponderCandidates,
            CrlLimits limits)
            throws PkixException {
        if (limits == null) {
            throw new IllegalArgumentException("limits must not be null");
        }
        if (untrustedResponderCandidates == null) {
            throw new IllegalArgumentException("untrustedResponderCandidates must not be null");
        }
        for (int i = 0; i < untrustedResponderCandidates.size(); i++) {
            if (untrustedResponderCandidates.get(i) == null) {
                throw new IllegalArgumentException(
                        "untrustedResponderCandidates must not contain null, index " + i);
            }
        }
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("anchors must not be null or empty");
        }
        if (evidence == null) {
            throw new IllegalArgumentException("evidence must not be null");
        }
        if (window == null) {
            throw new IllegalArgumentException("window must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        checkPeerChainSize(peerChain);
        if (evidence.size() != peerChain.size()) {
            throw new IllegalArgumentException(
                    "evidence size ("
                            + evidence.size()
                            + ") must match peer chain size ("
                            + peerChain.size()
                            + ")");
        }

        List<GostCertificate> effective = validateChain(peerChain, anchors);
        return checkRevocationEvidence(
                effective, evidence, window, policy, untrustedResponderCandidates, limits);
    }

    /**
     * Проверяет только доказательства отзыва, без валидации цепочки.
     *
     * <p>Нужен producer-стороне CAdES-X Long для раннего применения политики
     * до встраивания. Цепочка трактуется как leaf-first, последний элемент —
     * якорь. Все сертификаты ниже якоря должны иметь доказательства.</p>
     *
     * @param chain    цепочка leaf-first
     * @param evidence доказательства, параллельно цепочке
     * @param window   окно подписи/сбора
     * @param policy   политика свежести
     * @throws PkixException при отзыве, отсутствии доказательств или
     *         отсутствии good-доказательства в окне
     */
    public static void validateRevocationEvidence(
            List<GostCertificate> chain,
            List<CertRevocationEvidence> evidence,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy)
            throws PkixException {
        validateRevocationEvidence(chain, evidence, window, policy, CrlLimits.DEFAULT);
    }

    /**
     * То же, что
     * {@link #validateRevocationEvidence(List, List, RevocationEvidenceWindow,
     * RevocationFreshnessPolicy)}, с заданными пределами размера и числа записей CRL.
     *
     * @param limits пределы размера и числа записей CRL (не null)
     * @throws PkixException при отзыве, нехватке доказательств или превышении пределов CRL
     */
    public static void validateRevocationEvidence(
            List<GostCertificate> chain,
            List<CertRevocationEvidence> evidence,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            CrlLimits limits)
            throws PkixException {
        if (limits == null) {
            throw new IllegalArgumentException("limits must not be null");
        }
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("chain must not be null or empty");
        }
        if (evidence == null) {
            throw new IllegalArgumentException("evidence must not be null");
        }
        if (window == null) {
            throw new IllegalArgumentException("window must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        if (evidence.size() != chain.size()) {
            throw new IllegalArgumentException(
                    "evidence size ("
                            + evidence.size()
                            + ") must match chain size ("
                            + chain.size()
                            + ")");
        }
        checkRevocationEvidence(chain, evidence, window, policy, List.of(), limits);
    }

    private static List<CertRevocationEvidence> checkRevocationEvidence(
            List<GostCertificate> effectiveChain,
            List<CertRevocationEvidence> evidence,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            List<GostCertificate> untrustedResponderCandidates,
            CrlLimits limits)
            throws PkixException {
        int n = effectiveChain.size();
        // Возвращаем только прошедшее проверку: evidence якоря (индекс n-1) сюда не попадает,
        // его подпись не проверяется, и отдавать его потребителю как проверенное нельзя.
        List<CertRevocationEvidence> verified = new ArrayList<>(Math.max(0, n - 1));
        for (int i = 0; i < n - 1; i++) {
            CertRevocationEvidence item = evidence.get(i);
            GostCertificate cert = effectiveChain.get(i);
            GostCertificate issuer = effectiveChain.get(i + 1);

            if (item == null || item.isEmpty()) {
                throw new PkixException(
                        "CAdES-X Long: no revocation evidence for chain["
                                + i
                                + "], serial=0x"
                                + cert.getSerialNumberBigInt().toString(16));
            }

            List<byte[]> crls = uniqueEvidence(item.crlDers(), "CRL", cert, i);
            List<byte[]> ocsps = uniqueEvidence(item.ocspResponseDers(), "OCSP", cert, i);
            if (crls.size() + ocsps.size() > GostOids.MAX_REVOCATION_EVIDENCE_PER_CERT) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "CAdES-X Long: total revocation evidence count "
                                + (crls.size() + ocsps.size())
                                + " exceeds limit "
                                + GostOids.MAX_REVOCATION_EVIDENCE_PER_CERT
                                + " for chain["
                                + i
                                + "], serial=0x"
                                + cert.getSerialNumberBigInt().toString(16));
            }

            boolean goodInWindow = false;
            for (byte[] crlDer : crls) {
                EvidenceFreshness freshness =
                        CrlVerifier.verifyEvidence(crlDer, cert, issuer, window, policy, limits);
                if (freshness == EvidenceFreshness.IN_WINDOW) {
                    goodInWindow = true;
                }
            }
            for (byte[] ocspDer : ocsps) {
                EvidenceFreshness freshness =
                        OcspVerifier.verifyEvidence(
                                ocspDer,
                                cert.getSerialNumber(),
                                issuer,
                                window,
                                policy,
                                untrustedResponderCandidates);
                if (freshness == EvidenceFreshness.IN_WINDOW) {
                    goodInWindow = true;
                }
            }

            if (!goodInWindow) {
                throw new PkixException(
                        PkixException.Reason.REVOCATION_EVIDENCE_OUT_OF_WINDOW,
                        "CAdES-X Long: no good revocation evidence in the required time window for chain["
                                + i
                                + "]");
            }
            verified.add(new CertRevocationEvidence(crls, ocsps));
        }

        LOG.log(
                Level.DEBUG,
                "CAdES-X Long chain validation passed (leaf serial=0x{0}); policy={1}",
                effectiveChain.get(0).getSerialNumberBigInt().toString(16),
                policy);
        return List.copyOf(verified);
    }

    private static List<byte[]> uniqueEvidence(
            List<byte[]> source, String kind, GostCertificate cert, int chainIndex)
            throws PkixException {
        List<byte[]> unique = new ArrayList<>(source.size());
        for (byte[] value : source) {
            boolean duplicate = false;
            for (byte[] existing : unique) {
                if (Arrays.equals(existing, value)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                unique.add(value);
            }
        }
        if (unique.size() > GostOids.MAX_REVOCATION_EVIDENCE_PER_CERT) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long: "
                            + kind
                            + " evidence count "
                            + unique.size()
                            + " exceeds limit "
                            + GostOids.MAX_REVOCATION_EVIDENCE_PER_CERT
                            + " for chain["
                            + chainIndex
                            + "], serial=0x"
                            + cert.getSerialNumberBigInt().toString(16));
        }
        return unique;
    }

    /**
     * Общий цикл OCSP/CRL для проверки отзыва.
     *
     * @param effectiveChain     эффективная цепочка leaf-first
     * @param revocationDataSize число элементов revocationData (размер peer-цепочки)
     */
    private static void checkRevocation(
            List<GostCertificate> effectiveChain,
            int revocationDataSize,
            List<CertRevocationData> revocationData,
            CrlLimits limits)
            throws PkixException {
        if (revocationData == null) {
            throw new IllegalArgumentException("revocationData must not be null");
        }
        if (revocationData.size() != revocationDataSize) {
            throw new IllegalArgumentException(
                    "revocationData size ("
                            + revocationData.size()
                            + ") must match peer chain size ("
                            + revocationDataSize
                            + ")");
        }

        int checked = 0;
        int skipped = 0;
        int n = effectiveChain.size();
        for (int i = 0; i < n - 1; i++) {
            CertRevocationData rd = i < revocationDataSize ? revocationData.get(i) : null;
            if (rd == null) {
                skipped++;
                LOG.log(
                        Level.DEBUG,
                        "No revocation data for cert chain[{0}], serial=0x{1}",
                        i,
                        effectiveChain.get(i).getSerialNumberBigInt().toString(16));
                continue;
            }

            GostCertificate cert = effectiveChain.get(i);
            GostCertificate issuer = effectiveChain.get(i + 1);

            if (rd.ocspResponse() != null) {
                OcspVerifier.verify(rd.ocspResponse(), cert.getSerialNumber(), issuer);
            } else {
                CrlVerifier.verify(rd.crlDer(), cert, issuer, null, limits);
            }
            checked++;
        }

        if (skipped > 0) {
            // Проверка отзыва пропущена по решению вызывающего (нет данных): библиотека
            // продолжает, значит оператору нужна одна запись за проверку, а не по записи на
            // каждый сертификат цепочки
            LOG.log(
                    Level.WARNING,
                    "Revocation not checked for {0} of {1} certificate(s), leaf serial=0x{2}",
                    skipped,
                    n - 1,
                    effectiveChain.get(0).getSerialNumberBigInt().toString(16));
        }
        LOG.log(
                Level.DEBUG,
                "Certificate chain validation passed (leaf serial=0x{0}); revocation checked={1}, skipped={2}",
                effectiveChain.get(0).getSerialNumberBigInt().toString(16),
                checked,
                skipped);
    }

    /**
     * Считает не-self-issued промежуточные CA между cert[certIndex] и leaf (исключая leaf).
     * <p>
     * Self-issued определяется как совпадение subjectDN соседних сертификатов:
     * {@code cert[j].subjectDN == cert[j+1].subjectDN}. Поскольку DN-валидация
     * гарантирует {@code cert[j].issuerDN == cert[j+1].subjectDN}, это эквивалентно
     * проверке {@code cert[j].issuerDN == cert[j].subjectDN} (self-issued per RFC 5280).
     * <p>
     * Использует {@link GostCertificate#subjectDnEquals(GostCertificate, GostCertificate)}
     * — побайтовое сравнение без копирования.
     *
     * @param chain     цепочка leaf-first
     * @param certIndex индекс сертификата, для которого считаются следующие CA
     * @return количество не-self-issued промежуточных CA между cert[certIndex] и leaf
     */
    private static int countFollowingNonSelfIssuedCA(List<GostCertificate> chain, int certIndex) {
        int count = 0;
        for (int j = certIndex - 1; j >= 1; j--) {
            if (!GostCertificate.subjectDnEquals(chain.get(j), chain.get(j + 1))) {
                count++;
            }
        }
        return count;
    }

    // ========================================================================
    // Name Constraints enforcement (RFC 5280 §6.1.4)
    // ========================================================================

    /**
     * Root-to-leaf проход для проверки Name Constraints.
     * <p>
     * Ограничения накапливаются от верхнего сертификата цепочки вниз.
     * Верх эффективной цепочки — локальный сертификат-якорь, поэтому его
     * NameConstraints аутентифицированы. На каждом не-self-issued сертификате
     * проверяются накопленные ограничения, затем аккумулируются новые.
     * Self-issued CA не проходят проверку собственного имени накопленными ограничениями
     * (RFC 5280 §6.1.4(k)), но их собственные ограничения накапливаются для нижестоящих.
     */
    private static void validateNameConstraintsPass(List<GostCertificate> chain)
            throws PkixException {
        int n = chain.size();
        List<NameConstraintsData> accumulated = new ArrayList<>();

        for (int i = n - 1; i >= 0; i--) {
            GostCertificate cert = chain.get(i);

            // Проверка этого сертификата против уже накопленных ограничений.
            // Пропускаем для root (i == n-1, нет вышестоящего) и для self-issued.
            // RFC 5280 §4.2.1.10: self-issued промежуточный не проверяется,
            // но leaf (последний сертификат пути) проверяется всегда.
            if (i < n - 1 && (i == 0 || !cert.isSelfIssued())) {
                checkCertAgainstConstraints(cert, accumulated);
            }

            // Накопление ограничений из этого сертификата (только для CA, кроме leaf).
            if (i > 0) {
                NameConstraintsData nc = cert.nameConstraintsInternal();
                if (!nc.isEmpty()) {
                    // Структурно некорректные NameConstraints нельзя интерпретировать
                    // безопасно: например, пропущенный GeneralSubtree мог бы скрыть
                    // ограничение. Отклоняем всю цепочку до любых эвристик.
                    if (nc.hasMalformed) {
                        throw new PkixException(
                                "Certificate chain: malformed NameConstraints at cert[" + i + "]");
                    }
                    // RFC 5280 описывает имена, а не шаблоны. Wildcard в NC не
                    // определён и может дать fail-open при сопоставлении, поэтому
                    // отклоняем такие ограничения целиком.
                    if (containsWildcard(nc.permittedDnsNames)
                            || containsWildcard(nc.excludedDnsNames)
                            || containsWildcard(nc.permittedRfc822Names)
                            || containsWildcard(nc.excludedRfc822Names)
                            || containsWildcard(nc.permittedUris)
                            || containsWildcard(nc.excludedUris)) {
                        throw new PkixException(
                                "Certificate chain: wildcard in NameConstraints is not allowed"
                                        + " at cert["
                                        + i
                                        + "]");
                    }
                    // Пустой constraint и "." после нормализации не задают имя.
                    // Для excluded это fail-open, поэтому отклоняем весь NC.
                    if (hasEmptyNameConstraint(nc.permittedDnsNames)
                            || hasEmptyNameConstraint(nc.excludedDnsNames)
                            || hasEmptyNameConstraint(nc.permittedRfc822Names)
                            || hasEmptyNameConstraint(nc.excludedRfc822Names)
                            || hasEmptyNameConstraint(nc.permittedUris)
                            || hasEmptyNameConstraint(nc.excludedUris)) {
                        throw new PkixException(
                                "Certificate chain: empty name constraint in NameConstraints"
                                        + " at cert["
                                        + i
                                        + "]");
                    }
                    if (nc.nonCritical) {
                        throw new PkixException(
                                "Certificate chain: NameConstraints must be critical"
                                        + " (RFC 5280 §4.2.1.10) at cert["
                                        + i
                                        + "]");
                    }
                    // otherName/x400/EDI/registeredID и форма mailbox в rfc822Name не
                    // поддерживаются. Проверка enforcement — в checkCertAgainstConstraints(),
                    // где известен SAN сертификата: имя той же формы -> отказ с исключением,
                    // иначе ограничение неприменимо и это пишется там на DEBUG
                    if (nc.hasInvalidMinMax) {
                        throw new PkixException(
                                "Certificate chain: NameConstraints min != 0 or max present"
                                        + " at cert["
                                        + i
                                        + "]");
                    }
                    accumulated.add(nc);
                }
            }
        }
    }

    /**
     * Проверяет SAN (все типы) сертификата против списка накопленных ограничений.
     * Каждый набор из accumulated должен быть удовлетворён (AND-семантика между уровнями CA).
     */
    private static void checkCertAgainstConstraints(
            GostCertificate cert, List<NameConstraintsData> accumulated) throws PkixException {
        if (accumulated.isEmpty()) {
            return;
        }

        // Subject DN разбирается лениво: при ограничениях только на DNS/IP/URI
        // он не участвует в проверке, и строгий разбор legacy-кодировки не
        // должен приводить к отказу.
        DirectoryNameSubtree.Dn subjectDnParsed = null;
        String[] sanDnsNames = cert.getSanDnsNames();
        byte[][] sanIps = cert.getSanIpAddresses();
        String[] sanRfc822Names = cert.getSanRfc822Names();
        String[] sanUris = cert.getSanUris();
        List<DirectoryNameSubtree.Dn> directoryNames = null;
        List<String> subjectEmails = null;

        for (NameConstraintsData nc : accumulated) {
            // Permitted: ограничение применяется только к присутствующим SAN того же типа.
            // Если SAN нужного типа отсутствует — vacuously satisfied (RFC 5280).
            if (nc.permittedDnsNames != null
                    && nc.permittedDnsNames.length > 0
                    && sanDnsNames != null) {
                // RFC 5280 §4.2.1.10: каждое dNSName в сертификате должно входить
                // в permittedSubtrees. Одного совпавшего SAN недостаточно —
                // иначе подчинённый CA добавляет легальное имя и выпускает
                // сертификат на любое другое.
                for (String san : sanDnsNames) {
                    if (!isDnsNameInPermitted(san, nc.permittedDnsNames)) {
                        throw new PkixException(
                                "Certificate chain: SAN dNSName not in permitted subtrees");
                    }
                }
            }
            if (nc.permittedIps != null && nc.permittedIps.length > 0 && sanIps != null) {
                // То же для iPAddress: каждое имя должно попасть в permitted.
                for (byte[] san : sanIps) {
                    if (!isIpInSubtrees(san, nc.permittedIps)) {
                        throw new PkixException(
                                "Certificate chain: SAN iPAddress not in permitted subtrees");
                    }
                }
            }

            // Excluded: ограничение применяется только к присутствующим SAN того же типа.
            if (nc.excludedDnsNames != null && sanDnsNames != null) {
                for (String san : sanDnsNames) {
                    if (isDnsNameInExcludedSubtrees(san, nc.excludedDnsNames)) {
                        throw new PkixException(
                                "Certificate chain: SAN dNSName in excluded subtrees");
                    }
                }
            }
            if (nc.excludedIps != null && sanIps != null) {
                for (byte[] san : sanIps) {
                    if (isIpInExcludedSubtrees(san, nc.excludedIps)) {
                        throw new PkixException(
                                "Certificate chain: SAN iPAddress in excluded subtrees");
                    }
                }
            }

            // --- rfc822Name ---
            // Mailbox-формы (user@host) не сопоставляются, но делают rfc822-ограничение
            // активным: иначе имена из subject emailAddress вообще не попадали в проверку.
            boolean rfc822NcActive =
                    (nc.permittedRfc822Names != null && nc.permittedRfc822Names.length > 0)
                            || (nc.excludedRfc822Names != null && nc.excludedRfc822Names.length > 0)
                            || nc.hasUnsupportedRfc822Form;
            String[] effectiveRfc822 = sanRfc822Names;
            if (rfc822NcActive) {
                // Сознательное ужесточение сверх буквального RFC 5280 §4.2.1.10 (там
                // emailAddress проверяется при отсутствии SAN): subject emailAddress
                // проверяется ВСЕГДА вместе с SAN rfc822. Недоверенный подчинённый УЦ
                // иначе кладёт разрешённый rfc822Name в SAN, а запрещённый адрес в subject,
                // который S/MIME-клиенты по-прежнему читают.
                if (subjectEmails == null) {
                    if (subjectDnParsed == null) {
                        subjectDnParsed = DirectoryNameSubtree.parse(cert.getSubjectDnBytes());
                    }
                    subjectEmails = extractSubjectEmailAddresses(subjectDnParsed);
                }
                effectiveRfc822 = mergeRfc822Names(sanRfc822Names, subjectEmails);
            }
            if (rfc822NcActive && effectiveRfc822 != null) {
                // Под активным rfc822-NC имя без '@', с пустым доменом или
                // wildcard-доменом невалидно. Wildcard-семантика к email не
                // применяется, поэтому такие имена нельзя сопоставлять молча.
                for (String san : effectiveRfc822) {
                    if (!isValidRfc822San(san)) {
                        throw new PkixException(
                                "Certificate chain: rfc822Name has invalid mailbox form"
                                        + " under active rfc822Name NameConstraints");
                    }
                }
            }
            if (nc.permittedRfc822Names != null
                    && nc.permittedRfc822Names.length > 0
                    && effectiveRfc822 != null) {
                // RFC 5280: permitted rfc822 без ведущей точки — только сам хост,
                // с ведущей точкой — только поддомены.
                for (String san : effectiveRfc822) {
                    String domain = extractEmailDomain(san);
                    if (!isRfc822HostInSubtrees(domain, nc.permittedRfc822Names)) {
                        throw new PkixException(
                                "Certificate chain: rfc822Name not in permitted subtrees");
                    }
                }
            }
            if (nc.excludedRfc822Names != null && effectiveRfc822 != null) {
                for (String san : effectiveRfc822) {
                    String domain = extractEmailDomain(san);
                    if (isRfc822HostInSubtrees(domain, nc.excludedRfc822Names)) {
                        throw new PkixException(
                                "Certificate chain: rfc822Name in excluded subtrees");
                    }
                }
            }

            // --- URI ---
            if (nc.permittedUris != null && nc.permittedUris.length > 0 && sanUris != null) {
                // Каждое URI-имя должно войти в permittedSubtrees.
                String[] permittedUris = normalizeUriConstraints(nc.permittedUris);
                for (String san : sanUris) {
                    String host = extractUriHost(san);
                    if (!isUriHostInConstraint(host, permittedUris)) {
                        throw new PkixException(
                                "Certificate chain: SAN URI not in permitted subtrees");
                    }
                }
            }
            if (nc.excludedUris != null && sanUris != null) {
                String[] excludedUris = normalizeUriConstraints(nc.excludedUris);
                for (String san : sanUris) {
                    String host = extractUriHost(san);
                    if (isUriHostInConstraint(host, excludedUris)) {
                        throw new PkixException("Certificate chain: SAN URI in excluded subtrees");
                    }
                }
            }

            // --- directoryName ---
            if ((nc.excludedDirectoryNames != null && nc.excludedDirectoryNames.length > 0)
                    || (nc.permittedDirectoryNames != null
                            && nc.permittedDirectoryNames.length > 0)) {
                if (directoryNames == null) {
                    if (subjectDnParsed == null) {
                        subjectDnParsed = DirectoryNameSubtree.parse(cert.getSubjectDnBytes());
                    }
                    directoryNames = parseDirectoryNameValues(cert, subjectDnParsed);
                }
                List<DirectoryNameSubtree.Dn> excluded =
                        parseDirectoryConstraints(nc.excludedDirectoryNames);
                for (DirectoryNameSubtree.Dn name : directoryNames) {
                    for (DirectoryNameSubtree.Dn subtree : excluded) {
                        if (DirectoryNameSubtree.isWithinSubtree(
                                name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED)) {
                            throw new PkixException(
                                    "Certificate chain: directoryName is within"
                                            + " excluded subtrees");
                        }
                    }
                }
                List<DirectoryNameSubtree.Dn> permitted =
                        parseDirectoryConstraints(nc.permittedDirectoryNames);
                if (!permitted.isEmpty() && !directoryNames.isEmpty()) {
                    for (DirectoryNameSubtree.Dn name : directoryNames) {
                        boolean matched = false;
                        for (DirectoryNameSubtree.Dn subtree : permitted) {
                            if (DirectoryNameSubtree.isWithinSubtree(
                                    name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED)) {
                                matched = true;
                                break;
                            }
                        }
                        if (!matched) {
                            throw new PkixException(
                                    "Certificate chain: directoryName not in"
                                            + " permitted subtrees");
                        }
                    }
                }
            }

            // --- Неподдерживаемые формы (otherName, x400, EDI, registeredID) ---
            // RFC 5280 §4.2.1.10: ограничение на форму нужно обработать или отклонить
            // сертификат, в котором такая форма есть. Формы сопоставляются раздельно:
            // ограничение на registeredID не относится к otherName в SAN.
            if (!nc.unsupportedNameForms.isEmpty()) {
                if (!Collections.disjoint(
                        nc.unsupportedNameForms, cert.getSanUnsupportedNameForms())) {
                    throw new PkixException(
                            "Certificate chain: NameConstraints constrain a GeneralName form"
                                    + " that is not supported and the certificate has a name"
                                    + " of that form in SAN; constraints cannot be enforced"
                                    + " — rejecting chain");
                }
                // Ограничение на форму, которой нет в сертификате, по RFC 5280 не применяется:
                // это штатный исход, а не деградация проверки, поэтому DEBUG
                LOG.log(
                        Level.DEBUG,
                        "Certificate chain: NameConstraints contain unsupported GeneralName"
                                + " forms {0} but the certificate has no names of those forms"
                                + " in SAN, constraints not applicable",
                        nc.unsupportedNameForms);
            }

            // --- rfc822Name mailbox-form: fail-closed если лист содержит rfc822Name ---
            if (nc.hasUnsupportedRfc822Form && effectiveRfc822 != null) {
                throw new PkixException(
                        "Certificate chain: NameConstraints contain unsupported"
                                + " rfc822Name mailbox form"
                                + " and certificate has rfc822Name;"
                                + " constraints cannot be enforced — rejecting chain");
            }
            if (nc.hasUnsupportedRfc822Form && effectiveRfc822 == null) {
                LOG.log(
                        Level.DEBUG,
                        "Certificate chain: NameConstraints contain unsupported"
                                + " rfc822Name mailbox form but certificate has no"
                                + " rfc822Name in SAN and no emailAddress in subject,"
                                + " constraints not applicable");
            }
        }
    }

    /**
     * Объединяет rfc822Name из SAN и emailAddress из subject без дублей.
     *
     * @return объединённый набор в нижнем регистре или {@code null}, если оба источника пусты
     */
    private static String[] mergeRfc822Names(String[] sanNames, List<String> subjectEmails) {
        Set<String> merged = new LinkedHashSet<>();
        if (sanNames != null) {
            for (String name : sanNames) {
                merged.add(name.toLowerCase(Locale.ROOT));
            }
        }
        for (String email : subjectEmails) {
            merged.add(email.toLowerCase(Locale.ROOT));
        }
        return merged.isEmpty() ? null : merged.toArray(new String[0]);
    }

    /**
     * Собирает имена directoryName: непустой subject DN и все directoryName SAN.
     *
     * <p>Пустой subject допускается RFC 5280 и пропускается; пустой
     * directoryName SAN — некорректное имя, поэтому fail-closed.</p>
     */
    private static List<DirectoryNameSubtree.Dn> parseDirectoryNameValues(
            GostCertificate cert, DirectoryNameSubtree.Dn subject) throws PkixException {
        List<DirectoryNameSubtree.Dn> names = new ArrayList<>();
        if (!subject.isEmpty()) {
            names.add(subject);
        }
        byte[][] sanDirNames = cert.getSanDirectoryNames();
        if (sanDirNames != null) {
            for (byte[] san : sanDirNames) {
                DirectoryNameSubtree.Dn name = DirectoryNameSubtree.parse(san);
                if (name.isEmpty()) {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "Certificate chain: empty directoryName SAN");
                }
                names.add(name);
            }
        }
        return names;
    }

    /** Извлекает emailAddress из subject DN для rfc822 NameConstraints. */
    private static List<String> extractSubjectEmailAddresses(DirectoryNameSubtree.Dn subject)
            throws PkixException {
        List<String> result = new ArrayList<>();
        for (DirectoryNameSubtree.Rdn rdn : subject.rdns) {
            for (DirectoryNameSubtree.Ava ava : rdn.avas) {
                if (!GostOids.ATTR_EMAIL.equals(ava.oid)) {
                    continue;
                }
                String value = DirectoryNameSubtree.stringValue(ava);
                if (value == null) {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "Certificate chain: subject emailAddress is not"
                                    + " a decodable string");
                }
                result.add(value);
            }
        }
        return result;
    }

    /** Разбирает ограничения directoryName; пустое ограничение — fail-closed. */
    private static List<DirectoryNameSubtree.Dn> parseDirectoryConstraints(byte[][] constraints)
            throws PkixException {
        List<DirectoryNameSubtree.Dn> result = new ArrayList<>();
        if (constraints == null) {
            return result;
        }
        for (byte[] constraint : constraints) {
            DirectoryNameSubtree.Dn subtree = DirectoryNameSubtree.parse(constraint);
            if (subtree.isEmpty()) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Certificate chain: empty directoryName constraint");
            }
            result.add(subtree);
        }
        return result;
    }

    /**
     * Label-aware suffix matching для dNSName.
     *
     * <p>RFC 5280: bare-constraint {@code example.com} включает сам хост и
     * поддомены. Ведущая точка ({@code .example.com}) — расширение OpenSSL/Go:
     * только поддомены, без самого хоста. Завершающая точка FQDN нормализуется.</p>
     */
    static boolean isDnsNameInPermitted(String name, String[] constraints) {
        String lower = normalizeDnsName(name);
        if (lower.isEmpty()) {
            return false;
        }
        for (String c : constraints) {
            String lowerC = normalizeDnsName(c);
            if (lowerC.isEmpty()) {
                continue;
            }
            if (lowerC.startsWith(".")) {
                if (lower.endsWith(lowerC) && lower.length() > lowerC.length()) {
                    return true;
                }
            } else if (lower.equals(lowerC) || lower.endsWith("." + lowerC)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Сопоставление host из rfc822Name по RFC 5280 §4.2.1.10.
     *
     * <p>Bare-constraint {@code example.com} — только сам хост; constraint с
     * ведущей точкой ({@code .example.com}) — только поддомены. Это отличается
     * от dNSName, где bare-constraint включает поддомены.</p>
     */
    private static boolean isRfc822HostInSubtrees(String host, String[] constraints) {
        String lower = normalizeDnsName(host);
        if (lower.isEmpty()) {
            return false;
        }
        for (String c : constraints) {
            String lowerC = normalizeDnsName(c);
            if (lowerC.isEmpty()) {
                continue;
            }
            if (lowerC.startsWith(".")) {
                if (lower.endsWith(lowerC) && lower.length() > lowerC.length()) {
                    return true;
                }
            } else if (lower.equals(lowerC)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверяет excluded dNSName с учётом wildcard-SAN.
     *
     * <p>Wildcard-SAN покрывает ровно одну метку (RFC 6125 §6.4.3). Если
     * excluded-поддерево содержит эту метку, wildcard фактически покрывает
     * запрещённое имя. Пересечение считаем по меткам, а не через
     * {@link GostCertificate#matchDnsName}: для невалидных для hostname
     * wildcard-ов ({@code *.com}, IDN) это даёт больше отказов, а не меньше.</p>
     */
    private static boolean isDnsNameInExcludedSubtrees(String name, String[] excluded) {
        if (isDnsNameInPermitted(name, excluded)) {
            return true;
        }
        String lower = normalizeDnsName(name);
        if (!lower.startsWith("*.")) {
            return false;
        }
        for (String constraint : excluded) {
            if (wildcardIntersectsDnsSubtree(lower, constraint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Пересекается ли wildcard {@code *.S} с excluded-поддеревом {@code C}.
     *
     * <p>Wildcard покрывает имена вида {@code L.S}. Bare {@code C} включает сам C
     * и поддомены; {@code .C} — только поддомены. Поэтому при {@code C} ровно на
     * одну метку ниже {@code S} пересечение есть только для bare C. Более глубокий
     * C wildcard не покрывает.</p>
     */
    private static boolean wildcardIntersectsDnsSubtree(String wildcardSan, String constraint) {
        String suffix = wildcardSan.substring(2);
        if (suffix.isEmpty() || suffix.indexOf('*') >= 0) {
            return false;
        }
        String c = normalizeDnsName(constraint);
        if (c.isEmpty()) {
            return false;
        }
        boolean strictSubdomains = c.startsWith(".");
        if (strictSubdomains) {
            c = c.substring(1);
            if (c.isEmpty()) {
                return false;
            }
        }
        if (suffix.equals(c) || suffix.endsWith("." + c)) {
            return true;
        }
        if (c.endsWith("." + suffix)) {
            String prefix = c.substring(0, c.length() - suffix.length() - 1);
            return !strictSubdomains && !prefix.isEmpty() && prefix.indexOf('.') < 0;
        }
        return false;
    }

    private static String normalizeDnsName(String name) {
        if (name == null) {
            return "";
        }
        String normalized = name.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    /** @return true если constraint после нормализации пуст или равен "." */
    private static boolean hasEmptyNameConstraint(String[] names) {
        if (names == null) {
            return false;
        }
        for (String name : names) {
            String normalized = normalizeDnsName(name);
            if (normalized.isEmpty() || normalized.equals(".")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Валидная ли mailbox-форма rfc822Name под активным rfc822-NC.
     * Требуем непустой домен и запрещаем wildcard в домене.
     */
    private static boolean isValidRfc822San(String rfc822Name) {
        int at = rfc822Name.lastIndexOf('@');
        if (at < 0 || at == rfc822Name.length() - 1) {
            return false;
        }
        String domain = rfc822Name.substring(at + 1);
        return domain.indexOf('*') < 0;
    }

    /** @return true если хотя бы одно значение NC содержит wildcard-символ. */
    private static boolean containsWildcard(String[] names) {
        if (names == null) {
            return false;
        }
        for (String name : names) {
            if (name != null && name.indexOf('*') >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверяет iPAddress сертификата против списка constraint-префиксов.
     * Constraint из 8 байт (IPv4: 4 байта адреса + 4 байта маски)
     * или 32 байт (IPv6: 16 байта адреса + 16 байта маски).
     * Сравнение: (address[j] & mask[j]) == (constraintAddr[j] & mask[j]).
     */
    static boolean isIpInSubtrees(byte[] address, byte[][] constraints) {
        for (byte[] constraint : constraints) {
            int maskLen = constraint.length / 2;
            // Семейства адресов должны совпадать: IPv4 constraint (maskLen=4) может
            // сравниваться только с 4-байтным IPv4 SAN-адресом.
            if (maskLen != address.length) {
                continue;
            }
            boolean match = true;
            for (int j = 0; j < maskLen; j++) {
                if ((address[j] & constraint[j + maskLen])
                        != (constraint[j] & constraint[j + maskLen])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверяет iPAddress сертификата против excluded-поддеревьев с учётом отображённой формы.
     *
     * <p>Один и тот же IPv4-адрес записывается двумя способами: 4 байтами и IPv4-mapped IPv6
     * ({@code ::ffff:a.b.c.d}, 16 байт). Для запрета этого мало сравнить адрес только в его
     * собственной форме: SAN {@code 10.0.0.1} иначе проходил бы мимо запрета
     * {@code ::ffff:10.0.0.0/120}, а SAN {@code ::ffff:10.0.0.1} - мимо {@code 10.0.0.0/8}.
     * Поэтому адрес проверяется в обеих формах и против ограничений обоих семейств, при любой
     * длине маски.</p>
     *
     * <p>Для permitted так нельзя, и {@link #isIpInSubtrees} остаётся строгим: смешение семейств
     * там расширило бы разрешение, а не запрет, поэтому адрес другой формы отвергается
     * (fail-closed). Следствие: под permitted IPv4-ограничением SAN в mapped-форме не принимается.</p>
     */
    static boolean isIpInExcludedSubtrees(byte[] address, byte[][] constraints) {
        if (isIpInSubtrees(address, constraints)) {
            return true;
        }
        byte[] counterpart = ipv4MappedCounterpart(address);
        return counterpart != null && isIpInSubtrees(counterpart, constraints);
    }

    /**
     * Парная форма IPv4-адреса: для 4 байт - mapped IPv6 из 16 байт, для mapped IPv6 - 4 байта
     * IPv4, для остальных адресов {@code null}.
     */
    private static byte[] ipv4MappedCounterpart(byte[] address) {
        if (address.length == IPV4_ADDRESS_LENGTH) {
            byte[] mapped = new byte[IPV6_ADDRESS_LENGTH];
            mapped[IPV4_MAPPED_ZERO_BYTES] = IPV4_MAPPED_MARKER;
            mapped[IPV4_MAPPED_ZERO_BYTES + 1] = IPV4_MAPPED_MARKER;
            System.arraycopy(
                    address,
                    0,
                    mapped,
                    IPV6_ADDRESS_LENGTH - IPV4_ADDRESS_LENGTH,
                    IPV4_ADDRESS_LENGTH);
            return mapped;
        }
        if (address.length != IPV6_ADDRESS_LENGTH) {
            return null;
        }
        for (int i = 0; i < IPV4_MAPPED_ZERO_BYTES; i++) {
            if (address[i] != 0) {
                return null;
            }
        }
        if (address[IPV4_MAPPED_ZERO_BYTES] != IPV4_MAPPED_MARKER
                || address[IPV4_MAPPED_ZERO_BYTES + 1] != IPV4_MAPPED_MARKER) {
            return null;
        }
        return java.util.Arrays.copyOfRange(
                address, IPV6_ADDRESS_LENGTH - IPV4_ADDRESS_LENGTH, IPV6_ADDRESS_LENGTH);
    }

    /**
     * Извлекает host из URI SAN. Fail-closed:
     * — невалидный URI (URISyntaxException) -> {@link PkixException}
     * — отсутствует authority/host -> {@link PkixException}
     * — host является IP-адресом -> {@link PkixException} (RFC 5280 §4.2.1.10 MUST)
     * — иначе host приводится к lowercase A-label без завершающей точки: {@code a.evil.com.} и
     *   {@code a.evil.com} - одно имя, и запрет {@code .evil.com} обязан сработать на обоих.
     *   Имя, которое не приводится к такому виду, отвергается ({@code PARSE_ERROR}).
     */
    private static String extractUriHost(String uri) throws PkixException {
        URI parsed;
        try {
            parsed = new URI(uri);
        } catch (URISyntaxException e) {
            throw new PkixException("Certificate chain: SAN URI is not a valid URI: " + uri, e);
        }
        String host = parsed.getHost();
        if (host == null || host.isEmpty()) {
            throw new PkixException(
                    "Certificate chain: SAN URI missing authority/host component"
                            + " under active URI NameConstraints: "
                            + uri);
        }
        // Числовые формы IPv4 (2130706433, 127.1, 0x7f000001) считаем IP, а не DNS-именем:
        // иначе они прошли бы мимо запрета IP-хоста как обычные имена.
        if (GostDnsName.isIpAddressOrNumericForm(host)) {
            throw new PkixException(
                    "Certificate chain: SAN URI has IP address as host"
                            + " under active URI NameConstraints (RFC 5280 MUST reject): "
                            + uri);
        }
        try {
            return GostDnsName.toAsciiHostname(host);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "Certificate chain: SAN URI host is not a valid DNS name: " + uri,
                    e);
        }
    }

    /**
     * Приводит URI-ограничения к тому же виду, что и host из {@link #extractUriHost}: lowercase
     * A-label без завершающей точки. Ведущая точка ({@code .example.com}) - признак «только
     * поддомены» и сохраняется. Нормализация одна на все SAN: ограничения не пересчитываются
     * в цикле по именам.
     *
     * @throws PkixException {@code PARSE_ERROR}, если ограничение не приводится к имени
     */
    private static String[] normalizeUriConstraints(String[] constraints) throws PkixException {
        String[] normalized = new String[constraints.length];
        for (int i = 0; i < constraints.length; i++) {
            String constraint = constraints[i];
            boolean subdomainsOnly = constraint.startsWith(".");
            String body = subdomainsOnly ? constraint.substring(1) : constraint;
            if (body.isEmpty()) {
                // Пустое ограничение никого не совпадает (как и раньше): оставляем как есть
                normalized[i] = constraint;
                continue;
            }
            try {
                String ascii = GostDnsName.toAsciiHostname(body);
                normalized[i] = subdomainsOnly ? "." + ascii : ascii;
            } catch (IllegalArgumentException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Certificate chain: URI NameConstraint is not a valid DNS name",
                        e);
            }
        }
        return normalized;
    }

    /**
     * Проверяет host из URI SAN против списка URI-ограничений (RFC 5280 §4.2.1.10).
     *
     * <p>Двухрежимный синтаксис, отличный от dNSName:
     * <ul>
     *   <li>Ограничение с ведущей точкой ({@code .example.com}) — suffix-совпадение,
     *       но НЕ матчит голый {@code example.com} без поддомена
     *   <li>Ограничение без ведущей точки ({@code example.com}) — точное совпадение хоста
     * </ul>
     *
     * <p>Хост и ограничения приходят уже нормализованными ({@link #extractUriHost},
     * {@link #normalizeUriConstraints}): регистр, A-label и завершающая точка здесь не
     * пересматриваются.</p>
     */
    private static boolean isUriHostInConstraint(String host, String[] constraints) {
        for (String c : constraints) {
            if (c.startsWith(".")) {
                if (host.endsWith(c) && host.length() > c.length()) {
                    return true;
                }
            } else if (host.equals(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Извлекает доменную часть из rfc822Name (RFC 5280 §4.2.1.10).
     * Ограничение применяется к доменной части, а не к полному адресу.
     * Если '@' отсутствует — возвращается строка как есть (доменное имя).
     */
    private static String extractEmailDomain(String rfc822Name) {
        int at = rfc822Name.lastIndexOf('@');
        return at >= 0 ? rfc822Name.substring(at + 1) : rfc822Name;
    }
}
