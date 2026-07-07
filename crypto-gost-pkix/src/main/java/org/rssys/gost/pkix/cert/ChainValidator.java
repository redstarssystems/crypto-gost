package org.rssys.gost.pkix.cert;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Чистая PKIX-валидация цепочек сертификатов (RFC 5280).
 * <p>
 * Проверяет цепочку доверия: подписи, DN-совпадения, CA-флаги,
 * pathLen, NameConstraints, срок действия, algorithm consistency,
 * known critical extensions, опционально — CertificatePolicies leaf-сертификата.
 * <p>
 * Не содержит TLS-специфики (алертов, CertificateVerify).
 * Все ошибки — {@link PkixException} (checked).
 * <p>
 * Не проверяет статус отзыва сертификатов (CRL/OCSP).
 * Для полной проверки с отзывом используйте {@link #validateChainWithRevocation}
 * или вызывайте {@link CrlVerifier} / {@link OcspVerifier} отдельно после этого метода.
 */
public final class ChainValidator {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.ChainValidator");

    private ChainValidator() {}

    /**
     * Валидирует цепочку сертификатов: подписи, DN, CA-флаги, pathLen.
     * <p>
     * Обходит цепочку от leaf (i=0) до root (i=n-1), проверяя на каждом шаге:
     * <ul>
     *   <li>срок действия каждого сертификата</li>
     *   <li>подпись cert[i] ключом cert[i+1]</li>
     *   <li>IssuerDN(cert[i]) == SubjectDN(cert[i+1])</li>
     *   <li>CA-флаг и pathLen на intermediate</li>
     *   <li>algorithm consistency и known critical extensions</li>
     *   <li>Name Constraints (RFC 5280 §4.2.1.10) — root-to-leaf проход,
     *       включая ограничения trust anchor</li>
     * </ul>
     * Root-сертификат верифицируется переданным {@code caPublicKeys}.
     *
     * @param chain        цепочка leaf-first
     * @param caPublicKeys список доверенных ключей CA (не пустой, не null)
     * @throws PkixException при ошибке валидации цепочки
     */
    private static final int MAX_CERT_CHAIN_LENGTH = 10;

    public static void validateChain(
            List<GostCertificate> chain, List<PublicKeyParameters> caPublicKeys)
            throws PkixException {
        validateChain(chain, caPublicKeys, (String[]) null);
    }

    /**
     * Валидирует цепочку сертификатов с опциональной проверкой политик leaf-сертификата.
     * <p>
     * <b>Важно:</b> это <b>не</b> RFC 5280 §6.1 policy validation. Проверяется только
     * leaf-сертификат (первый в цепочке). Промежуточные CA, PolicyMappings,
     * PolicyConstraints, InhibitAnyPolicy не обрабатываются.
     * <p>
     * Если {@code requiredPolicyOids} пуст или {@code null} — проверка политик
     * не выполняется, поведение идентично {@link #validateChain(List, List)}.
     * <p>
     * Сертификат считается удовлетворяющим требованиям политики, если:
     * <ul>
     *   <li>его CertificatePolicies содержат хотя бы один OID из
     *       {@code requiredPolicyOids}, или</li>
     *   <li>его CertificatePolicies содержат anyPolicy
     *       ({@link GostOids#ANY_POLICY}, 2.5.29.32.0)</li>
     * </ul>
     * Если расширение CertificatePolicies отсутствует у leaf-сертификата —
     * {@link PkixException.Reason#POLICY_VIOLATION}.
     *
     * @param chain              цепочка leaf-first
     * @param caPublicKeys       список доверенных ключей CA (не пустой, не null)
     * @param requiredPolicyOids требуемые OID политик в точечной нотации.
     *                           {@code null} или пустой массив — проверка политик не выполняется
     * @throws PkixException при ошибке валидации цепочки или несоответствии политик
     */
    public static void validateChain(
            List<GostCertificate> chain,
            List<PublicKeyParameters> caPublicKeys,
            String... requiredPolicyOids)
            throws PkixException {
        int n = chain.size();
        if (n < 1) {
            throw new PkixException(
                    "Certificate chain: empty chain — at least one certificate required");
        }
        if (n > MAX_CERT_CHAIN_LENGTH) {
            throw new PkixException(
                    PkixException.Reason.CHAIN_TOO_LONG,
                    "Certificate chain exceeds maximum depth of " + MAX_CERT_CHAIN_LENGTH);
        }
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
        // RFC 5280 §3.2: trust anchor — CA-флаг и keyCertSign не проверяются.
        // Валидность определяется присутствием в доверенных caPublicKeys,
        // а не значениями расширений сертификата.
        // Проверка pathLen на root-сертификате (RFC 5280 §6.1 — trust anchor
        // должен соблюдать ограничение, даже если он последний в цепочке)
        int rootPl = root.getPathLen();
        if (rootPl >= 0) {
            int remaining = countFollowingNonSelfIssuedCA(chain, n - 1);
            if (remaining > rootPl) {
                throw new PkixException(
                        PkixException.Reason.PATH_LEN_EXCEEDED,
                        "Certificate chain: pathLen constraint exceeded at root");
            }
        }
        if (root.isExpired()) {
            throw new PkixException(
                    PkixException.Reason.EXPIRED,
                    "Certificate chain: root is expired or not yet valid");
        }
        boolean rootVerified = false;
        for (PublicKeyParameters key : caPublicKeys) {
            if (root.verifySignature(key)) {
                rootVerified = true;
                break;
            }
        }
        if (!rootVerified) {
            throw new PkixException(
                    PkixException.Reason.ROOT_NOT_SIGNED,
                    "Certificate chain: root not signed by any trusted CA");
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
        // Обход root-to-leaf: ограничения накапливаются от доверенного якоря вниз,
        // включая NameConstraints самого trust anchor.
        validateNameConstraintsPass(chain);
        LOG.log(
                Level.DEBUG,
                "Certificate chain validation passed (leaf serial=0x{0})",
                chain.get(0).getSerialNumberBigInt().toString(16));
    }

    /**
     * Валидирует цепочку сертификатов вместе с проверкой статуса отзыва (OCSP/CRL).
     * <p>
     * Сначала выполняет PKIX-валидацию цепочки (вызов {@link #validateChain(List, List)}),
     * затем для каждого сертификата, кроме trust anchor, проверяет статус отзыва
     * из предоставленных данных:
     * <ol>
     *   <li>Если предоставлен OCSP-ответ — проверка через
     *       {@link OcspVerifier#verify(byte[], byte[], GostCertificate)}</li>
     *   <li>Иначе если предоставлен CRL — проверка через
     *       {@link CrlVerifier#verify(byte[], byte[], PublicKeyParameters, byte[])}</li>
     *   <li>Иначе — сертификат пропускается (warn-лог, не ошибка)</li>
     * </ol>
     * <p>
     * <b>null в {@code revocationData} означает пропуск проверки отзыва для этого
     * сертификата — ответственность на вызывающем.</b>
     * Если вызывающий передаёт null-записи для всех сертификатов,
     * метод вырождается в обычный {@link #validateChain} без проверки отзыва.
     * <p>
     * Приоритет OCSP над CRL соответствует RFC 5280 и принятому в проекте паттерну
     * (см. {@code GostX509TrustManager.checkCrl()}).
     * <p>
     * Не поддерживает delegated CRL signer, delegated OCSP responder, nonce-проверку,
     * delta CRL — для этих случаев используйте {@link CrlVerifier} / {@link OcspVerifier}
     * напрямую с полными сигнатурами.
     *
     * @param chain           цепочка leaf-first
     * @param caPublicKeys    доверенные ключи CA
     * @param revocationData  данные отзыва, параллельно chain; null-элемент означает «нет данных для этого индекса»
     * @throws PkixException          при ошибке валидации цепочки или обнаружении отзыва
     * @throws IllegalArgumentException если revocationData.size() != chain.size()
     */
    public static void validateChainWithRevocation(
            List<GostCertificate> chain,
            List<PublicKeyParameters> caPublicKeys,
            List<CertRevocationData> revocationData)
            throws PkixException {
        validateChain(chain, caPublicKeys);

        int n = chain.size();
        if (revocationData == null) {
            throw new IllegalArgumentException("revocationData must not be null");
        }
        if (revocationData.size() != n) {
            throw new IllegalArgumentException(
                    "revocationData size ("
                            + revocationData.size()
                            + ") must match chain size ("
                            + n
                            + ")");
        }

        for (int i = 0; i < n - 1; i++) {
            CertRevocationData rd = revocationData.get(i);
            if (rd == null) {
                LOG.log(
                        Level.WARNING,
                        "No revocation data for cert chain[{0}], serial=0x{1}",
                        i,
                        chain.get(i).getSerialNumberBigInt().toString(16));
                continue;
            }

            GostCertificate cert = chain.get(i);
            GostCertificate issuer = chain.get(i + 1);

            if (rd.ocspResponse() != null) {
                OcspVerifier.verify(rd.ocspResponse(), cert.getSerialNumber(), issuer);
            } else {
                CrlVerifier.verify(
                        rd.crlDer(),
                        cert.getSerialNumber(),
                        issuer.getPublicKey(),
                        cert.getIssuerDnBytes());
            }
        }

        LOG.log(
                Level.DEBUG,
                "Certificate chain validation with revocation passed (leaf serial=0x{0})",
                chain.get(0).getSerialNumberBigInt().toString(16));
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
     * Ограничения накапливаются от trust anchor вниз по цепочке
     * (включая NameConstraints самого root-сертификата). На каждом не-self-issued
     * сертификате проверяются накопленные ограничения, затем аккумулируются новые.
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
            if (i < n - 1 && !cert.isSelfIssued()) {
                checkCertAgainstConstraints(cert, accumulated);
            }

            // Накопление ограничений из этого сертификата (только для CA, кроме leaf).
            if (i > 0) {
                NameConstraintsData nc = cert.getNameConstraints();
                if (!nc.isEmpty()) {
                    if (nc.nonCritical) {
                        throw new PkixException(
                                "Certificate chain: NameConstraints must be critical"
                                        + " (RFC 5280 §4.2.1.10) at cert["
                                        + i
                                        + "]");
                    }
                    if (nc.hasUnsupportedNameType) {
                        // БЕЗОПАСНОСТЬ: это WARNING, а не reject, только пока
                        // GostCertificate НЕ экспонирует accessor'ы для
                        // rfc822Name / URI / otherName из SAN.
                        // parseSanGeneralNames() извлекает лишь dNSName [2] и
                        // iPAddress [7]. Если в будущем добавят getSanEmails() /
                        // getSanUris() / etc. — это место обязано быть
                        // пересмотрено на предмет enforcement.
                        LOG.log(
                                Level.WARNING,
                                "Certificate chain: NameConstraints contains unsupported"
                                        + " GeneralName type at cert["
                                        + i
                                        + "];"
                                        + " constraints of this type are ignored"
                                        + " (leaf SAN does not expose these name forms)");
                    }
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
     * Проверяет SAN (dNSName, iPAddress) сертификата против списка накопленных ограничений.
     * Каждый набор из accumulated должен быть удовлетворён (AND-семантика между уровнями CA).
     */
    private static void checkCertAgainstConstraints(
            GostCertificate cert, List<NameConstraintsData> accumulated) throws PkixException {
        if (accumulated.isEmpty()) {
            return;
        }

        String[] sanDnsNames = cert.getSanDnsNames();
        byte[][] sanIps = cert.getSanIpAddresses();

        for (NameConstraintsData nc : accumulated) {
            // Permitted: ограничение применяется только к присутствующим SAN того же типа.
            // Если SAN нужного типа отсутствует — vacuously satisfied (RFC 5280).
            if (nc.permittedDnsNames != null
                    && nc.permittedDnsNames.length > 0
                    && sanDnsNames != null) {
                boolean matched = false;
                for (String san : sanDnsNames) {
                    if (isDnsNameInPermitted(san, nc.permittedDnsNames)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    throw new PkixException(
                            "Certificate chain: SAN dNSName not in permitted subtrees");
                }
            }
            if (nc.permittedIps != null && nc.permittedIps.length > 0 && sanIps != null) {
                boolean matched = false;
                for (byte[] san : sanIps) {
                    if (isIpInSubtrees(san, nc.permittedIps)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    throw new PkixException(
                            "Certificate chain: SAN iPAddress not in permitted subtrees");
                }
            }

            // Excluded: ограничение применяется только к присутствующим SAN того же типа.
            if (nc.excludedDnsNames != null && sanDnsNames != null) {
                for (String san : sanDnsNames) {
                    if (isDnsNameInPermitted(san, nc.excludedDnsNames)) {
                        throw new PkixException(
                                "Certificate chain: SAN dNSName in excluded subtrees");
                    }
                }
            }
            if (nc.excludedIps != null && sanIps != null) {
                for (byte[] san : sanIps) {
                    if (isIpInSubtrees(san, nc.excludedIps)) {
                        throw new PkixException(
                                "Certificate chain: SAN iPAddress in excluded subtrees");
                    }
                }
            }
        }
    }

    /**
     * Label-aware suffix matching для dNSName.
     * <p>
     * Имя "host.example.com" матчит constraint "example.com" (точка-граница),
     * но "notexample.com" не матчит. Точное совпадение тоже считается match.
     */
    static boolean isDnsNameInPermitted(String name, String[] constraints) {
        String lower = name.toLowerCase();
        for (String c : constraints) {
            if (lower.equals(c)) {
                return true;
            }
            if (lower.endsWith("." + c)) {
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
}
