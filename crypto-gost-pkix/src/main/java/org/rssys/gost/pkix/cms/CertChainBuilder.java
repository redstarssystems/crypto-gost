package org.rssys.gost.pkix.cms;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Построение цепочки сертификатов leaf→root из неупорядоченного набора.
 *
 * <p>Используется {@link CmsSignedDataVerifier} для построения цепочки из
 * сертификатов, извлечённых из CMS SignedData.certificates (SET),
 * и доверенных корневых сертификатов.
 */
public final class CertChainBuilder {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.CertChainBuilder");

    private CertChainBuilder() {}

    /**
     * Строит цепочку leaf-first, останавливаясь на локальном сертификате-якоре.
     *
     * <p>Алгоритм на каждом уровне строго в таком порядке:
     * <ol>
     *   <li>{@code current} побайтово равен якорю — цепочка завершена;</li>
     *   <li>{@code current} выпущен якорем — локальный якорь добавляется в конец,
     *       всё присланное выше игнорируется;</li>
     *   <li>только затем выбирается issuer из {@code pool} (и якорей) с приоритетом
     *       AKI/SKI и проверкой подписи.</li>
     * </ol>
     *
     * <p>Порядок важен: если сертификат из подписи и доверенный якорь имеют один
     * subject DN (перевыпущенный корень, закреплённый промежуточный CA), якорь
     * обязан выиграть. Иначе вложенный старый корень с тем же ключом перекрыл бы
     * перевыпущенный и его ограничения/срок перестали бы применяться.</p>
     *
     * <p>Любой сертификат в {@code trustedRoots} — самостоятельный якорь.
     * Ограничения и срок вышестоящих сертификатов для него не наследуются.</p>
     *
     * <p>Поддельный корень с тем же DN/ключом, но чужой подписью не проходит:
     * проверка подписи якорем не удаётся, и цепочка отклоняется.</p>
     *
     * <p>Защита от DoS:
     * <ul>
     *   <li>{@code visited} Set (по {@code ByteBuffer} subject DN bytes) — предотвращает циклы</li>
     *   <li>лимит глубины {@link CmsConstants#MAX_CERT_CHAIN_LENGTH} — жёсткий потолок</li>
     * </ul>
     *
     * <p>Если в pool/trustedRoots несколько сертификатов с одинаковым subject DN
     * (ротация ключей CA), кандидаты приоритизируются по совпадению их SKI с AKI
     * подписываемого сертификата (RFC 5280 §4.2.1.1), затем пробуются остальные с тем
     * же DN — до первого, чью подпись удаётся проверить.
     *
     * <p><b>Ограничение (non-goal):</b> это не полный backtracking по нескольким путям.
     * Если кандидат проходит проверку подписи, но выше по цепочке упирается в
     * {@link PkixException.Reason#INCOMPLETE_CHAIN}, альтернативный кандидат того же
     * уровня, ведущий к доверенному корню, не пробуется. Разрешается только коллизия
     * Subject DN на одном уровне.
     *
     * @param leaf         листовой сертификат (подписант)
     * @param pool         промежуточные сертификаты из SignedData.certificates
     * @param trustedRoots доверенные сертификаты-якоря (корни или промежуточные CA)
     * @return цепочка [leaf, intermediate..., trustedAnchor], leaf-first
     * @throws PkixException при обрыве, цикле или превышении глубины
     */
    public static List<GostCertificate> buildChain(
            GostCertificate leaf, List<GostCertificate> pool, List<GostCertificate> trustedRoots)
            throws PkixException {

        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new PkixException("Trusted roots list must not be null or empty");
        }

        List<GostCertificate> chain = new ArrayList<>();
        chain.add(leaf);

        // Инвариант дедупликации: ByteBuffer.equals/hashCode зависят от [position, limit).
        // ByteBuffer.wrap(fullArray) всегда даёт position=0, поэтому равные DN дают равные
        // ключи. Нельзя вводить slice()/явный position() для этих ключей — иначе тихо
        // сломается обнаружение петли по дублю subject DN.
        Set<ByteBuffer> visited = new HashSet<>();
        visited.add(ByteBuffer.wrap(leaf.getSubjectDnBytes()));

        GostCertificate current = leaf;
        int maxDepth = CmsConstants.MAX_CERT_CHAIN_LENGTH;

        while (true) {
            // Якорь имеет приоритет над любым сертификатом из подписи. DER-сравнение
            // исключает подмену якоря сертификатом с тем же DN/ключом, но другим DER.
            if (trustedRoots.contains(current)) {
                return chain;
            }

            GostCertificate anchor = findAnchorIssuer(current, trustedRoots);
            if (anchor != null) {
                if (chain.size() >= maxDepth) {
                    throw new PkixException(
                            PkixException.Reason.CHAIN_TOO_LONG,
                            "Certificate chain exceeds maximum depth of " + maxDepth);
                }
                chain.add(anchor);
                return chain;
            }

            byte[] issuerDn = current.getIssuerDnBytes();

            // Loop-detection — один раз на уровень глубины (по issuer subject DN),
            // до перебора кандидатов с этим DN. Все кандидаты уровня имеют один subject DN
            // (== issuerDn по построению collectBySubjectDn), поэтому если оставить проверку
            // внутри retry-цикла, второй кандидат при коллизии DN дал бы visited.add()==false
            // и CHAIN_LOOP вместо честной попытки — ровно в сценарии ротации ключей CA.
            if (!visited.add(ByteBuffer.wrap(issuerDn))) {
                throw new PkixException(
                        PkixException.Reason.CHAIN_LOOP,
                        "Certificate chain: loop detected — duplicate subject DN");
            }

            List<GostCertificate> candidates = collectBySubjectDn(issuerDn, pool, trustedRoots);
            // Сам сертификат не может быть своим издателем; иначе self-signed
            // непроверенный корень замкнул бы цепочку на себя.
            candidates.removeIf(current::equals);
            if (candidates.isEmpty()) {
                throw new PkixException(
                        PkixException.Reason.INCOMPLETE_CHAIN,
                        "Certificate chain: issuer not found in certificates pool or trusted roots");
            }

            GostCertificate issuer = selectIssuer(current, candidates);
            if (issuer == null) {
                LOG.log(
                        Level.DEBUG,
                        "No candidate issuer verified for subject={0} ({1} candidate(s) tried)",
                        current.getSubjectDnForLog(GostCertificate.DN_LOG_MAX_CHARS),
                        candidates.size());
                throw new PkixException(
                        PkixException.Reason.SIGNATURE_INVALID,
                        "Certificate chain: signature verification failed for issuer");
            }

            if (chain.size() >= maxDepth) {
                throw new PkixException(
                        PkixException.Reason.CHAIN_TOO_LONG,
                        "Certificate chain exceeds maximum depth of " + maxDepth);
            }
            chain.add(issuer);
            current = issuer;
        }
    }

    /**
     * Ищет якорь, выпустивший {@code cert}.
     *
     * <p>AKI/SKI задаёт только приоритет среди якорей с одинаковым subject DN:
     * при перевыпуске корня SKI может измениться, поэтому окончательное решение
     * принимает проверка подписи.</p>
     */
    private static GostCertificate findAnchorIssuer(
            GostCertificate cert, List<GostCertificate> anchors) {
        byte[] issuerDn = cert.getIssuerDnBytes();
        byte[] aki = cert.getAuthorityKeyIdentifier();
        if (aki != null) {
            for (GostCertificate anchor : anchors) {
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
        for (GostCertificate anchor : anchors) {
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

    private static List<GostCertificate> collectBySubjectDn(
            byte[] subjectDnBytes, List<GostCertificate> pool, List<GostCertificate> trustedRoots) {
        // pool раньше trustedRoots: промежуточные предпочтительнее для построения пути,
        // корень сверяется отдельно (trustedRoots.contains по полному DER) в конце.
        List<GostCertificate> result = new ArrayList<>();
        collectInto(subjectDnBytes, pool, result);
        collectInto(subjectDnBytes, trustedRoots, result);
        return result;
    }

    private static void collectInto(
            byte[] subjectDnBytes, List<GostCertificate> certs, List<GostCertificate> out) {
        for (GostCertificate c : certs) {
            if (Arrays.equals(c.getSubjectDnBytes(), subjectDnBytes)) {
                out.add(c);
            }
        }
    }

    /**
     * Выбирает issuer из кандидатов одного subject DN: сперва по совпадению SKI кандидата
     * с AKI подписываемого сертификата, затем перебором остальных, до первого, чья подпись
     * проверяется. Возвращает {@code null}, если ни один кандидат не подошёл.
     */
    private static GostCertificate selectIssuer(
            GostCertificate current, List<GostCertificate> candidates) {
        for (GostCertificate c : orderByAkiSki(current, candidates)) {
            if (current.verifySignature(c.getPublicKey())) {
                return c;
            }
        }
        return null;
    }

    /**
     * Ставит вперёд кандидатов, чей SKI совпадает с AKI подписываемого сертификата
     * (RFC 5280 §4.2.1.1): при ротации ключей CA с одинаковым Subject DN это указывает
     * на правильный ключ. Если AKI отсутствует или кандидат один — порядок не меняется.
     */
    private static List<GostCertificate> orderByAkiSki(
            GostCertificate current, List<GostCertificate> candidates) {
        byte[] aki = current.getAuthorityKeyIdentifier();
        if (aki == null || candidates.size() == 1) {
            return candidates;
        }
        List<GostCertificate> matched = new ArrayList<>(candidates.size());
        List<GostCertificate> rest = new ArrayList<>(candidates.size());
        for (GostCertificate c : candidates) {
            byte[] ski = c.getSubjectKeyIdentifier();
            if (ski != null && Arrays.equals(ski, aki)) {
                matched.add(c);
            } else {
                rest.add(c);
            }
        }
        matched.addAll(rest);
        return matched;
    }
}
