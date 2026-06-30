package org.rssys.gost.pkix.cms;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;

/**
 * Построение цепочки сертификатов leaf→root из неупорядоченного набора.
 *
 * <p>Используется {@link CmsSignedDataVerifier} для построения цепочки из
 * сертификатов, извлечённых из CMS SignedData.certificates (SET),
 * и доверенных корневых сертификатов.
 */
public final class CertChainBuilder {

    private CertChainBuilder() {}

    /**
     * Строит цепочку leaf-first от листового сертификата до доверенного корня.
     *
     * <p>Алгоритм:
     * <ol>
     *   <li>Начать с {@code leaf}</li>
     *   <li>Для каждого сертификата найти issuer по совпадению
     *       {@link GostCertificate#getIssuerDnBytes()} → {@link GostCertificate#getSubjectDnBytes()}
     *       в {@code pool}, затем в {@code trustedRoots}</li>
     *   <li>На каждом шаге проверять подпись: {@code current.verifySignature(issuer.getPublicKey())}</li>
     *   <li>Остановиться на self-signed или последнем из {@code trustedRoots}</li>
     * </ol>
     *
     * <p>Защита от DoS:
     * <ul>
     *   <li>{@code visited} Set (по {@code ByteBuffer} subject DN bytes) — предотвращает циклы</li>
     *   <li>лимит глубины {@link CmsConstants#MAX_CERT_CHAIN_LENGTH} — жёсткий потолок</li>
     * </ul>
     *
     * <p>Если в pool несколько сертификатов с одинаковым subject DN (перевыпуск),
     * берётся первый. При коллизии DN, если первый найденный кандидат не проходит
     * проверку подписи, остальные кандидаты с тем же DN не пробуются — верификация
     * завершается ошибкой {@link PkixException.Reason#SIGNATURE_INVALID}.
     * В легитимном сценарии ротации ключей CA это может дать ложноотрицательный
     * результат. Полноценная поддержка (приоритизация по AKI/SKI) —
     * предмет будущего улучшения.
     *
     * @param leaf         листовой сертификат (подписант)
     * @param pool         промежуточные сертификаты из SignedData.certificates
     * @param trustedRoots доверенные корневые сертификаты
     * @return цепочка [leaf, intermediate..., trustedRoot], leaf-first
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

        Set<ByteBuffer> visited = new HashSet<>();
        visited.add(ByteBuffer.wrap(leaf.getSubjectDnBytes()));

        GostCertificate current = leaf;
        int maxDepth = CmsConstants.MAX_CERT_CHAIN_LENGTH;

        while (!current.isSelfSigned()) {
            if (chain.size() >= maxDepth) {
                throw new PkixException(
                        PkixException.Reason.CHAIN_TOO_LONG,
                        "Certificate chain exceeds maximum depth of " + maxDepth);
            }

            byte[] issuerDn = current.getIssuerDnBytes();
            GostCertificate issuer = findBySubjectDn(issuerDn, pool);
            if (issuer == null) {
                issuer = findBySubjectDn(issuerDn, trustedRoots);
            }
            if (issuer == null) {
                throw new PkixException(
                        PkixException.Reason.INCOMPLETE_CHAIN,
                        "Certificate chain: issuer not found in certificates pool or trusted roots");
            }

            ByteBuffer issuerSubjectWrap = ByteBuffer.wrap(issuer.getSubjectDnBytes());
            if (!visited.add(issuerSubjectWrap)) {
                throw new PkixException(
                        PkixException.Reason.CHAIN_LOOP,
                        "Certificate chain: loop detected — duplicate subject DN");
            }

            if (!current.verifySignature(issuer.getPublicKey())) {
                throw new PkixException(
                        PkixException.Reason.SIGNATURE_INVALID,
                        "Certificate chain: signature verification failed for issuer");
            }

            chain.add(issuer);
            current = issuer;
        }

        // Последний сертификат цепочки должен быть среди доверенных корней.
        // Сравнение по полному DER (GostCertificate.equals), а не по subject DN,
        // чтобы исключить подмену корня сертификатом с тем же DN, но чужим ключом.
        GostCertificate last = chain.get(chain.size() - 1);
        if (!trustedRoots.contains(last)) {
            throw new PkixException(
                    PkixException.Reason.ROOT_NOT_TRUSTED,
                    "Certificate chain: root certificate is not among trusted roots");
        }

        return chain;
    }

    private static GostCertificate findBySubjectDn(
            byte[] subjectDnBytes, List<GostCertificate> certs) {
        for (GostCertificate c : certs) {
            if (Arrays.equals(c.getSubjectDnBytes(), subjectDnBytes)) {
                return c;
            }
        }
        return null;
    }
}
