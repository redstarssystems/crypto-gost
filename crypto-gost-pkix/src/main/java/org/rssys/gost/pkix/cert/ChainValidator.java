package org.rssys.gost.pkix.cert;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Чистая PKIX-валидация цепочек сертификатов (RFC 5280).
 * <p>
 * Проверяет цепочку доверия: подписи, DN-совпадения, CA-флаги,
 * pathLen, срок действия, algorithm consistency, known critical extensions.
 * <p>
 * Не содержит TLS-специфики (алертов, CertificateVerify).
 * Все ошибки — {@link PkixException} (checked).
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
     * </ul>
     * Root-сертификат верифицируется переданным {@code caPublicKeys}.
     *
     * @param chain        цепочка leaf-first
     * @param caPublicKeys список доверенных ключей CA (не пустой, не null)
     * @throws PkixException при ошибке валидации цепочки
     */
    public static void validateChain(
            List<GostCertificate> chain, List<PublicKeyParameters> caPublicKeys)
            throws PkixException {
        int n = chain.size();
        if (n < 1) {
            throw new PkixException(
                    "Certificate chain: empty chain — at least one certificate required");
        }
        LOG.log(
                Level.INFO,
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
        LOG.log(
                Level.INFO,
                "Certificate chain validation passed (leaf serial=0x{0})",
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
}
