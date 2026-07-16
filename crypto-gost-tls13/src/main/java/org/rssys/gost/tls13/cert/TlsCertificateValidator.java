package org.rssys.gost.tls13.cert;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.crypto.TlsSignatureCodec;
import org.rssys.gost.tls13.message.TlsEncoding;

/**
 * TLS-обёртка для валидации цепочек сертификатов и CertificateVerify.
 * <p>
 * Делегирует чистую PKIX-валидацию цепочки в {@link ChainValidator},
 * добавляя TLS-специфику: OCSP-степплинг, проверку hostname, KU/EKU в
 * контексте TLS, а также {@link #verifyCertificateVerify(byte[], GostCertificate, byte[], boolean)}.
 * Все PKIX-ошибки ({@link PkixException}) оборачиваются в {@link TlsException}
 * с соответствующим alert-кодом.
 */
public final class TlsCertificateValidator {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.tls13.cert.TlsCertificateValidator");

    private TlsCertificateValidator() {}

    /**
     * Проверяет цепочку сертификатов сервера (RFC 5280, RFC 8446 §4.4.2.2).
     * <p>
     * Включает: expiry, unknown critical extensions, algorithm consistency,
     * hostname (SAN dNSName), KeyUsage.digitalSignature, EKU.serverAuth,
     * опциональный OCSP-степплинг, и валидацию цепочки до CA.
     *
     * @param chain              цепочка leaf-first (leaf = chain[0])
     * @param serverHostname     ожидаемое DNS-имя сервера (null = не проверять)
     * @param requireOcspStapling true — OCSP-ответ обязателен
     * @param caPublicKeys       список доверенных ключей CA (null или пустой = не проверять цепочку;
     *                           OCSP leaf не верифицируется при self-signed chain.size() == 1;
     *                           при chain.size() > 1 OCSP верифицируется ключом issuer-сертификата)
     * @throws TlsException при ошибке валидации
     */
    public static void checkServerCertificateChain(
            List<GostCertificate> chain,
            String serverHostname,
            boolean requireOcspStapling,
            List<PublicKeyParameters> caPublicKeys)
            throws TlsException {
        checkServerCertificateChain(
                chain,
                serverHostname,
                requireOcspStapling,
                caPublicKeys,
                org.rssys.gost.pkix.GostOids.MAX_OCSP_AGE_MS);
    }

    /**
     * Перегрузка {@link #checkServerCertificateChain(List, String, boolean, List)} с
     * настраиваемой политикой свежести OCSP (RFC 6960 §2.4).
     *
     * @param chain              цепочка leaf-first (leaf = chain[0])
     * @param serverHostname     ожидаемое DNS-имя сервера (null = не проверять)
     * @param requireOcspStapling true — OCSP-ответ обязателен
     * @param caPublicKeys       список доверенных ключей CA (null или пустой = не проверять цепочку)
     * @param maxOcspAgeMs       максимальный возраст OCSP-ответа без {@code nextUpdate} в мс
     * @throws TlsException при ошибке валидации
     */
    public static void checkServerCertificateChain(
            List<GostCertificate> chain,
            String serverHostname,
            boolean requireOcspStapling,
            List<PublicKeyParameters> caPublicKeys,
            long maxOcspAgeMs)
            throws TlsException {
        // Defense-in-depth: engine перехватывает пустой chain раньше (receiveCertificate),
        // но IndexOutOfBounds здесь недопустим — RFC 8446 §4.4.2 требует непустой список от
        // сервера.
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Empty server certificate chain");
        }
        GostCertificate leaf = chain.get(0);

        if (leaf.isExpired()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE, "Server certificate expired");
        }
        if (leaf.hasUnknownCriticalExtension()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: unknown critical extension in leaf");
        }
        if (!leaf.isAlgConsistent()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: algorithm mismatch in leaf");
        }
        if (serverHostname != null && !leaf.verifyHostname(serverHostname)) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate hostname mismatch: expected="
                            + serverHostname
                            + ", certificate SAN="
                            + Arrays.toString(leaf.getSanDnsNames()));
        }
        if (!leaf.isKeyUsageValid()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate KeyUsage missing digitalSignature");
        }
        if (!leaf.isEkuValidForServer()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate ExtendedKeyUsage missing serverAuth");
        }
        if (requireOcspStapling && !leaf.hasOcspResponse()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Server did not provide OCSP stapling response");
        }
        boolean hasCaKeys = caPublicKeys != null && !caPublicKeys.isEmpty();
        if (leaf.hasOcspResponse()) {
            GostCertificate issuer = chain.size() > 1 ? chain.get(1) : null;
            if (issuer != null) {
                TlsCertUtils.verifyOcspResponse(leaf, issuer, maxOcspAgeMs);
            } else if (requireOcspStapling) {
                throw new TlsException(
                        TlsConstants.ALERT_BAD_CERTIFICATE,
                        "OCSP stapling required but no issuer certificate available"
                                + " for verification");
            } else {
                LOG.log(
                        Level.WARNING,
                        "OCSP response present but no issuer certificate available"
                                + " — skipping verification");
            }
        }

        // OCSP для intermediate сертификатов: fail-closed.
        // Невалидный OCSP-ответ прерывает handshake — TlsException не перехватывается намеренно.
        // RFC 6960 не обязывает проверять OCSP для intermediate в TLS, но если ответ есть —
        // он должен быть корректным.
        for (int i = 1; i < chain.size() - 1; i++) {
            GostCertificate ic = chain.get(i);
            if (ic.hasOcspResponse()) {
                TlsCertUtils.verifyOcspResponse(ic, chain.get(i + 1), maxOcspAgeMs);
            }
        }

        if (hasCaKeys) {
            validateChain(chain, caPublicKeys);
        }
    }

    /**
     * Проверяет цепочку сертификатов клиента (mTLS, RFC 8446 §4.4.2.2).
     * <p>
     * Включает: expiry, unknown critical extensions, algorithm consistency,
     * KeyUsage.digitalSignature, EKU.clientAuth, и валидацию цепочки до CA.
     *
     * @param chain        цепочка leaf-first (leaf = chain[0])
     * @param caPublicKeys список доверенных ключей CA (null или пустой = не проверять цепочку)
     * @throws TlsException при ошибке валидации
     */
    public static void checkClientCertificateChain(
            List<GostCertificate> chain, List<PublicKeyParameters> caPublicKeys)
            throws TlsException {
        checkClientCertificateChain(
                chain, caPublicKeys, org.rssys.gost.pkix.GostOids.MAX_OCSP_AGE_MS);
    }

    /**
     * Перегрузка {@link #checkClientCertificateChain(List, List)} с настраиваемой
     * политикой свежести OCSP (RFC 6960 §2.4).
     *
     * @param chain        цепочка leaf-first (leaf = chain[0])
     * @param caPublicKeys список доверенных ключей CA (null или пустой = не проверять цепочку)
     * @param maxOcspAgeMs максимальный возраст OCSP-ответа без {@code nextUpdate} в мс
     * @throws TlsException при ошибке валидации
     */
    public static void checkClientCertificateChain(
            List<GostCertificate> chain, List<PublicKeyParameters> caPublicKeys, long maxOcspAgeMs)
            throws TlsException {
        // Defense-in-depth: engine перехватывает пустой chain раньше (receiveClientCertificate),
        // но если сюда дойдёт пустой список — IndexOutOfBounds недопустим.
        // certificate_required семантически корректен: сервер требует сертификат клиента.
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_CERTIFICATE_REQUIRED, "Empty client certificate chain");
        }
        GostCertificate leaf = chain.get(0);

        if (leaf.isExpired()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE, "Client certificate expired");
        }
        if (leaf.hasUnknownCriticalExtension()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: unknown critical extension");
        }
        if (!leaf.isAlgConsistent()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE, "Client certificate: algorithm mismatch");
        }
        if (!leaf.isKeyUsageValid()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: KeyUsage missing digitalSignature");
        }
        if (!leaf.isEkuValidForClient()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: ExtendedKeyUsage missing clientAuth");
        }

        // Верификация stapled-OCSP клиента, симметрично серверному пути.
        // Без сети: проверяется только уже присланный в CertificateEntry ответ.
        // Если ответ есть — он обязан быть корректным (fail-closed); отсутствие ответа
        // не является ошибкой (активный fetch клиентского OCSP вне скоупа tls13-слоя).
        if (leaf.hasOcspResponse()) {
            GostCertificate issuer = chain.size() > 1 ? chain.get(1) : null;
            if (issuer != null) {
                TlsCertUtils.verifyOcspResponse(leaf, issuer, maxOcspAgeMs);
            } else {
                LOG.log(
                        Level.WARNING,
                        "Client OCSP response present but no issuer certificate available"
                                + " — skipping verification");
            }
        }

        if (caPublicKeys != null && !caPublicKeys.isEmpty()) {
            validateChain(chain, caPublicKeys);
        }
    }

    /**
     * Валидирует цепочку сертификатов: подписи, DN, CA-флаги, pathLen.
     * <p>
     * Обходит цепочку от leaf (i=0) до root (i=n-1), проверяя на каждом шаге:
     * <ul>
     *   <li>срок действия каждого сертификата</li>
     *   <li>подпись cert[i] ключом cert[i+1]</li>
     *   <li>IssuerDN(cert[i]) == SubjectDN(cert[i+1])</li>
     *   <li>CA-флаг и pathLen на intermediate: remaining = i-1 (количество
     *       intermediate CA между cert[i] и leaf; n-i-2 считало бы к root)</li>
     *   <li>algorithm consistency и unknown critical extensions</li>
     * </ul>
     * Root-сертификат верифицируется переданным {@code caPublicKeys}.
     *
     * @param chain        цепочка leaf-first
     * @param caPublicKeys список доверенных ключей CA (не пустой, не null)
     * @throws TlsException при ошибке валидации цепочки
     */
    public static void validateChain(
            List<GostCertificate> chain, List<PublicKeyParameters> caPublicKeys)
            throws TlsException {
        try {
            ChainValidator.validateChain(chain, caPublicKeys);
        } catch (PkixException e) {
            int alert;
            switch (e.reason()) {
                case EXPIRED:
                    alert = TlsConstants.ALERT_CERTIFICATE_EXPIRED;
                    break;
                case ROOT_NOT_SIGNED:
                    alert = TlsConstants.ALERT_UNKNOWN_CA;
                    break;
                default:
                    alert = TlsConstants.ALERT_BAD_CERTIFICATE;
            }
            throw new TlsException((byte) alert, e.getMessage());
        }
    }

    /**
     * Проверяет CertificateVerify (RFC 8446 §4.4.3, RFC 9367 §3.2).
     * <p>
     * Извлекает схему подписи, подпись, строит sigContent через
     * {@link TlsEncoding#buildSigContent(byte[], String)} и верифицирует
     * хеш через {@link TlsSignatureCodec#verify(byte[], byte[], PublicKeyParameters, int)}.
     *
     * @param cvBody       тело CertificateVerify
     * @param cert         сертификат для проверки подписи
     * @param hsTranscript транскрипт handshake-сообщений
     * @param isServer     true — серверный CertificateVerify, false — клиентский
     * @throws IOException при ошибке верификации
     */
    public static void verifyCertificateVerify(
            byte[] cvBody, GostCertificate cert, byte[] hsTranscript, boolean isServer)
            throws IOException {
        verifyCertificateVerify(cvBody, cert, hsTranscript, isServer, false);
    }

    /**
     * Перегрузка с флагом совместимости openssl-gost-provider.
     *
     * @see #verifyCertificateVerify(byte[], GostCertificate, byte[], boolean)
     */
    public static void verifyCertificateVerify(
            byte[] cvBody,
            GostCertificate cert,
            byte[] hsTranscript,
            boolean isServer,
            boolean interopAcceptGostBaseSigScheme)
            throws IOException {
        if (cvBody.length < 4) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "CertificateVerify body too short: " + cvBody.length);
        }
        int scheme = ((cvBody[0] & 0xFF) << 8) | (cvBody[1] & 0xFF);
        if (!TlsCertUtils.hasSignatureScheme(
                cert.getPublicKey(), scheme, interopAcceptGostBaseSigScheme)) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate key type does not match signature scheme " + scheme);
        }
        if (interopAcceptGostBaseSigScheme) {
            int certNamedGroup = TlsCiphersuite.paramsToNamedGroup(cert.getPublicKey().getParams());
            int expectedScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
            if (scheme != expectedScheme) {
                LOG.log(
                        Level.WARNING,
                        "interopAcceptGostBaseSigScheme: server sent scheme 0x"
                                + Integer.toHexString(scheme)
                                + " (expected 0x"
                                + Integer.toHexString(expectedScheme)
                                + ") — known openssl-gost-provider incompatibility");
            }
        }
        int sigLen = ((cvBody[2] & 0xFF) << 8) | (cvBody[3] & 0xFF);
        if (4 + sigLen > cvBody.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "CertificateVerify: sigLen " + sigLen + " exceeds message body");
        }
        byte[] sig = Arrays.copyOfRange(cvBody, 4, 4 + sigLen);

        String context =
                isServer
                        ? TlsConstants.SERVER_CERTIFICATE_VERIFY_CTX
                        : TlsConstants.CLIENT_CERTIFICATE_VERIFY_CTX;
        byte[] sigContent = TlsEncoding.buildSigContent(hsTranscript, context);

        int sigHashLen = cert.getPublicKey().getParams().hlen;
        Digest d = HkdfStreebog.newDigest(sigHashLen);
        d.update(sigContent, 0, sigContent.length);
        byte[] hash = new byte[sigHashLen];
        d.doFinal(hash, 0);
        int rolen = sigHashLen;
        if (!TlsSignatureCodec.verify(hash, sig, cert.getPublicKey(), rolen)) {
            LOG.log(
                    Level.WARNING,
                    "CertificateVerify signature verification failed: subject={0}",
                    cert.getSubjectDnForLog(128));
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "CertificateVerify signature verification failed");
        }
    }
}
