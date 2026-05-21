package org.rssys.gost.tls13.cert;

import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.crypto.TlsSignatureCodec;
import org.rssys.gost.tls13.message.TlsEncoding;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Валидация цепочек сертификатов и CertificateVerify (RFC 5280, RFC 8446 §4.4.2.2).
 * <p>
 * Вынесена из {@link TlsSession} для unit-тестирования и возможной замены.
 * <p>
 * Все методы package-private — вызываются только из {@code TlsSession}.
 */
public final class TlsCertificateValidator {

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
     * @param caPublicKeys       список доверенных ключей CA (null или пустой = не проверять цепочку)
     * @throws TlsException при ошибке валидации
     */
    public static void checkServerCertificateChain(List<TlsCertificate> chain,
                                              String serverHostname,
                                              boolean requireOcspStapling,
                                              List<PublicKeyParameters> caPublicKeys) throws TlsException {
        TlsCertificate leaf = chain.get(0);

        if (leaf.isExpired()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Server certificate expired");
        }
        if (leaf.hasUnknownCriticalExtension()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: unknown critical extension in leaf");
        }
        if (!leaf.isAlgConsistent()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: algorithm mismatch in leaf");
        }
        if (serverHostname != null && !leaf.verifyHostname(serverHostname)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate hostname mismatch: " + serverHostname);
        }
        if (!leaf.isKeyUsageValid()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate KeyUsage missing digitalSignature");
        }
        if (!leaf.isEkuValidForServer()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate ExtendedKeyUsage missing serverAuth");
        }
        if (requireOcspStapling && !leaf.hasOcspResponse()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Server did not provide OCSP stapling response");
        }
        boolean hasCaKeys = caPublicKeys != null && !caPublicKeys.isEmpty();
        if (leaf.hasOcspResponse() && hasCaKeys) {
            PublicKeyParameters ocspKey = chain.size() > 1
                    ? chain.get(1).getPublicKey()
                    : caPublicKeys.get(0);
            TlsCertificate issuer = chain.size() > 1 ? chain.get(1) : null;
            try {
                leaf.verifyOcspResponse(ocspKey, issuer);
            } catch (TlsException e) {
                // Если подпись OCSP не совпала с issuer-ключом — пробуем
                // делегированные responder-сертификаты из поля certs BasicOCSPResponse
                List<byte[]> delegatedCerts = TlsOcspVerifier.extractDelegatedCerts(
                        leaf.getOcspResponse());
                if (!delegatedCerts.isEmpty()) {
                    boolean verified = false;
                    for (byte[] dcDer : delegatedCerts) {
                        TlsCertificate dc = new TlsCertificate(dcDer);
                        // 4 pre-checks для delegated responder (RFC 6960 §4.2.2.2):
                        // дёшево → дорого: validity, EKU, KU, signature
                        if (dc.isExpired()) continue;
                        if (!dc.isOcspSigning()) continue;
                        if (!dc.isKeyUsageValid()) continue;
                        boolean delegValid;
                        if (issuer != null) {
                            delegValid = dc.verify(issuer.getPublicKey());
                        } else {
                            delegValid = false;
                            for (PublicKeyParameters k : caPublicKeys) {
                                if (dc.verify(k)) { delegValid = true; break; }
                            }
                        }
                        if (!delegValid) continue;
                        PublicKeyParameters dcKey = dc.getPublicKey();
                        try {
                            leaf.verifyOcspResponse(dcKey, issuer);
                            verified = true;
                            break;
                        } catch (TlsException ignored) {
                            // Пробуем следующий cert
                        }
                    }
                    if (!verified) throw e; // Ни один delegated cert не подошёл
                } else {
                    throw e; // Нет delegated certs — перевыбрасываем оригинальную ошибку
                }
            }
        }

        // OCSP для intermediate сертификатов: fail-closed.
        // Невалидный OCSP-ответ прерывает handshake — TlsException не перехватывается намеренно.
        // RFC 6960 не обязывает проверять OCSP для intermediate в TLS, но если ответ есть —
        // он должен быть корректным.
        for (int i = 1; i < chain.size() - 1; i++) {
            TlsCertificate ic = chain.get(i);
            if (ic.hasOcspResponse()) {
                TlsCertificate icIssuer = chain.get(i + 1);
                ic.verifyOcspResponse(icIssuer.getPublicKey(), icIssuer);
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
    public static void checkClientCertificateChain(List<TlsCertificate> chain,
                                               List<PublicKeyParameters> caPublicKeys) throws TlsException {
        // Defense-in-depth: engine перехватывает пустой chain раньше (receiveClientCertificate),
        // но если сюда дойдёт пустой список — IndexOutOfBounds недопустим.
        // certificate_required семантически корректен: сервер требует сертификат клиента.
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(TlsConstants.ALERT_CERTIFICATE_REQUIRED,
                    "Empty client certificate chain");
        }
        TlsCertificate leaf = chain.get(0);

        if (leaf.isExpired()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate expired");
        }
        if (leaf.hasUnknownCriticalExtension()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: unknown critical extension");
        }
        if (!leaf.isAlgConsistent()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: algorithm mismatch");
        }
        if (!leaf.isKeyUsageValid()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: KeyUsage missing digitalSignature");
        }
        if (!leaf.isEkuValidForClient()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client certificate: ExtendedKeyUsage missing clientAuth");
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
    public static void validateChain(List<TlsCertificate> chain,
                                List<PublicKeyParameters> caPublicKeys) throws TlsException {
        int n = chain.size();
        for (int i = 0; i < n - 1; i++) {
            TlsCertificate cert = chain.get(i);
            if (cert.isExpired()) {
                throw new TlsException(TlsConstants.ALERT_CERTIFICATE_EXPIRED,
                        "Certificate chain: cert[" + i + "] is expired or not yet valid");
            }
            TlsCertificate issuer = chain.get(i + 1);
            if (!cert.verify(issuer.getPublicKey())) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: cert[" + i + "] signature verification failed");
            }
            if (!Arrays.equals(cert.getIssuerDnBytes(), issuer.getSubjectDnBytes())) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: DN mismatch at cert[" + i + "]");
            }
            if (i > 0 && !cert.isCA()) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: cert[" + i + "] is not a CA");
            }
            if (i > 0 && !cert.isKeyCertSignSet()) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: cert[" + i + "] missing keyCertSign");
            }
            int pl = cert.getPathLen();
            // i-1: сколько intermediate CA между cert[i] и leaf[0]
            // (n-i-2 было бы неверно — считает CAs к root, не к leaf)
            int remaining = i - 1;
            if (pl >= 0 && remaining > pl) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: pathLen constraint exceeded at cert[" + i + "]");
            }
            if (!cert.isAlgConsistent()) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: algorithm mismatch at cert[" + i + "]");
            }
            if (cert.hasUnknownCriticalExtension()) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Certificate chain: unknown critical extension at cert[" + i + "]");
            }
        }
        TlsCertificate root = chain.get(n - 1);
        if (root.isExpired()) {
            throw new TlsException(TlsConstants.ALERT_CERTIFICATE_EXPIRED,
                    "Certificate chain: root is expired or not yet valid");
        }
        boolean rootVerified = false;
        for (PublicKeyParameters key : caPublicKeys) {
            if (root.verify(key)) { rootVerified = true; break; }
        }
        if (!rootVerified) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: root not signed by any trusted CA");
        }
        if (!root.isAlgConsistent()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: algorithm mismatch at root");
        }
        if (root.hasUnknownCriticalExtension()) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate chain: unknown critical extension at root");
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
    public static void verifyCertificateVerify(byte[] cvBody, TlsCertificate cert,
                                          byte[] hsTranscript,
                                          boolean isServer) throws IOException {
        int scheme = ((cvBody[0] & 0xFF) << 8) | (cvBody[1] & 0xFF);
        if (!cert.hasSignatureScheme(scheme)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Certificate key type does not match signature scheme " + scheme);
        }
        int sigLen = ((cvBody[2] & 0xFF) << 8) | (cvBody[3] & 0xFF);
        byte[] sig = Arrays.copyOfRange(cvBody, 4, 4 + sigLen);

        String context = isServer
                ? TlsConstants.SERVER_CERTIFICATE_VERIFY_CTX
                : TlsConstants.CLIENT_CERTIFICATE_VERIFY_CTX;
        byte[] sigContent = TlsEncoding.buildSigContent(hsTranscript, context);

        int sigHashLen = cert.getPublicKey().getParams().hlen;
        Digest d = sigHashLen == 64 ? new Streebog512() : new Streebog256();
        d.update(sigContent, 0, sigContent.length);
        byte[] hash = new byte[sigHashLen];
        d.doFinal(hash, 0);
        int rolen = sigHashLen;
        if (!TlsSignatureCodec.verify(hash, sig, cert.getPublicKey(), rolen)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "CertificateVerify signature verification failed");
        }
    }
}
