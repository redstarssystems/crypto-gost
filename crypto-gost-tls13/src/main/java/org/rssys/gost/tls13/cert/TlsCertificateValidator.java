package org.rssys.gost.tls13.cert;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.crypto.TlsSignatureCodec;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

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

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.tls13.cert.TlsCertificateValidator");

    /**
     * Режим совместимости включён локально, а расхождение схем повторяется на каждом
     * рукопожатии. Одна запись на процесс: иначе журнал заполняется одинаковыми WARNING.
     */
    private static final java.util.concurrent.atomic.AtomicBoolean INTEROP_WARNING_LOGGED =
            new java.util.concurrent.atomic.AtomicBoolean();

    private TlsCertificateValidator() {}

    /**
     * Полная проверка сертификата партнёра: leaf (срок, KeyUsage, EKU, hostname для сервера),
     * PKIX-цепочка до якорей и присланный OCSP-staple.
     *
     * @param chain  peer-цепочка leaf-first
     * @param policy политика с якорями
     * @return эффективная цепочка leaf-first
     * @throws TlsException при ошибке проверки
     * @throws IllegalStateException если политика создана без якорей
     */
    public static List<GostCertificate> validate(List<GostCertificate> chain, TlsPeerPolicy policy)
            throws TlsException {
        List<GostCertificate> effective = validateStructure(chain, policy);
        validateRevocation(effective, policy);
        return effective;
    }

    /**
     * Проверяет структуру и leaf-свойства без OCSP/CRL: leaf (срок, KeyUsage, EKU, hostname) и
     * PKIX-цепочку до якорей.
     *
     * <p>Стадийность нужна JSSE: сетевая загрузка отзыва выполняется только после этой проверки,
     * чтобы битая цепочка не вызывала запросов к сети. Возвращённую эффективную цепочку используют
     * для загрузки отзыва и затем передают в {@link #validateRevocation}.</p>
     *
     * @param chain  peer-цепочка leaf-first
     * @param policy политика с якорями
     * @return эффективная цепочка leaf-first
     * @throws TlsException при ошибке структуры или PKIX-валидации
     * @throws IllegalStateException если политика создана без якорей
     */
    public static List<GostCertificate> validateStructure(
            List<GostCertificate> chain, TlsPeerPolicy policy) throws TlsException {
        requireChain(chain, policy);
        TrustAnchors anchors = policy.requiredAnchors();
        // Leaf эффективной цепочки - это leaf пира, поэтому его свойства проверяются до
        // построения цепочки; так якорь не достраивается и подписи не проверяются дважды.
        checkLeafStructure(chain, policy);
        try {
            return ChainValidator.validateChain(chain, anchors);
        } catch (PkixException e) {
            throw toTlsException(e);
        }
    }

    /**
     * Проверяет только отзыв по уже присланным OCSP-ответам цепочки. Ничего не загружает из сети;
     * вызывать после {@link #validateStructure}.
     *
     * <p>Присланный staple проверяется всегда; при {@link TlsPeerPolicy#requireOcspStaple(boolean)}
     * его отсутствие для leaf даёт {@code bad_certificate}. Staple leaf без издателя в цепочке
     * (закреплённый одиночный сертификат) игнорируется с предупреждением, если staple не
     * обязателен, и отвергается, если обязателен. Для промежуточных сертификатов присланный
     * ответ проверяется всегда (fail-closed).</p>
     *
     * @param chain  эффективная цепочка leaf-first
     * @param policy политика (обязательность staple и возраст ответа)
     * @throws TlsException если staple обязателен, но отсутствует, или невалиден
     */
    public static void validateRevocation(List<GostCertificate> chain, TlsPeerPolicy policy)
            throws TlsException {
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        if (policy.isServer()) {
            checkServerRevocation(
                    chain,
                    policy.requiresOcspStaple(),
                    policy.maxOcspAgeMs(),
                    policy.maxThisUpdateAge());
        } else {
            checkClientRevocation(
                    chain,
                    policy.requiresOcspStaple(),
                    policy.maxOcspAgeMs(),
                    policy.maxThisUpdateAge());
        }
    }

    /**
     * Проверяет только leaf-сертификат, без проверки цепочки: leaf-свойства и присланный staple.
     *
     * <p>Предназначен для явного небезопасного режима (политики {@code serverLeafOnly} и
     * {@code clientLeafOnly}); политику с якорями принимает, якоря при этом не используются.</p>
     *
     * @param chain  цепочка leaf-first (leaf = chain[0])
     * @param policy политика
     * @throws TlsException при ошибке проверки
     */
    public static void validateLeafOnly(List<GostCertificate> chain, TlsPeerPolicy policy)
            throws TlsException {
        requireChain(chain, policy);
        checkLeafStructure(chain, policy);
        validateRevocation(chain, policy);
    }

    private static void requireChain(List<GostCertificate> chain, TlsPeerPolicy policy)
            throws TlsException {
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        if (chain == null || chain.isEmpty()) {
            // Серверная пустая цепочка - ошибка разбора (RFC 8446 §4.4.2), клиентская - сервер
            // требует сертификат.
            throw policy.isServer()
                    ? new TlsException(
                            TlsConstants.ALERT_DECODE_ERROR, "Empty server certificate chain")
                    : new TlsException(
                            TlsConstants.ALERT_CERTIFICATE_REQUIRED,
                            "Empty client certificate chain");
        }
    }

    private static void checkLeafStructure(List<GostCertificate> chain, TlsPeerPolicy policy)
            throws TlsException {
        if (policy.isServer()) {
            checkServerCertificateLeafStructure(chain, policy.serverHostname());
        } else {
            checkClientCertificateLeafStructure(chain);
        }
    }

    private static void checkServerRevocation(
            List<GostCertificate> chain,
            boolean requireOcspStapling,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws TlsException {
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Empty server certificate chain");
        }
        GostCertificate leaf = chain.get(0);
        if (requireOcspStapling && !leaf.hasOcspResponse()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Server did not provide OCSP stapling response");
        }
        if (leaf.hasOcspResponse()) {
            GostCertificate issuer = chain.size() > 1 ? chain.get(1) : null;
            if (issuer != null) {
                TlsCertUtils.verifyOcspResponse(leaf, issuer, maxOcspAgeMs, maxThisUpdateAge);
            } else if (requireOcspStapling) {
                throw new TlsException(
                        TlsConstants.ALERT_BAD_CERTIFICATE,
                        "OCSP stapling required but no issuer certificate available"
                                + " for verification");
            } else {
                // Данные собеседника: он сам присылает staple, WARNING заполнялся бы
                // на каждом соединении. Отказ (если политика строгая) идёт исключением.
                LOG.log(
                        Level.DEBUG,
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
                TlsCertUtils.verifyOcspResponse(
                        ic, chain.get(i + 1), maxOcspAgeMs, maxThisUpdateAge);
            }
        }
    }

    private static void checkServerCertificateLeafStructure(
            List<GostCertificate> chain, String serverHostname) throws TlsException {
        // Defense-in-depth: engine перехватывает пустой chain раньше (receiveCertificate),
        // но IndexOutOfBounds здесь недопустим — RFC 8446 §4.4.2 требует непустой список от
        // сервера.
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR, "Empty server certificate chain");
        }
        GostCertificate leaf = chain.get(0);

        if (leaf.isExpired()) {
            // RFC 8446 §6.2: просроченный сертификат - certificate_expired, как и у промежуточных
            throw new TlsException(
                    TlsConstants.ALERT_CERTIFICATE_EXPIRED, "Server certificate expired");
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
    }

    private static void checkClientRevocation(
            List<GostCertificate> chain,
            boolean requireOcspStapling,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws TlsException {
        // Defense-in-depth: engine перехватывает пустой chain раньше (receiveClientCertificate),
        // но если сюда дойдёт пустой список — IndexOutOfBounds недопустим.
        // certificate_required семантически корректен: сервер требует сертификат клиента.
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_CERTIFICATE_REQUIRED, "Empty client certificate chain");
        }
        GostCertificate leaf = chain.get(0);
        if (requireOcspStapling && !leaf.hasOcspResponse()) {
            throw new TlsException(
                    TlsConstants.ALERT_BAD_CERTIFICATE,
                    "Client did not provide OCSP stapling response");
        }
        if (leaf.hasOcspResponse()) {
            GostCertificate issuer = chain.size() > 1 ? chain.get(1) : null;
            if (issuer != null) {
                TlsCertUtils.verifyOcspResponse(leaf, issuer, maxOcspAgeMs, maxThisUpdateAge);
            } else if (requireOcspStapling) {
                throw new TlsException(
                        TlsConstants.ALERT_BAD_CERTIFICATE,
                        "Client OCSP response present but no issuer certificate available");
            } else {
                LOG.log(
                        Level.DEBUG,
                        "Client OCSP response present but no issuer certificate available"
                                + " — skipping verification");
            }
        }

        // OCSP для intermediate сертификатов: fail-closed, если ответ прислан.
        for (int i = 1; i < chain.size() - 1; i++) {
            GostCertificate ic = chain.get(i);
            if (ic.hasOcspResponse()) {
                TlsCertUtils.verifyOcspResponse(
                        ic, chain.get(i + 1), maxOcspAgeMs, maxThisUpdateAge);
            }
        }
    }

    private static void checkClientCertificateLeafStructure(List<GostCertificate> chain)
            throws TlsException {
        if (chain == null || chain.isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_CERTIFICATE_REQUIRED, "Empty client certificate chain");
        }
        GostCertificate leaf = chain.get(0);

        if (leaf.isExpired()) {
            // RFC 8446 §6.2: просроченный сертификат - certificate_expired, как и у промежуточных
            throw new TlsException(
                    TlsConstants.ALERT_CERTIFICATE_EXPIRED, "Client certificate expired");
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
    }

    private static TlsException toTlsException(PkixException e) {
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
        // Исходное исключение остаётся причиной. Отзыв здесь не возникает: проверка цепочки его
        // не выдаёт, его выдают проверки OCSP и CRL (см. TlsCertUtils.verifyOcspResponse)
        return new TlsException((byte) alert, e.getMessage(), e);
    }

    /**
     * Проверяет CertificateVerify (RFC 8446 §4.4.3, RFC 9367 §3.2).
     * <p>
     * Извлекает схему подписи, подпись, строит sigContent через
     * {@link TlsEncoding#buildSigContent(byte[], String)} и верифицирует
     * хеш через {@link TlsSignatureCodec#verify(
     *     byte[], byte[], org.rssys.gost.signature.PublicKeyParameters, int)}.
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
        if (cvBody.length < TlsConstants.CERTIFICATE_VERIFY_HEADER_SIZE) {
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
            if (scheme != expectedScheme && INTEROP_WARNING_LOGGED.compareAndSet(false, true)) {
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
        if (TlsConstants.CERTIFICATE_VERIFY_HEADER_SIZE + sigLen > cvBody.length) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "CertificateVerify: sigLen " + sigLen + " exceeds message body");
        }
        byte[] sig =
                Arrays.copyOfRange(
                        cvBody,
                        TlsConstants.CERTIFICATE_VERIFY_HEADER_SIZE,
                        TlsConstants.CERTIFICATE_VERIFY_HEADER_SIZE + sigLen);

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
            // В предупреждении только серийный номер: WARNING включён по умолчанию, а DN
            // квалифицированного сертификата клиента несёт ФИО, СНИЛС и ИНН. DN доступен на DEBUG
            LOG.log(
                    Level.WARNING,
                    "CertificateVerify signature verification failed: serial=0x{0}",
                    cert.getSerialNumberBigInt().toString(16));
            if (LOG.isLoggable(Level.DEBUG)) {
                LOG.log(
                        Level.DEBUG,
                        "CertificateVerify signature verification failed: subject={0}",
                        cert.getSubjectDnForLog(GostCertificate.DN_LOG_MAX_CHARS));
            }
            // RFC 8446 §4.4.3: неверная подпись - decrypt_error, а не bad_certificate: сам
            // сертификат может быть в порядке, не сошлась подпись рукопожатия
            throw new TlsException(
                    TlsConstants.ALERT_DECRYPT_ERROR,
                    "CertificateVerify signature verification failed");
        }
    }
}
